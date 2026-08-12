// crates/ql-cli/src/otlp.rs
//
//! Export the audit chain as OTLP logs, for ingestion by an existing
//! observability stack.
//!
//! ## What this is, and deliberately is not
//!
//! This is an **exporter**, not a backend. There is no dashboard, no storage,
//! and no query layer here, and there should not be: that would mean competing
//! with Datadog, Grafana, and Splunk on their own ground with a solo team.
//! Emitting OTLP means feeding the stack a team already runs instead.
//!
//! ## Why hand-rolled rather than the OpenTelemetry SDK
//!
//! The SDK brings a large dependency tree, a tokio runtime, and a background
//! export pipeline — all to serialize a bounded, already-durable file into
//! JSON. QuantmLayer's audit log is not live telemetry: it is a
//! hash-chained record on disk that is complete before this code runs, so
//! there is nothing to batch, retry, or flush. Writing the OTLP JSON directly
//! keeps the exporter at zero new dependencies and keeps `ql` a single static
//! binary, which is the property that makes the install path work at all.
//!
//! The output is OTLP/HTTP JSON exactly as a collector's `/v1/logs` endpoint
//! accepts it, so it is delivered by `curl`, by the collector's `filelog`
//! receiver, or by whatever the operator already uses to ship files.
//!
//! ## What the telemetry is worth
//!
//! Application-layer tracing records what an agent *said* it did — the tool
//! calls it declared. These records are what it actually did: every exec, every
//! endpoint, as observed by the kernel. The two disagree more often than is
//! comfortable, and the disagreement is the interesting signal.
//!
//! ## Fidelity limit
//!
//! An exported copy is no longer tamper-evident. The chain's integrity lives in
//! `prev_hash`/`hash` over the whole sequence; once records are reshaped into
//! OTLP and land in a system that reorders, samples, or drops them, that
//! property is gone. Each record therefore carries its own hash and sequence as
//! attributes so an investigator can come back to the original log and verify
//! there — the export is a lead, and the chain stays the evidence.

use ql_audit::{AuditRecord, Decision};

/// The instrumentation scope name reported in the OTLP payload.
const SCOPE: &str = "quantmlayer";

/// Escape a string for embedding in JSON. Hand-rolled to match the rest of
/// this module's no-new-dependency stance; `serde_json` is already available
/// and is used for the structural work, but attribute values funnel through
/// here so that agent-chosen bytes cannot break the document.
fn esc(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

/// One OTLP key/value attribute.
fn attr(key: &str, value: &str) -> String {
    format!(
        "{{\"key\":{},\"value\":{{\"stringValue\":{}}}}}",
        esc(key),
        esc(value)
    )
}

/// One OTLP integer attribute.
fn attr_int(key: &str, value: u64) -> String {
    format!(
        "{{\"key\":{},\"value\":{{\"intValue\":\"{}\"}}}}",
        esc(key),
        value
    )
}

/// Map a decision to an OTLP severity.
///
/// A denial is `WARN`, not `ERROR`: it is the system working as configured,
/// and a wall of ERRORs for correct behaviour would train an operator to mute
/// the whole stream. Field traces routinely show an agent probing something it
/// turns out not to need.
fn severity(d: &Decision) -> (u32, &'static str) {
    match d {
        Decision::Allow => (9, "INFO"),
        Decision::Deny => (13, "WARN"),
        Decision::Info => (9, "INFO"),
    }
}

/// Render `records` as an OTLP/HTTP logs payload.
///
/// `host` and `cell_id` become resource attributes when supplied, so records
/// from different machines or cells stay distinguishable after ingestion.
pub fn render(records: &[AuditRecord], host: Option<&str>, cell_id: Option<&str>) -> String {
    let mut resource_attrs = vec![
        attr("service.name", "quantmlayer"),
        attr("telemetry.sdk.name", "quantmlayer"),
        attr("telemetry.sdk.language", "rust"),
    ];
    if let Some(h) = host {
        resource_attrs.push(attr("host.name", h));
    }
    if let Some(c) = cell_id {
        resource_attrs.push(attr("quantmlayer.cell.id", c));
    }

    let mut log_records = Vec::with_capacity(records.len());
    for r in records {
        let (sev_num, sev_text) = severity(&r.event.decision);
        let decision = match r.event.decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Info => "info",
        };

        let mut attrs = vec![
            attr("quantmlayer.actor", &r.event.actor),
            attr("quantmlayer.action", &r.event.action),
            attr("quantmlayer.target", &r.event.target),
            attr("quantmlayer.decision", decision),
            // Sequence and hash travel with each record so an investigator can
            // return to the source log and verify the chain there. The export
            // itself cannot carry that guarantee.
            attr_int("quantmlayer.seq", r.seq),
            attr("quantmlayer.record_hash", &r.hash),
        ];
        if !r.event.detail.is_empty() {
            attrs.push(attr("quantmlayer.detail", &r.event.detail));
        }
        // EU AI Act Article 12 actor identity, when the log carries it.
        if let Some(sys) = &r.event.system {
            attrs.push(attr("quantmlayer.system.kind", &sys.kind));
            attrs.push(attr("quantmlayer.system.id", &sys.system_id));
            if let Some(mv) = &sys.model_version {
                attrs.push(attr("quantmlayer.system.model_version", mv));
            }
        }

        log_records.push(format!(
            "{{\"timeUnixNano\":\"{}\",\"observedTimeUnixNano\":\"{}\",\
             \"severityNumber\":{},\"severityText\":{},\
             \"body\":{{\"stringValue\":{}}},\"attributes\":[{}]}}",
            r.event.ts_millis.saturating_mul(1_000_000),
            r.event.ts_millis.saturating_mul(1_000_000),
            sev_num,
            esc(sev_text),
            esc(&format!(
                "{} {} {}",
                r.event.action, decision, r.event.target
            )),
            attrs.join(",")
        ));
    }

    format!(
        "{{\"resourceLogs\":[{{\"resource\":{{\"attributes\":[{}]}},\
         \"scopeLogs\":[{{\"scope\":{{\"name\":{}}},\"logRecords\":[{}]}}]}}]}}",
        resource_attrs.join(","),
        esc(SCOPE),
        log_records.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ql_audit::{AuditEvent, AuditLog};

    fn log_with(events: Vec<(&str, &str, &str, Decision, &str)>) -> Vec<AuditRecord> {
        let mut log = AuditLog::new();
        for (actor, action, target, decision, detail) in events {
            log.append(AuditEvent {
                ts_millis: 1_700_000_000_000,
                actor: actor.into(),
                action: action.into(),
                target: target.into(),
                decision,
                detail: detail.into(),
                system: None,
            })
            .unwrap();
        }
        log.records().to_vec()
    }

    /// The payload is valid JSON in OTLP's logs shape, with one logRecord per
    /// audit record. A collector rejects the whole batch on a malformed
    /// document, so this is the property everything else rests on.
    #[test]
    fn renders_a_well_formed_otlp_logs_document() {
        let recs = log_with(vec![
            (
                "broker",
                "egress.connect",
                "pypi.org:443",
                Decision::Allow,
                "",
            ),
            (
                "broker",
                "egress.connect",
                "pastebin.com:443",
                Decision::Deny,
                "host not in allow-list",
            ),
        ]);
        let out = render(&recs, Some("box-1"), Some("cell-abc"));
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

        let logs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(logs.as_array().unwrap().len(), 2);
        assert_eq!(v["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"], SCOPE);

        // Nanosecond timestamps, as OTLP requires — milliseconds would be off
        // by a factor of a million and land every record at the epoch.
        assert_eq!(logs[0]["timeUnixNano"], "1700000000000000000");
    }

    /// A denial is WARN, not ERROR. Denials are the system working; a stream
    /// of ERRORs for correct behaviour gets muted, and then the one that
    /// mattered is muted too.
    #[test]
    fn a_denial_is_a_warning_not_an_error() {
        let recs = log_with(vec![
            ("broker", "egress.connect", "a:443", Decision::Allow, ""),
            ("broker", "egress.connect", "b:443", Decision::Deny, ""),
            ("run", "session.start", "cell", Decision::Info, ""),
        ]);
        let v: serde_json::Value = serde_json::from_str(&render(&recs, None, None)).unwrap();
        let logs = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(logs[0]["severityText"], "INFO");
        assert_eq!(logs[1]["severityText"], "WARN");
        assert_eq!(logs[1]["severityNumber"], 13);
        assert_eq!(logs[2]["severityText"], "INFO");
    }

    /// Sequence and record hash travel with every record, so an exported copy
    /// points back at the chain that can actually be verified.
    #[test]
    fn every_record_carries_its_seq_and_hash_back_to_the_chain() {
        let recs = log_with(vec![(
            "exec",
            "exec.run",
            "abc",
            Decision::Allow,
            "pid 1 (sh)",
        )]);
        let v: serde_json::Value = serde_json::from_str(&render(&recs, None, None)).unwrap();
        let attrs = v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();

        let get = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .unwrap_or_else(|| panic!("missing attribute {k}"))
                .clone()
        };
        assert_eq!(get("quantmlayer.seq")["value"]["intValue"], "0");
        assert_eq!(
            get("quantmlayer.record_hash")["value"]["stringValue"],
            recs[0].hash
        );
        assert_eq!(
            get("quantmlayer.detail")["value"]["stringValue"],
            "pid 1 (sh)"
        );
    }

    /// **Injection defense.** Targets and details are agent-chosen strings; a
    /// quote or newline in one must not break the document, or a contained
    /// agent could forge log records in whatever ingests this.
    #[test]
    fn agent_chosen_strings_cannot_break_the_document() {
        let hostile = "evil\",\"injected\":\"yes\n\r\t\\ end";
        let recs = log_with(vec![(
            "broker",
            "egress.connect",
            hostile,
            Decision::Deny,
            hostile,
        )]);
        let out = render(&recs, Some(hostile), None);

        // Still parses, and the hostile text stayed a value rather than
        // becoming structure.
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("valid JSON despite hostile input");
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert!(rec["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["key"] != "injected"));
        let target = rec["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == "quantmlayer.target")
            .unwrap();
        assert_eq!(target["value"]["stringValue"], hostile);
    }

    /// An empty log still produces a valid (empty) batch rather than malformed
    /// JSON — a collector should get "nothing happened", not a parse error.
    #[test]
    fn an_empty_log_is_still_a_valid_batch() {
        let v: serde_json::Value = serde_json::from_str(&render(&[], None, None)).unwrap();
        assert_eq!(
            v["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}
