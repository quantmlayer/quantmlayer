// crates/ql-cli/src/mcp_gateway.rs
//
//! # MCP inspection gateway (feature B, bounded half)
//!
//! A stateful inspection layer for the MCP JSON-RPC stream. MCP servers
//! aggregate credentials for DBs/CRMs/dev tools and enforce **no** security at
//! the protocol layer, so a rug-pulled or buggy server can issue malformed or
//! dangerous tool calls. This module adds two deterministic checks on
//! `tools/call` messages, reusing the position `ql mcp wrap` already gives us in
//! the JSON-RPC path:
//!
//! 1. **Schema validation** — validate a `tools/call`'s `arguments` against the
//!    tool's declared input schema (advertised by the server in `tools/list`).
//!    Out-of-contract calls (unknown tool, missing required arg, wrong type) are
//!    rejected before the host model executes them.
//! 2. **State-change gating** — a profile-declared policy classifies methods/
//!    tools as state-changing and either allows or gates them. Gated calls are
//!    blocked fail-closed and audited. This is a *capability wall for MCP tools*
//!    — the same deterministic shape as the exec/network walls, not a semantic
//!    "is this call wise" judgment (that half stays explicitly out of scope).
//!
//! Everything here is **pure and deterministic** so it is unit-testable without
//! a live server; the proxy shell (reading stdio, forwarding messages) is a thin
//! layer over these decisions.

use serde_json::{Map, Value};
use std::collections::HashMap;

/// A tool's declared interface, as advertised by an MCP server in `tools/list`.
/// We keep only what we validate against.
#[derive(Debug, Clone)]
pub struct ToolSchema {
    /// Tool name (the `name` in a `tools/call`).
    pub name: String,
    /// Names of required arguments (from the JSON Schema `required` array).
    pub required: Vec<String>,
    /// Declared property name -> JSON Schema primitive type ("string",
    /// "number", "integer", "boolean", "object", "array"). Properties not
    /// listed are unconstrained. Empty = no property typing available.
    pub properties: HashMap<String, String>,
    /// If false, arguments not in `properties` are rejected (JSON Schema
    /// `additionalProperties: false`). Defaults to true (permissive) when the
    /// server does not declare it.
    pub additional_properties: bool,
}

impl ToolSchema {
    /// Parse a single tool object from a `tools/list` result into a [`ToolSchema`].
    /// Returns `None` if it has no name. Missing/loose schema fields degrade to
    /// permissive (we validate what the server declared, nothing more).
    pub fn from_tool_json(tool: &Value) -> Option<ToolSchema> {
        let name = tool.get("name")?.as_str()?.to_string();
        let input = tool.get("inputSchema").or_else(|| tool.get("input_schema"));
        let mut required = Vec::new();
        let mut properties = HashMap::new();
        let mut additional_properties = true;
        if let Some(schema) = input {
            if let Some(req) = schema.get("required").and_then(Value::as_array) {
                required = req
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (k, v) in props {
                    if let Some(t) = v.get("type").and_then(Value::as_str) {
                        properties.insert(k.clone(), t.to_string());
                    } else {
                        // property with no declared type: record it as known but
                        // unconstrained so additionalProperties=false still allows it.
                        properties.insert(k.clone(), String::new());
                    }
                }
            }
            if let Some(ap) = schema.get("additionalProperties").and_then(Value::as_bool) {
                additional_properties = ap;
            }
        }
        Some(ToolSchema {
            name,
            required,
            properties,
            additional_properties,
        })
    }
}

/// The outcome of inspecting one `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the call to the server unchanged.
    Allow,
    /// Reject the call; the reason is safe to surface and to audit.
    Deny(String),
}

impl Verdict {
    #[cfg(test)]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Deny(r) => Some(r),
            Verdict::Allow => None,
        }
    }
}

/// The gateway's policy: which tools are known (schemas) and how state-change
/// gating is configured. Built from `tools/list` plus the profile.
#[derive(Debug, Clone, Default)]
pub struct GatewayPolicy {
    /// Known tool schemas by name (populated from `tools/list`).
    pub tools: HashMap<String, ToolSchema>,
    /// If true, a `tools/call` for a tool NOT in `tools` is denied (fail-closed
    /// on unknown tools). If false, unknown tools are allowed (schema unknown ⇒
    /// unchecked). Default true: fail closed.
    pub deny_unknown_tools: bool,
    /// Whether the server has advertised its tools yet (a `tools/list` response
    /// was seen). Until this is true, "unknown tool" means "not learned yet",
    /// NOT "does not exist" — so unknown-tool denial is suppressed to avoid a
    /// startup race blocking legitimate calls. A server that never advertises
    /// tools leaves this false and unknown-tool checks stay open (there is
    /// nothing to validate against).
    pub schemas_loaded: bool,
    /// Tools/methods explicitly gated as state-changing: a call to one of these
    /// is denied unless it also appears in [`Self::allow_state_change`].
    pub gate_state_change: Vec<String>,
    /// Tools pre-authorized to perform state changes (the allow-list that opens
    /// a gate). A gated tool here is allowed; a gated tool not here is denied.
    pub allow_state_change: Vec<String>,
}

impl GatewayPolicy {
    /// A permissive-schema, fail-closed-on-unknown default.
    pub fn new() -> Self {
        GatewayPolicy {
            tools: HashMap::new(),
            deny_unknown_tools: true,
            schemas_loaded: false,
            gate_state_change: Vec::new(),
            allow_state_change: Vec::new(),
        }
    }

    /// Load tool schemas from a `tools/list` JSON-RPC *result* value (the object
    /// containing a `tools` array). Returns how many schemas were loaded. Marks
    /// schemas as loaded when a `tools` array is present (even if empty), so the
    /// unknown-tool gate activates only after the server has spoken.
    pub fn load_tools_from_list_result(&mut self, result: &Value) -> usize {
        let mut n = 0;
        if let Some(tools) = result.get("tools").and_then(Value::as_array) {
            self.schemas_loaded = true;
            for t in tools {
                if let Some(schema) = ToolSchema::from_tool_json(t) {
                    self.tools.insert(schema.name.clone(), schema);
                    n += 1;
                }
            }
        }
        n
    }

    /// Is `tool` gated as state-changing without being allowed?
    fn is_blocked_state_change(&self, tool: &str) -> bool {
        self.gate_state_change.iter().any(|g| g == tool)
            && !self.allow_state_change.iter().any(|a| a == tool)
    }
}

/// Inspect a parsed `tools/call` (its `name` and `arguments`) against the
/// policy. Pure and total: same inputs always give the same verdict.
///
/// Order of checks (first failure wins, most specific first):
/// 1. state-change gate (policy intent is highest priority),
/// 2. unknown-tool fail-closed,
/// 3. schema validation (required args, types, additionalProperties).
pub fn inspect_tools_call(policy: &GatewayPolicy, name: &str, arguments: &Value) -> Verdict {
    // 1. State-change gating — a deterministic capability wall for MCP tools.
    if policy.is_blocked_state_change(name) {
        return Verdict::Deny(format!(
            "tool `{name}` is gated as state-changing and not in the allow-list"
        ));
    }

    // 2. Unknown tool: fail closed if configured (default) — but only once the
    // server has actually advertised its tools. Before that, an unknown tool
    // means "not learned yet", not "does not exist"; denying then would be a
    // startup race that blocks legitimate calls.
    let Some(schema) = policy.tools.get(name) else {
        return if policy.deny_unknown_tools && policy.schemas_loaded {
            Verdict::Deny(format!(
                "tool `{name}` is not in the server's advertised tool list"
            ))
        } else {
            Verdict::Allow
        };
    };

    // 3. Schema validation. Arguments must be an object (or absent → empty).
    let empty = Map::new();
    let args = match arguments {
        Value::Object(m) => m,
        Value::Null => &empty,
        _ => return Verdict::Deny(format!("tool `{name}` arguments must be a JSON object")),
    };

    // 3a. Required arguments present.
    for req in &schema.required {
        if !args.contains_key(req) {
            return Verdict::Deny(format!("tool `{name}` missing required argument `{req}`"));
        }
    }

    // 3b. Declared-type checks + additionalProperties.
    for (key, val) in args {
        match schema.properties.get(key) {
            Some(ty) if !ty.is_empty() => {
                if !json_type_matches(ty, val) {
                    return Verdict::Deny(format!(
                        "tool `{name}` argument `{key}` should be {ty}, got {}",
                        json_type_name(val)
                    ));
                }
            }
            Some(_) => { /* declared but untyped: accept */ }
            None => {
                if !schema.additional_properties {
                    return Verdict::Deny(format!(
                        "tool `{name}` has unexpected argument `{key}` (additionalProperties: false)"
                    ));
                }
            }
        }
    }

    Verdict::Allow
}

/// Does a JSON value match a JSON Schema primitive type name? `integer` accepts
/// only whole numbers; `number` accepts any number.
fn json_type_matches(ty: &str, val: &Value) -> bool {
    match ty {
        "string" => val.is_string(),
        "number" => val.is_number(),
        "integer" => val.is_i64() || val.is_u64(),
        "boolean" => val.is_boolean(),
        "object" => val.is_object(),
        "array" => val.is_array(),
        "null" => val.is_null(),
        _ => true, // unknown declared type: don't second-guess the server
    }
}

fn json_type_name(val: &Value) -> &'static str {
    match val {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::Null => "null",
    }
}

/// Extract `(name, arguments)` from a JSON-RPC `tools/call` request. Returns
/// `None` if the message is not a well-formed `tools/call`. The proxy calls this
/// to decide whether a message needs inspection at all.
pub fn parse_tools_call(msg: &Value) -> Option<(String, Value)> {
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = msg.get("params")?;
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    Some((name, arguments))
}

// ---------------------------------------------------------------------------
// Live proxy shell — a thin layer over the pure logic above.
// ---------------------------------------------------------------------------

use std::io::{BufRead, Write};
use std::process::ExitCode;

/// `ql mcp gateway [--gate <tool>]... [--allow <tool>]... [--open] -- <server cmd...>`
///
/// Spawn the real MCP server and sit in the JSON-RPC stream between it and the
/// client (stdin = from client, stdout = to client). Learn tool schemas from
/// the server's `tools/list` responses; inspect each `tools/call` from the
/// client with [`inspect_tools_call`]. Denied calls never reach the server — the
/// gateway replies with a JSON-RPC error in their place.
///
/// This is the bounded, deterministic half of feature B. It is a *capability
/// wall for MCP tools*, not a semantic judge.
pub fn cmd(args: &[String]) -> ExitCode {
    // Parse options up to `--`, then the server command after it.
    let mut policy = GatewayPolicy::new();
    let mut it = args.iter();
    let mut server_cmd: Vec<String> = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gate" => {
                if let Some(t) = it.next() {
                    policy.gate_state_change.push(t.clone());
                }
            }
            "--allow" => {
                if let Some(t) = it.next() {
                    policy.allow_state_change.push(t.clone());
                }
            }
            "--open" => policy.deny_unknown_tools = false,
            "--" => {
                server_cmd = it.by_ref().cloned().collect();
                break;
            }
            other => {
                eprintln!("ql mcp gateway: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    if server_cmd.is_empty() {
        eprintln!(
            "usage: ql mcp gateway [--gate <tool>]... [--allow <tool>]... [--open] -- <server cmd...>"
        );
        return ExitCode::from(2);
    }

    match run_proxy(policy, &server_cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ql mcp gateway: {e}");
            ExitCode::from(1)
        }
    }
}

/// A JSON-RPC error reply standing in for a denied `tools/call`, echoing the
/// original request id so the client correlates it. Uses code -32001 (server
/// error range) with the deny reason.
fn deny_reply(id: &Value, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": -32001,
            "message": format!("blocked by ql mcp gateway: {reason}")
        }
    })
}

/// Drive the proxy. Spawns the server, relays server→client on a thread, and
/// inspects client→server on the main thread. Returns the server's exit code.
fn run_proxy(policy: GatewayPolicy, server_cmd: &[String]) -> std::io::Result<ExitCode> {
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    let mut child = Command::new(&server_cmd[0])
        .args(&server_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut to_server = child.stdin.take().expect("piped stdin");
    let from_server = child.stdout.take().expect("piped stdout");
    let mut reader = std::io::BufReader::new(from_server);

    // Shared policy: the server→client thread updates tool schemas from
    // `tools/list` results; the client→server loop reads them for inspection.
    let policy = Arc::new(Mutex::new(policy));

    // --- Proactive schema handshake (closes the startup race) ------------
    // Before relaying any client traffic, the gateway asks the server for its
    // tools itself and blocks until it learns them. This guarantees schemas are
    // loaded before any client `tools/call` is inspected, so the unknown-tool
    // and schema checks are enforced from the very first call — not dependent on
    // the client happening to send `tools/list` first.
    //
    // Any server responses read during the handshake that are NOT our tools/list
    // reply are buffered and flushed to the client before normal relay begins,
    // so nothing the server said is lost.
    let mut buffered_for_client: Vec<String> = Vec::new();
    {
        // Use a distinctive id unlikely to collide with the client's.
        let handshake_id = "__ql_gateway_tools_list__";
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": handshake_id, "method": "tools/list"
        });
        writeln!(to_server, "{req}")?;
        to_server.flush()?;

        // Read until we see the reply to our handshake id (schemas learned) or
        // the server closes. Bound the wait so a server that never answers
        // tools/list cannot hang the gateway forever: after a fixed number of
        // non-matching lines we give up and proceed (schemas stay unloaded →
        // unknown-tool checks stay open, which is the documented safe default).
        let mut lines_scanned = 0;
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break; // server closed during handshake
            }
            let trimmed = line.trim_end().to_string();
            if let Ok(v) = serde_json::from_str::<Value>(&trimmed) {
                let is_our_reply = v.get("id").and_then(Value::as_str) == Some(handshake_id);
                if is_our_reply {
                    if let Some(result) = v.get("result") {
                        let loaded = {
                            let mut p = policy.lock().unwrap();
                            p.load_tools_from_list_result(result)
                        };
                        eprintln!("ql mcp gateway: learned {loaded} tool schema(s) at startup");
                    }
                    break; // handshake complete
                }
                // Some other server message (e.g. a log/notification): buffer it
                // to forward to the client, and if it happens to carry tools,
                // learn from it too.
                if let Some(result) = v.get("result") {
                    let mut p = policy.lock().unwrap();
                    p.load_tools_from_list_result(result);
                }
            }
            buffered_for_client.push(trimmed);
            lines_scanned += 1;
            if lines_scanned > 100 {
                eprintln!(
                    "ql mcp gateway: server did not answer tools/list; proceeding (unknown-tool checks open)"
                );
                break;
            }
        }
    }

    // server → client relay (continues learning schemas from any later
    // tools/list results too). First flush anything buffered during handshake.
    let policy_srv = Arc::clone(&policy);
    let relay = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        {
            let mut out = stdout.lock();
            for line in &buffered_for_client {
                let _ = writeln!(out, "{line}");
            }
            let _ = out.flush();
        }
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if let Some(result) = v.get("result") {
                    let loaded = {
                        let mut p = policy_srv.lock().unwrap();
                        p.load_tools_from_list_result(result)
                    };
                    if loaded > 0 {
                        eprintln!("ql mcp gateway: learned {loaded} tool schema(s)");
                    }
                }
            }
            let mut out = stdout.lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    });

    // client → server: inspect each tools/call before forwarding.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let parsed: Option<Value> = serde_json::from_str(&line).ok();
        if let Some(msg) = &parsed {
            if let Some((name, arguments)) = parse_tools_call(msg) {
                let verdict = {
                    let p = policy.lock().unwrap();
                    inspect_tools_call(&p, &name, &arguments)
                };
                if let Verdict::Deny(reason) = verdict {
                    // Do not forward. Reply to the client with an error instead.
                    let id = msg.get("id").cloned().unwrap_or(Value::Null);
                    let reply = deny_reply(&id, &reason);
                    let mut out = stdout.lock();
                    let _ = writeln!(out, "{reply}");
                    let _ = out.flush();
                    eprintln!("ql mcp gateway: DENIED tools/call `{name}` — {reason}");
                    continue;
                }
            }
        }
        // Allowed (or not a tools/call): forward verbatim.
        writeln!(to_server, "{line}")?;
        to_server.flush()?;
    }

    // Client closed: close server stdin, wait for both to finish.
    drop(to_server);
    let status = child.wait()?;
    let _ = relay.join();
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy_with_writer() -> GatewayPolicy {
        let mut p = GatewayPolicy::new();
        p.load_tools_from_list_result(&json!({
            "tools": [
                {
                    "name": "read_file",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "delete_file",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                }
            ]
        }));
        p
    }

    #[test]
    fn loads_tool_schemas() {
        let p = policy_with_writer();
        assert_eq!(p.tools.len(), 2);
        assert!(p.tools.contains_key("read_file"));
        assert_eq!(p.tools["read_file"].required, vec!["path"]);
        assert!(!p.tools["read_file"].additional_properties);
    }

    #[test]
    fn valid_call_is_allowed() {
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "read_file", &json!({ "path": "/etc/hosts" }));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn missing_required_arg_is_denied() {
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "read_file", &json!({}));
        assert!(matches!(v, Verdict::Deny(_)));
        assert!(v.reason().unwrap().contains("required argument `path`"));
    }

    #[test]
    fn wrong_type_is_denied() {
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "read_file", &json!({ "path": 123 }));
        assert!(v.reason().unwrap().contains("should be string"));
    }

    #[test]
    fn additional_property_denied_when_schema_is_strict() {
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "read_file", &json!({ "path": "/x", "sneaky": "extra" }));
        assert!(v.reason().unwrap().contains("unexpected argument `sneaky`"));
    }

    #[test]
    fn additional_property_allowed_when_schema_is_permissive() {
        // delete_file declared no additionalProperties:false → permissive.
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "delete_file", &json!({ "path": "/x", "force": true }));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn unknown_tool_is_fail_closed_by_default() {
        let p = policy_with_writer();
        let v = inspect_tools_call(&p, "exfiltrate", &json!({}));
        assert!(v
            .reason()
            .unwrap()
            .contains("not in the server's advertised"));
    }

    #[test]
    fn unknown_tool_allowed_when_configured_open() {
        let mut p = policy_with_writer();
        p.deny_unknown_tools = false;
        let v = inspect_tools_call(&p, "some_new_tool", &json!({}));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn state_change_gate_blocks_unless_allowed() {
        let mut p = policy_with_writer();
        p.gate_state_change = vec!["delete_file".into()];
        // Gated and not allowed → denied even though the schema is valid.
        let v = inspect_tools_call(&p, "delete_file", &json!({ "path": "/x" }));
        assert!(v.reason().unwrap().contains("gated as state-changing"));
        // Now allow it → passes (schema still checked).
        p.allow_state_change = vec!["delete_file".into()];
        let v = inspect_tools_call(&p, "delete_file", &json!({ "path": "/x" }));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn state_change_gate_takes_priority_over_schema() {
        // A gated tool with INVALID args is still denied for the gate reason,
        // proving gate is checked first (deterministic, policy-intent-first).
        let mut p = policy_with_writer();
        p.gate_state_change = vec!["delete_file".into()];
        let v = inspect_tools_call(&p, "delete_file", &json!({}));
        assert!(v.reason().unwrap().contains("gated as state-changing"));
    }

    #[test]
    fn unknown_tool_allowed_before_schemas_loaded() {
        // Startup race: a tools/call arrives before the server's tools/list
        // response was processed. Must NOT fail-closed (would block a valid
        // call). A fresh policy has schemas_loaded = false.
        let p = GatewayPolicy::new();
        assert!(!p.schemas_loaded);
        let v = inspect_tools_call(&p, "read_file", &json!({ "path": "/x" }));
        assert_eq!(v, Verdict::Allow, "must not deny before schemas are known");
    }

    #[test]
    fn loading_tools_marks_schemas_loaded() {
        let p = policy_with_writer();
        assert!(
            p.schemas_loaded,
            "loading a tools/list must set schemas_loaded"
        );
    }

    #[test]
    fn parses_tools_call_message() {
        let msg = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/x" } }
        });
        let (name, args) = parse_tools_call(&msg).unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args, json!({ "path": "/x" }));
    }

    #[test]
    fn non_tools_call_is_not_parsed() {
        let msg = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        assert!(parse_tools_call(&msg).is_none());
    }

    #[test]
    fn tools_call_without_arguments_defaults_empty() {
        let msg = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "ping" }
        });
        let (name, args) = parse_tools_call(&msg).unwrap();
        assert_eq!(name, "ping");
        assert_eq!(args, json!({}));
    }
}
