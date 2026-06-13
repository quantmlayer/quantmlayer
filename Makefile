# QuantmLayer — developer task runner.
#
# These targets are the project's CI gates. Every PR must pass `make check`.

.PHONY: all check test test-priv fmt fmt-fix clippy benchmark bench-build overhead clean \
        build-release install uninstall install-apparmor uninstall-apparmor

# Install layout (override with `make install PREFIX=/opt/quantmlayer`).
PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin
APPARMOR_SRC := packaging/apparmor/usr.local.bin.ql
APPARMOR_DST := /etc/apparmor.d/usr.local.bin.ql

# Default: the gates that must pass before any change is accepted.
all: check

# The full pre-merge gate: formatting, lint, and the standard test suite.
# (clippy is included; it requires a rustup toolchain. On environments without
# it, run `make fmt test` directly.)
check: fmt clippy test

# Unit + integration tests that do NOT need elevated namespace privileges.
test:
	cargo test --workspace

# Privileged tests: the live containment tests (SSH-theft, etc.) that need
# unprivileged user+mount namespaces. Run where those are permitted.
test-priv:
	cargo test --workspace -- --include-ignored

# Formatting gate (check only; fails if the tree is unformatted).
fmt:
	cargo fmt --check

# Apply formatting.
fmt-fix:
	cargo fmt

# Lint gate. Warnings are errors.
clippy:
	cargo clippy --all-targets -- -D warnings

# THE CREDIBILITY ENGINE.
# Runs every attack against every backend, writes RESULTS.md + results.json,
# then renders CSV (and a plot if matplotlib is present). Never hand-edited.
# Build the benchmark binaries: ql-bench AND its attack probes (ql-forkprobe,
# ql-syscallprobe, ql-netprobe). `cargo build -p ql-bench` builds every binary
# in the package, unlike `cargo run` which builds only the default one. Run as
# your normal user.
bench-build:
	cargo build --release -p ql-bench

# Run the attack benchmark and render the scorecard.
#
# For the FULL matrix — including the fork-bomb row, whose cgroup wall needs
# privilege — run as root after building:   make bench-build && sudo make benchmark
# Rootless (`make benchmark`) also works, but the cgroup-backed row will not be
# fully exercised (see the posture notes in README.md).
benchmark:
	@test -x target/release/ql-bench || { \
	  echo "Build the benchmark first (as your normal user):"; \
	  echo "    make bench-build"; \
	  exit 1; \
	}
	./target/release/ql-bench --out benchmark
	-python3 benchmark/report.py benchmark/results.json

clean:
	cargo clean
	rm -f benchmark/results.json benchmark/results.csv benchmark/results.png benchmark/RESULTS.md

# --- Packaging / install -----------------------------------------------------

# Build the optimized `ql` binary.
build-release:
	cargo build --release -p ql-cli

# Install the `ql` binary to $(PREFIX)/bin (default /usr/local/bin).
#
# Build first as your NORMAL user (`make build-release` or `cargo build
# --release -p ql-cli`), then `sudo make install`. We deliberately do NOT build
# here: running cargo under sudo runs as root, which has no rustup toolchain and
# shouldn't be compiling your code anyway. This target only copies the binary.
install:
	@test -f target/release/ql || { \
	  echo "error: target/release/ql not found."; \
	  echo "Build it first as your normal user (not sudo):"; \
	  echo "    make build-release   # or: cargo build --release -p ql-cli"; \
	  exit 1; \
	}
	install -d $(BINDIR)
	install -m755 target/release/ql $(BINDIR)/ql
	@echo "Installed $(BINDIR)/ql"
	@echo "On a hardened kernel, also run: sudo make install-apparmor"

uninstall:
	rm -f $(BINDIR)/ql
	@echo "Removed $(BINDIR)/ql"

# Install + load the AppArmor profile that lets `ql` use unprivileged user
# namespaces on hardened kernels (Ubuntu 24.04, or 22.04 on the 6.8+ HWE
# kernel), so rootless `ql run` works without disabling the system-wide
# protection. Requires root (run with sudo) and AppArmor 4.x userspace.
install-apparmor:
	@test -x $(PREFIX)/bin/ql || echo "note: $(PREFIX)/bin/ql not found yet — run 'sudo make install' first so the profile attaches to the installed binary."
	install -d /etc/apparmor.d
	install -m644 $(APPARMOR_SRC) $(APPARMOR_DST)
	apparmor_parser -r $(APPARMOR_DST)
	@echo "Loaded AppArmor profile $(APPARMOR_DST) for $(PREFIX)/bin/ql."
	@echo "Rootless 'ql run' should now work on this host."

uninstall-apparmor:
	-apparmor_parser -R $(APPARMOR_DST)
	-rm -f $(APPARMOR_DST)
	@echo "Removed AppArmor profile $(APPARMOR_DST)."

# Measure per-call containment overhead (cold start, no pooling). Build first
# with `make bench-build` (as your user); run under sudo for all walls.
overhead:
	@test -x target/release/ql-overhead || { \
	  echo "Build the benchmark binaries first (as your normal user): make bench-build"; \
	  exit 1; \
	}
	./target/release/ql-overhead
