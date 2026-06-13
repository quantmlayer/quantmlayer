# AppArmor profile for the QuantmLayer `ql` binary.
#
# WHY THIS EXISTS
# On hardened kernels — Ubuntu 24.04, and 22.04 running the 6.8+ HWE kernel —
# unprivileged user namespaces are restricted by AppArmor: an unconfined program
# may *create* a user namespace but is denied the use of capabilities *inside*
# it. QuantmLayer's cell needs those capabilities (to write uid/gid maps, mount
# over secrets, and bring up the cell's network), so without a profile granting
# `userns`, rootless `ql run` fails closed with:
#
#     ql-enforce: refusing to run agent uncontained:
#       ... wall `namespace` failed: setgroups deny: Permission denied
#
# This profile grants `ql` the `userns` permission while otherwise leaving it
# unconfined (`flags=(default_allow)`), so rootless containment works WITHOUT
# disabling the system-wide protection — which would weaken every other program
# on the host. This is the same mechanism Ubuntu ships for Chrome, flatpak, etc.
#
# INSTALL
#   sudo make install            # puts the binary at /usr/local/bin/ql
#   sudo make install-apparmor   # installs + loads this profile
#
# The profile attaches to the binary at /usr/local/bin/ql. If you run `ql` from
# a different path (e.g. ./target/release/ql during development), either install
# it to /usr/local/bin or change the attachment path below to match.
#
# Requires AppArmor 4.x userspace (Ubuntu 24.04, or 22.04 with updated
# apparmor). On older apparmor that cannot parse this syntax, use the posture
# documented in the README instead (sysctl toggle or running under root).

abi <abi/4.0>,

include <tunables/global>

profile ql /usr/local/bin/ql flags=(default_allow) {
  # Permit creation of, and full capability use within, unprivileged user
  # namespaces. This is the single permission the hardened-kernel restriction
  # otherwise withholds.
  userns,

  # Site-specific additions/overrides, if an operator needs them.
  include if exists <local/ql>
}
