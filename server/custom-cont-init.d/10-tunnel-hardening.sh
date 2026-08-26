#!/usr/bin/with-contenv bash
# Managed by Ansible.
#
# linuxserver/openssh-server ships AllowTcpForwarding no, which silently breaks
# the ONLY thing this container exists for: `ssh -D` dynamic forwarding. Login
# succeeds and the local SOCKS listener opens, but every channel is refused
# with "administratively prohibited".
#
# TWO traps, both hit while building this:
#  1. sshd runs with `-f /config/sshd/sshd_config`, NOT /etc/ssh/sshd_config.
#     Patching the latter looks correct and changes nothing.
#  2. This is Alpine, so sed is BUSYBOX: `0,/re/s||…|` and the `I` flag are GNU
#     extensions and silently no-op. Hence filter-and-append below, which needs
#     nothing beyond grep.
set -u

patch_cfg() {
  CFG="$1"
  [ -f "$CFG" ] || return 0
  TMP="${CFG}.st.tmp"
  # Strip every existing (or commented) occurrence, then append our value.
  # Idempotent: re-running converges on exactly one line per key.
  grep -viE "^[#[:space:]]*(AllowTcpForwarding|X11Forwarding|AllowAgentForwarding|GatewayPorts|PermitTunnel|PasswordAuthentication|PermitRootLogin|MaxAuthTries)[[:space:]]" \
    "$CFG" > "$TMP" && mv "$TMP" "$CFG"
  {
    echo ""
    echo "# --- split-tunnel hardening (managed) ---"
    echo "AllowTcpForwarding yes"     # the entire purpose of this container
    echo "X11Forwarding no"
    echo "AllowAgentForwarding no"
    echo "GatewayPorts no"
    echo "PermitTunnel no"
    echo "PasswordAuthentication no"
    echo "PermitRootLogin no"
    echo "MaxAuthTries 3"
  } >> "$CFG"
  echo "[tunnel-hardening] $CFG -> $(grep -c '^AllowTcpForwarding yes' "$CFG") x AllowTcpForwarding yes"
}

patch_cfg /config/sshd/sshd_config
patch_cfg /etc/ssh/sshd_config
