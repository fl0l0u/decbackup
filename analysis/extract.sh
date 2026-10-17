#!/bin/sh
# Exfiltrate a file from the SNS VM.  SCP/SFTP is blocked on the device and
# the admin shell is a restricted csh whitelist without cat/od, so the
# working channel is openssl's base64 filter over ssh stdout.
#
#   ./extract.sh /usr/Firewall/sbin/decbackup  out/decbackup
#
# Verify integrity afterwards with md5 on both sides (md5 is whitelisted;
# ls -l works for sizes).
set -e
VM=${VM:?set VM=user@host}
remote=$1
local=${2:-$(basename "$remote")}
sshpass -p "${SSHPASS:?set SSHPASS}" ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null "$VM" \
    "openssl base64 -in $remote" 2>/dev/null | base64 -d > "$local"
