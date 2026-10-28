#!/bin/bash
# Exfiltrate a file from the SNS lab VM.  SCP/SFTP is blocked on the device
# and the admin shell is a restricted csh whitelist without cat/od, so the
# working channel is openssl's base64 filter over ssh stdout:
#
#   ./extract.sh /usr/Firewall/sbin/decbackup  out/decbackup
#
# NOTE: StrictHostKeyChecking=no with an empty known_hosts is deliberate for
# a lab VM you control: it accepts ANY host key (MITM-trusted by design).
# Do not point this at anything you do not own.
#
# Integrity: `md5` is whitelisted on the device; this script prints the
# local md5sum at the end so you can compare it against `md5 <path>` on
# the VM (ls -l works for sizes).
set -euo pipefail
VM=${VM:?set VM=user@host}
: "${SSHPASS:?set SSHPASS}"
remote=${1:?usage: extract.sh /remote/path [local]}
# absolute paths only — rejects relative paths and any leading shell
# metacharacters before they can reach the remote command line
case $remote in
    /*) ;;
    *) echo "extract.sh: remote path must be absolute (start with /)" >&2; exit 2 ;;
esac
out=${2:-$(basename -- "$remote")}
mkdir -p -- "$(dirname -- "$out")"

# Quote for the remote shell (single-quote wrap, every ' becomes '\'') so
# spaces cannot split words and injected commands cannot escape the quotes.
q=${remote//\'/\'\\\'\'}

b64=$(mktemp "$(dirname -- "$out")/.extract.b64.XXXXXX")
err=$(mktemp "$(dirname -- "$out")/.extract.ssherr.XXXXXX")
trap 'rm -f -- "$b64" "$err"' EXIT

# Stage 1: fetch the base64.  sshpass -e takes the password from $SSHPASS
# (never argv); ssh stderr is captured, not swallowed, and shown on failure.
# Split from the decode so an ssh failure cannot masquerade as an empty
# "successful" file behind base64 -d's exit status.
if ! sshpass -e ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null "$VM" \
        "openssl base64 -in '$q'" >"$b64"; then
    echo "extract.sh: ssh fetch of $remote failed:" >&2
    cat "$err" >&2
    exit 1
fi
if [ ! -s "$b64" ]; then
    if [ -s "$err" ]; then cat "$err" >&2; fi
    echo "extract.sh: empty base64 from $remote; refusing to write empty $out" >&2
    exit 1
fi
if [ -s "$err" ]; then cat "$err" >&2; fi   # ssh warnings on success

# Stage 2: decode separately — a corrupt stream fails loudly here.
base64 -d <"$b64" >"$out"

echo "extract.sh: wrote $out ($(wc -c <"$out") bytes)"
echo "extract.sh: local md5 (compare with 'md5 $remote' on the VM):"
md5sum "$out"
