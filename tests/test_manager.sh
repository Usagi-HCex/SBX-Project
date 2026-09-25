#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export SBX_SOURCE_ONLY=1
# shellcheck source=../src/sbx-manager.sh
source "$ROOT/src/sbx-manager.sh"

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

FIXTURE_ASSET="$tmp/source-asset"
printf 'verified release payload\n' >"$FIXTURE_ASSET"
fixture_digest=$(sha256sum "$FIXTURE_ASSET" | awk '{print $1}')

secure_curl() {
  [[ ${1:-} == -o && $# == 3 ]] || return 1
  cp "$FIXTURE_ASSET" "$2"
}

release_json=$(jq -cn \
  --arg name 'core-linux-amd64.tar.gz' \
  --arg url 'https://github.com/Owner/Repo/releases/download/v1.2.3/core-linux-amd64.tar.gz' \
  --arg digest "sha256:$fixture_digest" \
  '{assets:[{name:$name,browser_download_url:$url,digest:$digest,state:"uploaded"}]}')

download_verified_release_asset Owner/Repo core-linux-amd64.tar.gz "$tmp/output" <<<"$release_json"
cmp "$FIXTURE_ASSET" "$tmp/output"

if download_verified_release_asset Owner/Repo missing.tar.gz "$tmp/missing" <<<"$release_json"; then
  printf 'missing release asset was unexpectedly accepted\n' >&2
  exit 1
fi

bad_digest_json=$(jq '.assets[0].digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  <<<"$release_json")
if download_verified_release_asset Owner/Repo core-linux-amd64.tar.gz "$tmp/bad" <<<"$bad_digest_json"; then
  printf 'invalid release digest was unexpectedly accepted\n' >&2
  exit 1
fi

SB_BIN="$tmp/sing-box"
XR_BIN="$tmp/xray"
if require_core_for_protocol sb-vless-ws 2>/dev/null; then
  printf 'missing Sing-box core was unexpectedly accepted\n' >&2
  exit 1
fi
if require_core_for_protocol xr-vless-ws 2>/dev/null; then
  printf 'missing Xray core was unexpectedly accepted\n' >&2
  exit 1
fi

printf '#!/usr/bin/env bash\nexit 0\n' >"$SB_BIN"
printf '#!/usr/bin/env bash\nexit 0\n' >"$XR_BIN"
chmod 755 "$SB_BIN" "$XR_BIN"
require_core_for_protocol sb-vless-ws
require_core_for_protocol xr-vless-ws

firewall_log="$tmp/firewall.log"
iptables() {
  printf '%s\n' "$*" >>"$firewall_log"
  [[ " $* " != *" -C "* ]]
}
plan='{"ports":[{"protocol":"udp","start":24444,"end":24444,"source":"sb-hysteria2"},{"protocol":"udp","start":40000,"end":41000,"source":"sb-hysteria2"}],"redirects":[{"protocol":"udp","start":40000,"end":41000,"target":24444,"source":"sb-hysteria2"}]}'
firewall_apply_family iptables "$plan"
grep -F -- '-A SBX_INPUT -p udp --dport 24444 -j ACCEPT' "$firewall_log" >/dev/null
grep -F -- '-A SBX_INPUT -p udp --dport 40000:41000 -j ACCEPT' "$firewall_log" >/dev/null
grep -F -- '-t nat -A SBX_PREROUTING -p udp --dport 40000:41000 -j REDIRECT --to-ports 24444' "$firewall_log" >/dev/null

service_log="$tmp/service.log"
core_count() {
  printf '1'
}
systemctl() {
  printf '%s\n' "$*" >>"$service_log"
  return 0
}
sync_core_services unused 0 1
if grep -F 'restart sbx-sing-box.service' "$service_log" >/dev/null; then
  printf 'unchanged Sing-box was unexpectedly restarted\n' >&2
  exit 1
fi
grep -F 'restart sbx-xray.service' "$service_log" >/dev/null

warp_log="$tmp/warp.log"
printf 'VERSION_CODENAME=noble\n' >"$tmp/os-release"
SBX_OS_RELEASE_FILE="$tmp/os-release"
SBX_WARP_REPO_FILE="$tmp/cloudflare-client.list"
SBX_WARP_KEYRING="$tmp/cloudflare-warp-archive-keyring.gpg"
mock_fingerprint=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
gpg() {
  local arg previous='' output=''
  for arg in "$@"; do
    [[ "$previous" == --output ]] && output=$arg
    previous=$arg
  done
  if [[ -n "$output" ]]; then
    printf 'mock keyring\n' >"$output"
  else
    printf 'fpr:::::::::%s:\n' "$mock_fingerprint"
  fi
}
apt-get() {
  printf 'apt-get %s\n' "$*" >>"$warp_log"
}
apt-cache() {
  printf 'apt-cache %s\n' "$*" >>"$warp_log"
  return 1
}
install_warp_package
grep -F 'https://pkg.cloudflareclient.com/ noble main' "$SBX_WARP_REPO_FILE" >/dev/null
grep -F 'apt-get update -o Dir::Etc::sourcelist=' "$warp_log" >/dev/null
grep -F 'apt-get install -y cloudflare-warp' "$warp_log" >/dev/null
if grep -F 'apt-cache ' "$warp_log" >/dev/null; then
  printf 'WARP installation unexpectedly depended on apt-cache policy\n' >&2
  exit 1
fi
[[ -s "$SBX_WARP_KEYRING" ]]

printf 'Manager shell tests passed.\n'
