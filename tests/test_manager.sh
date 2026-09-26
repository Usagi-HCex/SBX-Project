#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export SBX_SOURCE_ONLY=1
# shellcheck source=../src/sbx-manager.sh
source "$ROOT/src/sbx-manager.sh"

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

editable_value=''
secret_value=''
read_editable editable_value '' <<<'editable input'
read_secret secret_value '' <<<'secret input'
[[ "$editable_value" == 'editable input' ]]
[[ "$secret_value" == 'secret input' ]]
declare -f read_editable | grep -F 'builtin read -e -r' >/dev/null
declare -f read_secret | grep -F 'builtin read -e -r -s' >/dev/null

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

printf '%s\n' '#!/usr/bin/env bash' \
  'if [[ ${1:-} == generate && ${2:-} == reality-keypair ]]; then' \
  '  printf "PrivateKey: sb-private\\nPublicKey: sb-public\\n"' \
  'fi' \
  'exit 0' >"$SB_BIN"
printf '%s\n' '#!/usr/bin/env bash' \
  'case ${1:-} in' \
  '  x25519) printf "PrivateKey: xr-private\\nPassword (PublicKey): xr-public\\nHash32: ignored\\n" ;;' \
  "  vlessenc) printf '%s\\n' 'Authentication: X25519' '\"decryption\": \"server-x25519\"' '\"encryption\": \"client-x25519\"' '' 'Authentication: ML-KEM-768' '\"decryption\": \"server-mlkem\"' '\"encryption\": \"client-mlkem\"' ;;" \
  'esac' \
  'exit 0' >"$XR_BIN"
chmod 755 "$SB_BIN" "$XR_BIN"
require_core_for_protocol sb-vless-ws
require_core_for_protocol xr-vless-ws

reality_record=$(make_reality_record xr-vless-reality 24443 \
  11111111-1111-4111-8111-111111111111 www.microsoft.com 443 chrome)
[[ $(jq -r '.private_key' <<<"$reality_record") == xr-private ]]
[[ $(jq -r '.public_key' <<<"$reality_record") == xr-public ]]
[[ $(jq -r '.handshake_port' <<<"$reality_record") == 443 ]]
vless_record=$(generate_vless_encryption_record x25519)
[[ $(jq -r '.decryption' <<<"$vless_record") == server-x25519 ]]
[[ $(jq -r '.encryption' <<<"$vless_record") == client-x25519 ]]
vless_record=$(generate_vless_encryption_record mlkem768)
[[ $(jq -r '.decryption' <<<"$vless_record") == server-mlkem ]]
[[ $(jq -r '.encryption' <<<"$vless_record") == client-mlkem ]]

STATE_FILE="$tmp/state.json"
cert_file="$tmp/fullchain.pem"
key_file="$tmp/private.key"
printf 'certificate\n' >"$cert_file"
printf 'private key\n' >"$key_file"
jq -n --arg cert "$cert_file" --arg key "$key_file" '
  {certificate:{domain:"origin.example.com",fullchain:$cert,key:$key},
   protocols:{"xr-vless-ws":{port:28080,tls:true},"sb-vmess-ws":{port:18080,tls:false}}}
' >"$STATE_FILE"
[[ $(argo_origin_url xr-vless-ws) == https://localhost:28080 ]]
[[ $(argo_origin_url sb-vmess-ws) == http://localhost:18080 ]]
[[ $(argo_origin_request xr-vless-ws | jq -r '.originServerName') == origin.example.com ]]
[[ $(argo_origin_request sb-vmess-ws | jq -c '.') == '{}' ]]
token_binding=$(show_token_binding_requirements xr-vless-ws token.example.com)
grep -F 'Public hostname：token.example.com' <<<"$token_binding" >/dev/null
grep -F 'Service URL：   https://localhost:28080' <<<"$token_binding" >/dev/null
grep -F 'Origin Server Name：origin.example.com' <<<"$token_binding" >/dev/null

valid_tunnel_token='eyJhIjoiMDEyMzQ1Njc4OWFiY2RlZiIsInQiOiIwMTIzNDU2NyJ9'
is_cloudflare_tunnel_token "$valid_tunnel_token"
if is_cloudflare_tunnel_token 'not-a-cloudflare-token'; then
  printf 'invalid Cloudflare tunnel token was unexpectedly accepted\n' >&2
  exit 1
fi

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

SECRET_DIR="$tmp/secrets"
LOG_DIR="$tmp/log"
SYSTEMD_DIR="$tmp/systemd"
CF_BIN='/usr/local/bin/cloudflared'
mkdir -p "$SECRET_DIR" "$LOG_DIR" "$SYSTEMD_DIR"
write_argo_token_env "$valid_tunnel_token"
[[ $(stat -c '%a' "$SECRET_DIR/argo.env") == 600 ]]
grep -Fx "TUNNEL_TOKEN=$valid_tunnel_token" "$SECRET_DIR/argo.env" >/dev/null
write_argo_unit_fixed
grep -F "EnvironmentFile=$SECRET_DIR/argo.env" "$SYSTEMD_DIR/sbx-argo.service" >/dev/null
grep -F "ExecStart=$CF_BIN tunnel --no-autoupdate" "$SYSTEMD_DIR/sbx-argo.service" >/dev/null
if grep -F -- '--token' "$SYSTEMD_DIR/sbx-argo.service" >/dev/null \
  || grep -F -- "$valid_tunnel_token" "$SYSTEMD_DIR/sbx-argo.service" >/dev/null; then
  printf 'Cloudflare tunnel token leaked into the systemd command line\n' >&2
  exit 1
fi

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
printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/warp-cli"
chmod 755 "$tmp/warp-cli"
PATH="$tmp:$PATH"
install_warp_package
grep -F 'https://pkg.cloudflareclient.com/ noble main' "$SBX_WARP_REPO_FILE" >/dev/null
grep -F 'apt-get update -o Dir::Etc::sourcelist=' "$warp_log" >/dev/null
grep -F 'apt-get install -y cloudflare-warp' "$warp_log" >/dev/null
if grep -F 'apt-cache ' "$warp_log" >/dev/null; then
  printf 'WARP installation unexpectedly depended on apt-cache policy\n' >&2
  exit 1
fi
[[ -s "$SBX_WARP_KEYRING" ]]

curl_mode=plus
curl() {
  local output='' url=''
  while (($# > 0)); do
    case "$1" in
      --output) output=$2; shift 2 ;;
      http://*|https://*) url=$1; shift ;;
      *) shift ;;
    esac
  done
  case "$curl_mode:$url" in
    plus:*) printf 'warp=plus\n' >"$output"; printf '200' ;;
    policy:*) printf 'blocked by team policy\n' >"$output"; printf '403' ;;
    fallback:https://*) return 60 ;;
    fallback:http://*) : >"$output"; printf '204' ;;
    fail:*) return 7 ;;
    *) return 1 ;;
  esac
}
for curl_mode in plus policy fallback; do
  verify_warp_proxy 40000 >/dev/null
done
curl_mode=fail
if verify_warp_proxy 40000 >/dev/null 2>&1; then
  printf 'failed WARP SOCKS5 probes were unexpectedly accepted\n' >&2
  exit 1
fi

rm -f -- "$tmp/warp-cli"
mkdir -p "$tmp/no-tools"
saved_path=$PATH
PATH="$tmp/no-tools"
prompt_called=0
prompt() {
  prompt_called=1
  printf '40000'
}
install_warp_package() {
  return 1
}
if install_warp_free >/dev/null 2>&1; then
  printf 'failed WARP package installation was unexpectedly accepted\n' >&2
  exit 1
fi
PATH=$saved_path
if ((prompt_called != 0)); then
  printf 'WARP port was prompted after package installation failed\n' >&2
  exit 1
fi

STATE_FILE="$tmp/token-state.json"
jq -n '{
  certificate:{domain:"",fullchain:"",key:""},
  protocols:{"xr-vless-ws":{port:28080,tls:false}},
  argo:{mode:"off",target:"",hostname:"",tunnel_id:"",account_id:""}
}' >"$STATE_FILE"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/cloudflared"
chmod 755 "$tmp/cloudflared"
CF_BIN="$tmp/cloudflared"
choose_argo_target() { printf 'xr-vless-ws'; }
prompt() { printf 'token.example.com'; }
confirm() { return 0; }
read_secret() { printf -v "$1" '%s' "$valid_tunnel_token"; }
stop_argo_local() { :; }
sleep() { :; }
show_nodes() { :; }
commit_candidate() { cp "$1" "$STATE_FILE"; }
cf_api() {
  printf 'Token mode unexpectedly called the Cloudflare API\n' >&2
  return 1
}
install_argo_token >/dev/null
[[ $(jq -r '.argo.mode' "$STATE_FILE") == token ]]
[[ $(jq -r '.argo.target' "$STATE_FILE") == xr-vless-ws ]]
[[ $(jq -r '.argo.hostname' "$STATE_FILE") == token.example.com ]]

printf 'Manager shell tests passed.\n'
