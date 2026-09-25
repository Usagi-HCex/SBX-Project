#!/usr/bin/env bash
# Interactive sing-box + Xray manager for Debian/Ubuntu systemd hosts.
set -Eeuo pipefail
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VERSION="0.1.6"
ETC_DIR="${SBX_ETC_DIR:-/etc/sbx-manager}"
STATE_FILE="$ETC_DIR/state.json"
CERT_DIR="$ETC_DIR/certs"
SECRET_DIR="$ETC_DIR/secrets"
LOG_DIR="${SBX_LOG_DIR:-/var/log/sbx-manager}"
LIB_DIR="${SBX_LIB_DIR:-/usr/local/lib/sbx-manager}"
GENERATOR="$LIB_DIR/sbx_generator.py"
SYSTEMD_DIR="${SBX_SYSTEMD_DIR:-/etc/systemd/system}"
BIN_DIR="${SBX_BIN_DIR:-/usr/local/bin}"
SB_BIN="$BIN_DIR/sing-box"
XR_BIN="$BIN_DIR/xray"
CF_BIN="$BIN_DIR/cloudflared"
ACME_HOME="/opt/sbx-manager/acme"
ACME_CONFIG="$ETC_DIR/acme"
ACME_FIREWALL_MARKER="/run/sbx-manager-acme-http01"
FIREWALL_CHAIN="SBX_INPUT"
FIREWALL_NAT_CHAIN="SBX_PREROUTING"

if [[ -t 1 ]]; then
  C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_BLUE='\033[36m'; C_RESET='\033[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_RESET=''
fi

info() { printf '%b[信息]%b %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok() { printf '%b[完成]%b %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%b[警告]%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%b[错误]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请使用 root 运行。"
}

require_commands() {
  local missing=() command
  for command in curl jq python3 openssl tar unzip install systemctl ss iptables ip6tables; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done
  ((${#missing[@]} == 0)) || die "缺少依赖：${missing[*]}。请重新执行 install.sh。"
}

ensure_layout() {
  install -d -m 700 "$ETC_DIR" "$CERT_DIR" "$SECRET_DIR" "$LOG_DIR" "$ACME_CONFIG"
  [[ -x "$GENERATOR" || -f "$GENERATOR" ]] || die "找不到生成器：$GENERATOR"
  if [[ ! -f "$STATE_FILE" ]]; then
    python3 "$GENERATOR" init --output "$STATE_FILE"
    chmod 600 "$STATE_FILE"
  fi
}

is_valid_port() {
  [[ ${1:-} =~ ^[0-9]+$ ]] && ((1 <= 10#$1 && 10#$1 <= 65535))
}

is_valid_domain() {
  local value=${1:-}
  [[ ${#value} -le 253 && "$value" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_valid_hostname_or_ip() {
  local value=${1:-}
  [[ -n "$value" && "$value" =~ ^[A-Za-z0-9._:-]+$ ]]
}

is_safe_token() {
  local value=${1:-}
  [[ -n "$value" && "$value" =~ ^[A-Za-z0-9._~+/=-]+$ ]]
}

is_valid_transport_path() {
  local value=${1:-}
  [[ ${#value} -le 201 && "$value" =~ ^/[A-Za-z0-9._~/-]+$ ]]
}

prompt() {
  local message=$1 default=${2:-} answer
  if [[ -n "$default" ]]; then
    read -r -p "$message [$default]: " answer
    printf '%s' "${answer:-$default}"
  else
    read -r -p "$message: " answer
    printf '%s' "$answer"
  fi
}

confirm() {
  local message=$1 answer
  read -r -p "$message [y/N]: " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

random_port() {
  local port i
  for ((i=0; i<100; i++)); do
    port=$(shuf -i 10000-60000 -n 1)
    if ! jq -e --argjson port "$port" '.protocols[]? | select(.port == $port)' "$STATE_FILE" >/dev/null \
      && ! ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "(^|:)$port$"; then
      printf '%s' "$port"
      return 0
    fi
  done
  return 1
}

prompt_port() {
  local suggested answer
  suggested=$(random_port) || die "无法找到空闲端口。"
  while true; do
    answer=$(prompt "监听端口" "$suggested")
    if ! is_valid_port "$answer"; then
      warn "端口必须为 1-65535。"
    elif jq -e --argjson port "$answer" '.protocols[]? | select(.port == $port)' "$STATE_FILE" >/dev/null; then
      warn "端口已被本工具中的其他协议占用。"
    elif ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "(^|:)${answer}$"; then
      warn "端口正被系统中的进程监听。"
    else
      printf '%s' "$answer"
      return 0
    fi
  done
}

prompt_transport_path() {
  local label=$1 suggested=$2 answer
  while true; do
    answer=$(prompt "$label" "$suggested")
    if is_valid_transport_path "$answer"; then
      printf '%s' "$answer"
      return 0
    fi
    warn "路径必须以 / 开头，只能包含字母、数字、点、下划线、波浪线、斜杠或连字符，且不超过 201 字符。"
  done
}

hopping_range_conflicts() {
  local start=$1 end=$2 base_port=$3
  jq -e --argjson start "$start" --argjson end "$end" '
    .protocols | to_entries[]?
    | select(.key == "sb-tuic" or .key == "sb-shadowsocks" or .key == "xr-shadowsocks")
    | select(.value.port >= $start and .value.port <= $end)
  ' "$STATE_FILE" >/dev/null && return 0
  ss -H -lnu 2>/dev/null | awk -v start="$start" -v end="$end" -v base="$base_port" '
    {
      value=$5
      sub(/^.*:/, "", value)
      if (value ~ /^[0-9]+$/ && value >= start && value <= end && value != base) found=1
    }
    END {exit !found}
  '
}

prompt_hopping_range() {
  local base_port=$1 start end
  while true; do
    start=$(prompt "Hy2 跳跃起始 UDP 端口" "20000")
    end=$(prompt "Hy2 跳跃结束 UDP 端口" "30000")
    if ! is_valid_port "$start" || ! is_valid_port "$end" || ((10#$start >= 10#$end)); then
      warn "端口跳跃范围必须是 1-65535 内从小到大的两个端口。"
    elif hopping_range_conflicts "$start" "$end" "$base_port"; then
      warn "范围内存在其他 UDP 入站或系统 UDP 监听端口，请换一个范围。"
    else
      printf '%s %s' "$start" "$end"
      return 0
    fi
  done
}

secure_curl() {
  curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --retry 2 "$@"
}

github_latest_tag() {
  local repository=$1
  secure_curl "https://api.github.com/repos/$repository/releases/latest" | jq -er '.tag_name'
}

github_release_json() {
  local repository=$1 requested_tag=${2:-} endpoint
  if [[ -n "$requested_tag" ]]; then
    [[ "$requested_tag" =~ ^[vV]?[0-9][0-9A-Za-z._-]*$ ]] \
      || { warn "不安全的版本标签：$requested_tag"; return 1; }
    endpoint="https://api.github.com/repos/$repository/releases/tags/$requested_tag"
  else
    endpoint="https://api.github.com/repos/$repository/releases/latest"
  fi
  if ! secure_curl "$endpoint"; then
    warn "无法读取 $repository 的 GitHub Release 信息。"
    return 1
  fi
}

download_verified_release_asset() {
  local repository=$1 asset=$2 output=$3 metadata url digest expected actual
  if ! metadata=$(jq -cer --arg asset "$asset" '
      [.assets[]? | select(.name == $asset) |
        {url:.browser_download_url,digest:.digest,state:.state}]
      | if length == 1 then .[0] else error("release asset not found") end
    '); then
    warn "GitHub Release 中未找到资产：$asset"
    return 1
  fi
  url=$(jq -er '.url' <<<"$metadata") || return 1
  digest=$(jq -er '.digest' <<<"$metadata") || return 1
  [[ $(jq -r '.state' <<<"$metadata") == uploaded ]] \
    || { warn "发布资产尚未上传完成：$asset"; return 1; }
  [[ "$url" == "https://github.com/$repository/releases/download/"*"/$asset" ]] \
    || { warn "发布资产下载地址异常，拒绝安装。"; return 1; }
  [[ "$digest" =~ ^sha256:([0-9a-fA-F]{64})$ ]] \
    || { warn "发布资产缺少有效的 GitHub SHA-256 摘要。"; return 1; }
  expected=${BASH_REMATCH[1]}
  if ! secure_curl -o "$output" "$url"; then
    warn "下载失败：$asset"
    return 1
  fi
  actual=$(sha256sum "$output" | awk '{print $1}')
  [[ "${actual,,}" == "${expected,,}" ]] \
    || { warn "$asset 的 SHA-256 校验失败。"; return 1; }
}

install_singbox() {
  local requested_tag release_json tag version arch asset tmp archive source_binary staged
  requested_tag=${1:-${SBX_SINGBOX_VERSION:-}}
  if ! release_json=$(github_release_json SagerNet/sing-box "$requested_tag"); then
    return 1
  fi
  tag=$(jq -er '.tag_name' <<<"$release_json") \
    || { warn "Sing-box Release 缺少版本标签。"; return 1; }
  version=${tag#v}
  case $(uname -m) in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) warn "Sing-box 暂不支持当前架构：$(uname -m)"; return 1 ;;
  esac
  asset="sing-box-${version}-linux-${arch}.tar.gz"
  tmp=$(mktemp -d)
  archive="$tmp/$asset"
  info "从 SagerNet 官方发布页下载 sing-box $tag"
  if ! download_verified_release_asset SagerNet/sing-box "$asset" "$archive" <<<"$release_json"; then
    rm -rf -- "$tmp"
    return 1
  fi
  if ! tar -xzf "$archive" -C "$tmp"; then
    rm -rf -- "$tmp"
    warn "Sing-box 发布包解压失败。"
    return 1
  fi
  source_binary="$tmp/sing-box-${version}-linux-${arch}/sing-box"
  [[ -f "$source_binary" ]] \
    || { rm -rf -- "$tmp"; warn "Sing-box 发布包结构异常。"; return 1; }
  staged="$tmp/sing-box"
  install -m 755 "$source_binary" "$staged"
  if ! "$staged" version >/dev/null 2>&1; then
    rm -rf -- "$tmp"
    warn "下载的 Sing-box 无法在当前系统运行。"
    return 1
  fi
  if (( $(core_count 'sb-') > 0 )) && [[ -s "$ETC_DIR/sing-box.json" ]] \
    && ! "$staged" check -c "$ETC_DIR/sing-box.json"; then
    rm -rf -- "$tmp"
    warn "现有 Sing-box 配置与新内核不兼容，已保留原内核。"
    return 1
  fi
  if ! install -m 755 "$staged" "$SB_BIN"; then
    rm -rf -- "$tmp"
    warn "无法安装 Sing-box 到 $SB_BIN。"
    return 1
  fi
  rm -rf -- "$tmp"
  ok "Sing-box 已安装：$($SB_BIN version | head -n1)"
}

install_xray() {
  local requested_tag release_json tag arch asset tmp archive source_binary staged
  requested_tag=${1:-${SBX_XRAY_VERSION:-}}
  if ! release_json=$(github_release_json XTLS/Xray-core "$requested_tag"); then
    return 1
  fi
  tag=$(jq -er '.tag_name' <<<"$release_json") \
    || { warn "Xray Release 缺少版本标签。"; return 1; }
  case $(uname -m) in
    x86_64|amd64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    *) warn "Xray 暂不支持当前架构：$(uname -m)"; return 1 ;;
  esac
  asset="Xray-linux-${arch}.zip"
  tmp=$(mktemp -d)
  archive="$tmp/$asset"
  info "从 XTLS 官方发布页下载 Xray $tag"
  if ! download_verified_release_asset XTLS/Xray-core "$asset" "$archive" <<<"$release_json"; then
    rm -rf -- "$tmp"
    return 1
  fi
  if ! unzip -q "$archive" -d "$tmp/xray"; then
    rm -rf -- "$tmp"
    warn "Xray 发布包解压失败。"
    return 1
  fi
  source_binary="$tmp/xray/xray"
  [[ -f "$source_binary" ]] \
    || { rm -rf -- "$tmp"; warn "Xray 发布包结构异常。"; return 1; }
  staged="$tmp/xray-core"
  install -m 755 "$source_binary" "$staged"
  if ! "$staged" version >/dev/null 2>&1; then
    rm -rf -- "$tmp"
    warn "下载的 Xray 无法在当前系统运行。"
    return 1
  fi
  if (( $(core_count 'xr-') > 0 )) && [[ -s "$ETC_DIR/xray.json" ]] \
    && ! "$staged" run -test -config "$ETC_DIR/xray.json"; then
    rm -rf -- "$tmp"
    warn "现有 Xray 配置与新内核不兼容，已保留原内核。"
    return 1
  fi
  if ! install -m 755 "$staged" "$XR_BIN"; then
    rm -rf -- "$tmp"
    warn "无法安装 Xray 到 $XR_BIN。"
    return 1
  fi
  rm -rf -- "$tmp"
  ok "Xray 已安装：$($XR_BIN version | head -n1)"
}

install_cloudflared() {
  local tag arch asset url tmp
  tag=${1:-${SBX_CLOUDFLARED_VERSION:-}}
  [[ -n "$tag" ]] || tag=$(github_latest_tag cloudflare/cloudflared)
  case $(uname -m) in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "cloudflared 暂不支持当前架构：$(uname -m)" ;;
  esac
  asset="cloudflared-linux-${arch}"
  url="https://github.com/cloudflare/cloudflared/releases/download/${tag}/${asset}"
  tmp=$(mktemp)
  info "从 Cloudflare 官方发布页下载 cloudflared $tag"
  secure_curl -o "$tmp" "$url"
  install -m 755 "$tmp" "$CF_BIN"
  rm -f -- "$tmp"
  ok "cloudflared 已安装：$($CF_BIN --version)"
}

write_core_units() {
  install -d -m 755 "$SYSTEMD_DIR"
  cat >"$SYSTEMD_DIR/sbx-sing-box.service" <<EOF
[Unit]
Description=SBX Manager sing-box core
After=network-online.target sbx-firewall.service
Wants=network-online.target sbx-firewall.service

[Service]
Type=simple
ExecStart=$SB_BIN run -c $ETC_DIR/sing-box.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  cat >"$SYSTEMD_DIR/sbx-xray.service" <<EOF
[Unit]
Description=SBX Manager Xray core
After=network-online.target sbx-firewall.service
Wants=network-online.target sbx-firewall.service

[Service]
Type=simple
ExecStart=$XR_BIN run -config $ETC_DIR/xray.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  cat >"$SYSTEMD_DIR/sbx-firewall.service" <<'EOF'
[Unit]
Description=SBX Manager host firewall rules
After=network-pre.target nftables.service ufw.service firewalld.service
Before=sbx-sing-box.service sbx-xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbx-manager firewall-apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >"$SYSTEMD_DIR/sbx-watchdog.service" <<EOF
[Unit]
Description=SBX Manager health check

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sbx-manager healthcheck
EOF
  cat >"$SYSTEMD_DIR/sbx-watchdog.timer" <<'EOF'
[Unit]
Description=Run SBX Manager health check every two minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
RandomizedDelaySec=20s
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
}

firewall_clear_family() {
  local command=$1
  command -v "$command" >/dev/null 2>&1 || return 0
  while "$command" -w 5 -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; do
    "$command" -w 5 -D INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1 || break
  done
  "$command" -w 5 -F "$FIREWALL_CHAIN" >/dev/null 2>&1 || true
  "$command" -w 5 -X "$FIREWALL_CHAIN" >/dev/null 2>&1 || true
  while "$command" -w 5 -t nat -C PREROUTING -j "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1; do
    "$command" -w 5 -t nat -D PREROUTING -j "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || break
  done
  "$command" -w 5 -t nat -F "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || true
  "$command" -w 5 -t nat -X "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || true
}

firewall_clear() {
  firewall_clear_family iptables
  firewall_clear_family ip6tables
}

firewall_apply_family() {
  local command=$1 plan=$2 protocol start end source dport target
  if ! "$command" -w 5 -N "$FIREWALL_CHAIN" >/dev/null 2>&1; then
    "$command" -w 5 -F "$FIREWALL_CHAIN"
  fi
  while "$command" -w 5 -C INPUT -j "$FIREWALL_CHAIN" >/dev/null 2>&1; do
    "$command" -w 5 -D INPUT -j "$FIREWALL_CHAIN"
  done
  "$command" -w 5 -I INPUT 1 -j "$FIREWALL_CHAIN"
  while IFS=$'\t' read -r protocol start end source; do
    [[ -n "$protocol" ]] || continue
    dport=$start
    [[ "$start" == "$end" ]] || dport="$start:$end"
    "$command" -w 5 -A "$FIREWALL_CHAIN" -p "$protocol" --dport "$dport" -j ACCEPT
  done < <(jq -r '.ports[] | [.protocol, (.start|tostring), (.end|tostring), .source] | @tsv' <<<"$plan")

  if (( $(jq '.redirects | length' <<<"$plan") > 0 )); then
    if ! "$command" -w 5 -t nat -N "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1; then
      "$command" -w 5 -t nat -F "$FIREWALL_NAT_CHAIN"
    fi
    while "$command" -w 5 -t nat -C PREROUTING -j "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1; do
      "$command" -w 5 -t nat -D PREROUTING -j "$FIREWALL_NAT_CHAIN"
    done
    "$command" -w 5 -t nat -I PREROUTING 1 -j "$FIREWALL_NAT_CHAIN"
    while IFS=$'\t' read -r protocol start end target source; do
      [[ -n "$protocol" ]] || continue
      dport=$start
      [[ "$start" == "$end" ]] || dport="$start:$end"
      "$command" -w 5 -t nat -A "$FIREWALL_NAT_CHAIN" -p "$protocol" \
        --dport "$dport" -j REDIRECT --to-ports "$target"
    done < <(jq -r '.redirects[] | [.protocol, (.start|tostring), (.end|tostring), (.target|tostring), .source] | @tsv' <<<"$plan")
  else
    while "$command" -w 5 -t nat -C PREROUTING -j "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1; do
      "$command" -w 5 -t nat -D PREROUTING -j "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || break
    done
    "$command" -w 5 -t nat -F "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || true
    "$command" -w 5 -t nat -X "$FIREWALL_NAT_CHAIN" >/dev/null 2>&1 || true
  fi
}

firewall_plan_json() {
  python3 "$GENERATOR" firewall-plan --state "${1:-$STATE_FILE}"
}

firewall_apply() {
  local state=${1:-$STATE_FILE} plan count
  plan=$(firewall_plan_json "$state") || return 1
  if [[ -e "$ACME_FIREWALL_MARKER" ]]; then
    plan=$(jq '
      .ports += [{protocol:"tcp",start:80,end:80,source:"acme-http01"}]
      | .ports |= unique_by([.protocol,.start,.end])
    ' <<<"$plan")
  fi
  count=$(jq '.ports | length' <<<"$plan")
  if ((count == 0)); then
    firewall_clear
    return 0
  fi
  firewall_apply_family iptables "$plan" || return 1
  if [[ -s /proc/net/if_inet6 ]]; then
    firewall_apply_family ip6tables "$plan" || return 1
  else
    firewall_clear_family ip6tables
  fi
}

sync_firewall() {
  local state=${1:-$STATE_FILE} plan count
  plan=$(firewall_plan_json "$state") || return 1
  count=$(jq '.ports | length' <<<"$plan")
  if ! firewall_apply "$state"; then
    warn "无法同步 SBX 防火墙规则。"
    return 1
  fi
  if ((count > 0)); then
    systemctl enable sbx-firewall.service >/dev/null
  else
    systemctl disable sbx-firewall.service >/dev/null 2>&1 || true
  fi
}

show_firewall_requirements() {
  local plan protocol start end source range
  plan=$(firewall_plan_json "${1:-$STATE_FILE}") || return 1
  printf '\n主机防火墙已由 SBX 自动同步；云厂商安全组还需允许：\n'
  if (( $(jq '.ports | length' <<<"$plan") == 0 )); then
    printf '  （当前没有入站端口）\n'
    return 0
  fi
  while IFS=$'\t' read -r protocol start end source; do
    range=$start
    [[ "$start" == "$end" ]] || range="$start-$end"
    printf '  - %-3s %-11s %s\n' "${protocol^^}" "$range" "$(protocol_label "$source")"
  done < <(jq -r '.ports[] | [.protocol, (.start|tostring), (.end|tostring), .source] | @tsv' <<<"$plan")
}

firewall_status() {
  show_firewall_requirements
  printf '\nIPv4 SBX 规则：\n'
  iptables -w 5 -S "$FIREWALL_CHAIN" 2>/dev/null || printf '  （没有规则链）\n'
  iptables -w 5 -t nat -S "$FIREWALL_NAT_CHAIN" 2>/dev/null || true
  if [[ -s /proc/net/if_inet6 ]]; then
    printf '\nIPv6 SBX 规则：\n'
    ip6tables -w 5 -S "$FIREWALL_CHAIN" 2>/dev/null || printf '  （没有规则链）\n'
    ip6tables -w 5 -t nat -S "$FIREWALL_NAT_CHAIN" 2>/dev/null || true
  fi
}

core_count() {
  local prefix=$1 state=${2:-$STATE_FILE}
  jq --arg prefix "$prefix" '[.protocols | keys[] | select(startswith($prefix))] | length' "$state"
}

sync_core_services() {
  local state=${1:-$STATE_FILE} restart_sb=${2:-1} restart_xr=${3:-1}
  local sb_count xr_count failed=0
  sb_count=$(core_count 'sb-' "$state")
  xr_count=$(core_count 'xr-' "$state")
  if ((sb_count > 0)); then
    systemctl enable sbx-sing-box.service >/dev/null
    if ((restart_sb)) || ! systemctl is-active --quiet sbx-sing-box.service; then
      systemctl restart sbx-sing-box.service || failed=1
    fi
  else
    systemctl disable --now sbx-sing-box.service >/dev/null 2>&1 || true
  fi
  if ((xr_count > 0)); then
    systemctl enable sbx-xray.service >/dev/null
    if ((restart_xr)) || ! systemctl is-active --quiet sbx-xray.service; then
      systemctl restart sbx-xray.service || failed=1
    fi
  else
    systemctl disable --now sbx-xray.service >/dev/null 2>&1 || true
  fi
  return "$failed"
}

render_candidate() {
  local candidate=$1 output_dir=$2
  python3 "$GENERATOR" render \
    --state "$candidate" \
    --sing-box "$output_dir/sing-box.json" \
    --xray "$output_dir/xray.json" \
    --nodes "$output_dir/nodes.txt"
}

validate_candidate_configs() {
  local candidate=$1 output_dir=$2
  if (( $(core_count 'sb-' "$candidate") > 0 )); then
    [[ -x "$SB_BIN" ]] || { warn "Sing-box 尚未安装。"; return 1; }
    "$SB_BIN" check -c "$output_dir/sing-box.json"
  fi
  if (( $(core_count 'xr-' "$candidate") > 0 )); then
    [[ -x "$XR_BIN" ]] || { warn "Xray 尚未安装。"; return 1; }
    "$XR_BIN" run -test -config "$output_dir/xray.json"
  fi
}

commit_candidate() {
  local candidate=$1 work backup had_state=0 had_sb=0 had_xr=0 had_nodes=0
  local sb_changed=1 xr_changed=1
  work=$(mktemp -d)
  backup="$work/backup"
  install -d -m 700 "$backup" "$work/new"
  render_candidate "$candidate" "$work/new" || { rm -rf -- "$work"; return 1; }
  validate_candidate_configs "$candidate" "$work/new" || { rm -rf -- "$work"; return 1; }
  [[ -f "$STATE_FILE" ]] && { cp -p "$STATE_FILE" "$backup/state.json"; had_state=1; }
  [[ -f "$ETC_DIR/sing-box.json" ]] && { cp -p "$ETC_DIR/sing-box.json" "$backup/sing-box.json"; had_sb=1; }
  [[ -f "$ETC_DIR/xray.json" ]] && { cp -p "$ETC_DIR/xray.json" "$backup/xray.json"; had_xr=1; }
  [[ -f "$ETC_DIR/nodes.txt" ]] && { cp -p "$ETC_DIR/nodes.txt" "$backup/nodes.txt"; had_nodes=1; }
  ((had_sb)) && cmp -s "$backup/sing-box.json" "$work/new/sing-box.json" && sb_changed=0
  ((had_xr)) && cmp -s "$backup/xray.json" "$work/new/xray.json" && xr_changed=0
  install -m 600 "$candidate" "$STATE_FILE"
  install -m 600 "$work/new/sing-box.json" "$ETC_DIR/sing-box.json"
  install -m 600 "$work/new/xray.json" "$ETC_DIR/xray.json"
  install -m 600 "$work/new/nodes.txt" "$ETC_DIR/nodes.txt"
  if ! sync_firewall "$STATE_FILE" || ! sync_core_services "$STATE_FILE" "$sb_changed" "$xr_changed"; then
    warn "新配置未能正常启动，正在回滚。"
    if ((had_state)); then install -m 600 "$backup/state.json" "$STATE_FILE"; else rm -f -- "$STATE_FILE"; fi
    if ((had_sb)); then install -m 600 "$backup/sing-box.json" "$ETC_DIR/sing-box.json"; else rm -f -- "$ETC_DIR/sing-box.json"; fi
    if ((had_xr)); then install -m 600 "$backup/xray.json" "$ETC_DIR/xray.json"; else rm -f -- "$ETC_DIR/xray.json"; fi
    if ((had_nodes)); then install -m 600 "$backup/nodes.txt" "$ETC_DIR/nodes.txt"; else rm -f -- "$ETC_DIR/nodes.txt"; fi
    if ((had_state)); then
      sync_firewall "$STATE_FILE" || true
      sync_core_services "$STATE_FILE" 1 1 || true
    else
      firewall_clear
      systemctl disable --now sbx-sing-box.service sbx-xray.service sbx-firewall.service >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work"
    return 1
  fi
  rm -rf -- "$work"
}

mutate_state() {
  local filter=$1
  shift
  local candidate
  candidate=$(mktemp)
  if ! jq "$@" "$filter" "$STATE_FILE" >"$candidate"; then
    rm -f -- "$candidate"
    return 1
  fi
  if commit_candidate "$candidate"; then
    rm -f -- "$candidate"
    return 0
  fi
  rm -f -- "$candidate"
  return 1
}

detect_public_ip() {
  local trace
  trace=$(secure_curl --max-time 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
  awk -F= '$1 == "ip" {print $2; exit}' <<<"$trace"
}

bootstrap() {
  require_root
  require_commands
  ensure_layout
  write_core_units
  if (( $(core_count 'sb-') > 0 )) && [[ ! -x "$SB_BIN" ]]; then
    warn "检测到已有 Sing-box 协议但内核缺失；请运行 sbx 后进入“内核管理”安装。"
  fi
  if (( $(core_count 'xr-') > 0 )) && [[ ! -x "$XR_BIN" ]]; then
    warn "检测到已有 Xray 协议但内核缺失；请运行 sbx 后进入“内核管理”安装。"
  fi
  if [[ $(jq -r '.argo.mode' "$STATE_FILE") != off && ! -x "$CF_BIN" ]]; then
    warn "检测到已有 Argo 配置但 cloudflared 缺失，正在自动恢复。"
    install_cloudflared
  fi
  if [[ -z $(jq -r '.server' "$STATE_FILE") ]]; then
    local detected candidate
    detected=$(detect_public_ip || true)
    if [[ -n "$detected" ]]; then
      candidate=$(mktemp)
      jq --arg server "$detected" '.server = $server' "$STATE_FILE" >"$candidate"
      commit_candidate "$candidate" || true
      rm -f -- "$candidate"
    else
      commit_candidate "$STATE_FILE" || true
    fi
  else
    commit_candidate "$STATE_FILE" || true
  fi
  if jq -e '.watchdog == true' "$STATE_FILE" >/dev/null; then
    systemctl enable --now sbx-watchdog.timer >/dev/null
  fi
  ok "SBX Manager 初始化完成。快捷命令：sbx"
}

new_uuid() {
  python3 -c 'import uuid; print(uuid.uuid4())'
}

new_password() {
  openssl rand -base64 24 | tr -d '\n' | tr '/+' '_-'
}

certificate_ready() {
  local domain fullchain key
  domain=$(jq -r '.certificate.domain' "$STATE_FILE")
  fullchain=$(jq -r '.certificate.fullchain' "$STATE_FILE")
  key=$(jq -r '.certificate.key' "$STATE_FILE")
  [[ -n "$domain" && -s "$fullchain" && -s "$key" ]]
}

require_core_for_protocol() {
  local protocol_id=$1
  if [[ "$protocol_id" == sb-* && ! -x "$SB_BIN" ]]; then
    warn "Sing-box 内核尚未安装。请返回主菜单，先进入“内核管理”安装 Sing-box。"
    return 1
  elif [[ "$protocol_id" == xr-* && ! -x "$XR_BIN" ]]; then
    warn "Xray 内核尚未安装。请返回主菜单，先进入“内核管理”安装 Xray。"
    return 1
  fi
  if [[ "$protocol_id" == sb-* ]] && ! "$SB_BIN" version >/dev/null 2>&1; then
    warn "Sing-box 内核存在但无法运行。请进入“内核管理”重新安装。"
    return 1
  elif [[ "$protocol_id" == xr-* ]] && ! "$XR_BIN" version >/dev/null 2>&1; then
    warn "Xray 内核存在但无法运行。请进入“内核管理”重新安装。"
    return 1
  fi
}

protocol_label() {
  case "$1" in
    sb-vless-reality) printf 'Sing-box VLESS Reality Vision' ;;
    sb-vless-ws) printf 'Sing-box VLESS WebSocket（支持 Argo）' ;;
    sb-vmess-ws) printf 'Sing-box VMess WebSocket（支持 Argo）' ;;
    sb-hysteria2) printf 'Sing-box Hysteria2（需要证书）' ;;
    sb-tuic) printf 'Sing-box TUIC v5（需要证书）' ;;
    sb-anytls) printf 'Sing-box AnyTLS（需要证书）' ;;
    sb-shadowsocks) printf 'Sing-box Shadowsocks 2022' ;;
    xr-vless-reality) printf 'Xray VLESS Reality Vision' ;;
    xr-vless-ws) printf 'Xray VLESS WebSocket（支持 Argo）' ;;
    xr-vmess-ws) printf 'Xray VMess WebSocket（支持 Argo）' ;;
    xr-vless-xhttp-reality) printf 'Xray VLESS XHTTP Reality' ;;
    xr-trojan) printf 'Xray Trojan TLS（需要证书）' ;;
    xr-shadowsocks) printf 'Xray Shadowsocks 2022' ;;
    *) printf '%s' "$1" ;;
  esac
}

protocol_id_from_choice() {
  case "$1" in
    1) printf 'sb-vless-reality' ;;
    2) printf 'sb-vless-ws' ;;
    3) printf 'sb-vmess-ws' ;;
    4) printf 'sb-hysteria2' ;;
    5) printf 'sb-tuic' ;;
    6) printf 'sb-anytls' ;;
    7) printf 'sb-shadowsocks' ;;
    8) printf 'xr-vless-reality' ;;
    9) printf 'xr-vless-ws' ;;
    10) printf 'xr-vmess-ws' ;;
    11) printf 'xr-vless-xhttp-reality' ;;
    12) printf 'xr-trojan' ;;
    13) printf 'xr-shadowsocks' ;;
    *) return 1 ;;
  esac
}

make_reality_record() {
  local protocol_id=$1 port=$2 uuid=$3 server_name=$4 output private public short_id path=${5:-}
  if [[ "$protocol_id" == sb-* ]]; then
    output=$($SB_BIN generate reality-keypair)
  else
    output=$($XR_BIN x25519)
  fi
  private=$(awk -F: '/PrivateKey/ {gsub(/[[:space:]\"]/, "", $2); print $2; exit}' <<<"$output")
  public=$(awk -F: '/PublicKey|Password/ {gsub(/[[:space:]\"]/, "", $2); print $2; exit}' <<<"$output")
  short_id=$(openssl rand -hex 4)
  [[ -n "$private" && -n "$public" ]] || die "无法解析 Reality 密钥。"
  jq -cn \
    --argjson port "$port" --arg uuid "$uuid" --arg server_name "$server_name" \
    --arg private_key "$private" --arg public_key "$public" --arg short_id "$short_id" \
    --arg path "$path" \
    '{port:$port,uuid:$uuid,server_name:$server_name,private_key:$private_key,public_key:$public_key,short_id:$short_id}
     + (if $path == "" then {} else {path:$path} end)'
}

add_protocol() {
  local choice protocol_id port uuid password path server_name method record candidate
  local congestion key_bytes hopping_range hop_start hop_end obfs_password
  printf '\n可安装协议：\n'
  local i id
  for i in {1..13}; do
    id=$(protocol_id_from_choice "$i")
    printf '  %2d) %s\n' "$i" "$(protocol_label "$id")"
  done
  printf '   0) 返回\n'
  read -r -p '请选择协议 [0-13]: ' choice
  [[ "$choice" == 0 ]] && return 0
  protocol_id=$(protocol_id_from_choice "$choice") || { warn "无效选择。"; return 1; }
  if jq -e --arg id "$protocol_id" '.protocols[$id] != null' "$STATE_FILE" >/dev/null; then
    warn "该协议已经安装；如需更换参数，请先卸载后重装。"
    return 1
  fi
  require_core_for_protocol "$protocol_id" || return 1
  case "$protocol_id" in
    sb-hysteria2|sb-tuic|sb-anytls|xr-trojan)
      if ! certificate_ready; then
        warn "该协议需要有效证书。请先进入“证书管理”申请 Let's Encrypt 证书。"
        return 1
      fi
      ;;
  esac
  port=$(prompt_port)
  uuid=$(new_uuid)
  password=$(new_password)
  path="/${uuid}-ws"
  case "$protocol_id" in
    sb-vless-reality|xr-vless-reality|xr-vless-xhttp-reality)
      while true; do
        server_name=$(prompt "Reality 伪装域名" "www.microsoft.com")
        is_valid_domain "$server_name" && break
        warn "请输入标准域名，不要带协议或路径。"
      done
      [[ "$protocol_id" == xr-vless-xhttp-reality ]] || path=''
      [[ -z "$path" ]] || path=$(prompt_transport_path "XHTTP 路径" "/${uuid}-xhttp")
      record=$(make_reality_record "$protocol_id" "$port" "$uuid" "$server_name" "$path")
      ;;
    sb-vless-ws|sb-vmess-ws|xr-vless-ws|xr-vmess-ws)
      path=$(prompt_transport_path "WebSocket 路径" "$path")
      record=$(jq -cn --argjson port "$port" --arg uuid "$uuid" --arg path "$path" \
        '{port:$port,uuid:$uuid,path:$path}')
      ;;
    sb-tuic)
      while true; do
        congestion=$(prompt "TUIC 拥塞控制（cubic/new_reno/bbr）" "bbr")
        [[ "$congestion" == cubic || "$congestion" == new_reno || "$congestion" == bbr ]] && break
        warn "只支持 cubic、new_reno 或 bbr。"
      done
      record=$(jq -cn --argjson port "$port" --arg uuid "$uuid" --arg password "$password" \
        --arg congestion "$congestion" \
        '{port:$port,uuid:$uuid,password:$password,congestion_control:$congestion}')
      ;;
    sb-hysteria2)
      record=$(jq -cn --argjson port "$port" --arg password "$password" \
        '{port:$port,password:$password}')
      if confirm "启用 Hysteria2 UDP 端口跳跃？"; then
        hopping_range=$(prompt_hopping_range "$port")
        read -r hop_start hop_end <<<"$hopping_range"
        record=$(jq -c --argjson start "$hop_start" --argjson end "$hop_end" \
          '.port_hopping = {enabled:true,start:$start,end:$end}' <<<"$record")
      fi
      if confirm "启用 Hysteria2 Salamander 混淆？"; then
        obfs_password=$(new_password)
        record=$(jq -c --arg password "$obfs_password" \
          '.obfs = {type:"salamander",password:$password}' <<<"$record")
      fi
      ;;
    sb-anytls|xr-trojan)
      record=$(jq -cn --argjson port "$port" --arg password "$password" \
        '{port:$port,password:$password}')
      ;;
    sb-shadowsocks|xr-shadowsocks)
      printf '\nShadowsocks 2022 算法：\n  1) AES-128-GCM\n  2) AES-256-GCM\n  3) ChaCha20-Poly1305\n'
      while true; do
        choice=$(prompt "请选择" "1")
        case "$choice" in
          1) method='2022-blake3-aes-128-gcm'; key_bytes=16; break ;;
          2) method='2022-blake3-aes-256-gcm'; key_bytes=32; break ;;
          3) method='2022-blake3-chacha20-poly1305'; key_bytes=32; break ;;
          *) warn "无效选择。" ;;
        esac
      done
      password=$(openssl rand -base64 "$key_bytes" | tr -d '\n')
      record=$(jq -cn --argjson port "$port" --arg password "$password" --arg method "$method" \
        '{port:$port,password:$password,method:$method}')
      ;;
    *) die "内部错误：未知协议 $protocol_id" ;;
  esac
  candidate=$(mktemp)
  jq --arg id "$protocol_id" --argjson record "$record" '.protocols[$id] = $record' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    rm -f -- "$candidate"
    ok "已安装：$(protocol_label "$protocol_id")，端口 $port。"
    show_firewall_requirements
    show_nodes false
  else
    rm -f -- "$candidate"
    warn "配置自检或服务启动失败，未安装该协议。"
    return 1
  fi
}

installed_protocols() {
  local ids id
  mapfile -t ids < <(jq -r '.protocols | keys[]' "$STATE_FILE")
  if ((${#ids[@]} == 0)); then
    printf '  （尚未安装协议）\n'
    return 0
  fi
  for id in "${ids[@]}"; do
    printf '  - %-48s 端口 %s\n' "$(protocol_label "$id")" "$(jq -r --arg id "$id" '.protocols[$id].port' "$STATE_FILE")"
  done
}

stop_argo_local() {
  systemctl disable --now sbx-argo.service >/dev/null 2>&1 || true
}

remove_protocol() {
  local ids choice protocol_id candidate target
  mapfile -t ids < <(jq -r '.protocols | keys[]' "$STATE_FILE")
  if ((${#ids[@]} == 0)); then
    warn "没有已安装的协议。"
    return 0
  fi
  printf '\n已安装协议：\n'
  local i
  for i in "${!ids[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "$(protocol_label "${ids[$i]}")"
  done
  printf '  0) 返回\n'
  read -r -p "请选择要卸载的协议 [0-${#ids[@]}]: " choice
  [[ "$choice" == 0 ]] && return 0
  [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#ids[@]})) || { warn "无效选择。"; return 1; }
  protocol_id=${ids[$((choice - 1))]}
  target=$(jq -r '.argo.target' "$STATE_FILE")
  if [[ "$target" == "$protocol_id" ]]; then
    warn "该入站正被 Argo 隧道使用。请先在 Argo 管理中改绑或移除隧道。"
    return 1
  fi
  confirm "确认卸载 $(protocol_label "$protocol_id")？" || return 0
  candidate=$(mktemp)
  jq --arg id "$protocol_id" 'del(.protocols[$id])' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    rm -f -- "$candidate"
    ok "已卸载：$(protocol_label "$protocol_id")。"
    show_firewall_requirements
  else
    rm -f -- "$candidate"
    warn "卸载后的配置未通过检查，已保留原配置。"
    return 1
  fi
}

configure_hysteria2() {
  local choice port candidate hopping_range hop_start hop_end obfs_password
  if ! jq -e '.protocols["sb-hysteria2"] != null' "$STATE_FILE" >/dev/null; then
    warn "尚未安装 Sing-box Hysteria2。"
    return 1
  fi
  port=$(jq -r '.protocols["sb-hysteria2"].port' "$STATE_FILE")
  while true; do
    printf '\nHysteria2 高级设置\n'
    if jq -e '.protocols["sb-hysteria2"].port_hopping.enabled == true' "$STATE_FILE" >/dev/null; then
      printf '  端口跳跃：已启用（%s-%s -> %s/UDP）\n' \
        "$(jq -r '.protocols["sb-hysteria2"].port_hopping.start' "$STATE_FILE")" \
        "$(jq -r '.protocols["sb-hysteria2"].port_hopping.end' "$STATE_FILE")" "$port"
    else
      printf '  端口跳跃：未启用\n'
    fi
    if jq -e '.protocols["sb-hysteria2"].obfs != null' "$STATE_FILE" >/dev/null; then
      printf '  Salamander 混淆：已启用\n'
    else
      printf '  Salamander 混淆：未启用\n'
    fi
    printf '\n  1) 启用/修改端口跳跃范围\n  2) 禁用端口跳跃\n'
    printf '  3) 启用/更换 Salamander 混淆密码\n  4) 禁用 Salamander 混淆\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1)
        hopping_range=$(prompt_hopping_range "$port")
        read -r hop_start hop_end <<<"$hopping_range"
        candidate=$(mktemp)
        jq --argjson start "$hop_start" --argjson end "$hop_end" \
          '.protocols["sb-hysteria2"].port_hopping = {enabled:true,start:$start,end:$end}' \
          "$STATE_FILE" >"$candidate"
        if commit_candidate "$candidate"; then
          ok "Hysteria2 端口跳跃已同步，无需重启 Sing-box。"
          show_firewall_requirements
          show_nodes false
        fi
        rm -f -- "$candidate"
        ;;
      2)
        candidate=$(mktemp)
        jq 'del(.protocols["sb-hysteria2"].port_hopping)' "$STATE_FILE" >"$candidate"
        if commit_candidate "$candidate"; then
          ok "Hysteria2 端口跳跃已禁用，旧 NAT 规则已删除。"
          show_firewall_requirements
          show_nodes false
        fi
        rm -f -- "$candidate"
        ;;
      3)
        obfs_password=$(new_password)
        candidate=$(mktemp)
        jq --arg password "$obfs_password" \
          '.protocols["sb-hysteria2"].obfs = {type:"salamander",password:$password}' \
          "$STATE_FILE" >"$candidate"
        if commit_candidate "$candidate"; then
          ok "Salamander 混淆已启用并自动重启 Sing-box。"
          show_nodes false
        fi
        rm -f -- "$candidate"
        ;;
      4)
        candidate=$(mktemp)
        jq 'del(.protocols["sb-hysteria2"].obfs)' "$STATE_FILE" >"$candidate"
        if commit_candidate "$candidate"; then
          ok "Salamander 混淆已禁用并自动重启 Sing-box。"
          show_nodes false
        fi
        rm -f -- "$candidate"
        ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

protocol_menu() {
  local choice
  while true; do
    printf '\n协议管理\n'
    installed_protocols
    printf '\n  1) 安装协议\n  2) 卸载协议\n  3) Hysteria2 端口跳跃/混淆\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) add_protocol || true ;;
      2) remove_protocol || true ;;
      3) configure_hysteria2 || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

core_status() {
  local version
  printf '\n内核状态\n'
  if [[ -x "$SB_BIN" ]] && version=$("$SB_BIN" version 2>/dev/null | head -n1); then
    printf '  Sing-box：已安装（%s）\n' "$version"
  elif [[ -e "$SB_BIN" ]]; then
    printf '  Sing-box：文件存在但无法运行，请重新安装\n'
  else
    printf '  Sing-box：未安装\n'
  fi
  if [[ -x "$XR_BIN" ]] && version=$("$XR_BIN" version 2>/dev/null | head -n1); then
    printf '  Xray：已安装（%s）\n' "$version"
  elif [[ -e "$XR_BIN" ]]; then
    printf '  Xray：文件存在但无法运行，请重新安装\n'
  else
    printf '  Xray：未安装\n'
  fi
}

install_or_update_core() {
  local core=$1 prefix label unit
  case "$core" in
    sing-box)
      prefix=sb-
      label=Sing-box
      unit=sbx-sing-box.service
      install_singbox || return 1
      ;;
    xray)
      prefix=xr-
      label=Xray
      unit=sbx-xray.service
      install_xray || return 1
      ;;
    *)
      warn "未知内核：$core"
      return 1
      ;;
  esac
  if (( $(core_count "$prefix") > 0 )); then
    if commit_candidate "$STATE_FILE"; then
      systemctl restart "$unit" || {
        warn "$label 新内核已安装，但服务重启失败，请查看日志。"
        return 1
      }
      ok "$label 现有协议配置已验证并重新加载。"
    else
      warn "$label 已安装，但现有协议配置未能重新加载，请查看日志。"
      return 1
    fi
  fi
}

core_menu() {
  local choice
  while true; do
    core_status
    printf '\n内核管理\n'
    printf '  1) 安装/更新 Sing-box\n'
    printf '  2) 安装/更新 Xray\n'
    printf '  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) install_or_update_core sing-box || true ;;
      2) install_or_update_core xray || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

show_nodes() {
  local with_qr=${1:-true} header='' line
  local work
  work=$(mktemp -d)
  render_candidate "$STATE_FILE" "$work"
  install -m 600 "$work/nodes.txt" "$ETC_DIR/nodes.txt"
  printf '\n节点信息（仅在本机生成）：\n\n'
  cat "$work/nodes.txt"
  if [[ "$with_qr" == true ]] && command -v qrencode >/dev/null 2>&1 && [[ -t 1 ]]; then
    while IFS= read -r line; do
      if [[ "$line" == \[*\] ]]; then
        header=$line
      elif [[ -n "$line" ]]; then
        printf '\n%s\n' "$header"
        qrencode -t ANSIUTF8 "$line" || true
      fi
    done <"$work/nodes.txt"
  fi
  rm -rf -- "$work"
}

set_prefix() {
  local prefix candidate
  prefix=$(prompt "节点名称前缀" "$(jq -r '.node_prefix' "$STATE_FILE")")
  [[ -n "$prefix" && ${#prefix} -le 48 && "$prefix" != *$'\n'* ]] || { warn "前缀不能为空且最多 48 个字符。"; return 1; }
  candidate=$(mktemp)
  jq --arg prefix "$prefix" '.node_prefix = $prefix' "$STATE_FILE" >"$candidate"
  commit_candidate "$candidate" && ok "节点前缀已更新。"
  rm -f -- "$candidate"
}

set_server() {
  local server candidate
  server=$(prompt "节点服务器地址（IP 或域名）" "$(jq -r '.server' "$STATE_FILE")")
  is_valid_hostname_or_ip "$server" || { warn "服务器地址格式不安全。"; return 1; }
  candidate=$(mktemp)
  jq --arg server "$server" '.server = $server' "$STATE_FILE" >"$candidate"
  commit_candidate "$candidate" && ok "节点服务器地址已更新。"
  rm -f -- "$candidate"
}

set_route_mode() {
  local mode=$1 candidate
  if [[ "$mode" == warp ]]; then
    systemctl is-active --quiet warp-svc || { warn "WARP 服务未运行，请先安装并配置 WARP。"; return 1; }
    warp-cli --accept-tos settings 2>/dev/null | grep -Eqi 'WarpProxy|proxy' \
      || { warn "WARP 不是 Local proxy 模式，拒绝切换以避免路由黑洞。"; return 1; }
  fi
  candidate=$(mktemp)
  jq --arg mode "$mode" '.routing.mode = $mode' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    ok "所有已安装入站已切换为 $mode 出站。"
  fi
  rm -f -- "$candidate"
}

route_menu() {
  local choice current
  while true; do
    current=$(jq -r '.routing | "模式=" + .mode + "，SOCKS5=127.0.0.1:" + (.socks_port|tostring)' "$STATE_FILE")
    printf '\n出站路由管理（当前：%s）\n' "$current"
    printf '  1) 全部切换为 direct 本机出站\n  2) 全部切换为 WARP SOCKS5 出站\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) set_route_mode direct || true ;;
      2) set_route_mode warp || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

write_acme_units_and_hooks() {
  cat >"$LIB_DIR/acme-pre.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077
active_file=/run/sbx-manager-acme-active
firewall_marker=/run/sbx-manager-acme-http01
: >"$active_file"
: >"$firewall_marker"
if ! /usr/local/sbin/sbx-manager firewall-apply; then
  rm -f -- "$firewall_marker"
  /usr/local/sbin/sbx-manager firewall-apply >/dev/null 2>&1 || true
  exit 1
fi
for unit in sbx-sing-box.service sbx-xray.service; do
  if systemctl is-active --quiet "$unit"; then
    printf '%s\n' "$unit" >>"$active_file"
    systemctl stop "$unit"
  fi
done
EOF
  cat >"$LIB_DIR/acme-post.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
active_file=/run/sbx-manager-acme-active
firewall_marker=/run/sbx-manager-acme-http01
failed=0
if [[ -f "$active_file" ]]; then
  while IFS= read -r unit; do
    case "$unit" in
      sbx-sing-box.service|sbx-xray.service) systemctl start "$unit" || failed=1 ;;
    esac
  done <"$active_file"
  rm -f -- "$active_file"
fi
rm -f -- "$firewall_marker"
/usr/local/sbin/sbx-manager firewall-apply || failed=1
exit "$failed"
EOF
  cat >"$LIB_DIR/cert-reload.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
systemctl try-restart sbx-sing-box.service sbx-xray.service >/dev/null 2>&1 || true
EOF
  chmod 700 "$LIB_DIR/acme-pre.sh" "$LIB_DIR/acme-post.sh" "$LIB_DIR/cert-reload.sh"
  cat >"$SYSTEMD_DIR/sbx-acme-renew.service" <<EOF
[Unit]
Description=Renew SBX Manager ACME certificates
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$ACME_HOME/acme.sh --cron --home $ACME_HOME --config-home $ACME_CONFIG
EOF
  cat >"$SYSTEMD_DIR/sbx-acme-renew.timer" <<'EOF'
[Unit]
Description=Twice-daily SBX Manager certificate renewal check

[Timer]
OnCalendar=*-*-* 03,15:20:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
}

install_acme_client() {
  local tag tmp archive source_script source_dir
  if [[ -x "$ACME_HOME/acme.sh" ]] \
    && bash -n "$ACME_HOME/acme.sh" >/dev/null 2>&1 \
    && "$ACME_HOME/acme.sh" --version >/dev/null 2>&1; then
    write_acme_units_and_hooks
    return 0
  fi
  if [[ -d "$ACME_HOME" ]]; then
    warn "检测到不完整或损坏的 acme.sh 程序目录，正在清理后重装（证书与配置保留）。"
    rm -rf -- "$ACME_HOME"
  fi
  tag=${SBX_ACME_VERSION:-}
  [[ -n "$tag" ]] || tag=$(github_latest_tag acmesh-official/acme.sh)
  tmp=$(mktemp -d)
  archive="$tmp/acme.tar.gz"
  info "从 acme.sh 官方 GitHub 发布页下载 $tag"
  secure_curl -o "$archive" "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${tag}.tar.gz"
  tar -xzf "$archive" -C "$tmp"
  source_script=$(find "$tmp" -mindepth 2 -maxdepth 2 -type f -name acme.sh | head -n1)
  [[ -n "$source_script" ]] || { rm -rf -- "$tmp"; die "acme.sh 发布包结构异常。"; }
  source_dir=${source_script%/*}
  if ! (
    cd "$source_dir"
    bash ./acme.sh --install --home "$ACME_HOME" --config-home "$ACME_CONFIG" --nocron --noprofile
  ); then
    rm -rf -- "$tmp"
    die "acme.sh 安装失败。"
  fi
  rm -rf -- "$tmp"
  [[ -x "$ACME_HOME/acme.sh" ]] || die "acme.sh 安装失败。"
  write_acme_units_and_hooks
  ok "acme.sh 已安装。"
}

install_issued_certificate() {
  local domain=$1
  "$ACME_HOME/acme.sh" --install-cert -d "$domain" --ecc \
    --home "$ACME_HOME" --config-home "$ACME_CONFIG" \
    --key-file "$CERT_DIR/private.key" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "$LIB_DIR/cert-reload.sh"
  chmod 600 "$CERT_DIR/private.key" "$CERT_DIR/fullchain.pem"
}

save_certificate_state() {
  local domain=$1 acme_domain=${2:-$1} kind=${3:-domain}
  local identifiers_json=${4:-} profile=${5:-classic} candidate saved=false
  [[ -n "$identifiers_json" ]] \
    || identifiers_json=$(jq -cn --arg identifier "$acme_domain" '[ $identifier ]')
  candidate=$(mktemp)
  jq --arg domain "$domain" --arg acme_domain "$acme_domain" \
    --arg kind "$kind" --arg profile "$profile" --argjson identifiers "$identifiers_json" \
    --arg fullchain "$CERT_DIR/fullchain.pem" --arg key "$CERT_DIR/private.key" \
    '.certificate = {domain:$domain,acme_domain:$acme_domain,kind:$kind,profile:$profile,
      identifiers:$identifiers,fullchain:$fullchain,key:$key}' \
    "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    systemctl enable --now sbx-acme-renew.timer >/dev/null
    ok "证书已安装并启用无人值守续期。"
    saved=true
  else
    warn "证书已签发，但现有代理配置未通过自检。证书保留在 $CERT_DIR。"
  fi
  rm -f -- "$candidate"
  [[ "$saved" == true ]]
}

register_acme_account() {
  local email
  email=$(prompt "Let's Encrypt 联系邮箱（可留空）")
  if [[ -n "$email" && ! "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
    warn "邮箱格式无效。"
    return 1
  fi
  if [[ -n "$email" ]]; then
    "$ACME_HOME/acme.sh" --register-account -m "$email" --server letsencrypt \
      --home "$ACME_HOME" --config-home "$ACME_CONFIG" || true
  fi
}

run_standalone_issue() {
  local label=$1 issue_status
  shift
  set +e
  "$ACME_HOME/acme.sh" --issue "$@" --standalone --keylength ec-256 --server letsencrypt \
    --pre-hook "$LIB_DIR/acme-pre.sh" --post-hook "$LIB_DIR/acme-post.sh" \
    --home "$ACME_HOME" --config-home "$ACME_CONFIG"
  issue_status=$?
  set -e
  "$LIB_DIR/acme-post.sh" || true
  if ((issue_status != 0)); then
    warn "$label 签发失败，已尝试恢复代理服务。"
    return "$issue_status"
  fi
}

detect_public_certificate_ips() {
  local v4 v6
  v4=$(secure_curl -4 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
    | awk -F= '$1 == "ip" {print $2; exit}' || true)
  v6=$(secure_curl -6 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
    | awk -F= '$1 == "ip" {print $2; exit}' || true)
  printf '%s' "${v4}${v4:+${v6:+ }}${v6}"
}

issue_certificate_ip() {
  local detected raw normalized acme_primary client_identity current_server normalized_server identifiers_json ip
  local -a ips=() domain_args=()
  install_acme_client
  detected=$(detect_public_certificate_ips)
  [[ -n "$detected" ]] && info "检测到本机公网 IP：$detected"
  while true; do
    raw=$(prompt "输入一个公网 IP，或同时输入 IPv4 IPv6（第一个为 ACME 主标识）" "$detected")
    if normalized=$(python3 "$GENERATOR" normalize-ip --value "$raw" 2>/dev/null); then
      break
    fi
    warn "请输入一个公网 IPv4/IPv6，或各输入一个；私网、保留地址和同族双 IP 不支持。"
  done
  read -r -a ips <<<"$normalized"
  for ip in "${ips[@]}"; do
    domain_args+=(-d "$ip")
  done
  register_acme_account || return 1
  info "开始申请 Let's Encrypt shortlived IP 证书；公网 TCP/80 必须能直接到达本机。"
  run_standalone_issue "IP 证书" "${domain_args[@]}" \
    --certificate-profile shortlived --days 3 || return 1
  acme_primary=${ips[0]}
  client_identity=$acme_primary
  current_server=$(jq -r '.server' "$STATE_FILE")
  normalized_server=$(python3 "$GENERATOR" normalize-ip --value "$current_server" 2>/dev/null || true)
  for ip in "${ips[@]}"; do
    [[ "$ip" == "$normalized_server" ]] && client_identity=$ip
  done
  identifiers_json=$(printf '%s\n' "${ips[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')
  install_issued_certificate "$acme_primary" || return 1
  save_certificate_state "$client_identity" "$acme_primary" ip "$identifiers_json" shortlived || return 1
}

issue_certificate_standalone() {
  local domain
  install_acme_client
  while true; do
    domain=$(prompt "需要签发证书的域名")
    is_valid_domain "$domain" && break
    warn "域名格式无效。"
  done
  register_acme_account || return 1
  info "开始 HTTP-01 签发；域名必须已解析到本机，公网 TCP/80 必须可达。"
  run_standalone_issue "HTTP-01 域名证书" -d "$domain" || return 1
  install_issued_certificate "$domain" || return 1
  save_certificate_state "$domain" "$domain" domain || return 1
}

issue_certificate_dns_cf() {
  local domain client_domain base_domain cf_token cf_account
  install_acme_client
  while true; do
    domain=$(prompt "需要签发证书的域名（可输入 *.example.com）")
    if [[ "$domain" == \*.* ]]; then
      is_valid_domain "${domain#*.}" && break
    elif is_valid_domain "$domain"; then
      break
    fi
    warn "域名格式无效。"
  done
  client_domain=$domain
  if [[ "$domain" == \*.* ]]; then
    base_domain=${domain#*.}
    while true; do
      client_domain=$(prompt "客户端 SNI 域名（必须由该泛域名覆盖）" "proxy.$base_domain")
      if is_valid_domain "$client_domain" && [[ "$client_domain" == *".$base_domain" ]]; then
        break
      fi
      warn "SNI 必须是 *.$base_domain 覆盖的具体域名。"
    done
  fi
  register_acme_account || return 1
  read -r -s -p 'Cloudflare API Token（需要 Zone DNS Edit）: ' cf_token
  printf '\n'
  cf_account=$(prompt "Cloudflare Account ID")
  is_safe_token "$cf_token" || { warn "API Token 格式不安全。"; return 1; }
  [[ "$cf_account" =~ ^[0-9a-fA-F]{32}$ ]] || { warn "Account ID 应为 32 位十六进制。"; return 1; }
  info "开始 DNS-01 签发。API Token 将由 acme.sh 以 root-only 权限保存，供无人值守续期使用。"
  if ! CF_Token="$cf_token" CF_Account_ID="$cf_account" \
    "$ACME_HOME/acme.sh" --issue -d "$domain" --dns dns_cf --keylength ec-256 --server letsencrypt \
      --home "$ACME_HOME" --config-home "$ACME_CONFIG"; then
    unset cf_token CF_Token
    warn "Cloudflare DNS-01 签发失败。"
    return 1
  fi
  unset cf_token CF_Token
  install_issued_certificate "$domain" || return 1
  save_certificate_state "$client_domain" "$domain" domain || return 1
}

renew_certificate_now() {
  local domain
  domain=$(jq -r '.certificate.acme_domain // .certificate.domain' "$STATE_FILE")
  [[ -n "$domain" && -x "$ACME_HOME/acme.sh" ]] || { warn "尚未配置 ACME 证书。"; return 1; }
  "$ACME_HOME/acme.sh" --renew -d "$domain" --ecc --force \
    --home "$ACME_HOME" --config-home "$ACME_CONFIG"
  install_issued_certificate "$domain" || return 1
  ok "证书已续期并重新加载服务。"
}

certificate_status() {
  local domain acme_domain kind profile identifiers fullchain
  domain=$(jq -r '.certificate.domain' "$STATE_FILE")
  acme_domain=$(jq -r '.certificate.acme_domain // .certificate.domain' "$STATE_FILE")
  kind=$(jq -r '.certificate.kind // "domain"' "$STATE_FILE")
  profile=$(jq -r '.certificate.profile // "classic"' "$STATE_FILE")
  identifiers=$(jq -r '(.certificate.identifiers // []) | join(", ")' "$STATE_FILE")
  fullchain=$(jq -r '.certificate.fullchain' "$STATE_FILE")
  [[ -n "$identifiers" ]] || identifiers=$acme_domain
  printf '\n证书类型：%s\n证书标识：%s\n客户端校验标识：%s\nACME Profile：%s\n' \
    "$kind" "${identifiers:-未配置}" "${domain:-未配置}" "$profile"
  if [[ -s "$fullchain" ]]; then
    openssl x509 -in "$fullchain" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null \
      || openssl x509 -in "$fullchain" -noout -subject -issuer -dates
  else
    printf '证书文件不存在。\n'
  fi
  systemctl list-timers sbx-acme-renew.timer --no-pager 2>/dev/null || true
}

certificate_menu() {
  local choice
  while true; do
    printf '\n证书管理\n'
    printf '  1) HTTP-01（80 端口）申请/替换 IPv4/IPv6 IP 证书\n'
    printf '  2) HTTP-01（80 端口）申请/替换域名证书\n'
    printf '  3) Cloudflare DNS-01 申请/替换域名或泛域名证书\n'
    printf '  4) 立即续期\n  5) 查看证书与自动续期状态\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) issue_certificate_ip || true ;;
      2) issue_certificate_standalone || true ;;
      3) issue_certificate_dns_cf || true ;;
      4) renew_certificate_now || true ;;
      5) certificate_status ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

argo_compatible_ids() {
  jq -r '.protocols | keys[] | select(
    . == "sb-vless-ws" or . == "sb-vmess-ws" or
    . == "xr-vless-ws" or . == "xr-vmess-ws")' "$STATE_FILE"
}

choose_argo_target() {
  local ids choice i
  mapfile -t ids < <(argo_compatible_ids)
  ((${#ids[@]} > 0)) || { warn "请先安装一个支持 Argo 的 VLESS/VMess WebSocket 入站。"; return 1; }
  printf '\n可绑定的入站：\n' >&2
  for i in "${!ids[@]}"; do
    printf '  %d) %s（端口 %s）\n' "$((i + 1))" "$(protocol_label "${ids[$i]}")" \
      "$(jq -r --arg id "${ids[$i]}" '.protocols[$id].port' "$STATE_FILE")" >&2
  done
  read -r -p "请选择 [1-${#ids[@]}]: " choice
  [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#ids[@]})) || return 1
  printf '%s' "${ids[$((choice - 1))]}"
}

write_argo_unit_quick() {
  local target=$1 port
  port=$(jq -r --arg id "$target" '.protocols[$id].port' "$STATE_FILE")
  : >"$LOG_DIR/argo.log"
  cat >"$SYSTEMD_DIR/sbx-argo.service" <<EOF
[Unit]
Description=SBX Manager Cloudflare Quick Tunnel
After=network-online.target sbx-sing-box.service sbx-xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$CF_BIN tunnel --no-autoupdate --edge-ip-version auto --protocol http2 --loglevel info --logfile $LOG_DIR/argo.log --url http://localhost:$port
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

write_argo_unit_fixed() {
  cat >"$SYSTEMD_DIR/sbx-argo.service" <<EOF
[Unit]
Description=SBX Manager Cloudflare Named Tunnel
After=network-online.target sbx-sing-box.service sbx-xray.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$SECRET_DIR/argo.env
ExecStart=$CF_BIN tunnel --no-autoupdate --edge-ip-version auto --protocol http2 run --token \${ARGO_TOKEN}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

cf_api() {
  local method=$1 url=$2 token=$3 data=${4:-} config output status
  config=$(mktemp)
  output=$(mktemp)
  printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token" >"$config"
  chmod 600 "$config"
  if [[ -n "$data" ]]; then
    status=$(curl --silent --show-error --output "$output" --write-out '%{http_code}' \
      --request "$method" --config "$config" --data "$data" --proto '=https' --tlsv1.2 "$url") || status=000
  else
    status=$(curl --silent --show-error --output "$output" --write-out '%{http_code}' \
      --request "$method" --config "$config" --proto '=https' --tlsv1.2 "$url") || status=000
  fi
  rm -f -- "$config"
  if [[ "$status" =~ ^2 && $(jq -r '.success // false' "$output" 2>/dev/null) == true ]]; then
    cat "$output"
    rm -f -- "$output"
    return 0
  fi
  warn "Cloudflare API 请求失败（HTTP $status）：$(jq -r '[.errors[]?.message] | join("; ")' "$output" 2>/dev/null || printf '未知错误')"
  rm -f -- "$output"
  return 1
}

start_argo_quick_for_target() {
  local target=$1 candidate hostname i
  [[ -x "$CF_BIN" ]] || install_cloudflared
  stop_argo_local
  write_argo_unit_quick "$target"
  systemctl enable --now sbx-argo.service >/dev/null
  info "正在等待 Cloudflare 分配临时域名（最多约 30 秒）……"
  hostname=''
  for i in {1..15}; do
    hostname=$(grep -Eo 'https://[-a-z0-9]+\.trycloudflare\.com' "$LOG_DIR/argo.log" 2>/dev/null | tail -n1 | sed 's#https://##' || true)
    [[ -n "$hostname" ]] && break
    sleep 2
  done
  if [[ -z "$hostname" ]]; then
    systemctl status sbx-argo.service --no-pager -l || true
    warn "未获取到临时域名；请查看 journalctl -u sbx-argo。"
    return 1
  fi
  candidate=$(mktemp)
  jq --arg target "$target" --arg hostname "$hostname" '
    .argo = {mode:"quick",target:$target,hostname:$hostname,tunnel_id:"",account_id:""}' \
    "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    ok "临时 Argo 已绑定到 $(protocol_label "$target")：$hostname"
  fi
  rm -f -- "$candidate"
}

install_argo_quick() {
  local target mode
  mode=$(jq -r '.argo.mode' "$STATE_FILE")
  [[ "$mode" != fixed ]] || {
    warn "当前为固定隧道；请先在隧道管理中移除固定隧道。"
    return 1
  }
  target=$(choose_argo_target) || return 1
  start_argo_quick_for_target "$target"
}

upsert_cloudflare_dns() {
  local token=$1 zone_id=$2 hostname=$3 tunnel_id=$4 records record_id payload response
  records=$(cf_api GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=CNAME&name=$hostname" "$token") || return 1
  record_id=$(jq -r '.result[0].id // empty' <<<"$records")
  payload=$(jq -cn --arg name "$hostname" --arg content "${tunnel_id}.cfargotunnel.com" \
    '{type:"CNAME",name:$name,content:$content,proxied:true,ttl:1}')
  if [[ -n "$record_id" ]]; then
    response=$(cf_api PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" "$token" "$payload") || return 1
  else
    response=$(cf_api POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" "$token" "$payload") || return 1
  fi
  jq -r '.result.id' <<<"$response"
}

install_argo_fixed() {
  local target account_id zone_id hostname tunnel_name api_token port base payload response tunnel_id tunnel_token config_payload dns_record_id candidate mode
  mode=$(jq -r '.argo.mode' "$STATE_FILE")
  [[ "$mode" == off ]] || {
    warn "已有 Argo 隧道正在使用；请先移除，再创建固定隧道。"
    return 1
  }
  target=$(choose_argo_target) || return 1
  [[ -x "$CF_BIN" ]] || install_cloudflared
  account_id=$(prompt "Cloudflare Account ID")
  zone_id=$(prompt "Cloudflare Zone ID")
  while true; do
    hostname=$(prompt "固定隧道域名（例如 proxy.example.com）")
    is_valid_domain "$hostname" && break
    warn "域名格式无效。"
  done
  tunnel_name=$(prompt "隧道名称" "sbx-$(hostname -s | tr -cd 'A-Za-z0-9_-')")
  read -r -s -p 'Cloudflare API Token（Tunnel Write + Zone DNS Edit）: ' api_token
  printf '\n'
  [[ "$account_id" =~ ^[0-9a-fA-F]{32}$ && "$zone_id" =~ ^[0-9a-fA-F]{32}$ ]] \
    || { warn "Account ID/Zone ID 应为 32 位十六进制。"; return 1; }
  is_safe_token "$api_token" || { warn "API Token 格式不安全。"; return 1; }
  [[ "$tunnel_name" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { warn "隧道名称仅允许字母、数字、下划线和连字符。"; return 1; }
  port=$(jq -r --arg id "$target" '.protocols[$id].port' "$STATE_FILE")
  base="https://api.cloudflare.com/client/v4/accounts/$account_id/cfd_tunnel"
  payload=$(jq -cn --arg name "$tunnel_name" '{name:$name,config_src:"cloudflare"}')
  response=$(cf_api POST "$base" "$api_token" "$payload") || return 1
  tunnel_id=$(jq -r '.result.id' <<<"$response")
  [[ "$tunnel_id" =~ ^[0-9a-fA-F-]{36}$ ]] || { warn "Cloudflare 未返回有效 Tunnel ID。"; return 1; }
  config_payload=$(jq -cn --arg host "$hostname" --arg service "http://localhost:$port" \
    '{config:{ingress:[{hostname:$host,service:$service,originRequest:{}},{service:"http_status:404"}],originRequest:{}}}')
  cf_api PUT "$base/$tunnel_id/configurations" "$api_token" "$config_payload" >/dev/null || {
    warn "隧道已创建但 ingress 写入失败。Tunnel ID：$tunnel_id"
    return 1
  }
  dns_record_id=$(upsert_cloudflare_dns "$api_token" "$zone_id" "$hostname" "$tunnel_id") || {
    warn "隧道已创建但 DNS 写入失败。Tunnel ID：$tunnel_id"
    return 1
  }
  response=$(cf_api GET "$base/$tunnel_id/token" "$api_token") || return 1
  tunnel_token=$(jq -r '.result' <<<"$response")
  is_safe_token "$tunnel_token" || { warn "Cloudflare 返回了异常隧道令牌。"; return 1; }
  printf 'ARGO_TOKEN=%s\n' "$tunnel_token" >"$SECRET_DIR/argo.env"
  chmod 600 "$SECRET_DIR/argo.env"
  unset api_token tunnel_token
  stop_argo_local
  write_argo_unit_fixed
  systemctl enable --now sbx-argo.service >/dev/null
  candidate=$(mktemp)
  jq --arg target "$target" --arg hostname "$hostname" --arg tunnel_id "$tunnel_id" \
    --arg account_id "$account_id" --arg zone_id "$zone_id" --arg dns_record_id "$dns_record_id" '
    .argo = {mode:"fixed",target:$target,hostname:$hostname,tunnel_id:$tunnel_id,
      account_id:$account_id,zone_id:$zone_id,dns_record_id:$dns_record_id}' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    ok "固定 Argo 已创建并绑定到 $(protocol_label "$target")：$hostname"
  fi
  rm -f -- "$candidate"
}

rebind_argo() {
  local mode target old_target hostname account_id tunnel_id api_token port payload candidate
  mode=$(jq -r '.argo.mode' "$STATE_FILE")
  [[ "$mode" != off ]] || { warn "尚未配置 Argo。"; return 1; }
  target=$(choose_argo_target) || return 1
  old_target=$(jq -r '.argo.target' "$STATE_FILE")
  [[ "$target" != "$old_target" ]] || { info "已经绑定到该入站。"; return 0; }
  if [[ "$mode" == quick ]]; then
    warn "临时隧道重绑会分配新的 trycloudflare.com 域名。"
    start_argo_quick_for_target "$target"
    return
  fi
  hostname=$(jq -r '.argo.hostname' "$STATE_FILE")
  account_id=$(jq -r '.argo.account_id' "$STATE_FILE")
  tunnel_id=$(jq -r '.argo.tunnel_id' "$STATE_FILE")
  port=$(jq -r --arg id "$target" '.protocols[$id].port' "$STATE_FILE")
  read -r -s -p 'Cloudflare API Token（Tunnel Write）: ' api_token
  printf '\n'
  is_safe_token "$api_token" || { warn "API Token 格式不安全。"; return 1; }
  payload=$(jq -cn --arg host "$hostname" --arg service "http://localhost:$port" \
    '{config:{ingress:[{hostname:$host,service:$service,originRequest:{}},{service:"http_status:404"}],originRequest:{}}}')
  cf_api PUT "https://api.cloudflare.com/client/v4/accounts/$account_id/cfd_tunnel/$tunnel_id/configurations" \
    "$api_token" "$payload" >/dev/null || return 1
  unset api_token
  candidate=$(mktemp)
  jq --arg target "$target" '.argo.target = $target' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    ok "固定 Argo 已重绑到 $(protocol_label "$target")。"
  fi
  rm -f -- "$candidate"
}

remove_argo() {
  local mode account_id tunnel_id zone_id record_id api_token candidate
  mode=$(jq -r '.argo.mode' "$STATE_FILE")
  [[ "$mode" != off ]] || { info "Argo 未启用。"; return 0; }
  if [[ "$mode" == fixed ]] && confirm "是否同时删除 Cloudflare 端的隧道和 DNS 记录？"; then
    account_id=$(jq -r '.argo.account_id' "$STATE_FILE")
    tunnel_id=$(jq -r '.argo.tunnel_id' "$STATE_FILE")
    zone_id=$(jq -r '.argo.zone_id // empty' "$STATE_FILE")
    record_id=$(jq -r '.argo.dns_record_id // empty' "$STATE_FILE")
    read -r -s -p 'Cloudflare API Token（Tunnel Write + Zone DNS Edit）: ' api_token
    printf '\n'
    is_safe_token "$api_token" || { warn "API Token 格式不安全。"; return 1; }
    stop_argo_local
    [[ -z "$record_id" ]] || cf_api DELETE "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" "$api_token" >/dev/null || true
    cf_api DELETE "https://api.cloudflare.com/client/v4/accounts/$account_id/cfd_tunnel/$tunnel_id" "$api_token" >/dev/null || true
    unset api_token
  else
    stop_argo_local
  fi
  : >"$SECRET_DIR/argo.env"
  chmod 600 "$SECRET_DIR/argo.env"
  candidate=$(mktemp)
  jq '.argo = {mode:"off",target:"",hostname:"",tunnel_id:"",account_id:""}' "$STATE_FILE" >"$candidate"
  commit_candidate "$candidate" && ok "Argo 本地配置已移除。"
  rm -f -- "$candidate"
}

argo_status() {
  printf '\nArgo 配置：\n'
  jq -r '.argo | "  模式：" + .mode + "\n  目标：" + (.target // "") + "\n  域名：" + (.hostname // "") + "\n  Tunnel ID：" + (.tunnel_id // "")' "$STATE_FILE"
  systemctl --no-pager --full status sbx-argo.service 2>/dev/null || true
}

argo_menu() {
  local choice
  while true; do
    printf '\nArgo 隧道管理\n'
    printf '  1) 创建/重建临时 Quick Tunnel\n'
    printf '  2) 通过 Cloudflare API 创建固定隧道并配置 DNS\n'
    printf '  3) 修改隧道绑定的 WebSocket 入站\n'
    printf '  4) 查看状态\n  5) 停止并移除隧道\n  6) 更新 cloudflared\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) install_argo_quick || true ;;
      2) install_argo_fixed || true ;;
      3) rebind_argo || true ;;
      4) argo_status ;;
      5) remove_argo || true ;;
      6) install_cloudflared; systemctl try-restart sbx-argo.service || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

write_warp_mdm_free() {
  local port=$1
  install -d -m 700 /var/lib/cloudflare-warp
  cat >/var/lib/cloudflare-warp/mdm.xml <<EOF
<dict>
  <key>onboarding</key>
  <false/>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>$port</integer>
</dict>
EOF
  chmod 600 /var/lib/cloudflare-warp/mdm.xml
}

write_warp_mdm_zt() {
  local port=$1 organization=$2 client_id=$3 client_secret=$4
  install -d -m 700 /var/lib/cloudflare-warp
  cat >/var/lib/cloudflare-warp/mdm.xml <<EOF
<dict>
  <key>auth_client_id</key>
  <string>$client_id</string>
  <key>auth_client_secret</key>
  <string>$client_secret</string>
  <key>auto_connect</key>
  <integer>1</integer>
  <key>onboarding</key>
  <false/>
  <key>organization</key>
  <string>$organization</string>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>$port</integer>
</dict>
EOF
  chmod 600 /var/lib/cloudflare-warp/mdm.xml
}

install_warp_package() {
  local codename tmp key_source keyring source_fingerprints keyring_fingerprints candidate os_release
  local repo_file system_keyring had_repo=0 had_keyring=0
  command -v apt-get >/dev/null 2>&1 || { warn "官方 cloudflare-warp 自动安装目前仅支持 Debian/Ubuntu。"; return 1; }
  if ! command -v gpg >/dev/null 2>&1; then
    apt-get update
    apt-get install -y gnupg
  fi
  # shellcheck disable=SC1091
  os_release=${SBX_OS_RELEASE_FILE:-/etc/os-release}
  [[ -r "$os_release" ]] || { warn "无法读取系统版本信息：$os_release"; return 1; }
  source "$os_release"
  codename=${VERSION_CODENAME:-}
  [[ "$codename" =~ ^[a-z0-9.-]+$ ]] || { warn "无法识别安全的系统代号。"; return 1; }
  repo_file=${SBX_WARP_REPO_FILE:-/etc/apt/sources.list.d/cloudflare-client.list}
  system_keyring=${SBX_WARP_KEYRING:-/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg}
  tmp=$(mktemp -d)
  key_source="$tmp/pubkey.gpg"
  keyring="$tmp/cloudflare-warp-archive-keyring.gpg"
  info "添加 Cloudflare 官方软件源并安装 cloudflare-warp。"
  if ! secure_curl -o "$key_source" https://pkg.cloudflareclient.com/pubkey.gpg; then
    rm -rf -- "$tmp"
    warn "Cloudflare 官方公钥下载失败。"
    return 1
  fi
  if ! source_fingerprints=$(gpg --batch --show-keys --with-colons "$key_source" 2>/dev/null \
      | awk -F: '$1 == "fpr" && length($10) == 40 && $10 ~ /^[0-9A-Fa-f]+$/ {print toupper($10)}' \
      | LC_ALL=C sort -u) \
      || [[ -z "$source_fingerprints" ]]; then
    rm -rf -- "$tmp"
    warn "无法从 Cloudflare 官方公钥中读取完整指纹，拒绝添加软件源。"
    return 1
  fi
  if ! gpg --batch --yes --dearmor --output "$keyring" "$key_source"; then
    rm -rf -- "$tmp"
    warn "Cloudflare keyring 生成失败。"
    return 1
  fi
  if ! keyring_fingerprints=$(gpg --batch --show-keys --with-colons "$keyring" 2>/dev/null \
      | awk -F: '$1 == "fpr" && length($10) == 40 && $10 ~ /^[0-9A-Fa-f]+$/ {print toupper($10)}' \
      | LC_ALL=C sort -u) \
      || [[ "$keyring_fingerprints" != "$source_fingerprints" ]]; then
    rm -rf -- "$tmp"
    warn "Cloudflare keyring 与本次从官方地址获取的公钥不一致。"
    return 1
  fi
  install -d -m 755 "$(dirname -- "$system_keyring")" "$(dirname -- "$repo_file")"
  [[ -f "$repo_file" ]] && { cp -p "$repo_file" "$tmp/repo.backup"; had_repo=1; }
  [[ -f "$system_keyring" ]] && { cp -p "$system_keyring" "$tmp/keyring.backup"; had_keyring=1; }
  install -m 644 "$keyring" "$system_keyring"
  printf 'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n' \
    "$codename" >"$repo_file"
  if ! apt-get update \
      -o "Dir::Etc::sourcelist=$repo_file" \
      -o 'Dir::Etc::sourceparts=-' \
      -o 'APT::Get::List-Cleanup=0'; then
    if ((had_repo)); then install -m 644 "$tmp/repo.backup" "$repo_file"; else rm -f -- "$repo_file"; fi
    if ((had_keyring)); then install -m 644 "$tmp/keyring.backup" "$system_keyring"; else rm -f -- "$system_keyring"; fi
    rm -rf -- "$tmp"
    warn "Cloudflare 软件源签名验证失败，已恢复原仓库配置。"
    return 1
  fi
  if ! candidate=$(apt-cache policy cloudflare-warp | awk '/Candidate:/ {print $2; exit}'); then
    rm -rf -- "$tmp"
    warn "无法读取 cloudflare-warp 软件包候选版本。"
    return 1
  fi
  if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
    rm -rf -- "$tmp"
    warn "Cloudflare 软件源中没有适用于当前系统架构的 cloudflare-warp 包。"
    return 1
  fi
  if ! apt-get install -y cloudflare-warp; then
    rm -rf -- "$tmp"
    warn "cloudflare-warp 安装失败；已保留通过签名验证的官方仓库配置，便于重试。"
    return 1
  fi
  rm -rf -- "$tmp"
}

update_warp_port_state() {
  local port=$1 candidate
  candidate=$(mktemp)
  jq --argjson port "$port" '.routing.socks_port = $port' "$STATE_FILE" >"$candidate"
  if commit_candidate "$candidate"; then
    ok "WARP SOCKS5 端口已写入所有内核配置：127.0.0.1:$port"
  fi
  rm -f -- "$candidate"
}

verify_warp_proxy() {
  local port=$1 trace
  trace=$(curl --fail --silent --show-error --max-time 15 --socks5-hostname "127.0.0.1:$port" \
    https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  if grep -q '^warp=on' <<<"$trace"; then
    ok "WARP Local proxy 连通验证通过。"
    return 0
  fi
  warn "WARP 已配置，但代理连通验证未通过。请查看 warp-cli status 与 warp-cli settings。"
  return 1
}

prepare_warp_registration_reset() {
  if warp-cli --accept-tos registration show >/dev/null 2>&1; then
    confirm "检测到已有 WARP 注册。重新配置账户需要删除旧注册，是否继续？" || return 1
    warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
    warp-cli --accept-tos registration delete >/dev/null 2>&1 || true
  fi
}

install_warp_free() {
  local port
  command -v warp-cli >/dev/null 2>&1 || install_warp_package
  port=$(prompt "本机 SOCKS5 监听端口" "$(jq -r '.routing.socks_port' "$STATE_FILE")")
  is_valid_port "$port" || { warn "端口无效。"; return 1; }
  prepare_warp_registration_reset || return 1
  write_warp_mdm_free "$port"
  systemctl restart warp-svc
  sleep 2
  warp-cli --accept-tos registration new
  warp-cli --accept-tos tunnel protocol set MASQUE || true
  warp-cli --accept-tos connect
  update_warp_port_state "$port"
  verify_warp_proxy "$port" || true
}

install_warp_zt() {
  local port organization client_id client_secret
  command -v warp-cli >/dev/null 2>&1 || install_warp_package
  port=$(prompt "本机 SOCKS5 监听端口" "$(jq -r '.routing.socks_port' "$STATE_FILE")")
  is_valid_port "$port" || { warn "端口无效。"; return 1; }
  organization=$(prompt "Zero Trust Team 名称")
  read -r -p 'Service Token Client ID: ' client_id
  read -r -s -p 'Service Token Client Secret: ' client_secret
  printf '\n'
  [[ "$organization" =~ ^[A-Za-z0-9-]{1,63}$ ]] || { warn "Team 名称格式无效。"; return 1; }
  is_safe_token "$client_id" && is_safe_token "$client_secret" \
    || { warn "Service Token 格式不安全。"; return 1; }
  prepare_warp_registration_reset || return 1
  write_warp_mdm_zt "$port" "$organization" "$client_id" "$client_secret"
  unset client_secret
  systemctl restart warp-svc
  sleep 4
  warp-cli --accept-tos mdm refresh >/dev/null 2>&1 || true
  warp-cli --accept-tos tunnel protocol set MASQUE || true
  warp-cli --accept-tos connect || true
  update_warp_port_state "$port"
  warp-cli --accept-tos registration show || true
  warp-cli --accept-tos status || true
  verify_warp_proxy "$port" || true
}

change_warp_port() {
  local port candidate
  [[ -f /var/lib/cloudflare-warp/mdm.xml ]] || { warn "尚未通过本工具配置 WARP。"; return 1; }
  port=$(prompt "新的 SOCKS5 端口" "$(jq -r '.routing.socks_port' "$STATE_FILE")")
  is_valid_port "$port" || { warn "端口无效。"; return 1; }
  sed -i "/<key>proxy_port<\/key>/{n;s#<integer>[0-9]*</integer>#<integer>$port</integer>#;}" \
    /var/lib/cloudflare-warp/mdm.xml
  systemctl restart warp-svc
  warp-cli --accept-tos mdm refresh >/dev/null 2>&1 || true
  warp-cli --accept-tos connect || true
  update_warp_port_state "$port"
  verify_warp_proxy "$port" || true
}

warp_status() {
  if ! command -v warp-cli >/dev/null 2>&1; then
    printf 'Cloudflare WARP 未安装。\n'
    return 0
  fi
  warp-cli --accept-tos status || true
  warp-cli --accept-tos settings || true
  printf '管理器出站模式：%s\n' "$(jq -r '.routing.mode' "$STATE_FILE")"
  verify_warp_proxy "$(jq -r '.routing.socks_port' "$STATE_FILE")" || true
}

uninstall_warp() {
  confirm "确认卸载 Cloudflare 官方 WARP 客户端？" || return 0
  set_route_mode direct || true
  systemctl disable --now warp-svc >/dev/null 2>&1 || true
  if command -v apt-get >/dev/null 2>&1; then
    apt-get purge -y cloudflare-warp
  fi
  rm -f -- /var/lib/cloudflare-warp/mdm.xml
  ok "WARP 客户端已卸载；管理器出站已切回 direct。"
}

warp_menu() {
  local choice
  while true; do
    printf '\nWARP 管理（始终使用 Local proxy，不接管系统默认出口）\n'
    printf '  1) 安装/重配免费账户\n'
    printf '  2) 使用 Service Token + MDM 接入 Zero Trust\n'
    printf '  3) 修改 SOCKS5 端口\n  4) 查看与验证状态\n  5) 卸载 WARP\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) install_warp_free || true ;;
      2) install_warp_zt || true ;;
      3) change_warp_port || true ;;
      4) warp_status ;;
      5) uninstall_warp || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

service_state() {
  local unit=$1
  if systemctl is-active --quiet "$unit"; then
    printf '%b运行中%b' "$C_GREEN" "$C_RESET"
  elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    printf '%b已启用但未运行%b' "$C_RED" "$C_RESET"
  else
    printf '未启用'
  fi
}

status_overview() {
  printf '\nSBX Manager %s\n' "$VERSION"
  printf '  Sing-box：%s\n' "$(service_state sbx-sing-box.service)"
  printf '  Xray：    %s\n' "$(service_state sbx-xray.service)"
  printf '  Argo：    %s\n' "$(service_state sbx-argo.service)"
  printf '  WARP：    %s\n' "$(service_state warp-svc.service)"
  printf '  Watchdog：%s\n' "$(service_state sbx-watchdog.timer)"
  printf '  防火墙：  %s\n' "$(service_state sbx-firewall.service)"
  printf '  出站：    %s' "$(jq -r '.routing.mode' "$STATE_FILE")"
  if [[ $(jq -r '.routing.mode' "$STATE_FILE") == warp ]]; then
    printf ' -> socks5://127.0.0.1:%s' "$(jq -r '.routing.socks_port' "$STATE_FILE")"
  fi
  printf '\n  节点前缀：%s\n  服务器地址：%s\n' \
    "$(jq -r '.node_prefix' "$STATE_FILE")" "$(jq -r '.server' "$STATE_FILE")"
  installed_protocols
}

restart_component() {
  local component=${1:-all} unit
  case "$component" in
    sing-box|sb) unit=sbx-sing-box.service ;;
    xray|xr) unit=sbx-xray.service ;;
    argo) unit=sbx-argo.service ;;
    warp) unit=warp-svc.service ;;
    all)
      firewall_apply "$STATE_FILE" || warn "防火墙规则重新同步失败。"
      for unit in sbx-sing-box.service sbx-xray.service sbx-argo.service warp-svc.service; do
        systemctl is-enabled --quiet "$unit" 2>/dev/null && systemctl restart "$unit" || true
      done
      ok "已重启所有已启用组件。"
      return 0
      ;;
    *) die "未知组件：$component" ;;
  esac
  systemctl restart "$unit"
  ok "已重启 $component。"
}

healthcheck() {
  local unit failed=0
  firewall_apply "$STATE_FILE" || failed=1
  for unit in sbx-sing-box.service sbx-xray.service; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null && ! systemctl is-active --quiet "$unit"; then
      logger -t sbx-watchdog "$unit is down; restarting"
      systemctl restart "$unit" || failed=1
    fi
  done
  if [[ $(jq -r '.argo.mode' "$STATE_FILE") != off ]] && ! systemctl is-active --quiet sbx-argo.service; then
    logger -t sbx-watchdog "sbx-argo.service is down; restarting"
    systemctl restart sbx-argo.service || failed=1
  fi
  if [[ $(jq -r '.routing.mode' "$STATE_FILE") == warp ]] && ! systemctl is-active --quiet warp-svc.service; then
    logger -t sbx-watchdog "warp-svc.service is down while WARP routing is selected; restarting"
    systemctl restart warp-svc.service || failed=1
  fi
  return "$failed"
}

firewall_menu() {
  local choice
  while true; do
    printf '\n防火墙管理\n'
    printf '  1) 查看 SBX 规则与云安全组需求\n  2) 从当前协议重新同步规则\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) firewall_status ;;
      2) sync_firewall "$STATE_FILE" && ok "防火墙规则已重新同步。" || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

watchdog_menu() {
  local choice candidate
  while true; do
    printf '\nWatchdog：%s\n' "$(service_state sbx-watchdog.timer)"
    printf '  1) 启用（每 2 分钟）\n  2) 禁用\n  3) 立即健康检查\n  4) 查看最近日志\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1)
        candidate=$(mktemp)
        jq '.watchdog = true' "$STATE_FILE" >"$candidate"
        commit_candidate "$candidate"
        rm -f -- "$candidate"
        systemctl enable --now sbx-watchdog.timer >/dev/null
        ok "Watchdog 已启用。"
        ;;
      2)
        candidate=$(mktemp)
        jq '.watchdog = false' "$STATE_FILE" >"$candidate"
        commit_candidate "$candidate"
        rm -f -- "$candidate"
        systemctl disable --now sbx-watchdog.timer >/dev/null
        ok "Watchdog 已禁用。"
        ;;
      3) healthcheck && ok "健康检查完成。" || warn "部分服务无法恢复。" ;;
      4) journalctl -u sbx-watchdog.service -n 50 --no-pager || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

settings_menu() {
  local choice
  while true; do
    printf '\n通用设置\n'
    printf '  1) 修改节点前缀\n  2) 修改节点服务器地址\n  3) Watchdog 管理\n'
    printf '  4) 防火墙管理\n  5) 重新生成并自检配置\n  0) 返回\n'
    read -r -p '请选择: ' choice
    case "$choice" in
      1) set_prefix || true ;;
      2) set_server || true ;;
      3) watchdog_menu ;;
      4) firewall_menu ;;
      5) commit_candidate "$STATE_FILE" && ok "配置自检和加载完成。" || true ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

logs_menu() {
  local choice unit
  printf '\n  1) Sing-box\n  2) Xray\n  3) Argo\n  4) WARP\n  5) Watchdog\n  0) 返回\n'
  read -r -p '请选择日志: ' choice
  case "$choice" in
    1) unit=sbx-sing-box.service ;;
    2) unit=sbx-xray.service ;;
    3) unit=sbx-argo.service ;;
    4) unit=warp-svc.service ;;
    5) unit=sbx-watchdog.service ;;
    0) return 0 ;;
    *) warn "无效选择。"; return 1 ;;
  esac
  journalctl -u "$unit" -n 100 --no-pager || true
}

uninstall_manager() {
  local argo_mode
  confirm "确认卸载 SBX Manager、代理内核和本地配置？此操作不会卸载 WARP" || return 0
  argo_mode=$(jq -r '.argo.mode' "$STATE_FILE")
  if [[ "$argo_mode" == fixed ]]; then
    warn "Cloudflare 端的固定隧道不会在此步骤删除；如需删除，请先用 Argo 管理菜单。"
    confirm "仍然继续本地卸载？" || return 0
  fi
  for unit in sbx-sing-box.service sbx-xray.service sbx-argo.service sbx-firewall.service sbx-watchdog.timer sbx-acme-renew.timer; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done
  firewall_clear
  rm -f -- \
    "$SYSTEMD_DIR/sbx-sing-box.service" "$SYSTEMD_DIR/sbx-xray.service" \
    "$SYSTEMD_DIR/sbx-argo.service" "$SYSTEMD_DIR/sbx-watchdog.service" \
    "$SYSTEMD_DIR/sbx-firewall.service" "$SYSTEMD_DIR/sbx-watchdog.timer" "$SYSTEMD_DIR/sbx-acme-renew.service" \
    "$SYSTEMD_DIR/sbx-acme-renew.timer" "$SB_BIN" "$XR_BIN" "$CF_BIN" \
    /usr/local/sbin/sbx-manager /usr/local/bin/sbx
  systemctl daemon-reload
  [[ "$ETC_DIR" == /etc/sbx-manager ]] || die "拒绝删除非标准配置目录：$ETC_DIR"
  [[ "$LIB_DIR" == /usr/local/lib/sbx-manager ]] || die "拒绝删除非标准程序目录：$LIB_DIR"
  rm -rf -- /etc/sbx-manager /usr/local/lib/sbx-manager /opt/sbx-manager /var/log/sbx-manager
  printf 'SBX Manager 已卸载。Cloudflare WARP（如已安装）保持不变。\n'
}

main_menu() {
  local choice
  while true; do
    printf '\n%bSBX Manager %s%b — Sing-box + Xray 交互式管理\n' "$C_BLUE" "$VERSION" "$C_RESET"
    printf '  1) 协议安装/卸载\n'
    printf '  2) Sing-box / Xray 内核管理\n'
    printf '  3) 查看节点与二维码\n'
    printf "  4) Let's Encrypt 证书管理\n"
    printf '  5) Argo 隧道管理\n'
    printf '  6) Cloudflare WARP 管理\n'
    printf '  7) direct / WARP 出站切换\n'
    printf '  8) 服务状态\n  9) 重启所有组件\n 10) 设置、Watchdog 与防火墙\n 11) 查看日志\n 12) 卸载管理器\n  0) 退出\n'
    read -r -p '请选择 [0-12]: ' choice
    case "$choice" in
      1) protocol_menu ;;
      2) core_menu ;;
      3) show_nodes true ;;
      4) certificate_menu ;;
      5) argo_menu ;;
      6) warp_menu ;;
      7) route_menu ;;
      8) status_overview ;;
      9) restart_component all ;;
      10) settings_menu ;;
      11) logs_menu ;;
      12) uninstall_manager; return 0 ;;
      0) return 0 ;;
      *) warn "无效选择。" ;;
    esac
  done
}

usage() {
  cat <<EOF
用法：sbx-manager [menu|status|nodes|qr|restart [组件]|healthcheck|apply|firewall-apply|firewall-status|bootstrap|uninstall]
  组件：sing-box、xray、argo、warp、all
EOF
}

main() {
  local command=${1:-menu}
  require_root
  require_commands
  ensure_layout
  case "$command" in
    bootstrap) bootstrap ;;
    menu) main_menu ;;
    status) status_overview ;;
    nodes) show_nodes false ;;
    qr) show_nodes true ;;
    restart) restart_component "${2:-all}" ;;
    healthcheck) healthcheck ;;
    apply) commit_candidate "$STATE_FILE" && ok "配置已重新生成并加载。" ;;
    firewall-apply) firewall_apply "$STATE_FILE" ;;
    firewall-status) firewall_status ;;
    uninstall) uninstall_manager ;;
    -h|--help|help) usage ;;
    *) usage; return 1 ;;
  esac
}

if [[ ${SBX_SOURCE_ONLY:-0} != 1 ]]; then
  main "$@"
fi
