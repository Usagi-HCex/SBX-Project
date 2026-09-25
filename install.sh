#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '请使用 root 运行：sudo bash install.sh\n' >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --version >/dev/null 2>&1; then
  printf '当前版本仅支持使用 systemd 的 Linux。\n' >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  printf '当前版本支持 Debian 11/12/13 与 Ubuntu 22.04/24.04/26.04。\n' >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[[ -f "$SCRIPT_DIR/src/sbx-manager.sh" && -f "$SCRIPT_DIR/src/sbx_generator.py" ]] || {
  printf '安装包不完整：缺少 src 文件。\n' >&2
  exit 1
}

MANAGER_BIN=/usr/local/sbin/sbx-manager
GENERATOR_BIN=/usr/local/lib/sbx-manager/sbx_generator.py
SHORTCUT=/usr/local/bin/sbx
STATE_FILE=/etc/sbx-manager/state.json
SYSTEMD_DIR=/etc/systemd/system
MANAGED_UNITS=(
  sbx-sing-box.service sbx-xray.service sbx-argo.service sbx-firewall.service
  sbx-watchdog.service sbx-watchdog.timer
  sbx-acme-renew.service sbx-acme-renew.timer
)

has_existing_install() {
  local path
  for path in \
    "$MANAGER_BIN" "$SHORTCUT" /usr/local/lib/sbx-manager \
    /etc/sbx-manager /opt/sbx-manager /var/log/sbx-manager \
    "$SYSTEMD_DIR/sbx-sing-box.service" "$SYSTEMD_DIR/sbx-xray.service" \
    "$SYSTEMD_DIR/sbx-watchdog.service" "$SYSTEMD_DIR/sbx-watchdog.timer"; do
    [[ -e "$path" || -L "$path" ]] && return 0
  done
  return 1
}

existing_install_complete() {
  local unit
  [[ -x "$MANAGER_BIN" && -x "$GENERATOR_BIN" && -s "$STATE_FILE" ]] || return 1
  [[ -L "$SHORTCUT" && $(readlink -f "$SHORTCUT") == "$MANAGER_BIN" ]] || return 1
  bash -n "$MANAGER_BIN" >/dev/null 2>&1 || return 1
  python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(encoding="utf-8"), str(p), "exec")' \
    "$GENERATOR_BIN" >/dev/null 2>&1 || return 1
  python3 "$SCRIPT_DIR/src/sbx_generator.py" validate --state "$STATE_FILE" >/dev/null 2>&1 || return 1
  for unit in sbx-sing-box.service sbx-xray.service sbx-watchdog.service sbx-watchdog.timer; do
    [[ -f "$SYSTEMD_DIR/$unit" ]] || return 1
  done
}

cleanup_incomplete_install() {
  local unit firewall_command backup='' state_valid=false
  printf '[修复] 检测到上一版安装不完整，开始备份并清理项目残留。\n'
  if [[ -d /etc/sbx-manager ]]; then
    install -d -m 700 /var/backups
    backup="/var/backups/sbx-manager-incomplete-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
    tar -C / -czf "$backup" etc/sbx-manager
    chmod 600 "$backup"
    printf '[修复] 已备份原配置：%s\n' "$backup"
  fi
  if [[ -s "$STATE_FILE" ]] \
    && python3 "$SCRIPT_DIR/src/sbx_generator.py" validate --state "$STATE_FILE" >/dev/null 2>&1; then
    state_valid=true
  fi
  for unit in "${MANAGED_UNITS[@]}"; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done
  for firewall_command in iptables ip6tables; do
    command -v "$firewall_command" >/dev/null 2>&1 || continue
    while "$firewall_command" -w 5 -C INPUT -j SBX_INPUT >/dev/null 2>&1; do
      "$firewall_command" -w 5 -D INPUT -j SBX_INPUT >/dev/null 2>&1 || break
    done
    "$firewall_command" -w 5 -F SBX_INPUT >/dev/null 2>&1 || true
    "$firewall_command" -w 5 -X SBX_INPUT >/dev/null 2>&1 || true
    while "$firewall_command" -w 5 -t nat -C PREROUTING -j SBX_PREROUTING >/dev/null 2>&1; do
      "$firewall_command" -w 5 -t nat -D PREROUTING -j SBX_PREROUTING >/dev/null 2>&1 || break
    done
    "$firewall_command" -w 5 -t nat -F SBX_PREROUTING >/dev/null 2>&1 || true
    "$firewall_command" -w 5 -t nat -X SBX_PREROUTING >/dev/null 2>&1 || true
  done
  rm -f -- \
    "$SYSTEMD_DIR/sbx-sing-box.service" "$SYSTEMD_DIR/sbx-xray.service" \
    "$SYSTEMD_DIR/sbx-argo.service" "$SYSTEMD_DIR/sbx-firewall.service" "$SYSTEMD_DIR/sbx-watchdog.service" \
    "$SYSTEMD_DIR/sbx-watchdog.timer" "$SYSTEMD_DIR/sbx-acme-renew.service" \
    "$SYSTEMD_DIR/sbx-acme-renew.timer" "$MANAGER_BIN" "$SHORTCUT"
  rm -rf -- /usr/local/lib/sbx-manager
  if [[ "$state_valid" == true ]]; then
    printf '[修复] 原状态、节点凭据和证书有效，安装时将继续保留。\n'
  elif [[ -d /etc/sbx-manager ]]; then
    rm -rf -- /etc/sbx-manager
    printf '[修复] 原状态无效，已从工作目录移除；可从上述备份恢复。\n'
  fi
  systemctl daemon-reload
  systemctl reset-failed "${MANAGED_UNITS[@]}" >/dev/null 2>&1 || true
}

repair_cloudflare_warp_repo() {
  local repo_file=/etc/apt/sources.list.d/cloudflare-client.list
  local system_keyring=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  local tmp key_source keyring source_fingerprints keyring_fingerprints
  [[ -f "$repo_file" ]] || return 0
  grep -Fq 'pkg.cloudflareclient.com' "$repo_file" || return 0

  tmp=$(mktemp -d)
  if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
    mv -- "$repo_file" "$tmp/cloudflare-client.list.disabled"
    if ! apt-get update \
        || ! apt-get install -y --no-install-recommends ca-certificates curl gpg; then
      mv -- "$tmp/cloudflare-client.list.disabled" "$repo_file"
      rm -rf -- "$tmp"
      printf '[错误] 无法安装修复 Cloudflare 仓库所需的 curl/gpg。\n' >&2
      return 1
    fi
    mv -- "$tmp/cloudflare-client.list.disabled" "$repo_file"
  fi

  key_source="$tmp/pubkey.gpg"
  keyring="$tmp/cloudflare-warp-archive-keyring.gpg"
  printf '[修复] 刷新并验证 Cloudflare WARP 官方仓库签名密钥。\n'
  if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --output "$key_source" https://pkg.cloudflareclient.com/pubkey.gpg; then
    rm -rf -- "$tmp"
    printf '[错误] Cloudflare 官方公钥下载失败。\n' >&2
    return 1
  fi
  if ! source_fingerprints=$(gpg --batch --show-keys --with-colons "$key_source" 2>/dev/null \
      | awk -F: '$1 == "fpr" && length($10) == 40 && $10 ~ /^[0-9A-Fa-f]+$/ {print toupper($10)}' \
      | LC_ALL=C sort -u) \
      || [[ -z "$source_fingerprints" ]]; then
    rm -rf -- "$tmp"
    printf '[错误] 无法读取 Cloudflare 官方公钥的完整指纹。\n' >&2
    return 1
  fi
  if ! gpg --batch --yes --dearmor --output "$keyring" "$key_source"; then
    rm -rf -- "$tmp"
    printf '[错误] Cloudflare keyring 生成失败。\n' >&2
    return 1
  fi
  if ! keyring_fingerprints=$(gpg --batch --show-keys --with-colons "$keyring" 2>/dev/null \
      | awk -F: '$1 == "fpr" && length($10) == 40 && $10 ~ /^[0-9A-Fa-f]+$/ {print toupper($10)}' \
      | LC_ALL=C sort -u) \
      || [[ "$keyring_fingerprints" != "$source_fingerprints" ]]; then
    rm -rf -- "$tmp"
    printf '[错误] Cloudflare keyring 与本次从官方地址获取的公钥不一致。\n' >&2
    return 1
  fi
  install -d -m 755 /usr/share/keyrings
  install -m 644 "$keyring" "$system_keyring"
  rm -rf -- "$tmp"
}

export DEBIAN_FRONTEND=noninteractive
repair_cloudflare_warp_repo
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl jq python3 openssl tar unzip qrencode iproute2 coreutils \
  gpg socat hostname bsdutils findutils grep sed iptables

if has_existing_install; then
  if existing_install_complete; then
    printf '[升级] 检测到完整安装，将保留现有配置并覆盖程序文件。\n'
  else
    cleanup_incomplete_install
  fi
fi

install -d -m 755 /usr/local/lib/sbx-manager /usr/local/sbin /usr/local/bin
install -m 755 "$SCRIPT_DIR/src/sbx_generator.py" "$GENERATOR_BIN"
install -m 755 "$SCRIPT_DIR/src/sbx-manager.sh" "$MANAGER_BIN"
ln -sfn "$MANAGER_BIN" "$SHORTCUT"

"$MANAGER_BIN" bootstrap

printf '\n安装完成。以后输入 sbx 即可进入交互菜单。\n'
if [[ -t 0 && ${1:-} != --no-menu ]]; then
  exec "$MANAGER_BIN" menu
fi
