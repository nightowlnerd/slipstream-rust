#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_SCRIPT="${ROOT_DIR}/scripts/bench/run_rust_rust_10mb.sh"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
TRANSFER_BYTES="${TRANSFER_BYTES:-10485760}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-30}"
RUNS="${RUNS:-1}"
RUN_EXFIL="${RUN_EXFIL:-1}"
RUN_DOWNLOAD="${RUN_DOWNLOAD:-1}"
MEM_SAMPLE_SECS="${MEM_SAMPLE_SECS:-0.2}"
MEM_LOG="${MEM_LOG:-${ROOT_DIR}/.interop/mem-rust-rust-$(date +%Y%m%d_%H%M%S).csv}"
MAX_RSS_MB="${MAX_RSS_MB:-80}"

mkdir -p "$(dirname "${MEM_LOG}")"

cleanup() {
  if [[ -n "${BENCH_PID:-}" ]] && kill -0 "${BENCH_PID}" 2>/dev/null; then
    kill "${BENCH_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM HUP

RUNS="${RUNS}" \
RUN_EXFIL="${RUN_EXFIL}" \
RUN_DOWNLOAD="${RUN_DOWNLOAD}" \
TRANSFER_BYTES="${TRANSFER_BYTES}" \
SOCKET_TIMEOUT="${SOCKET_TIMEOUT}" \
DNS_LISTEN_PORT="${DNS_LISTEN_PORT}" \
TCP_TARGET_PORT="${TCP_TARGET_PORT}" \
CLIENT_TCP_PORT="${CLIENT_TCP_PORT}" \
"${BENCH_SCRIPT}" &
BENCH_PID=$!

server_pid=""
client_pid=""
for _ in $(seq 1 200); do
  server_pid=$(pgrep -f "slipstream-server.*--dns-listen-port ${DNS_LISTEN_PORT}" | head -n1 || true)
  client_pid=$(pgrep -f "slipstream-client.*--tcp-listen-port ${CLIENT_TCP_PORT}" | head -n1 || true)
  if [[ -n "${server_pid}" && -n "${client_pid}" ]]; then
    break
  fi
  sleep 0.05
done

printf "ts_ms,server_rss_kb,client_rss_kb\n" > "${MEM_LOG}"
while kill -0 "${BENCH_PID}" 2>/dev/null; do
  ts=$(date +%s%3N)
  rss_server=$(ps -o rss= -p "${server_pid}" 2>/dev/null | tr -d ' ' || true)
  rss_client=$(ps -o rss= -p "${client_pid}" 2>/dev/null | tr -d ' ' || true)
  printf "%s,%s,%s\n" "${ts}" "${rss_server:-0}" "${rss_client:-0}" >> "${MEM_LOG}"
  sleep "${MEM_SAMPLE_SECS}"
done

wait "${BENCH_PID}"

if [[ -s "${MEM_LOG}" ]]; then
  read -r maxs maxc < <(awk -F, 'NR>1 { if ($2+0 > maxs) maxs=$2+0; if ($3+0 > maxc) maxc=$3+0 }
    END { printf "%d %d", maxs+0, maxc+0 }' "${MEM_LOG}") || true
  maxs="${maxs:-0}"
  maxc="${maxc:-0}"
  printf "Peak RSS (KB): server=%d client=%d\n" "${maxs}" "${maxc}"
  if [[ "${MAX_RSS_MB}" != "0" ]]; then
    max_kb=$((MAX_RSS_MB * 1024))
    if [[ "${maxs}" -gt "${max_kb}" || "${maxc}" -gt "${max_kb}" ]]; then
      echo "Peak RSS exceeded ${MAX_RSS_MB}MB (server=${maxs}KB client=${maxc}KB)." >&2
      exit 1
    fi
  fi
fi
echo "mem log: ${MEM_LOG}"
