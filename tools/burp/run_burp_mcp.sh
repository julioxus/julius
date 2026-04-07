#!/usr/bin/env bash
set -euo pipefail

BURP_MCP_PORT="${BURP_MCP_PORT:-9876}"
BURP_MCP_BRIDGE_PORT="${BURP_MCP_BRIDGE_PORT:-9877}"
BURP_SSE_URL="${BURP_SSE_URL:-http://127.0.0.1:${BURP_MCP_PORT}/}"
BRIDGE_SSE_URL="${BRIDGE_SSE_URL:-http://127.0.0.1:${BURP_MCP_BRIDGE_PORT}/}"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
JAVA_BIN="${JAVA_BIN:-/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java}"
PROXY_JAR="${PROXY_JAR:-$HOME/.BurpSuite/mcp-proxy/mcp-proxy-all.jar}"

if [[ -z "${NODE_BIN}" ]]; then
  echo "node is required to run the Burp MCP bridge" >&2
  exit 1
fi

if [[ ! -x "${JAVA_BIN}" ]]; then
  echo "Burp Java runtime not found at ${JAVA_BIN}" >&2
  exit 1
fi

if [[ ! -f "${PROXY_JAR}" ]]; then
  echo "Burp MCP proxy jar not found at ${PROXY_JAR}" >&2
  exit 1
fi

if ! lsof -nP -iTCP:"${BURP_MCP_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Burp MCP SSE endpoint is not listening on 127.0.0.1:${BURP_MCP_PORT}" >&2
  exit 1
fi

bridge_pid=""
cleanup() {
  if [[ -n "${bridge_pid}" ]] && kill -0 "${bridge_pid}" >/dev/null 2>&1; then
    kill "${bridge_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_sse() {
  local url="$1"
  local attempts="${2:-20}"
  local delay="${3:-0.25}"
  local i status headers_file

  headers_file="$(mktemp)"
  trap 'rm -f "${headers_file}"; cleanup' EXIT

  for ((i = 0; i < attempts; i++)); do
    : >"${headers_file}"
    set +e
    curl -sS -N -m 1 -H 'Accept: text/event-stream' -D "${headers_file}" -o /dev/null "${url}" >/dev/null 2>&1
    status=$?
    set -e

    if [[ "${status}" -eq 0 || "${status}" -eq 28 ]] && grep -Eq '^HTTP/[0-9.]+ 200' "${headers_file}"; then
      rm -f "${headers_file}"
      trap cleanup EXIT
      return 0
    fi

    sleep "${delay}"
  done

  rm -f "${headers_file}"
  trap cleanup EXIT
  return 1
}

if ! lsof -nP -iTCP:"${BURP_MCP_BRIDGE_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  "${NODE_BIN}" -e '
const http = require("http");
const targetPort = process.env.BURP_MCP_PORT || "9876";
const bridgePort = process.env.BURP_MCP_BRIDGE_PORT || "9877";
const server = http.createServer((req, res) => {
  const normalizedPath = (req.url || "/")
    .replace(/^\/+/, "/")
    .replace(/^\/sse(?=\/|$)/, "") || "/";
  const headers = {
    ...req.headers,
    host: `127.0.0.1:${targetPort}`,
    origin: `http://127.0.0.1:${targetPort}`,
    accept: req.headers.accept || "text/event-stream",
  };
  const proxy = http.request(
    {
      hostname: "127.0.0.1",
      port: targetPort,
      path: normalizedPath,
      method: req.method,
      headers,
    },
    (upstream) => {
      res.writeHead(upstream.statusCode || 502, upstream.headers);
      upstream.pipe(res);
    }
  );
  req.pipe(proxy);
  proxy.on("error", () => {
    res.writeHead(502);
    res.end();
  });
});
server.listen(Number(bridgePort), "127.0.0.1");
' &
  bridge_pid="$!"
fi

if ! wait_for_sse "${BRIDGE_SSE_URL}"; then
  echo "Burp MCP bridge did not become ready on ${BRIDGE_SSE_URL}" >&2
  exit 1
fi

exec "${JAVA_BIN}" -jar "${PROXY_JAR}" --sse-url "${BRIDGE_SSE_URL}"
