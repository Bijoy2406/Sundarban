// All calls to the FastAPI backend live here. Paths start with /api (proxied by Vite).
// The operator key (Confirm, kill switch OFF) lives only in this tab's sessionStorage, never in a file or a URL.
const OPERATOR_STORAGE_KEY = "sundarbanOperatorKey";
export function getOperatorKey() {
  try { return sessionStorage.getItem(OPERATOR_STORAGE_KEY) || ""; } catch { return ""; }
}
export function setOperatorKey(value) {
  try { value ? sessionStorage.setItem(OPERATOR_STORAGE_KEY, value) : sessionStorage.removeItem(OPERATOR_STORAGE_KEY); } catch { /* storage blocked: the key just is not remembered */ }
}
const operatorHeaders = () => { const key = getOperatorKey(); return key ? { "X-Operator-Token": key } : {}; };

async function request(path, options = {}) {
  const { headers = {}, ...rest } = options;
  const res = await fetch(path, {
    ...rest,
    headers: { "Content-Type": "application/json", ...headers },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    throw new Error(`${res.status}: ${detail}`);
  }
  return body;
}

export const getHealth = () => request("/api/health");
export const getWallet = () => request("/api/wallet");
export const previewPlan = (form) => request("/api/plan", { method: "POST", body: JSON.stringify(form) });
export const executePlan = (form) => request("/api/execute", { method: "POST", body: JSON.stringify(form) });
export const confirmPlan = (request_id) => request("/api/confirm", {
  method: "POST", headers: operatorHeaders(), body: JSON.stringify({ request_id }),
});
export const testLlm = () => request("/api/llm/test", { method: "POST" });

export const sendChat = (message) => request("/api/chat", {
  method: "POST", body: JSON.stringify({ message }),
});
export const getSecurity = () => request("/api/security");
export const setKillSwitch = (enabled) => request("/api/kill-switch", {
  method: "POST", headers: enabled ? {} : operatorHeaders(), body: JSON.stringify({ enabled }),   // freezing never needs the key
});
export const getAudit = (limit = 50) => request(`/api/audit?limit=${limit}`);

export const getAttackFeed = () => request("/api/feed");
export const runAttackReplay = (attack_id) => request("/api/attack-replay", {
  method: "POST", body: JSON.stringify({ attack_id }),
});
