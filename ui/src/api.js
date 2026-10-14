// All calls to the FastAPI backend live here. Paths start with /api (proxied by Vite).

async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
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
export const testLlm = () => request("/api/llm/test", { method: "POST" });
