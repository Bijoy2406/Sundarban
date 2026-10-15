import { useEffect, useState } from "react";
import { getHealth, getWallet, previewPlan, testLlm } from "./api.js";

// Anvil's public test account #1, handy as a demo recipient on the LOCAL chain only.
const DEMO_RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

export default function App() {
  return (
    <div className="page">
      <header>
        <h1>Sentinel Wallet</h1>
        <p className="muted">Starting point · test tokens only · nothing is sent from this screen yet</p>
      </header>
      <StatusBar />
      <div className="grid">
        <WalletCard />
        <LlmCard />
      </div>
      <PlanCard />
    </div>
  );
}

function StatusBar() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getHealth().then(setHealth).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="status bad">Backend not reachable: {error}. Is uvicorn running on port 8000?</div>;
  if (!health) return <div className="status">Checking…</div>;
  const c = health.chain;
  return (
    <div className="status">
      <Pill ok={health.backend === "ok"} label="Backend" />
      <Pill ok={c.connected} label={`Chain: ${c.network}${c.chain_id ? ` (${c.chain_id})` : ""}`} />
      <Pill ok={c.token_deployed} label="TestUSD deployed" />
      <Pill ok={health.llm.api_key_set && !!health.llm.model} label="LLM configured" />
    </div>
  );
}

function Pill({ ok, label }) {
  return <span className={`pill ${ok ? "ok" : "bad"}`}>{ok ? "✓" : "✗"} {label}</span>;
}

function WalletCard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    getWallet().then(setData).catch((e) => setError(e.message));
  };
  useEffect(load, []);

  return (
    <section className="card">
      <div className="card-head">
        <h2>Wallet</h2>
        <button onClick={load}>Refresh</button>
      </div>
      {error && <p className="error">{error}</p>}
      {data && (
        <>
          <p className="mono small">{data.address}</p>
          <table>
            <tbody>
              {Object.entries(data.balances).map(([sym, amt]) => (
                <tr key={sym}>
                  <td>{sym}</td>
                  <td className="num">{amt}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Approvals</h3>
          {data.approvals.length === 0 ? (
            <p className="muted">No active approvals.</p>
          ) : (
            <table>
              <tbody>
                {data.approvals.map((a) => (
                  <tr key={a.spender}>
                    <td className="mono small">{a.spender}</td>
                    <td className="num">{a.allowance}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}

function LlmCard() {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = () => {
    setBusy(true);
    testLlm()
      .then(setResult)
      .catch((e) => setResult({ ok: false, error: e.message }))
      .finally(() => setBusy(false));
  };

  return (
    <section className="card">
      <div className="card-head">
        <h2>LLM connection</h2>
        <button onClick={run} disabled={busy}>{busy ? "Testing…" : "Test connection"}</button>
      </div>
      <p className="muted small">Uses LLM_BASE_URL, LLM_MODEL and LLM_API_KEY from .env. The key never leaves the backend.</p>
      {result && (result.ok ? (
        <p className="ok-text">✓ {result.model} replied “{result.reply}” in {result.latency_ms} ms</p>
      ) : (
        <p className="error">{result.error}</p>
      ))}
    </section>
  );
}

function PlanCard() {
  const [form, setForm] = useState({ action: "transfer", to: DEMO_RECIPIENT, amount: "10", unlimited: false });
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const set = (key) => (e) =>
    setForm({ ...form, [key]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  const submit = (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    previewPlan(form).then(setResult).catch((err) => setError(err.message));
  };

  return (
    <section className="card">
      <h2>Preview an action</h2>
      <p className="muted small">Builds the exact transaction, simulates it and asks the firewall. It does <b>not</b> send anything.</p>
      <form onSubmit={submit} className="form">
        <label>Action
          <select value={form.action} onChange={set("action")}>
            <option value="transfer">transfer</option>
            <option value="approve">approve</option>
            <option value="revoke">revoke</option>
          </select>
        </label>
        <label className="wide">{form.action === "transfer" ? "Recipient" : "Spender"}
          <input className="mono" value={form.to} onChange={set("to")} />
        </label>
        {form.action !== "revoke" && (
          <label>Amount (TUSD)
            <input value={form.amount} onChange={set("amount")} disabled={form.unlimited} />
          </label>
        )}
        {form.action === "approve" && (
          <label className="check">
            <input type="checkbox" checked={form.unlimited} onChange={set("unlimited")} /> unlimited
          </label>
        )}
        <button type="submit">Preview</button>
      </form>

      {error && <p className="error">{error}</p>}
      {result && <PlanResult result={result} />}
    </section>
  );
}

function PlanResult({ result }) {
  const { plan, simulation, decision } = result;
  const isStub = decision.rule_ids.includes("STUB");
  return (
    <div className="result">
      <div className={`decision ${decision.decision}`}>
        <strong>Firewall: {decision.decision.toUpperCase()}</strong>
        {isStub && <span className="tag">STUB: real rules not built yet</span>}
        <ul>{decision.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
      </div>
      <table>
        <tbody>
          <tr><td>Summary</td><td>{plan.summary}</td></tr>
          <tr><td>Function</td><td className="mono">{plan.function}</td></tr>
          <tr><td>Arguments</td><td className="mono small">{JSON.stringify(plan.args)}</td></tr>
          <tr><td>Contract</td><td className="mono small">{plan.to}</td></tr>
          <tr><td>Gas estimate</td><td>{plan.gas}</td></tr>
          <tr><td>Simulation</td><td>{simulation.ok
            ? `✓ would succeed · leaves wallet: ${simulation.outflow}${simulation.allowance_after !== null ? ` · allowance after: ${simulation.allowance_after}` : ""}`
            : `✗ would fail: ${simulation.revert_reason}`}</td></tr>
          <tr><td>Calldata</td><td className="mono small break">{plan.data}</td></tr>
        </tbody>
      </table>
      <button disabled title="Needs the execute API endpoint (issue #29)">Execute (coming: issue #29)</button>
    </div>
  );
}
