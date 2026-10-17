import { useEffect, useState } from "react";
import { getHealth, getWallet, previewPlan, executePlan, confirmPlan, testLlm, getAttackFeed, runAttackReplay } from "./api.js";

// Anvil's public test account #1, handy as a demo recipient on the LOCAL chain only.
const DEMO_RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

export default function App() {
  const [walletRefresh, setWalletRefresh] = useState(0);
  const onExecuted = () => setWalletRefresh((value) => value + 1);
  return (
    <div className="page">
      <header>
        <h1>Sentinel Wallet</h1>
        <p className="muted">Test tokens only · never use mainnet or real funds</p>
      </header>
      <StatusBar />
      <div className="grid">
        <WalletCard refreshKey={walletRefresh} />
        <LlmCard />
      </div>
      <PlanCard onExecuted={onExecuted} />
      <AttackReplayCard onExecuted={onExecuted} />
    </div>
  );
}

function StatusBar() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { getHealth().then(setHealth).catch((e) => setError(e.message)); }, []);
  if (error) return <div className="status bad">Backend not reachable: {error}. Is uvicorn running on port 8000?</div>;
  if (!health) return <div className="status">Checking…</div>;
  const c = health.chain;
  return <div className="status">
    <Pill ok={health.backend === "ok"} label="Backend" />
    <Pill ok={c.connected} label={`Chain: ${c.network}${c.chain_id ? ` (${c.chain_id})` : ""}`} />
    <Pill ok={c.token_deployed} label="TestUSD deployed" />
    <Pill ok={health.llm.api_key_set && !!health.llm.model} label="LLM configured" />
  </div>;
}

function Pill({ ok, label }) {
  return <span className={`pill ${ok ? "ok" : "bad"}`}>{ok ? "✓" : "✗"} {label}</span>;
}

function WalletCard({ refreshKey }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const load = () => {
    setLoading(true);
    setError("");
    getWallet().then(setData).catch((e) => setError(e.message)).finally(() => setLoading(false));
  };
  useEffect(load, [refreshKey]);
  return <section className="card">
    <div className="card-head"><h2>Wallet</h2><button onClick={load} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button></div>
    {error && <p className="error">{error}</p>}
    {data && <>
      <p className="mono small">{data.address}</p>
      <table><tbody>{Object.entries(data.balances).map(([sym, amt]) => <tr key={sym}><td>{sym}</td><td className="num">{amt}</td></tr>)}</tbody></table>
      <h3>Approvals</h3>
      {data.approvals.length === 0 ? <p className="muted">No active approvals.</p> : <table><tbody>
        {data.approvals.map((a) => <tr key={a.spender}><td className="mono small">{a.spender}</td><td className="num">{a.allowance}</td></tr>)}
      </tbody></table>}
    </>}
  </section>;
}

function LlmCard() {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = () => {
    setBusy(true);
    testLlm().then(setResult).catch((e) => setResult({ ok: false, error: e.message })).finally(() => setBusy(false));
  };
  return <section className="card">
    <div className="card-head"><h2>LLM connection</h2><button onClick={run} disabled={busy}>{busy ? "Testing…" : "Test connection"}</button></div>
    <p className="muted small">Uses LLM_BASE_URL, LLM_MODEL and LLM_API_KEY from .env. The key never leaves the backend.</p>
    {result && (result.ok ? <p className="ok-text">✓ {result.model} replied “{result.reply}” in {result.latency_ms} ms</p> : <p className="error">{result.error}</p>)}
  </section>;
}

function PlanCard({ onExecuted }) {
  const [form, setForm] = useState({ action: "transfer", to: DEMO_RECIPIENT, amount: "10", unlimited: false });
  const [result, setResult] = useState(null);        // the Preview answer (nothing is sent, nothing is counted)
  const [execution, setExecution] = useState(null);  // the answer of Execute / Confirm
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Any edit of the form invalidates what is on screen: preview, execution result and errors.
  const set = (key) => (e) => {
    setForm({ ...form, [key]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
    setResult(null);
    setExecution(null);
    setError("");
  };

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    setExecution(null);
    setBusy(true);
    try {
      setResult(await previewPlan(form));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const runExecute = async () => {
    setError("");
    setExecution(null);
    setBusy(true);
    try {
      const outcome = await executePlan(form);
      setExecution(outcome);
      if (outcome.status === "executed") onExecuted();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const runConfirm = async (requestId) => {
    setError("");
    setBusy(true);
    try {
      const outcome = await confirmPlan(requestId);
      setExecution(outcome);
      if (outcome.status === "executed") onExecuted();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  // Execute is offered after a preview that says allow or ask (a deny has nothing to execute).
  // Confirm is offered ONLY after the server itself answered "awaiting_confirmation" to Execute:
  // a preview is never confirmable, so it can not skip the question.
  const previewed = result?.decision?.decision;
  const showExecute = !!result && (previewed === "allow" || previewed === "ask") && !execution;
  const awaitingId = execution?.status === "awaiting_confirmation" ? execution.request_id : null;

  return (
    <section className="card">
      <h2>Preview an action</h2>
      <p className="muted small">
        Preview only checks: it sends nothing and does not count as spending. Execute re-runs every check on the
        server and sends only if the firewall allows it.
      </p>
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
        <button type="submit" disabled={busy}>{busy ? "Checking…" : "Preview"}</button>
      </form>

      {error && <p className="error">{error}</p>}
      {result && <PlanResult result={result} />}
      {execution && <ExecutionResult result={execution} />}
      {showExecute && (
        <button onClick={runExecute} disabled={busy}>
          {busy ? "Executing…" : previewed === "ask" ? "Execute (will ask for confirmation)" : "Execute"}
        </button>
      )}
      {awaitingId && (
        <button onClick={() => runConfirm(awaitingId)} disabled={busy}>
          {busy ? "Confirming…" : "Confirm transaction"}
        </button>
      )}
    </section>
  );
}

function PlanResult({ result }) {
  const { plan, simulation, decision } = result;
  const isStub = decision.rule_ids?.includes("STUB");
  return <div className="result">
    <div className={`decision ${decision.decision}`}>
      <strong>Firewall: {decision.decision.toUpperCase()}</strong>
      {isStub && <span className="tag">STUB: real rules not built yet</span>}
      <ul>{(decision.reasons || []).map((r, i) => <li key={`${i}-${r}`}>{r}</li>)}</ul>
    </div>
    <table><tbody>
      <tr><td>Summary</td><td>{plan.summary}</td></tr>
      <tr><td>Function</td><td className="mono">{plan.function}</td></tr>
      <tr><td>Arguments</td><td className="mono small">{JSON.stringify(plan.args)}</td></tr>
      <tr><td>Contract</td><td className="mono small">{plan.to}</td></tr>
      <tr><td>Gas estimate</td><td>{plan.gas}</td></tr>
      <tr><td>Simulation</td><td>{simulation.ok ? `✓ would succeed · leaves wallet: ${simulation.outflow}${simulation.allowance_after !== null ? ` · allowance after: ${simulation.allowance_after}` : ""}` : `✗ would fail: ${simulation.revert_reason}`}</td></tr>
      <tr><td>Calldata</td><td className="mono small break">{plan.data}</td></tr>
    </tbody></table>
  </div>;
}

function ExecutionResult({ result }) {
  return <div className="result">
    <div className={`decision ${result.decision?.decision || result.status}`}>
      <strong>{result.status === "executed" ? "Transaction sent" : result.status === "awaiting_confirmation" ? "Confirmation required" : "Transaction denied"}</strong>
      <ul>{(result.reasons || result.decision?.reasons || []).map((r, i) => <li key={`${i}-${r}`}>{r}</li>)}</ul>
    </div>
    {result.tx_hash && <p>Transaction hash: {result.explorer_url
      ? <a href={result.explorer_url} target="_blank" rel="noreferrer">{result.tx_hash}</a>
      : <code className="break">{result.tx_hash}</code>}</p>}
    {result.status === "awaiting_confirmation" && <p className="muted">Nothing has been sent yet. Review the request and confirm explicitly.</p>}
  </div>;
}


function AttackReplayCard({ onExecuted }) {
  const [attacks, setAttacks] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loadingFeed, setLoadingFeed] = useState(true);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    getAttackFeed()
      .then((data) => {
        const items = (data.items || []).filter((item) => item.attack);
        setAttacks(items);
        setSelectedId(items[0]?.id || "");
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoadingFeed(false));
  }, []);

  const run = async () => {
    setError("");
    setResult(null);
    setRunning(true);
    try {
      const replay = await runAttackReplay(selectedId);
      setResult(replay);
      onExecuted();
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <section className="card attack-replay">
      <div className="card-head">
        <h2>Attack replay</h2>
        <span className="tag">LOCAL ANVIL ONLY</span>
      </div>
      <p className="muted small">
        Run the selected synthetic feed attack against both agents. The naive agent intentionally bypasses
        firewall policy; the protected agent evaluates the same payload with its source marked untrusted.
        Test tokens only. This endpoint refuses non-local chains.
      </p>
      <div className="form">
        <label className="wide">Choose an attack from the feed
          <select value={selectedId} onChange={(event) => { setSelectedId(event.target.value); setResult(null); setError(""); }} disabled={loadingFeed || running}>
            {attacks.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.source === "nft_metadata" ? "NFT metadata" : "X reply"}</option>)}
          </select>
        </label>
        <button onClick={run} disabled={running || loadingFeed || !selectedId}>
          {loadingFeed ? "Loading feed…" : running ? "Running both agents…" : "Run attack replay"}
        </button>
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      {attacks.find((item) => item.id === selectedId) && (
        <div className="attack-payload">
          <strong>Selected payload</strong>
          <p>{attacks.find((item) => item.id === selectedId).text}</p>
        </div>
      )}
      {result && (
        <>
          <p className="muted small">Attack: {result.attack.title} · origin assigned by backend: <code>{result.attack.origin}</code></p>
          <div className="replay-columns">
            <section className="replay-panel naive-panel">
              <h3>Naive agent</h3>
              <div className={`decision ${result.naive.status === "drained" ? "deny" : "ask"}`}>
                <strong>{result.naive.status === "drained" ? "Attack succeeded — test funds lost" : "Naive execution did not complete"}</strong>
                <p>{result.naive.reason}</p>
              </div>
              {result.naive.tx_hash && <p>Approval transaction: <code className="break">{result.naive.tx_hash}</code></p>}
              {result.naive.drain_tx_hash && <p>Drain transaction: <code className="break">{result.naive.drain_tx_hash}</code></p>}
              {result.naive.balance_before !== null && (
                <table><tbody>
                  <tr><td>Victim balance before</td><td className="num">{result.naive.balance_before} TUSD</td></tr>
                  <tr><td>Victim balance after</td><td className="num">{result.naive.balance_after} TUSD</td></tr>
                  <tr><td>Balance lost</td><td className="num"><strong>{result.naive.balance_drop} TUSD</strong></td></tr>
                </tbody></table>
              )}
            </section>
            <section className="replay-panel protected-panel">
              <h3>Sentinel protected agent</h3>
              <div className={`decision ${result.protected.status === "blocked" ? "deny" : "ask"}`}>
                <strong>{result.protected.status === "blocked" ? "Firewall blocked the attack" : "Request needs investigation"}</strong>
                <ul>{(result.protected.reasons || []).map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}</ul>
              </div>
              {result.protected.decision?.rule_ids?.length > 0 && <p className="muted small">Rules: {result.protected.decision.rule_ids.join(", ")}</p>}
              <p>{result.protected.text}</p>
            </section>
          </div>
        </>
      )}
    </section>
  );
}
