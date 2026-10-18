import { useEffect, useState } from "react";
import { getHealth, getWallet, previewPlan, executePlan, confirmPlan, testLlm, sendChat, getSecurity, setKillSwitch, getAudit, getAttackFeed, runAttackReplay } from "./api.js";

// Anvil's public test account #1, handy as a demo recipient on the LOCAL chain only.
const DEMO_RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

export default function App() {
  const [walletRefresh, setWalletRefresh] = useState(0);
  const onExecuted = () => setWalletRefresh((value) => value + 1);
  return (
    <div className="page">
      <header>
        <h1>Sundarban</h1>
        <p className="muted">Test tokens only · never use mainnet or real funds</p>
      </header>
      <StatusBar />
      <div className="grid">
        <WalletCard refreshKey={walletRefresh} />
        <LlmCard />
      </div>
      <ChatCard onExecuted={onExecuted} />
      <SecurityCard />
      <AuditCard />
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
      if (outcome.status === "executed" || outcome.status === "pending") onExecuted();
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
      if (outcome.status === "executed" || outcome.status === "pending") onExecuted();
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
  return <div className="result">
    <div className={`decision ${decision.decision}`}>
      <strong>Firewall: {decision.decision.toUpperCase()}</strong>
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
      <strong>{result.status === "executed" ? "Transaction sent"
        : result.status === "pending" ? "Sent, waiting for confirmation"
        : result.status === "awaiting_confirmation" ? "Confirmation required" : "Transaction denied"}</strong>
      <ul>{(result.reasons || result.decision?.reasons || []).map((r, i) => <li key={`${i}-${r}`}>{r}</li>)}</ul>
    </div>
    {result.tx_hash && <p>Transaction hash: {result.explorer_url
      ? <a href={result.explorer_url} target="_blank" rel="noreferrer">{result.tx_hash}</a>
      : <code className="break">{result.tx_hash}</code>}</p>}
    {result.status === "awaiting_confirmation" && <p className="muted">Nothing has been sent yet. Review the request and confirm explicitly.</p>}
    {result.status === "pending" && <p className="muted">{result.message || "The transaction was broadcast but is not confirmed yet. Check the hash before trying again; do not send it twice."}</p>}
  </div>;
}


function ChatCard({ onExecuted }) {
  const [message, setMessage] = useState("");
  const [items, setItems] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const send = async (event) => {
    event.preventDefault();
    const text = message.trim();
    if (!text || busy) return;
    setMessage("");
    setError("");
    setItems((current) => [...current, { role: "user", text }]);
    setBusy(true);
    try {
      const reply = await sendChat(text);
      setItems((current) => [...current, { role: "agent", text: reply.text || "Request processed.", reply }]);
      if (reply.status === "executed" || reply.status === "pending" || reply.tx_hash) onExecuted();
    } catch {
      setError("I couldn't send that message to the wallet agent. Check that the backend is running and try again.");
    } finally {
      setBusy(false);
    }
  };
  const confirm = async (requestId) => {
    setError("");
    setBusy(true);
    try {
      const result = await confirmPlan(requestId);
      setItems((current) => [...current, { role: "agent", text: result.text || (result.status === "executed" ? "Confirmed. Transaction sent." : "Confirmation processed."), reply: result }]);
      if (result.status === "executed" || result.tx_hash) onExecuted();
    } catch {
      setError("Confirmation failed or expired. Nothing should be assumed to have been sent.");
    } finally {
      setBusy(false);
    }
  };
  return <section className="card">
    <h2>Chat with Sundarban</h2>
    <p className="muted small">The agent can interpret requests, but only the server-side firewall decides whether a transaction is allowed.</p>
    <div className="chat-log" aria-live="polite">
      {items.length === 0 && <p className="muted small">Try: “Send 10 TUSD to 0x…” Nothing is sent until the protected workflow permits it.</p>}
      {items.map((item, index) => <div className={`chat-message ${item.role}`} key={index}>
        <strong>{item.role === "user" ? "You" : "Sundarban"}</strong>
        <p>{item.text}</p>
        {item.reply?.decision && <DecisionCard decision={item.reply.decision} />}
        {item.reply?.tx_hash && <p className="small">Transaction: {item.reply.explorer_url
          ? <a href={item.reply.explorer_url} target="_blank" rel="noreferrer">{item.reply.tx_hash}</a>
          : <code className="break">{item.reply.tx_hash}</code>}</p>}
        {item.reply?.status === "awaiting_confirmation" && item.reply?.request_id && <button onClick={() => confirm(item.reply.request_id)} disabled={busy}>Confirm transaction</button>}
      </div>)}
    </div>
    <form className="chat-form" onSubmit={send}>
      <label className="sr-only" htmlFor="agent-message">Message the wallet agent</label>
      <input id="agent-message" value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Ask Sundarban to transfer or manage a token…" maxLength={4000} />
      <button type="submit" disabled={busy || !message.trim()}>{busy ? "Working…" : "Send"}</button>
    </form>
    {error && <p className="error" role="alert">{error}</p>}
  </section>;
}

function DecisionCard({ decision }) {
  if (!decision) return null;
  const kind = ["allow", "ask", "deny"].includes(decision.decision) ? decision.decision : "deny";
  return <div className={`decision ${kind}`}>
    <strong>{kind === "allow" ? "ALLOW" : kind === "ask" ? "CONFIRMATION REQUIRED" : "DENY"}</strong>
    {decision.rule_ids?.length > 0 && <p className="small">Rules: {decision.rule_ids.join(", ")}</p>}
    <ul>{(decision.reasons || []).map((reason, index) => <li key={index}>{reason}</li>)}</ul>
  </div>;
}

function SecurityCard() {
  const [enabled, setEnabled] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    getSecurity().then((data) => setEnabled(!!data.kill_switch_on)).catch(() => {
      setEnabled(true);
      setError("Could not verify kill-switch state; treating the wallet as frozen.");
    }).finally(() => setLoaded(true));
  }, []);
  const change = async (event) => {
    const next = event.target.checked;
    setBusy(true);
    setError("");
    try {
      const data = await setKillSwitch(next);
      setEnabled(!!data.kill_switch_on);
    } catch {
      setEnabled(true);
      setError("Could not safely update the kill switch. The wallet is treated as frozen.");
    } finally {
      setBusy(false);
    }
  };
  return <section className="card">
    <h2>Emergency kill switch</h2>
    <p className="muted small">When ON, the firewall should block wallet actions. If its state cannot be verified, this UI fails safe and shows ON.</p>
    <label className="switch-row">
      <input type="checkbox" checked={enabled} onChange={change} disabled={!loaded || busy} />
      <span className={`switch-status ${enabled ? "danger-text" : "ok-text"}`}>{enabled ? "ON · wallet frozen" : "OFF · actions subject to firewall rules"}</span>
    </label>
    {error && <p className="error" role="alert">{error}</p>}
  </section>;
}

function AuditCard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true);
    setError("");
    try { setData(await getAudit()); }
    catch { setError("The audit log could not be loaded safely. Please try again."); }
    finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);
  const integrity = data?.integrity;
  return <section className="card">
    <div className="card-head"><h2>Audit log</h2><button onClick={load} disabled={busy}>{busy ? "Refreshing…" : "Refresh log"}</button></div>
    {error && <p className="error" role="alert">{error}</p>}
    {integrity && <p className={integrity.ok ? "ok-text" : "error"}>
      {integrity.ok ? `Integrity verified · ${integrity.count} entries` : `Integrity check failed: ${integrity.reason || "unknown issue"}`}
    </p>}
    {data && data.entries.length === 0 && <p className="muted small">No audit entries yet.</p>}
    {data?.entries?.length > 0 && <div className="audit-list">
      {[...data.entries].reverse().map((entry) => <details className="audit-entry" key={entry.seq}>
        <summary><span>#{entry.seq}</span> {entry.ts} <span className="muted">{entry.event?.event || "event"}</span></summary>
        <pre>{JSON.stringify(entry.event, null, 2)}</pre>
        <p className="mono small break">Hash: {entry.hash}</p>
      </details>)}
    </div>}
  </section>;
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
        One attack, one extracted action, two agents. Both agents receive the <em>same</em> action, so the only
        difference is the firewall: the naive agent signs it, the protected agent asks the firewall, which uses the
        origin assigned by code (not the text). Test tokens only; this endpoint refuses non-local chains.
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
          <div className="attack-payload">
            <strong>Payload given to both agents</strong>
            <p>{result.attack.payload}</p>
            <p className="small">
              <strong>Action extracted from it</strong> ({result.intent.source === "llm" ? "by the real model, with no protection around the text" : "scripted: what a fooled model would extract"}):{" "}
              <code>{result.intent.action}{result.intent.unlimited ? " UNLIMITED" : ` ${result.intent.amount}`} {result.intent.token} → {result.intent.to}</code>
            </p>
            <p className="muted small">{result.intent.note}</p>
            <p className="small">
              <strong>Layer 1, model hardening:</strong>{" "}
              <span className={result.layer1.status === "fooled" ? "danger-text" : "ok-text"}>
                {result.layer1.status === "fooled" ? "not enough on its own" : "the model refused"}
              </span>{" "}
              · {result.layer1.detail} <strong>Layer 2, the firewall</strong> does not depend on the model.
            </p>
          </div>
          <div className="replay-columns">
            <section className="replay-panel naive-panel">
              <h3>Naive agent</h3>
              <div className={`decision ${["drained", "stolen"].includes(result.naive.status) ? "deny" : "ask"}`}>
                <strong>{["drained", "stolen"].includes(result.naive.status) ? "Attack succeeded — test funds lost"
                  : result.naive.status === "approved" ? "Attacker was approved; nothing was taken" : "Naive execution did not complete"}</strong>
                <p>{result.naive.reason}</p>
              </div>
              {result.naive.tx_hash && <p>{result.intent.action === "approve" ? "Approval" : "Transfer"} transaction: <code className="break">{result.naive.tx_hash}</code></p>}
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
              <h3>Sundarban protected agent</h3>
              <div className={`decision ${result.protected.status === "blocked" ? "deny" : "ask"}`}>
                <strong>{result.protected.status !== "blocked" ? "Request needs investigation"
                  : result.protected.decision ? "Firewall blocked the attack"
                  : "Refused before the firewall"}</strong>
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
