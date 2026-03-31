import { FormEvent, startTransition, useDeferredValue, useEffect, useState } from "react";

import { Panel } from "../components/Panel";
import { StatusBadge } from "../components/StatusBadge";
import { deleteJson, getJson, postJson } from "../lib/api";
import { formatCurrency, formatTimestamp } from "../lib/format";

type ProtocolEvent = {
  timestamp: string;
  phase: string;
  title: string;
  detail: string;
};

type SessionStatus = {
  clientId?: string;
  connected: boolean;
  authenticated: boolean;
  authenticatedEmail?: string | null;
  phase: string;
  lastAction?: string | null;
  connectedAt?: string | null;
  lastActivityAt?: string | null;
  protocolEvents: ProtocolEvent[];
  protocolSummary: {
    secureChannel: boolean;
    phase1Complete: boolean;
    phase2Complete: boolean;
  };
};

type BalanceData = {
  balance?: number;
};

export function AtmDashboard() {
  const [sessionStatus, setSessionStatus] = useState<SessionStatus | null>(null);
  const [balance, setBalance] = useState<number | null>(null);
  const [message, setMessage] = useState("Connect to start.");
  const [busy, setBusy] = useState(false);
  const [connectClientId, setConnectClientId] = useState("ATM Aurora");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [amount, setAmount] = useState("100");
  const deferredStatus = useDeferredValue(sessionStatus);

  async function refreshStatus(silent = false) {
    try {
      const payload = await getJson<SessionStatus>("/api/session/peek");
      startTransition(() => {
        setSessionStatus(payload.data);
      });

      if (payload.data.authenticated) {
        const balancePayload = await getJson<BalanceData>("/api/account/balance");
        setBalance(balancePayload.data.balance ?? null);
      } else {
        setBalance(null);
      }
      if (!silent) {
        setMessage(payload.message);
      }
    } catch (error) {
      if (!silent) {
        setMessage(error instanceof Error ? error.message : "Unable to refresh ATM state.");
      }
      setSessionStatus(null);
      setBalance(null);
    }
  }

  useEffect(() => {
    void refreshStatus(true);
  }, []);

  useEffect(() => {
    if (!sessionStatus?.connected) {
      return;
    }

    const timer = window.setInterval(() => {
      void refreshStatus(true);
    }, 12000);

    return () => window.clearInterval(timer);
  }, [sessionStatus?.connected]);

  async function handleConnect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const payload = await postJson<{
        session: object;
        protocolEvents: ProtocolEvent[];
        phase: string;
        protocolSummary: SessionStatus["protocolSummary"];
      }>("/api/session/connect", {
        clientId: connectClientId,
      });

      setSessionStatus({
        clientId: connectClientId,
        connected: true,
        authenticated: false,
        phase: payload.data.phase,
        protocolEvents: payload.data.protocolEvents,
        protocolSummary: payload.data.protocolSummary,
      });
      setBalance(null);
      setMessage(payload.message);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to connect ATM session.");
    } finally {
      setBusy(false);
    }
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      if (authMode === "register") {
        await postJson("/api/auth/register", { username, email, password });
        setUsername("");
        setPassword("");
        setAuthMode("login");
        setMessage("Account created. Sign in.");
      } else {
        const payload = await postJson("/api/auth/login", { email, password });
        setMessage(payload.message);
        setPassword("");
      }

      await refreshStatus(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Authentication request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleTransaction(kind: "deposit" | "withdraw") {
    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      setMessage("Enter a valid positive amount.");
      return;
    }

    setBusy(true);
    try {
      const path = kind === "deposit" ? "/api/account/deposit" : "/api/account/withdraw";
      const payload = await postJson<{ balance?: number }>(path, { amount: numericAmount });
      if (typeof payload.data.balance === "number") {
        setBalance(payload.data.balance);
      }
      setMessage(payload.message);
      await refreshStatus(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Transaction failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    setBusy(true);
    try {
      const payload = await postJson("/api/auth/logout");
      setMessage(payload.message);
      await refreshStatus(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Logout failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisconnect() {
    setBusy(true);
    try {
      const payload = await deleteJson("/api/session");
      setMessage(payload.message);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Disconnect failed.");
    } finally {
      setBusy(false);
      setSessionStatus(null);
      setBalance(null);
    }
  }

  const connectionTone = sessionStatus?.connected ? "good" : "neutral";
  const authTone = sessionStatus?.authenticated ? "good" : "warn";

  return (
    <main className="page-grid">
      <section className="hero-card">
        <p className="eyebrow">ATM</p>
        <h2>Simple secure banking.</h2>
        <p className="lead">Connect, sign in, and move money.</p>

        <div className="hero-stats">
          <div>
            <span>Channel</span>
            <strong>{deferredStatus?.protocolSummary.secureChannel ? "Established" : "Waiting"}</strong>
          </div>
          <div>
            <span>Access</span>
            <strong>{deferredStatus?.authenticated ? "Signed in" : "Guest"}</strong>
          </div>
          <div>
            <span>Balance</span>
            <strong>{formatCurrency(balance)}</strong>
          </div>
        </div>

        <div className="inline-status-row">
          <StatusBadge tone={connectionTone}>{sessionStatus?.connected ? "Connected" : "Disconnected"}</StatusBadge>
          <StatusBadge tone={authTone}>{sessionStatus?.authenticated ? "Signed in" : "Guest"}</StatusBadge>
        </div>

        <p className="status-message">{message}</p>
      </section>

      <Panel title="Connect">
        <form className="stack" onSubmit={handleConnect}>
          <label className="field">
            <span>Client ID</span>
            <input
              value={connectClientId}
              onChange={(event) => setConnectClientId(event.target.value)}
              autoComplete="off"
            />
          </label>
          <div className="button-row">
            <button disabled={busy} type="submit">
              {busy ? "Connecting..." : "Connect"}
            </button>
            <button disabled={busy || !sessionStatus?.connected} type="button" className="ghost" onClick={handleDisconnect}>
              Disconnect
            </button>
          </div>
        </form>
      </Panel>

      <Panel title={authMode === "register" ? "Create account" : "Sign in"}>
        <div className="segmented-control" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            className={authMode === "login" ? "segment active" : "segment"}
            onClick={() => setAuthMode("login")}
          >
            Login
          </button>
          <button
            type="button"
            className={authMode === "register" ? "segment active" : "segment"}
            onClick={() => setAuthMode("register")}
          >
            Register
          </button>
        </div>

        <form className="stack" onSubmit={handleAuth}>
          {authMode === "register" ? (
            <label className="field">
              <span>Username</span>
              <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
            </label>
          ) : null}
          <label className="field">
            <span>Email</span>
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={authMode === "register" ? "new-password" : "current-password"}
            />
          </label>
          <button disabled={busy || !sessionStatus?.connected} type="submit">
            {authMode === "register" ? "Create account" : "Sign in"}
          </button>
        </form>
      </Panel>

      <Panel title="Account" className="wide-panel">
        <div className="account-grid">
          <div className="balance-card">
            <span>Balance</span>
            <strong>{formatCurrency(balance)}</strong>
            <small>Last action: {sessionStatus?.lastAction ?? "No activity yet"}</small>
          </div>

          <div className="stack">
            <label className="field">
              <span>Amount</span>
              <input value={amount} onChange={(event) => setAmount(event.target.value)} inputMode="decimal" autoComplete="off" />
            </label>
            <div className="button-row">
              <button disabled={busy || !sessionStatus?.authenticated} type="button" onClick={() => void handleTransaction("deposit")}>
                Deposit
              </button>
              <button
                disabled={busy || !sessionStatus?.authenticated}
                type="button"
                className="ghost"
                onClick={() => void handleTransaction("withdraw")}
              >
                Withdraw
              </button>
            </div>
            <button disabled={busy || !sessionStatus?.authenticated} type="button" className="ghost" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      </Panel>

      <Panel title="Session" className="wide-panel">
        <div className="meta-grid">
          <div>
            <span className="meta-label">Connected</span>
            <strong>{formatTimestamp(deferredStatus?.connectedAt)}</strong>
          </div>
          <div>
            <span className="meta-label">Last activity</span>
            <strong>{formatTimestamp(deferredStatus?.lastActivityAt)}</strong>
          </div>
          <div>
            <span className="meta-label">Phase</span>
            <strong>{deferredStatus?.phase ?? "Disconnected"}</strong>
          </div>
        </div>

        <ul className="activity-feed">
          {(deferredStatus?.protocolEvents ?? []).map((event) => (
            <li key={`${event.timestamp}-${event.title}`}>
              <div>
                <p>{event.title}</p>
                <span>{event.detail}</span>
              </div>
              <small>{formatTimestamp(event.timestamp)}</small>
            </li>
          ))}
          {!deferredStatus?.protocolEvents?.length ? (
            <li className="empty-state">No session activity yet.</li>
          ) : null}
        </ul>
      </Panel>
    </main>
  );
}
