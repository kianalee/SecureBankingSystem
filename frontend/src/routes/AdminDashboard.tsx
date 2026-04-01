import { FormEvent, startTransition, useEffect, useState } from "react";

import { Panel } from "../components/Panel";
import { StatusBadge } from "../components/StatusBadge";
import { getJson, postJson } from "../lib/api";
import { formatTimestamp } from "../lib/format";

type SessionItem = {
  sessionId: string;
  clientId?: string;
  connected: boolean;
  authenticated: boolean;
  authenticatedEmail?: string | null;
  phase?: string;
  lastAction?: string | null;
  connectedAt?: string | null;
  lastSeenAt?: string | null;
};

type AuditItem = {
  id: string;
  email?: string;
  action?: string;
  time?: string | null;
};

type OverviewData = {
  server: {
    reachable: boolean;
    host: string;
    port: number;
    message: string;
  };
  sessions: {
    count: number;
    items: SessionItem[];
  };
  audit: {
    available: boolean;
    message: string;
    items: AuditItem[];
    path?: string | null;
  };
};

type AdminAuthData = {
  authenticated: boolean;
  configured: boolean;
};

export function AdminDashboard() {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [authStatus, setAuthStatus] = useState<AdminAuthData | null>(null);
  const [message, setMessage] = useState("Loading...");
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState("");
  const [authBusy, setAuthBusy] = useState(false);

  async function refreshAuthStatus() {
    const payload = await getJson<AdminAuthData>("/api/admin/auth/status");
    setAuthStatus(payload.data);
    return payload.data;
  }

  async function refresh() {
    try {
      const auth = await refreshAuthStatus();
      if (!auth.authenticated) {
        setOverview(null);
        setMessage(auth.configured ? "Admin password required." : "ADMIN_PANEL_PASSWORD is not configured.");
        return;
      }

      const payload = await getJson<OverviewData>("/api/admin/overview");
      startTransition(() => {
        setOverview(payload.data);
      });
      setMessage(payload.message);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to load admin data.");
      setOverview(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();

    const timer = window.setInterval(() => {
      void refresh();
    }, 8000);

    return () => window.clearInterval(timer);
  }, []);

  async function handleAdminLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthBusy(true);
    try {
      await postJson("/api/admin/auth/login", { password });
      setPassword("");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Admin login failed.");
    } finally {
      setAuthBusy(false);
      setLoading(false);
    }
  }

  async function handleAdminLogout() {
    setAuthBusy(true);
    try {
      await postJson("/api/admin/auth/logout");
      setOverview(null);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Admin logout failed.");
    } finally {
      setAuthBusy(false);
      setLoading(false);
    }
  }

  if (!authStatus?.authenticated) {
    return (
      <main className="page-grid admin-grid admin-layout">
        <section className="hero-card admin-hero compact-hero">
          <div className="hero-copy-row">
            <p className="eyebrow">Admin</p>
            <h2>Restricted panel.</h2>
            <p className="lead">Enter the admin password to continue.</p>
          </div>
          <p className="status-message">{loading ? "Checking access..." : message}</p>
        </section>

        <Panel title="Admin login" className="admin-auth-panel compact-panel">
          <form className="stack" onSubmit={handleAdminLogin}>
            <label className="field">
              <span>Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
              />
            </label>
            <button disabled={authBusy || !authStatus?.configured} type="submit">
              {authBusy ? "Checking..." : "Enter admin panel"}
            </button>
          </form>
        </Panel>
      </main>
    );
  }

  return (
    <main className="page-grid admin-grid admin-layout">
      <section className="hero-card admin-hero compact-hero">
        <div className="hero-copy-row">
          <p className="eyebrow">Admin</p>
          <h2>System overview.</h2>
          <p className="lead">Sessions, audit activity, server health.</p>
        </div>
        <div className="hero-side admin-hero-side">
          <p className="status-message">{loading ? "Refreshing..." : message}</p>
          <button className="ghost" type="button" onClick={handleAdminLogout} disabled={authBusy}>
            Sign out
          </button>
        </div>
      </section>

      <Panel title="Overview" className="compact-panel">
        <div className="hero-stats">
          <div>
            <span>Server</span>
            <strong>{overview?.server.reachable ? "Online" : "Offline"}</strong>
          </div>
          <div>
            <span>Sessions</span>
            <strong>{overview?.sessions.count ?? 0}</strong>
          </div>
          <div>
            <span>Audit</span>
            <strong>{overview?.audit.available ? "Live" : "Degraded"}</strong>
          </div>
        </div>
        <div className="inline-status-row">
          <StatusBadge tone={overview?.server.reachable ? "good" : "bad"}>
            {overview?.server.reachable ? "Bank reachable" : "Bank unavailable"}
          </StatusBadge>
          <StatusBadge tone={overview?.audit.available ? "good" : "warn"}>
            {overview?.audit.available ? "Audit available" : "Audit unavailable"}
          </StatusBadge>
        </div>
      </Panel>

      <Panel title="Active sessions" className="compact-panel admin-sessions-panel">
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>Client</th>
                <th>Identity</th>
                <th>Phase</th>
                <th>Last action</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {overview?.sessions.items.length ? (
                overview.sessions.items.map((session) => (
                  <tr key={session.sessionId}>
                    <td>{session.clientId ?? "Unknown ATM"}</td>
                    <td>{session.authenticatedEmail ?? (session.authenticated ? "Authenticated" : "Guest")}</td>
                    <td>{session.phase ?? "Unknown"}</td>
                    <td>{session.lastAction ?? "No activity"}</td>
                    <td>{formatTimestamp(session.lastSeenAt)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="empty-state">
                    No active sessions.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Audit log" className="compact-panel admin-audit-panel">
        {overview?.audit.available ? <p className="help-text"></p> : null}
        {overview?.audit.available ? null : <p className="empty-state">{overview?.audit.message}</p>}
        <ul className="activity-feed">
          {(overview?.audit.items ?? []).map((item) => (
            <li key={item.id}>
              <div>
                <p>{item.action ?? "Unknown action"}</p>
                <span>{item.email ?? "Unknown user"}</span>
              </div>
              <small>{formatTimestamp(item.time)}</small>
            </li>
          ))}
          {!overview?.audit.items.length ? <li className="empty-state">No audit entries.</li> : null}
        </ul>
      </Panel>
    </main>
  );
}
