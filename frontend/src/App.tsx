import { NavLink, Route, Routes } from "react-router-dom";

import { AdminDashboard } from "./routes/AdminDashboard";
import { AtmDashboard } from "./routes/AtmDashboard";

export function App() {
  return (
    <div className="app-frame">
      <header className="topbar">
        <div>
          <p className="eyebrow">SecureBankingSystem</p>
          <h1>Premium ATM Banking Demo</h1>
        </div>
        <nav className="topbar-nav" aria-label="Primary">
          <NavLink to="/app" className={({ isActive }) => navClass(isActive)}>
            ATM App
          </NavLink>
          <NavLink to="/admin" className={({ isActive }) => navClass(isActive)}>
            Admin Monitor
          </NavLink>
        </nav>
      </header>

      <Routes>
        <Route path="/" element={<AtmDashboard />} />
        <Route path="/app" element={<AtmDashboard />} />
        <Route path="/admin" element={<AdminDashboard />} />
      </Routes>
    </div>
  );
}

function navClass(isActive: boolean) {
  return isActive ? "nav-link nav-link-active" : "nav-link";
}
