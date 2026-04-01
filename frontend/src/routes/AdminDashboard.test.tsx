import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AdminDashboard } from "./AdminDashboard";

describe("AdminDashboard", () => {
  beforeEach(() => {
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        call += 1;
        if (call === 1) {
          return {
            ok: true,
            json: async () => ({
              status: "ok",
              message: "Admin auth status retrieved.",
              data: { authenticated: false, configured: true },
            }),
          };
        }

        return {
          ok: true,
          json: async () => ({
            status: "ok",
          message: "Admin overview retrieved.",
          data: {
            server: { reachable: true, host: "localhost", port: 1234, message: "reachable" },
            sessions: { count: 0, items: [] },
            audit: { available: true, message: "ok", items: [], path: "/tmp/audit.log" },
          },
        }),
      };
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the monitoring copy", async () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AdminDashboard />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Restricted panel.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enter admin panel" })).toBeInTheDocument();
  });
});
