import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AtmDashboard } from "./AtmDashboard";

describe("AtmDashboard", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          status: "ok",
          message: "Session snapshot retrieved.",
          data: {
            clientId: null,
            connected: false,
            authenticated: false,
            authenticatedEmail: null,
            authenticatedUid: null,
            phase: "disconnected",
            lastAction: null,
            connectedAt: null,
            lastActivityAt: null,
            protocolEvents: [],
            protocolSummary: {
              secureChannel: false,
              phase1Complete: false,
              phase2Complete: false,
            },
          },
        }),
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the connection and auth surfaces", async () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AtmDashboard />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Simple secure banking.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connect" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });
});
