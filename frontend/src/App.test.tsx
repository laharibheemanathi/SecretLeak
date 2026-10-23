import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import App from "./App";

vi.stubGlobal(
  "fetch",
  vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          total_scans: 0,
          total_findings: 0,
          dismissed_findings: 0,
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
          top_rules: [],
          recent_scans: [],
        }),
    }),
  ),
);

test("renders dashboard empty state", async () => {
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
  expect(await screen.findByText(/No scans yet/i)).toBeInTheDocument();
  expect(screen.getByText("SecretLeak")).toBeInTheDocument();
});

test("renders navigation links", async () => {
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
  expect(await screen.findByRole("link", { name: /New Scan/i })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Findings/i })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /About & Security/i })).toBeInTheDocument();
});
