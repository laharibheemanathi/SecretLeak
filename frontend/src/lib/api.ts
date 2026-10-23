import type {
  Dashboard,
  Finding,
  Scan,
  ScanDetail,
  SettingsResponse,
} from "../types/api";

/** Errors carry { detail: { code, message } }; never echo submitted content. */
async function fail(res: Response): Promise<never> {
  let message = `Request failed (${res.status})`;
  try {
    const body = await res.json();
    message = body?.detail?.message || message;
  } catch {
    /* non-JSON error body */
  }
  throw new Error(message);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (!(init?.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) await fail(res);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string }>("/api/health"),
  dashboard: () => request<Dashboard>("/api/dashboard"),

  scanText: (label: string, content: string) =>
    request<Scan>("/api/scans/text", {
      method: "POST",
      body: JSON.stringify({ label, content }),
    }),

  scanUpload: (files: FileList) => {
    const data = new FormData();
    Array.from(files).forEach((file) => data.append("files", file));
    return request<Scan>("/api/scans/upload", { method: "POST", body: data });
  },

  scanRepo: (path: string, includeHistory: boolean, label?: string) =>
    request<Scan>("/api/scans/repository", {
      method: "POST",
      body: JSON.stringify({ path, include_history: includeHistory, label }),
    }),

  scans: () => request<{ scans: Scan[] }>("/api/scans"),
  scanDetail: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  deleteScan: (id: string) =>
    request<{ deleted: boolean }>(`/api/scans/${id}`, { method: "DELETE" }),
  clearHistory: () =>
    request<{ deleted_scans: number }>("/api/scans", { method: "DELETE" }),

  findings: (params: Record<string, string>) => {
    const q = new URLSearchParams(params).toString();
    return request<{ findings: Finding[]; count: number }>(
      `/api/findings${q ? `?${q}` : ""}`,
    );
  },
  finding: (id: string) => request<Finding>(`/api/findings/${id}`),
  dismiss: (id: string, reason: string, note: string) =>
    request<Finding>(`/api/findings/${id}/dismiss`, {
      method: "POST",
      body: JSON.stringify({ reason, note }),
    }),
  restoreFinding: (id: string) =>
    request<Finding>(`/api/findings/${id}/restore`, { method: "POST" }),

  settings: () => request<SettingsResponse>("/api/settings"),
  saveSettings: (patch: Partial<SettingsResponse["settings"]>) =>
    request<SettingsResponse>("/api/settings", {
      method: "PUT",
      body: JSON.stringify(patch),
    }),
  resetSettings: () =>
    request<SettingsResponse>("/api/settings/reset", { method: "POST" }),

  reportUrl: (scanId: string, format: "json" | "csv") =>
    `/api/reports/${scanId}?format=${format}`,
};
