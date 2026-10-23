export type Severity = "critical" | "high" | "medium" | "low";
export type ScanMode = "text" | "upload" | "repository";

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  rule_name: string;
  category: string;
  severity: Severity;
  confidence: string;
  input_label: string;
  file_path: string | null;
  line: number;
  column: number;
  masked_preview: string;
  context_snippet: string;
  remediation: string;
  description: string;
  why_severity: string;
  fingerprint: string;
  created_at: string;
  dismissed: boolean;
  dismissal_reason?: string | null;
  dismissal_note?: string | null;
}

export interface SkippedFile {
  name: string;
  reason: string;
}

export interface Scan {
  id: string;
  created_at: string;
  mode: ScanMode;
  label: string;
  file_count: number;
  finding_count: number;
  dismissed_count: number;
  skipped_count: number;
  root_path: string | null;
  include_history: boolean;
  duration_ms: number;
  skipped_files: SkippedFile[];
}

export interface ScanDetail {
  scan: Scan;
  findings: Finding[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopRule {
  rule_id: string;
  rule_name: string;
  n: number;
}

export interface Dashboard {
  total_scans: number;
  total_findings: number;
  dismissed_findings: number;
  severity_counts: SeverityCounts;
  top_rules: TopRule[];
  recent_scans: Scan[];
}

export interface Settings {
  max_upload_mb: number;
  max_files_per_scan: number;
  max_paste_chars: number;
  entropy_enabled: boolean;
  entropy_threshold: number;
  git_history_enabled: boolean;
  max_repo_files: number;
  max_history_commits: number;
  hook_min_severity: Severity;
}

export interface DataLocations {
  data_dir: string;
  database_file: string;
  hmac_key_file: string;
  note: string;
}

export interface SettingsResponse {
  settings: Settings;
  locations: DataLocations;
}
