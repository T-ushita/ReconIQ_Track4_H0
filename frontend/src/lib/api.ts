/**
 * ReconIQ API client — thin wrapper around the FastAPI backend.
 * Set NEXT_PUBLIC_API_URL in your Vercel environment variables.
 */

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function startScan(payload: {
  url: string;
  enable_form_fuzzing?: boolean;
  fuzzing_authorized?: boolean;
}) {
  const res = await fetch(`${BASE}/api/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

export async function getScanStatus(sessionId: string) {
  const res = await fetch(`${BASE}/api/v1/scans/${sessionId}`);
  return res.json();
}

export async function getScanResults(sessionId: string) {
  const res = await fetch(`${BASE}/api/v1/scans/${sessionId}/results`);
  return res.json();
}

export async function getAgentInfo(sessionId: string) {
  const res = await fetch(`${BASE}/api/v1/scans/${sessionId}/agents`);
  return res.json();
}

export async function getSessions() {
  const res = await fetch(`${BASE}/api/v1/sessions`);
  return res.json();
}

export async function getHistory() {
  const res = await fetch(`${BASE}/api/v1/sessions/history`);
  return res.json();
}

export async function getReportDownloadUrl(sessionId: string): Promise<string> {
  // The /download endpoint returns a 302 to S3 presigned URL.
  // We return the redirect URL itself so the UI can open it in a new tab.
  return `${BASE}/api/v1/reports/${sessionId}/download`;
}

export async function getMetrics() {
  const res = await fetch(`${BASE}/metrics`);
  return res.json();
}
