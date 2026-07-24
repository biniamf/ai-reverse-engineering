
export function normalizeJobStatus(status) {
  return String(status || "unknown").toLowerCase();
}

export function isAnalysisReady(status) {
  const value = normalizeJobStatus(status);
  return value === "done" || value === "completed";
}

export function jobStateCopy(job) {
  const status = normalizeJobStatus(job && job.status);
  const safeMessage = job && (job.message || job.error_code);
  const messages = {
    queued: ["Analysis queued", "This binary is waiting for the analysis worker."],
    running: [
      "Analysis in progress",
      "Artifacts and chat will become available when Ghidra finishes.",
    ],
    failed: [
      "Analysis failed",
      safeMessage || "The service did not produce analysis artifacts.",
    ],
    error: [
      "Analysis failed",
      safeMessage || "The service did not produce analysis artifacts.",
    ],
    cancelled: [
      "Analysis cancelled",
      "This job was cancelled before artifacts were completed.",
    ],
    interrupted: [
      "Analysis interrupted",
      safeMessage ||
        "The service stopped before analysis completed. Re-upload the binary to analyze it again.",
    ],
  };
  const [title, body] =
    messages[status] || ["Analysis unavailable", `Job status: ${status}.`];
  return { status, title, body, ready: isAnalysisReady(status) };
}
