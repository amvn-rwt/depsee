/**
 * Fetches graph JSON from the local depsee server.
 */

const DEFAULT_ENDPOINT = "/api/graph";
const SBOM_UPLOAD_ENDPOINT = "/api/sbom";

export async function fetchGraph(endpoint = DEFAULT_ENDPOINT) {
  const res = await fetch(endpoint);
  if (!res.ok) {
    return { ok: false, status: res.status };
  }
  const data = await res.json();
  return { ok: true, data };
}

/**
 * POST multipart/form-data with field "file" (CycloneDX JSON).
 * Returns 202 + jobId; use {@link pollSbomJob} for the graph.
 * @param {File} file
 */
export async function postSbomFile(file) {
  const body = new FormData();
  body.append("file", file, file.name);

  const res = await fetch(SBOM_UPLOAD_ENDPOINT, {
    method: "POST",
    body,
  });

  const text = await res.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }

  if (res.status === 202 && payload && typeof payload.jobId === "string") {
    return { ok: true, jobId: payload.jobId };
  }

  if (!res.ok) {
    const msg =
      payload && typeof payload.error === "string"
        ? payload.error
        : text || `HTTP ${res.status}`;
    return { ok: false, status: res.status, error: msg };
  }

  return { ok: true, data: payload };
}

/**
 * POST /api/sbom via XMLHttpRequest for upload progress, then receive jobId (202).
 * @param {File} file
 * @param {(e: { loaded: number, total: number }) => void} [onUploadProgress]
 * @returns {Promise<{ ok: true, jobId: string } | { ok: false, status: number, error?: string }>}
 */
export function postSbomFileWithProgress(file, onUploadProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const body = new FormData();
    body.append("file", file, file.name);

    xhr.upload.addEventListener("progress", (ev) => {
      if (typeof onUploadProgress === "function") {
        onUploadProgress({
          loaded: ev.loaded,
          total: ev.lengthComputable ? ev.total : 0,
        });
      }
    });

    xhr.addEventListener("load", () => {
      const text = xhr.responseText;
      let payload = null;
      try {
        payload = text ? JSON.parse(text) : null;
      } catch {
        payload = null;
      }
      const status = xhr.status;
      if (status === 202 && payload && typeof payload.jobId === "string") {
        resolve({ ok: true, jobId: payload.jobId });
        return;
      }
      if (status >= 200 && status < 300) {
        resolve({
          ok: false,
          status,
          error: "expected 202 Accepted with jobId",
        });
        return;
      }
      const msg =
        payload && typeof payload.error === "string"
          ? payload.error
          : text || `HTTP ${status}`;
      resolve({ ok: false, status, error: msg });
    });

    xhr.addEventListener("error", () => {
      reject(new Error("network"));
    });
    xhr.addEventListener("abort", () => {
      reject(new Error("aborted"));
    });

    xhr.open("POST", SBOM_UPLOAD_ENDPOINT);
    xhr.send(body);
  });
}

/**
 * Polls GET /api/jobs/{id} until the job completes or fails.
 * @param {string} jobId
 * @param {object} [opts]
 * @param {(j: { phase: string, percent: number }) => void} [opts.onJobProgress]
 * @param {AbortSignal} [opts.signal]
 * @param {number} [opts.intervalMs]
 */
export async function pollSbomJob(jobId, opts = {}) {
  const { onJobProgress, signal, intervalMs = 500 } = opts;
  const path = `/api/jobs/${encodeURIComponent(jobId)}`;

  for (;;) {
    if (signal?.aborted) {
      throw new Error("aborted");
    }

    const res = await fetch(path);
    const text = await res.text();
    let job = null;
    try {
      job = text ? JSON.parse(text) : null;
    } catch {
      job = null;
    }

    if (!res.ok) {
      const errMsg =
        job && typeof job.error === "string" ? job.error : text || `HTTP ${res.status}`;
      return { ok: false, status: res.status, error: errMsg };
    }

    if (job.status === "completed") {
      if (!job.graph) {
        return { ok: false, error: "completed without graph" };
      }
      return { ok: true, data: job.graph };
    }
    if (job.status === "failed") {
      return {
        ok: false,
        error: typeof job.error === "string" ? job.error : "Job failed",
      };
    }

    if (typeof onJobProgress === "function") {
      onJobProgress({
        phase: typeof job.phase === "string" ? job.phase : "",
        percent: Number(job.percent) || 0,
      });
    }

    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
