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
 * Same as POST /api/sbom but uses XMLHttpRequest so upload progress is available.
 * @param {File} file
 * @param {(e: { loaded: number, total: number }) => void} [onUploadProgress] total is 0 if unknown
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
      if (status < 200 || status >= 300) {
        const msg =
          payload && typeof payload.error === "string"
            ? payload.error
            : text || `HTTP ${status}`;
        resolve({ ok: false, status, error: msg });
        return;
      }
      resolve({ ok: true, data: payload });
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
