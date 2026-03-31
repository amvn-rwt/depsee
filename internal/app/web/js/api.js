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
