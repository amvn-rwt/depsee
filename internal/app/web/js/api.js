/**
 * Fetches graph JSON from the local depsee server.
 */

const DEFAULT_ENDPOINT = "/api/graph";

export async function fetchGraph(endpoint = DEFAULT_ENDPOINT) {
  const res = await fetch(endpoint);
  if (!res.ok) {
    return { ok: false, status: res.status };
  }
  const data = await res.json();
  return { ok: true, data };
}
