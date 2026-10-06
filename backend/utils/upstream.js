// Helpers for building outbound requests to the engine APIs.

// Every axios call carries an explicit timeout so an upstream that accepts the
// connection and never answers cannot hold a socket open past the scan.
const DEFAULT_TIMEOUT = 8000;

// Encode a user-supplied value for use as one path segment of an upstream URL.
// encodeURIComponent stops "/", "?" and "#" from changing which endpoint is
// hit, but "." and ".." survive it and the URL parser resolves them as dot
// segments ("%2e%2e" too), so those are refused outright. ":" is left literal:
// it is legal inside a path segment, cannot change the endpoint, and keeps
// IPv6 lookups byte-identical to what the engine APIs received before.
function pathSegment(value) {
  const s = String(value);
  if (s === "." || s === "..") throw new Error("Invalid indicator");
  return encodeURIComponent(s).replace(/%3A/gi, ":");
}

// Race an engine call against its per-engine timeout. The engine receives an
// AbortSignal and passes it to axios, so when the timeout fires the upstream
// request is actually cancelled instead of left running in the background.
function withTimeout(id, fn, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`${id} timeout`));
    }, timeoutMs);
  });
  return Promise.race([fn(controller.signal), timeout])
    .finally(() => clearTimeout(timer));
}

module.exports = { DEFAULT_TIMEOUT, pathSegment, withTimeout };
