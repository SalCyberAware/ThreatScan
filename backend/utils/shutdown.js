// Graceful shutdown for the HTTP server.
//
// In the Docker image node runs as PID 1, and PID 1 ignores SIGTERM unless the
// app installs a handler. Without one, a deploy ends with the platform's
// SIGKILL, which cuts any SSE scan stream that is still open.
//
// On the first SIGTERM or SIGINT: log once, stop accepting connections, let
// in-flight requests and streams finish, then exit 0. If they have not finished
// by the deadline, close what is left and exit 1. Railway waits the Teardown
// Draining time between SIGTERM and SIGKILL: 15 seconds for this service, set
// in Settings > Deploy > Teardown (the default with Teardown off is 0). The
// 10 second default leaves room to exit cleanly.

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10000;
const SHUTDOWN_SIGNALS = ["SIGTERM", "SIGINT"];

// SHUTDOWN_TIMEOUT_MS as a positive integer number of milliseconds. Anything
// else (empty, zero, negative, fractional, not a number) falls back to the
// default with a warning, so a typo in a variable cannot stop the server from
// starting or make it exit immediately.
function parseShutdownTimeout(raw, warn = console.warn) {
  if (raw === undefined || raw === "") return DEFAULT_SHUTDOWN_TIMEOUT_MS;
  const text = String(raw).trim();
  const value = Number(text);
  if (/^[1-9]\d*$/.test(text) && Number.isSafeInteger(value)) return value;
  warn(`SHUTDOWN_TIMEOUT_MS must be a positive integer; using ${DEFAULT_SHUTDOWN_TIMEOUT_MS}`);
  return DEFAULT_SHUTDOWN_TIMEOUT_MS;
}

// Returns shutdown(signal). Only the first call does anything; later calls
// return false. `exit` and `log` are injected so tests never end the jest
// process or send it a real signal.
function createShutdown({ server, timeoutMs, log = console.log, exit = process.exit }) {
  let started = false;

  return function shutdown(signal) {
    if (started) return false;
    started = true;
    log(`${signal} received: shutdown started, waiting up to ${timeoutMs} ms for open requests`);

    const deadline = setTimeout(() => {
      log(`Shutdown deadline of ${timeoutMs} ms reached: closing remaining connections`);
      server.closeAllConnections();
      exit(1);
    }, timeoutMs);
    // The deadline alone must never keep the process alive.
    deadline.unref();

    // close() stops new connections and drops idle keep-alive ones; its callback
    // runs once every open request and stream has ended.
    server.close(err => {
      clearTimeout(deadline);
      if (err) {
        log(`Shutdown failed: ${err.message}`);
        exit(1);
        return;
      }
      exit(0);
    });
    return true;
  };
}

function installShutdownHandlers(server, options = {}) {
  const shutdown = createShutdown({ server, ...options });
  for (const signal of SHUTDOWN_SIGNALS) process.on(signal, () => shutdown(signal));
  return shutdown;
}

module.exports = {
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  parseShutdownTimeout,
  createShutdown,
  installShutdownHandlers,
};
