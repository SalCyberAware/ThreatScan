const http = require("node:http");
const net  = require("node:net");
const {
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  parseShutdownTimeout,
  createShutdown,
  installShutdownHandlers,
} = require("./shutdown");

// A real HTTP server on an ephemeral port. `exit` is a mock, so nothing here
// ends the jest process or sends it a signal. The returned promise resolves with
// the exit code the first time shutdown asks to exit.
function startServer(handler) {
  return new Promise(resolve => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function shutdownFor(server, timeoutMs = 2000) {
  let resolveExit;
  const exited = new Promise(resolve => { resolveExit = resolve; });
  const exit = jest.fn(code => resolveExit(code));
  const log = jest.fn();
  const shutdown = createShutdown({ server, timeoutMs, log, exit });
  return { shutdown, exit, log, exited };
}

// agent: false gives each request its own connection with no keep-alive, so a
// finished request cannot hold the server open through an idle socket.
function get(port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/", agent: false }, res => {
      let body = "";
      res.on("data", chunk => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
  });
}

function canConnect(port) {
  return new Promise(resolve => {
    const socket = net.connect(port, "127.0.0.1");
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
  });
}

describe("createShutdown", () => {
  test("stops accepting new connections and exits 0 when nothing is open", async () => {
    const server = await startServer((req, res) => res.end("ok"));
    const { port } = server.address();
    expect(await canConnect(port)).toBe(true);

    const { shutdown, log, exited } = shutdownFor(server);
    expect(shutdown("SIGTERM")).toBe(true);

    expect(await exited).toBe(0);
    expect(server.listening).toBe(false);
    expect(await canConnect(port)).toBe(false);
    expect(log).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[0][0]).toMatch(/^SIGTERM received: shutdown started/);
  });

  test("an open request finishes before the process exits", async () => {
    let release;
    let entered;
    const handlerEntered = new Promise(resolve => { entered = resolve; });
    const server = await startServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write("event: start\ndata: {}\n\n");
      release = () => res.end("event: done\ndata: {}\n\n");
      entered();
    });
    const { port } = server.address();

    const response = get(port);
    await handlerEntered;

    const { shutdown, exit, exited } = shutdownFor(server);
    shutdown("SIGTERM");

    // Shutdown has started, the stream is still open, and nothing has exited.
    await new Promise(resolve => setTimeout(resolve, 100));
    expect(exit).not.toHaveBeenCalled();

    release();
    const { status, body } = await response;
    expect(status).toBe(200);
    expect(body).toContain("event: done");
    expect(await exited).toBe(0);
  });

  test("the deadline closes a hanging connection and exits 1", async () => {
    const server = await startServer(() => { /* never responds */ });
    const { port } = server.address();
    const closeAll = jest.spyOn(server, "closeAllConnections");

    const hung = get(port).catch(err => err);
    await new Promise(resolve => setTimeout(resolve, 50));

    const { shutdown, log, exited } = shutdownFor(server, 200);
    shutdown("SIGTERM");

    expect(await exited).toBe(1);
    expect(closeAll).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[1][0]).toMatch(/deadline of 200 ms reached/);
    // The client sees its connection closed rather than a response.
    expect((await hung).code).toBe("ECONNRESET");
  });

  test("a second signal does nothing extra", async () => {
    const server = await startServer((req, res) => res.end("ok"));
    const close = jest.spyOn(server, "close");
    const { shutdown, exit, log, exited } = shutdownFor(server);

    expect(shutdown("SIGTERM")).toBe(true);
    expect(shutdown("SIGINT")).toBe(false);
    expect(shutdown("SIGTERM")).toBe(false);

    expect(await exited).toBe(0);
    expect(close).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledTimes(1);
  });

  test("the deadline timer is unref'd and cleared after a clean close", async () => {
    const server = await startServer((req, res) => res.end("ok"));
    const setSpy = jest.spyOn(global, "setTimeout");
    const clearSpy = jest.spyOn(global, "clearTimeout");
    try {
      const { shutdown, exited } = shutdownFor(server, 5000);
      shutdown("SIGTERM");
      const index = setSpy.mock.calls.findIndex(call => call[1] === 5000);
      const timer = setSpy.mock.results[index].value;
      expect(timer.hasRef()).toBe(false);
      expect(await exited).toBe(0);
      expect(clearSpy).toHaveBeenCalledWith(timer);
    } finally {
      setSpy.mockRestore();
      clearSpy.mockRestore();
    }
  });
});

describe("installShutdownHandlers", () => {
  test("SIGTERM and SIGINT both reach one shutdown, which runs once", () => {
    const server = { close: jest.fn(), closeAllConnections: jest.fn() };
    const exit = jest.fn();
    const log = jest.fn();
    const before = {
      SIGTERM: process.listeners("SIGTERM"),
      SIGINT: process.listeners("SIGINT"),
    };
    try {
      installShutdownHandlers(server, { timeoutMs: 1000, log, exit });
      expect(process.listenerCount("SIGTERM")).toBe(before.SIGTERM.length + 1);
      expect(process.listenerCount("SIGINT")).toBe(before.SIGINT.length + 1);

      // process.emit calls the listeners directly; no signal is sent.
      process.emit("SIGTERM");
      process.emit("SIGINT");
      process.emit("SIGTERM");

      expect(server.close).toHaveBeenCalledTimes(1);
      expect(log).toHaveBeenCalledTimes(1);
      expect(log.mock.calls[0][0]).toMatch(/^SIGTERM received/);
    } finally {
      for (const signal of ["SIGTERM", "SIGINT"]) {
        for (const listener of process.listeners(signal)) {
          if (!before[signal].includes(listener)) process.removeListener(signal, listener);
        }
      }
    }
  });
});

describe("parseShutdownTimeout", () => {
  test("defaults to 10 seconds when unset", () => {
    expect(DEFAULT_SHUTDOWN_TIMEOUT_MS).toBe(10000);
    expect(parseShutdownTimeout(undefined)).toBe(10000);
    expect(parseShutdownTimeout("")).toBe(10000);
  });

  test("accepts a positive integer", () => {
    expect(parseShutdownTimeout("2500")).toBe(2500);
    expect(parseShutdownTimeout(" 12000 ")).toBe(12000);
  });

  test.each(["0", "-5", "1.5", "10s", "abc", "1e4", "99999999999999999999"])(
    "rejects %p and falls back to the default with a warning",
    raw => {
      const warn = jest.fn();
      expect(parseShutdownTimeout(raw, warn)).toBe(10000);
      expect(warn).toHaveBeenCalledTimes(1);
    }
  );
});
