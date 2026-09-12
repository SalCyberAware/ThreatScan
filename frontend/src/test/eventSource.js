// A stand-in for the browser EventSource, which jsdom does not implement.
//
// App.jsx talks to the backend exclusively over SSE (`/scan/stream` and
// `/scan/bulk`), so every flow test drives the UI by constructing one of these,
// then pushing the same events the real server sends. Each instance records the
// URL it was opened with and whether the component closed it, which is how the
// specs assert on request parameters and cleanup.
import { act } from "@testing-library/react";

const instances = [];

class FakeEventSource {
  constructor(url) {
    this.url = String(url);
    this.listeners = {};
    this.onerror = null;
    this.closed = false;
    instances.push(this);
  }

  addEventListener(type, handler) {
    (this.listeners[type] ||= []).push(handler);
  }

  removeEventListener(type, handler) {
    this.listeners[type] = (this.listeners[type] || []).filter((h) => h !== handler);
  }

  close() {
    this.closed = true;
  }

  /** Deliver one named SSE event with a JSON payload, as the server would. */
  emit(type, data) {
    act(() => {
      for (const handler of this.listeners[type] || []) {
        handler({ data: JSON.stringify(data) });
      }
    });
  }

  /** Trip the connection-failure path. */
  fail() {
    act(() => {
      this.onerror?.(new Event("error"));
    });
  }
}

/** Replace globalThis.EventSource for the current test file. */
export function installEventSource() {
  globalThis.EventSource = FakeEventSource;
}

/** Forget every recorded instance — call between tests. */
export function resetEventSources() {
  instances.length = 0;
}

/** The connection the component opened most recently. */
export function lastEventSource() {
  return instances[instances.length - 1];
}

/** Every connection opened so far, oldest first. */
export function allEventSources() {
  return instances;
}

/** Query params of the most recent connection, as a plain object. */
export function lastParams() {
  const source = lastEventSource();
  const query = source.url.slice(source.url.indexOf("?") + 1);
  return Object.fromEntries(new URLSearchParams(query));
}
