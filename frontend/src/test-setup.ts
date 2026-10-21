import "@testing-library/jest-dom/vitest";

// jsdom does not implement ResizeObserver; components that measure themselves only need a no-op.
class RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
(globalThis as unknown as { ResizeObserver: typeof RO }).ResizeObserver ??= RO;
