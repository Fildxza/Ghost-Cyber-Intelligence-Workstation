import { describe, expect, it } from "vitest";
import { ago, fmtBytes, parseTs, short, utc, utcTime } from "./lib";

describe("time formatting", () => {
  it("renders backend UTC timestamps in fixed-width Zulu form", () => {
    expect(utc("2026-10-21T11:43:49.123456Z")).toBe("2026-10-21 11:43:49Z");
    expect(utcTime("2026-10-21T11:43:49.123456Z")).toBe("11:43:49");
  });
  it("shows an em dash for missing or invalid values instead of inventing a time", () => {
    expect(utc(null)).toBe("—");
    expect(utc("garbage")).toBe("—");
    expect(parseTs(undefined)).toBeNull();
  });
  it("computes relative age", () => {
    const now = Date.parse("2026-10-21T12:00:00Z");
    expect(ago("2026-10-21T11:59:30Z", now)).toBe("30s ago");
    expect(ago("2026-10-21T11:00:00Z", now)).toBe("1h ago");
    expect(ago("2026-10-19T12:00:00Z", now)).toBe("2d ago");
  });
});

describe("formatting helpers", () => {
  it("formats bytes", () => {
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(2048)).toBe("2.00 KB");
    expect(fmtBytes(5 * 1024 * 1024)).toBe("5.00 MB");
  });
  it("shortens long hashes in the middle", () => {
    const h = "a".repeat(64);
    expect(short(h, 8)).toBe("aaaaaaaa…aaaaaaaa");
    expect(short("abc", 8)).toBe("abc");
  });
});
