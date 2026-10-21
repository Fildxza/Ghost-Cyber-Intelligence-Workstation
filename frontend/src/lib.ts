import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

// ---- time -------------------------------------------------------------------------

const pad = (n: number) => String(n).padStart(2, "0");

export function parseTs(ts: string | null | undefined): Date | null {
  if (!ts) return null;
  const d = new Date(ts.endsWith("Z") || ts.includes("+") ? ts : ts + "Z");
  return Number.isNaN(d.getTime()) ? null : d;
}

/** 2026-10-21 15:04:09Z — UTC, fixed width, for logs and provenance. */
export function utc(ts: string | null | undefined): string {
  const d = parseTs(ts);
  if (!d) return "—";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
}

export function utcTime(ts: string | null | undefined): string {
  const d = parseTs(ts);
  return d ? `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}` : "—";
}

export function ago(ts: string | null | undefined, now = Date.now()): string {
  const d = parseTs(ts);
  if (!d) return "—";
  const s = Math.max(0, Math.round((now - d.getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
};

export const fmtNum = (n: number) => n.toLocaleString("en-GB");

export const short = (s: string, n = 14) => (s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s);

// ---- hooks ------------------------------------------------------------------------

export interface Loadable<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Fetch on mount / dependency change, optionally polling. Stale responses are discarded. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = [], pollMs?: number): Loadable<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async (silent = false) => {
    const id = ++seq.current;
    if (!silent) setLoading(true);
    try {
      const r = await fnRef.current();
      if (id === seq.current) {
        setData(r);
        setError(null);
      }
    } catch (e) {
      if (id === seq.current) setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void run();
    if (!pollMs) return;
    const t = window.setInterval(() => {
      if (!document.hidden) void run(true);
    }, pollMs);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs]);

  return { data, error, loading, reload: () => void run(true) };
}

export function useNow(intervalMs = 1000): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function useOnline(): boolean {
  const [online, setOnline] = useState(navigator.onLine);
  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
    };
  }, []);
  return online;
}

export function download(filename: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e));
