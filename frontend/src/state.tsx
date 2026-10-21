import { createContext, ReactNode, useCallback, useContext, useMemo, useState } from "react";
import { AppConfig, SystemStatus, Workspace, get, post } from "./api";
import { Loadable, useLoad, errMsg } from "./lib";

export interface Toast { id: number; kind: "ok" | "err" | "info"; text: string }

interface AppState {
  status: Loadable<SystemStatus>;
  /** true only when the last status poll actually succeeded */
  apiUp: boolean;
  workspaces: Loadable<Workspace[]>;
  workspace: Workspace | null;
  setWorkspace: (id: number) => Promise<void>;
  config: AppConfig | null;
  toasts: Toast[];
  notify: (kind: Toast["kind"], text: string) => void;
  dismissToast: (id: number) => void;
  navCompact: boolean;
  setNavCompact: (v: boolean) => void;
  fail: (e: unknown) => void;
}

const Ctx = createContext<AppState | null>(null);
let toastSeq = 1;

export function AppProvider({ children }: { children: ReactNode }) {
  const status = useLoad(() => get<SystemStatus>("/status"), [], 8000);
  const workspaces = useLoad(() => get<Workspace[]>("/workspaces"), []);
  const cfg = useLoad(() => get<AppConfig>("/config"), []);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [navCompact, setNavCompactState] = useState(() => {
    try {
      return localStorage.getItem("ghost.navCompact") === "1";
    } catch {
      return false;
    }
  });

  const setNavCompact = useCallback((v: boolean) => {
    setNavCompactState(v);
    try {
      localStorage.setItem("ghost.navCompact", v ? "1" : "0");
    } catch {
      /* storage unavailable — preference simply isn't persisted */
    }
  }, []);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const notify = useCallback((kind: Toast["kind"], text: string) => {
    const id = toastSeq++;
    setToasts((t) => [...t.slice(-3), { id, kind, text }]);
    window.setTimeout(() => dismissToast(id), kind === "err" ? 9000 : 4500);
  }, [dismissToast]);
  const fail = useCallback((e: unknown) => notify("err", errMsg(e)), [notify]);

  const apiUp = !!status.data && !status.error;
  const workspace = useMemo(() => {
    const list = workspaces.data ?? [];
    return list.find((w) => w.id === status.data?.active_workspace_id) ?? list[0] ?? null;
  }, [workspaces.data, status.data?.active_workspace_id]);

  const setWorkspace = useCallback(async (id: number) => {
    await post(`/workspaces/${id}/activate`);
    status.reload();
  }, [status]);

  const value: AppState = { status, apiUp, workspaces, workspace, setWorkspace, config: cfg.data, toasts, notify, dismissToast, navCompact, setNavCompact, fail };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp outside AppProvider");
  return v;
}
