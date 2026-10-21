import { useEffect, useRef, useState } from "react";
import { Overview } from "../api";

const SERIES = [
  { key: "findings", label: "FINDINGS", color: "#B7F36B" },
  { key: "operations", label: "OPERATIONS", color: "#6F9A64" },
  { key: "indicators", label: "INDICATORS", color: "#D6A64F" },
  { key: "evidence", label: "EVIDENCE", color: "#9FB4A3" },
  { key: "cases", label: "CASES", color: "#566A5C" },
] as const;

type Row = Overview["timeline"][number];

/** Stacked daily event counts from the audit trail. */
export default function Timeline({ data }: { data: Row[] }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.floor(e.contentRect.width))));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const H = 176, padL = 28, padB = 22, padT = 8, padR = 6;
  const totals = data.map((d) => SERIES.reduce((s, k) => s + d[k.key], 0));
  const max = Math.max(4, ...totals);
  const nice = Math.ceil(max / 4) * 4;
  const innerW = w - padL - padR, innerH = H - padT - padB;
  const bw = innerW / data.length;
  const y = (v: number) => padT + innerH - (v / nice) * innerH;
  const any = totals.some((t) => t > 0);

  return (
    <div ref={wrap} className="w-full">
      <svg width={w} height={H} role="img" aria-label="Daily activity over the last 14 days, from stored audit events" onMouseLeave={() => setHover(null)}>
        {[0, 1, 2, 3, 4].map((i) => {
          const v = (nice / 4) * i;
          return (
            <g key={i}>
              <line x1={padL} x2={w - padR} y1={y(v)} y2={y(v)} stroke="#243026" strokeWidth={1} strokeDasharray={i === 0 ? undefined : "2 4"} />
              <text x={padL - 6} y={y(v) + 3} textAnchor="end" fontSize={9} fill="#5d6c61" fontFamily="IBM Plex Mono">{v}</text>
            </g>
          );
        })}
        {data.map((d, i) => {
          let acc = 0;
          const x = padL + i * bw + bw * 0.16;
          return (
            <g key={d.date} onMouseEnter={() => setHover(i)}>
              <rect x={padL + i * bw} y={padT} width={bw} height={innerH} fill={hover === i ? "rgba(183,243,107,0.05)" : "transparent"} />
              {SERIES.map((s) => {
                const v = d[s.key];
                if (!v) return null;
                const y0 = y(acc), y1 = y(acc + v);
                acc += v;
                return <rect key={s.key} x={x} y={y1} width={bw * 0.68} height={Math.max(1, y0 - y1 - 1)} fill={s.color} />;
              })}
              {i % 2 === 0 || data.length < 8 ? <text x={x + bw * 0.34} y={H - 7} textAnchor="middle" fontSize={9} fill="#5d6c61" fontFamily="IBM Plex Mono">{d.date.slice(5)}</text> : null}
            </g>
          );
        })}
        {hover !== null && (() => {
          const d = data[hover];
          const rows = SERIES.filter((s) => d[s.key] > 0);
          const bx = Math.min(w - 150, Math.max(padL, padL + hover * bw - 50));
          return (
            <g pointerEvents="none">
              <rect x={bx} y={padT} width={142} height={18 + Math.max(1, rows.length) * 13} fill="#0B0F0D" stroke="#34443a" />
              <text x={bx + 8} y={padT + 13} fontSize={10} fill="#E5ECE5" fontFamily="IBM Plex Mono">{d.date}</text>
              {rows.length === 0 && <text x={bx + 8} y={padT + 26} fontSize={9.5} fill="#849487" fontFamily="IBM Plex Mono">no events</text>}
              {rows.map((s, j) => <text key={s.key} x={bx + 8} y={padT + 26 + j * 13} fontSize={9.5} fill={s.color} fontFamily="IBM Plex Mono">{s.label} {d[s.key]}</text>)}
            </g>
          );
        })()}
        {!any && <text x={w / 2} y={H / 2 - 4} textAnchor="middle" fontSize={10.5} fill="#849487" fontFamily="IBM Plex Mono" letterSpacing={1.5}>NO EVENTS RECORDED IN THE LAST 14 DAYS</text>}
      </svg>
      <ul className="mono mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] tracking-[0.1em] text-mute">
        {SERIES.map((s) => <li key={s.key} className="flex items-center gap-1.5"><span className="inline-block h-2 w-2" style={{ background: s.color }} />{s.label}</li>)}
      </ul>
    </div>
  );
}
