import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import { LocateFixed } from "lucide-react";
import { Overview } from "../api";
import { useApp } from "../state";
import { Badge, Button } from "../ui";

const SEV_COLOR: Record<string, string> = { critical: "#F06464", high: "#F06464", medium: "#D6A64F", low: "#E5ECE5", informational: "#B7F36B", unknown: "#849487" };
const DEFAULT_VIEW: [number, number] = [4.2, 108]; // regional default (South-East Asia); not a claim about any activity

/** Real Leaflet map. Markers appear only for stored indicators that have provider-supplied coordinates. */
export default function MapPanel({ points }: { points: Overview["geo"] }) {
  const { config } = useApp();
  const el = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerRef = useRef<L.LayerGroup | null>(null);
  const [coord, setCoord] = useState<string>("—");
  const [tileErrors, setTileErrors] = useState(0);
  const [tilesOk, setTilesOk] = useState(false);

  useEffect(() => {
    if (!el.current || !config) return;
    const map = L.map(el.current, { center: DEFAULT_VIEW, zoom: 4, minZoom: 2, maxZoom: 12, worldCopyJump: true, zoomControl: false, attributionControl: true });
    L.control.zoom({ position: "bottomright" }).addTo(map);
    const tiles = L.tileLayer(config.map.tile_url, { attribution: config.map.attribution, subdomains: "abc", maxZoom: 12, crossOrigin: true });
    tiles.on("tileerror", () => setTileErrors((n) => n + 1));
    tiles.on("tileload", () => { setTilesOk(true); setTileErrors(0); });
    tiles.addTo(map);
    layerRef.current = L.layerGroup().addTo(map);
    map.on("mousemove", (e) => setCoord(`${e.latlng.lat.toFixed(3)}°, ${e.latlng.lng.toFixed(3)}°`));
    map.on("mouseout", () => setCoord("—"));
    mapRef.current = map;
    const ro = new ResizeObserver(() => map.invalidateSize());
    ro.observe(el.current);
    window.setTimeout(() => map.invalidateSize(), 50);
    return () => { ro.disconnect(); map.remove(); mapRef.current = null; layerRef.current = null; };
  }, [config]);

  useEffect(() => {
    const layer = layerRef.current;
    const map = mapRef.current;
    if (!layer || !map) return;
    layer.clearLayers();
    points.forEach((p) => {
      L.circleMarker([p.lat, p.lon], { radius: 6, color: SEV_COLOR[p.severity] ?? "#849487", weight: 1.5, fillOpacity: 0.35 })
        .bindTooltip(`<b>${p.value}</b><br>${p.label ?? ""}<br>${p.severity.toUpperCase()} · ${p.confidence}`, { direction: "top" })
        .addTo(layer);
    });
    if (points.length) map.fitBounds(L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number])), { padding: [40, 40], maxZoom: 6 });
  }, [points]);

  const offline = tileErrors >= 3 && !tilesOk;
  return (
    <div className={`brackets bg-grid relative h-full min-h-[360px] border-0 ${config?.map.dark ? "" : "tiles-invert"}`}>
      <div ref={el} className="absolute inset-0" aria-label="Geospatial map" role="application" />
      <div className="mono pointer-events-none absolute left-3 top-3 z-[500] flex flex-col gap-1">
        <span className="bg-bg/90"><Badge tone="mute">GEOSPATIAL · {points.length} PLOTTED</Badge></span>
        {offline && <Badge tone="amber">BASEMAP UNAVAILABLE — NO TILE NETWORK</Badge>}
      </div>
      <div className="mono pointer-events-none absolute bottom-6 left-3 z-[500] border border-line2 bg-bg/85 px-2 py-1 text-[10px] tracking-[0.1em] text-mute">CURSOR {coord}</div>
      <div className="absolute right-3 top-3 z-[500]">
        <Button small aria-label="Reset map view" icon={<LocateFixed size={12} />} onClick={() => {
          const m = mapRef.current;
          if (!m) return;
          if (points.length) m.fitBounds(L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number])), { padding: [40, 40], maxZoom: 6 });
          else m.setView(DEFAULT_VIEW, 4);
        }}>Reset</Button>
      </div>
      {points.length === 0 && (
        <div className="pointer-events-none absolute inset-x-0 bottom-12 z-[500] flex justify-center px-4">
          <div className="max-w-md border border-line2 bg-bg/90 px-3 py-2 text-center text-[11.5px] text-mute">
            <span className="label !text-ink">NO GEOLOCATED INDICATORS</span><br />
            Pins appear only when an IP indicator is enriched by a configured geolocation provider (ipinfo). Nothing here is simulated.
          </div>
        </div>
      )}
    </div>
  );
}
