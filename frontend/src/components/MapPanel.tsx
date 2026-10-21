import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import { LocateFixed } from "lucide-react";
import { Overview } from "../api";
import { useApp } from "../state";
import { Badge, Button } from "../ui";

const SEV_COLOR: Record<string, string> = { critical: "#F06464", high: "#F06464", medium: "#D6A64F", low: "#E5ECE5", informational: "#B7F36B", unknown: "#849487" };
const DEFAULT_VIEW: [number, number] = [4.2, 108]; // regional default (South-East Asia); not a claim about any activity

/** Adds graticule lines (thin every 10°, stronger every 30°) so the vector basemap reads as a tactical grid. */
function graticule(map: L.Map): L.LayerGroup {
  const g = L.layerGroup();
  for (let lng = -180; lng <= 180; lng += 10) L.polyline([[-80, lng], [84, lng]], { color: "#34443a", weight: lng % 30 === 0 ? 0.9 : 0.4, opacity: lng % 30 === 0 ? 0.7 : 0.4, interactive: false }).addTo(g);
  for (let lat = -80; lat <= 80; lat += 10) L.polyline([[lat, -180], [lat, 180]], { color: "#34443a", weight: lat % 30 === 0 ? 0.9 : 0.4, opacity: lat % 30 === 0 ? 0.7 : 0.4, interactive: false }).addTo(g);
  return g.addTo(map);
}

/** Real Leaflet map. Default basemap is bundled vector data (no tiles, no third-party requests, works offline).
 *  Pins appear only for stored indicators that have provider-supplied coordinates. */
export default function MapPanel({ points }: { points: Overview["geo"] }) {
  const { config } = useApp();
  const el = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerRef = useRef<L.LayerGroup | null>(null);
  const [coord, setCoord] = useState<string>("—");
  const [country, setCountry] = useState<string | null>(null);
  const [tileErrors, setTileErrors] = useState(0);
  const [tilesOk, setTilesOk] = useState(false);
  const [vectorReady, setVectorReady] = useState(false);
  const raster = !!config?.map.tile_url;

  useEffect(() => {
    if (!el.current || !config) return;
    const map = L.map(el.current, { center: DEFAULT_VIEW, zoom: 3.5, minZoom: 2, maxZoom: 10, worldCopyJump: true, zoomControl: false, attributionControl: true, preferCanvas: true, zoomSnap: 0.5 });
    L.control.zoom({ position: "bottomright" }).addTo(map);
    map.attributionControl.setPrefix(false);
    let cancelled = false;
    if (config.map.tile_url) {
      const tiles = L.tileLayer(config.map.tile_url, { attribution: config.map.attribution, subdomains: "abc", maxZoom: 12, crossOrigin: true, referrerPolicy: "origin" });
      tiles.on("tileerror", () => setTileErrors((n) => n + 1));
      tiles.on("tileload", () => { setTilesOk(true); setTileErrors(0); });
      tiles.addTo(map);
    } else {
      map.attributionControl.addAttribution(config.map.attribution);
      void Promise.all([import("topojson-client"), import("world-atlas/countries-110m.json")]).then(([topo, world]) => {
        if (cancelled || !mapRef.current) return;
        const w = (world as { default?: unknown }).default ?? world;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fc = topo.feature(w as any, (w as any).objects.countries) as unknown as GeoJSON.FeatureCollection;
        fc.features = fc.features.filter((f) => (f.properties as { name?: string })?.name !== "Antarctica");
        graticule(map);
        L.geoJSON(fc, {
          style: { color: "#3b4e41", weight: 0.7, fillColor: "#18231c", fillOpacity: 1 },
          onEachFeature: (f, layer) => {
            const name = (f.properties as { name?: string })?.name ?? "";
            layer.on("mouseover", () => { (layer as L.Path).setStyle({ fillColor: "#22321f", color: "#B7F36B", weight: 1 }); setCountry(name); });
            layer.on("mouseout", () => { (layer as L.Path).setStyle({ fillColor: "#18231c", color: "#3b4e41", weight: 0.7 }); setCountry(null); });
          },
        }).addTo(map);
        setVectorReady(true);
      });
    }
    layerRef.current = L.layerGroup().addTo(map);
    map.on("mousemove", (e) => setCoord(`${e.latlng.lat.toFixed(3)}°, ${((((e.latlng.lng + 180) % 360) + 360) % 360 - 180).toFixed(3)}°`));
    map.on("mouseout", () => setCoord("—"));
    mapRef.current = map;
    const ro = new ResizeObserver(() => map.invalidateSize());
    ro.observe(el.current);
    window.setTimeout(() => map.invalidateSize(), 50);
    return () => { cancelled = true; ro.disconnect(); map.remove(); mapRef.current = null; layerRef.current = null; };
  }, [config]);

  useEffect(() => {
    const layer = layerRef.current;
    const map = mapRef.current;
    if (!layer || !map) return;
    layer.clearLayers();
    points.forEach((p) => {
      const color = SEV_COLOR[p.severity] ?? "#849487";
      const icon = L.divIcon({ className: "geo-pin", html: `<span class="geo-ring" style="--c:${color}"></span><span class="geo-dot" style="--c:${color}"></span>`, iconSize: [18, 18], iconAnchor: [9, 9] });
      L.marker([p.lat, p.lon], { icon, keyboard: true, title: p.value })
        .bindTooltip(`<b>${p.value}</b><br>${p.label ?? ""}<br>${p.severity.toUpperCase()} · ${p.confidence}`, { direction: "top" })
        .addTo(layer);
    });
    if (points.length) map.fitBounds(L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number])), { padding: [40, 40], maxZoom: 6 });
  }, [points, vectorReady]);

  const offline = raster && tileErrors >= 3 && !tilesOk;
  return (
    <div className={`brackets bg-grid relative h-full min-h-[360px] border-0 ${raster && !config?.map.dark ? "tiles-invert" : ""}`}>
      <div ref={el} className="absolute inset-0" aria-label="Geospatial map" role="application" />
      <div className="mono pointer-events-none absolute left-3 top-3 z-[500] flex flex-col gap-1">
        <span className="bg-bg/90"><Badge tone="mute">GEOSPATIAL · {points.length} PLOTTED</Badge></span>
        <span className="bg-bg/90"><Badge tone="mute">{raster ? "RASTER TILES (CONFIGURED)" : "BASEMAP · BUNDLED VECTOR · OFFLINE-CAPABLE"}</Badge></span>
        {offline && <Badge tone="amber">TILE PROVIDER UNREACHABLE OR BLOCKED</Badge>}
      </div>
      <div className="mono pointer-events-none absolute bottom-6 left-3 z-[500] flex flex-col gap-1">
        {country && <div className="border border-lime/40 bg-bg/90 px-2 py-1 text-[10px] tracking-[0.1em] text-lime">{country.toUpperCase()}</div>}
        <div className="border border-line2 bg-bg/85 px-2 py-1 text-[10px] tracking-[0.1em] text-mute">CURSOR {coord}</div>
      </div>
      <div className="absolute right-3 top-3 z-[500]">
        <Button small aria-label="Reset map view" icon={<LocateFixed size={12} />} onClick={() => {
          const m = mapRef.current;
          if (!m) return;
          if (points.length) m.fitBounds(L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number])), { padding: [40, 40], maxZoom: 6 });
          else m.setView(DEFAULT_VIEW, 3.5);
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
