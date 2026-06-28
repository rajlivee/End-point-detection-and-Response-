/**
 * dashboard/static/js/map.js
 * Leaflet.js GeoIP world map — dark tile, flagged connections as markers.
 */

let leafletMap = null;
const mapMarkers = {};   // ip → marker

function initMap() {
  const el = document.getElementById("geo-map");
  if (!el || leafletMap) return;

  leafletMap = L.map("geo-map", {
    center:          [20, 0],
    zoom:            2,
    zoomControl:     true,
    attributionControl: false,
  });

  // Dark tile layer (CartoDB Dark)
  L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {
      subdomains: "abcd",
      maxZoom:    19,
    }
  ).addTo(leafletMap);

  // Subtle attribution
  L.control.attribution({ prefix: false })
    .addAttribution("© CartoDB")
    .addTo(leafletMap);

  // Load existing flagged connections from API
  _loadExistingConnections();
}

async function _loadExistingConnections() {
  try {
    const res  = await fetch("/api/network");
    const data = await res.json();
    data.filter(c => c.flagged && c.lat && c.lng)
        .forEach(c => addMapMarker(c));
  } catch (_) {}
}

/**
 * Add or refresh a marker for a network connection.
 * @param {Object} conn — { ip, lat, lng, country, city, process_name, flagged }
 */
function addMapMarker(conn) {
  if (!leafletMap || !conn.lat || !conn.lng) return;

  const key  = conn.ip || conn.remote_ip || `${conn.lat},${conn.lng}`;
  const isBad = conn.flagged;

  // Custom pulsing marker
  const color = isBad ? "#ef4444" : "#10b981";
  const icon  = L.divIcon({
    className: "",
    html: `
      <div style="
        width:14px;height:14px;border-radius:50%;
        background:${color};
        box-shadow:0 0 0 4px ${color}44, 0 0 12px ${color}88;
        animation: mapPulse 2s infinite;">
      </div>`,
    iconSize:   [14, 14],
    iconAnchor: [7, 7],
  });

  const label = `
    <div style="font-family:Inter,sans-serif;font-size:12px;color:#f1f5f9;min-width:160px">
      <strong style="color:${color}">${conn.ip || conn.remote_ip || "?"}</strong><br>
      ${conn.country || "Unknown"} ${conn.city ? "· " + conn.city : ""}<br>
      <span style="color:#94a3b8">Process: ${conn.process_name || "?"}</span>
      ${isBad ? '<br><span style="color:#ef4444">⚠ Blacklisted IP</span>' : ""}
    </div>`;

  if (mapMarkers[key]) {
    mapMarkers[key].setIcon(icon).setPopupContent(label);
  } else {
    mapMarkers[key] = L.marker([conn.lat, conn.lng], { icon })
      .bindPopup(label, { className: "map-popup", maxWidth: 220 })
      .addTo(leafletMap);
  }
}

// Inject the pulse keyframe into the document once
(function injectPulseStyle() {
  if (document.getElementById("map-pulse-style")) return;
  const style = document.createElement("style");
  style.id    = "map-pulse-style";
  style.textContent = `
    @keyframes mapPulse {
      0%,100% { box-shadow: 0 0 0 2px transparent, 0 0 8px currentColor; }
      50%      { box-shadow: 0 0 0 8px transparent, 0 0 16px currentColor; }
    }
    .map-popup .leaflet-popup-content-wrapper {
      background: rgba(10,15,30,0.95);
      border: 1px solid rgba(51,65,85,0.6);
      border-radius: 8px;
      padding: 0;
    }
    .map-popup .leaflet-popup-content { margin: 10px 14px; }
    .map-popup .leaflet-popup-tip     { background: rgba(10,15,30,0.95); }
  `;
  document.head.appendChild(style);
})();

document.addEventListener("DOMContentLoaded", initMap);
