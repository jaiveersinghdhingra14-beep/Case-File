#!/usr/bin/env python3
"""
Generate an Interactive HTML Attack Graph from NetworkX for browser inspection.

Usage:
    python scripts/generate_graph_html.py ds_812ee6b0
    python scripts/generate_graph_html.py
"""
import argparse
import json
from pathlib import Path
import sys
import webbrowser

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.services.correlator import (
    build_attack_graph,
    correlate_incident_paths,
    export_graph_to_vis_json,
)
from backend.app.services.expander import expand_neighborhood
from backend.app.services.reducer import get_top_k_seeds
from backend.app.store import db


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CaseFile v2 - Interactive Attack Graph Visualization</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; overflow: hidden; height: 100vh; display: flex; flex-direction: column; }
    header { background: #1e293b; border-bottom: 1px solid #334155; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
    h1 { font-size: 18px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
    .badge { background: #0284c7; color: #fff; font-size: 11px; padding: 3px 8px; border-radius: 9999px; font-weight: 600; text-transform: uppercase; }
    .controls { display: flex; gap: 16px; align-items: center; }
    .legend { display: flex; gap: 14px; font-size: 12px; }
    .legend-item { display: flex; align-items: center; gap: 6px; }
    .dot { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
    .main { display: flex; flex: 1; position: relative; height: calc(100vh - 57px); }
    #network { flex: 1; height: 100%; background: radial-gradient(circle, #1e293b 0%, #0f172a 100%); }
    .drawer { width: 380px; background: #1e293b; border-left: 1px solid #334155; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 16px; }
    .card { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 14px; }
    .card h3 { font-size: 13px; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px; }
    .card p { font-size: 14px; color: #e2e8f0; line-height: 1.4; word-break: break-all; }
    .tag { display: inline-block; background: #ef4444; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; margin-right: 6px; }
    .metric { font-size: 24px; font-weight: 700; color: #38bdf8; }
    .search-box { background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 6px 12px; border-radius: 6px; font-size: 13px; width: 220px; }
  </style>
</head>
<body>
  <header>
    <h1>CaseFile v2 <span class="badge">Big-Log Graph Explorer</span></h1>
    <div class="legend">
      <div class="legend-item"><span class="dot" style="background:#ef4444"></span> Compromised Host</div>
      <div class="legend-item"><span class="dot" style="background:#a855f7"></span> External C2 / Adversary</div>
      <div class="legend-item"><span class="dot" style="background:#f97316"></span> Lateral Target</div>
      <div class="legend-item"><span class="dot" style="background:#22c55e"></span> Critical Asset</div>
    </div>
    <div class="controls">
      <input type="text" id="search" class="search-box" placeholder="Search IP / Host...">
      <button onclick="network.fit({animation: true})" style="background:#334155; color:#fff; border:none; padding:6px 12px; border-radius:6px; cursor:pointer;">Reset View</button>
    </div>
  </header>
  <div class="main">
    <div id="network"></div>
    <div class="drawer">
      <div class="card">
        <h3>Campaign Summary</h3>
        <p class="metric" id="incident-risk">RISK: 95.0 / 100</p>
        <p id="incident-title" style="margin-top:6px; font-weight:600;">Multi-Host Attack Campaign</p>
      </div>

      <div class="card">
        <h3>Inspection Details</h3>
        <p id="details-text">Click any node or connection arrow in the graph to inspect evidence, timestamp, MITRE technique, and raw telemetry.</p>
      </div>

      <div class="card">
        <h3>Blast Radius (PRD FR-6)</h3>
        <p id="blast-text">Compromised endpoints detected. Host isolation and perimeter egress blocking rules recommended.</p>
      </div>
    </div>
  </div>

  <script>
    const graphData = GRAPH_DATA_PLACEHOLDER;
    const container = document.getElementById("network");
    const data = {
      nodes: new vis.DataSet(graphData.nodes),
      edges: new vis.DataSet(graphData.edges)
    };

    const options = {
      nodes: {
        borderWidth: 2,
        shadow: true,
        font: { color: "#ffffff", size: 14 }
      },
      edges: {
        width: 2,
        shadow: true,
        arrows: { to: { enabled: true, scaleFactor: 1.2 } },
        color: { color: "#64748b", highlight: "#38bdf8" }
      },
      physics: {
        solver: "forceAtlas2Based",
        forceAtlas2Based: {
          gravitationalConstant: -70,
          centralGravity: 0.015,
          springLength: 140,
          springConstant: 0.08
        },
        stabilization: { iterations: 150 }
      },
      interaction: { hover: true, tooltipDelay: 100 }
    };

    const network = new vis.Network(container, data, options);

    network.on("selectNode", function(params) {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = data.nodes.get(nodeId);
        document.getElementById("details-text").innerHTML = `
          <strong>Node:</strong> ${node.id}<br>
          <strong>Label:</strong> ${node.label}<br>
          <strong>Shape:</strong> ${node.shape}<br>
          <span style="display:inline-block; margin-top:8px; padding:4px 8px; background:#0284c7; border-radius:4px; font-size:12px;">Active Graph Entity</span>
        `;
      }
    });

    network.on("selectEdge", function(params) {
      if (params.edges.length > 0) {
        const edgeId = params.edges[0];
        const edge = data.edges.get(edgeId);
        document.getElementById("details-text").innerHTML = `
          <strong>Connection:</strong> ${edge.from} &rarr; ${edge.to}<br>
          <strong>Technique:</strong> <span class="tag">${edge.label}</span><br>
          <pre style="margin-top:8px; font-size:11px; background:#020617; padding:8px; border-radius:4px; white-space:pre-wrap;">${edge.title || 'Telemetry Edge'}</pre>
        `;
      }
    });

    document.getElementById("search").addEventListener("input", function(e) {
      const term = e.target.value.toLowerCase().trim();
      if (!term) return;
      const found = data.nodes.get({
        filter: function(item) {
          return item.id.toLowerCase().includes(term) || item.label.toLowerCase().includes(term);
        }
      });
      if (found.length > 0) {
        network.focus(found[0].id, { scale: 1.2, animation: true });
      }
    });
  </script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate interactive HTML attack graph.")
    parser.add_argument("dataset_id", nargs="?", default="", help="Dataset ID (e.g. ds_812ee6b0). Picks latest ready if omitted.")
    parser.add_argument("--top-k", type=int, default=25, help="Number of seeds (default: 25)")
    parser.add_argument("--open", action="store_true", default=True, help="Automatically open generated HTML in browser")
    args = parser.parse_args()

    db.init_db()
    ds_id = args.dataset_id
    if not ds_id:
        ready = [d for d in db.list_datasets() if d.status == "ready"]
        if not ready:
            print("[ERROR] No ready datasets found.", file=sys.stderr)
            sys.exit(1)
        ds_id = ready[-1].dataset_id

    print("=" * 70)
    print("   CaseFile v2 - Generating Interactive Attack Graph Visualization")
    print("=" * 70)
    print(f"Dataset ID : {ds_id}")

    # 1. Run Reducer & Expander
    print("[1/3] Extracting Top-K seeds and expanding graph neighborhood...")
    seeds = get_top_k_seeds(ds_id, top_k=args.top_k, min_rarity_score=0.1)
    expanded = expand_neighborhood(ds_id, seeds, window_seconds=180, max_expanded_events=2000)

    # 2. Build NetworkX Attack Graph
    print(f"[2/3] Building NetworkX directed graph over {len(expanded)} candidate events...")
    G = build_attack_graph(expanded)
    incidents = correlate_incident_paths(ds_id, expanded)
    vis_data = export_graph_to_vis_json(G)

    print(f"  Nodes in Graph : {len(vis_data['nodes'])}")
    print(f"  Edges in Graph : {len(vis_data['edges'])}")
    print(f"  Campaigns Found: {len(incidents)}")

    # 3. Output HTML
    frontend_dir = BASE_DIR / "frontend"
    frontend_dir.mkdir(parents=True, exist_ok=True)
    out_html_path = frontend_dir / "attack_graph.html"

    rendered_html = HTML_TEMPLATE.replace("GRAPH_DATA_PLACEHOLDER", json.dumps(vis_data))
    if incidents:
        top_inc = incidents[0]
        rendered_html = rendered_html.replace("RISK: 95.0 / 100", f"RISK: {top_inc.risk_score} / 100")
        rendered_html = rendered_html.replace("Multi-Host Attack Campaign", top_inc.title)

    out_html_path.write_text(rendered_html, encoding="utf-8")
    print(f"[3/3] Interactive Attack Graph generated at:\n  --> {out_html_path.resolve()}")

    if args.open:
        print("\nOpening attack graph in your default browser...")
        webbrowser.open(str(out_html_path.resolve().as_uri()))

    print("\n" + "=" * 70)
    print("Graph visualization ready!")


if __name__ == "__main__":
    main()
