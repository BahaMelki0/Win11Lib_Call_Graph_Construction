"""Dash application offering a smooth single-page call graph explorer."""

from __future__ import annotations

import difflib
import json
import math
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import dash
import dash_cytoscape as cyto
import igraph as ig
import networkx as nx
from dash import Dash, Input, Output, State, dcc, html

from call_graph_win11.analysis.graph_loader import load_call_graph, load_generic_graph, to_igraph

PALETTE = [
    "#38bdf8",
    "#a855f7",
    "#ec4899",
    "#f97316",
    "#22d3ee",
    "#4ade80",
    "#facc15",
    "#fb7185",
]

LAYOUT_PRESETS = {
    "cose": {"name": "cose", "idealEdgeLength": 120, "nodeRepulsion": 4200},
    "concentric": {"name": "concentric", "padding": 25},
    "breadthfirst": {"name": "breadthfirst", "directed": True, "spacingFactor": 1.1, "padding": 25},
}

MODES = {"raw", "syscall", "unified", "auto"}
PERF_NODE_THRESHOLD = 1000


def _normalize_mode(mode: str | None) -> str:
    if not mode:
        return "unknown"
    lowered = mode.lower()
    if lowered in {"syscall_projection", "syscall-projection"}:
        return "syscall"
    return lowered


def _list_graph_files(base_dir: Path, excluded: set[Path] | None = None) -> List[Path]:
    base_dir = base_dir.expanduser().resolve()
    results: List[Path] = []
    excluded_resolved = {path.resolve() for path in excluded} if excluded else set()
    patterns = ("*.callgraph.json", "*.syscall.json", "*.syscall_projection.json")
    seen: set[Path] = set()
    for pattern in patterns:
        for path in base_dir.rglob(pattern):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in excluded_resolved or resolved in seen:
                continue
            seen.add(resolved)
            results.append(resolved)
    return sorted(results)


def _infer_mode_raw_from_payload(payload: dict) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    mode = payload.get("mode")
    if isinstance(mode, str) and mode:
        return mode.lower()
    if "schema_version" in payload and "layers" in payload:
        return "unified"
    if "functions" in payload and "edges" in payload:
        return "raw"
    if "nodes" in payload and "edges" in payload:
        return "syscall"
    return "unknown"


def _infer_mode_from_payload(payload: dict) -> str:
    return _normalize_mode(_infer_mode_raw_from_payload(payload))


def _infer_mode_from_file(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return "unknown"
    return _infer_mode_from_payload(payload)


def _infer_mode_raw_from_file(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return "unknown"
    return _infer_mode_raw_from_payload(payload)


@lru_cache(maxsize=256)
def _load_graph_cached(path: str, mtime: float) -> Tuple["ig.Graph", nx.DiGraph]:
    path_obj = Path(path)
    with path_obj.open("r", encoding="utf-8") as handle:
        payload = handle.read(1024)
    if "\"functions\"" in payload:
        nx_graph = load_call_graph(path_obj)
    else:
        nx_graph = load_generic_graph(path_obj)
    ig_graph = to_igraph(nx_graph)
    return ig_graph, nx_graph


def _subset_graph(graph: "ig.Graph", limit: int | None) -> Tuple["ig.Graph", set[str]]:
    if limit is None or graph.vcount() <= limit:
        return graph, set(graph.vs["node_id"])

    programs = {}
    for idx, program in enumerate(graph.vs["program"]):
        programs.setdefault(program, []).append(idx)

    per_program_quota = max(1, math.ceil(limit / max(1, len(programs))))
    selected: list[int] = []
    for idxs in programs.values():
        ranked = sorted(idxs, key=lambda i: graph.degree(i), reverse=True)
        selected.extend(ranked[:per_program_quota])

    if len(selected) < limit:
        remaining = [i for i in range(graph.vcount()) if i not in selected]
        remaining_ranked = sorted(remaining, key=lambda i: graph.degree(i), reverse=True)
        selected.extend(remaining_ranked[: max(0, limit - len(selected))])

    selected = selected[:limit]
    subgraph = graph.subgraph(selected)
    if subgraph.vcount() == 0:
        return subgraph, set()

    components = subgraph.components(mode="WEAK")
    if len(components) <= 1:
        return subgraph, set(subgraph.vs["node_id"])

    largest_component = max(components, key=len)
    reduced = subgraph.subgraph(largest_component)
    return reduced, set(reduced.vs["node_id"])


def _program_colors(programs: Iterable[str]) -> Dict[str, str]:
    colors: Dict[str, str] = {}
    palette_len = len(PALETTE)
    for idx, program in enumerate(sorted(programs)):
        colors[program] = PALETTE[idx % palette_len]
    colors.setdefault("unknown", "#94a3b8")
    return colors


def _vertex_attr(vertex: "ig.Vertex", attr: str, default=None):
    try:
        return vertex[attr]
    except KeyError:
        return default


def _edge_attr(edge: "ig.Edge", attr: str, default=None):
    try:
        return edge[attr]
    except KeyError:
        return default


def _legend_family(program: str) -> str:
    name = (program or "").lower()
    if name.startswith("api-ms-"):
        return "api-ms"
    if name.startswith("ext-ms-"):
        return "ext-ms"
    if name in {"ntdll", "ntdll.dll"}:
        return "ntdll"
    if name == "syscall":
        return "syscall"
    if name == "unknown":
        return "unknown"
    return "system32"


def _create_elements(
    graph: "ig.Graph",
    colors: Dict[str, str],
    highlight_nodes: Iterable[str],
    highlight_edges: Iterable[Tuple[str, str]],
    size_map: Optional[Dict[str, float]] = None,
    focus_nodes: Optional[set[str]] = None,
    prefix_program: bool = False,
    edge_kind_filter: Optional[set[str]] = None,
    perf_mode: bool = False,
) -> Tuple[List[dict], List[dict]]:
    nodes: List[dict] = []
    edges: List[dict] = []
    highlight_node_set = set(highlight_nodes)
    highlight_edge_set = set(highlight_edges)
    size_lookup = size_map or {}
    focus_nodes = focus_nodes or set()
    show_labels = not perf_mode

    hub_cutoff: Optional[float] = None
    if size_lookup:
        sorted_sizes = sorted(size_lookup.values())
        if sorted_sizes:
            cutoff_index = max(0, int(len(sorted_sizes) * 0.85) - 1)
            hub_cutoff = sorted_sizes[cutoff_index]

    for vertex in graph.vs:
        node_id = vertex["node_id"]
        program = _vertex_attr(vertex, "program", "unknown")
        label = (
            _vertex_attr(vertex, "name")
            or _vertex_attr(vertex, "qualified_name")
            or _vertex_attr(vertex, "address")
            or node_id
        )
        if label and len(label) > 48:
            label = label[:45] + "..."
        if prefix_program and program:
            label = f"{program}:{label}"
        size_value = size_lookup.get(node_id, 22.0)
        is_hub = hub_cutoff is not None and size_value >= hub_cutoff
        nodes.append({
            "data": {
                "id": node_id,
                "label": label,
                "program": program,
                "address": _vertex_attr(vertex, "address"),
                "qualified_name": _vertex_attr(vertex, "qualified_name"),
                "source": _vertex_attr(vertex, "source"),
                "layer": _vertex_attr(vertex, "layer"),
                "calling_convention": _vertex_attr(vertex, "calling_convention"),
                "is_external": bool(_vertex_attr(vertex, "is_external")),
                "color": colors.get(program, colors["unknown"]),
                "path_highlight": node_id in highlight_node_set,
                "path_focus": node_id in focus_nodes,
                "size": size_value,
                "hub": is_hub,
                "degree": vertex.degree(),
                "show_label": show_labels,
            }
        })

    for idx, (source_idx, target_idx) in enumerate(graph.get_edgelist()):
        source_id = graph.vs[source_idx]["node_id"]
        target_id = graph.vs[target_idx]["node_id"]
        edge = graph.es[idx]
        kind_value = _edge_attr(edge, "kind") or "unknown"
        if edge_kind_filter and kind_value not in edge_kind_filter:
            continue
        edges.append({
            "data": {
                "id": f"main-edge-{idx}",
                "source": source_id,
                "target": target_id,
                "path_highlight": (source_id, target_id) in highlight_edge_set,
                "kind": kind_value,
                "min_hops": _edge_attr(edge, "min_hops"),
                "site": _edge_attr(edge, "site"),
                "perf": perf_mode,
            }
        })

    return nodes, edges


def _filter_graph(graph: "ig.Graph", filters: Iterable[str]) -> Tuple["ig.Graph", set[str]]:
    if not filters:
        return graph, set(graph.vs["node_id"])

    nodes_to_keep = set(graph.vs["node_id"])

    if "external" in filters:
        external_nodes = {
            vertex["node_id"] for vertex in graph.vs if _vertex_attr(vertex, "is_external")
        }
        nodes_to_keep &= external_nodes

    if "apis_only" in filters:
        api_nodes = set()
        for vertex in graph.vs:
            source = _vertex_attr(vertex, "source", "").upper()
            layer = _vertex_attr(vertex, "layer", "").lower()
            if source in {"EXPORTED", "IMPORTED"}:
                api_nodes.add(vertex["node_id"])
            elif _vertex_attr(vertex, "is_external"):
                api_nodes.add(vertex["node_id"])
            elif layer == "syscall":
                api_nodes.add(vertex["node_id"])
        nodes_to_keep &= api_nodes

    if not nodes_to_keep:
        return graph.subgraph([]), set()

    if nodes_to_keep == set(graph.vs["node_id"]):
        return graph, nodes_to_keep

    indices = [vertex.index for vertex in graph.vs if vertex["node_id"] in nodes_to_keep]
    subgraph = graph.subgraph(indices)
    return subgraph, set(subgraph.vs["node_id"])


def create_app(
    data_dir: Path,
    *,
    default_limit: int = 100,
    excluded_paths: set[Path] | None = None,
    mode: str = "auto",
) -> Dash:
    data_dir = data_dir.expanduser().resolve()
    graph_files = _list_graph_files(data_dir, excluded=excluded_paths)

    mode = _normalize_mode(mode or "auto")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    file_entries: list[tuple[Path, str, str]] = []
    for path in graph_files:
        raw_mode = _infer_mode_raw_from_file(path)
        inferred_mode = _normalize_mode(raw_mode)
        if mode != "auto" and inferred_mode not in {mode, "unknown"}:
            continue
        file_entries.append((path, raw_mode, inferred_mode))

    if not file_entries:
        raise FileNotFoundError(
            f"No *.callgraph.json files found under {data_dir} for mode '{mode}'"
        )

    graph_options = [
        {"label": str(path.relative_to(data_dir)), "value": str(path.resolve())}
        for path, _, _ in file_entries
    ]
    graph_index = [
        {
            "label": str(path.relative_to(data_dir)),
            "value": str(path.resolve()),
            "mode_raw": raw_mode,
            "mode_filter": "projection" if raw_mode == "syscall_projection" else inferred_mode,
        }
        for path, raw_mode, inferred_mode in file_entries
    ]

    external_stylesheets = [
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
    ]
    app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
    app.title = "Windows Call Graph Explorer"

    app.layout = html.Div([
        dcc.Store(id="graph-index", data=graph_index),
        dcc.Store(id="jump-target"),
        dcc.Store(id="jump-applied", data=0),

        # ── Sidebar ──────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.H1("Call Graph Explorer", className="title"),
                html.P("Ghidra-exported Windows system libraries", className="subtitle"),
                html.Div([
                    html.Span("mode", className="header-meta-label"),
                    html.Span(id="graph-mode-label", className="header-meta-value"),
                ], className="header-meta"),
            ], className="header"),

            html.Div([
                html.Label("Library"),
                dcc.Dropdown(
                    id="graph-file",
                    options=graph_options,
                    value=graph_options[0]["value"],
                    clearable=False,
                    className="dropdown-control",
                    style={"zIndex": 1100},
                ),
            ], className="control"),

            html.Div([
                html.Label("Graph mode"),
                dcc.Checklist(
                    id="mode-filter",
                    options=[
                        {"label": "Raw", "value": "raw"},
                        {"label": "Unified", "value": "unified"},
                        {"label": "Syscall", "value": "syscall"},
                        {"label": "Projection", "value": "projection"},
                    ],
                    value=["raw", "unified", "syscall", "projection"],
                    className="chip-group",
                    inputStyle={"marginRight": "0.3rem"},
                    labelStyle={"display": "inline-flex", "alignItems": "center"},
                ),
            ], className="control"),

            html.Div([
                html.Label("Max nodes"),
                dcc.Slider(
                    id="node-limit",
                    min=100, max=5000, step=None,
                    marks={100: "100", 300: "300", 1000: "1k", 2500: "2.5k", 5000: "5k"},
                    value=100,
                    tooltip={"placement": "bottom", "always_visible": True},
                ),
                html.Label("Custom cap", style={"marginTop": "0.5rem"}),
                dcc.Input(
                    id="node-limit-custom",
                    type="number", min=0, step=50,
                    placeholder="0 = all nodes",
                    debounce=True,
                    className="text-input",
                ),
            ], className="control"),

            html.Div([
                html.Label("Layout"),
                dcc.Dropdown(
                    id="layout-mode",
                    options=[
                        {"label": "Force-directed (cose)", "value": "cose"},
                        {"label": "Concentric", "value": "concentric"},
                        {"label": "Breadthfirst", "value": "breadthfirst"},
                    ],
                    value="cose",
                    clearable=False,
                    className="dropdown-control",
                    style={"zIndex": 1090},
                ),
            ], className="control"),

            html.Div([
                html.Label("Node size"),
                dcc.RadioItems(
                    id="node-size-mode",
                    options=[
                        {"label": "Fixed", "value": "fixed"},
                        {"label": "Degree scaled", "value": "degree"},
                    ],
                    value="fixed",
                    className="radio-control",
                    inputStyle={"marginRight": "0.3rem"},
                    labelStyle={"display": "inline-flex", "alignItems": "center", "marginRight": "0.8rem"},
                ),
            ], className="control"),

            html.Div([
                html.Label("Performance"),
                dcc.RadioItems(
                    id="perf-mode",
                    options=[
                        {"label": "Auto (≥1k nodes)", "value": "auto"},
                        {"label": "On", "value": "on"},
                        {"label": "Off", "value": "off"},
                    ],
                    value="auto",
                    className="radio-control",
                    inputStyle={"marginRight": "0.3rem"},
                    labelStyle={"display": "inline-flex", "alignItems": "center", "marginRight": "0.8rem"},
                ),
            ], className="control"),

            html.Div([
                html.Label("Filters"),
                dcc.Checklist(
                    id="filters",
                    options=[
                        {"label": "Exported/imported APIs only", "value": "apis_only"},
                        {"label": "External nodes only", "value": "external"},
                    ],
                    value=[],
                    className="checklist",
                ),
            ], className="control"),

            html.Div([
                html.Label("Edge kinds"),
                dcc.Checklist(
                    id="edge-kind-filter",
                    options=[
                        {"label": "direct", "value": "direct"},
                        {"label": "import", "value": "import"},
                        {"label": "forwarder", "value": "forwarder"},
                        {"label": "apiset", "value": "apiset"},
                        {"label": "reaches", "value": "reaches"},
                        {"label": "projection", "value": "projection"},
                        {"label": "syscall", "value": "syscall"},
                        {"label": "ref", "value": "ref"},
                        {"label": "unknown", "value": "unknown"},
                    ],
                    value=["direct","import","forwarder","apiset","reaches","projection","syscall","ref","unknown"],
                    className="chip-group",
                    inputStyle={"marginRight": "0.3rem"},
                    labelStyle={"display": "inline-flex", "alignItems": "center"},
                ),
            ], className="control"),

            # Graph info
            html.Div([
                html.H3("Graph info", className="section-title"),
                html.Div([
                    html.Button("⬇ PNG", id="export-png", className="ui-button"),
                    html.Button("⬇ SVG", id="export-svg", className="ui-button"),
                ], className="export-row"),
                html.Div(id="graph-summary", className="stats"),
                html.Div(id="program-legend", className="legend-container"),
            ], className="section"),

            # Hover details
            html.Div([
                html.H3("Hover details", className="section-title"),
                html.Div(id="hover-details", className="stats"),
            ], className="section"),

            # Search
            html.Div([
                html.Label("Search"),
                html.Div([
                    dcc.Input(
                        id="search-query",
                        type="text",
                        placeholder="Function name or address…",
                        debounce=True,
                        className="text-input",
                    ),
                    html.Button("Jump", id="search-jump", className="ui-button"),
                ], className="search-row"),
                html.Div(id="search-status", className="footnote"),
            ], className="control"),

            # Path inspector
            html.Div([
                html.H3("Path inspector", className="section-title"),
                html.Div([
                    html.Label("Inbound depth"),
                    dcc.Slider(
                        id="focus-depth",
                        min=1, max=6, step=None,
                        marks={1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6"},
                        value=3,
                        tooltip={"placement": "bottom", "always_visible": True},
                    ),
                ], className="control", style={"marginBottom": "0.5rem"}),
                dcc.Checklist(
                    id="pin-focus",
                    options=[{"label": " Pin focus node", "value": "pin"}],
                    value=[],
                    className="path-mode-toggle",
                    inputStyle={"marginRight": "0.3rem"},
                    labelStyle={"display": "inline-flex", "alignItems": "center"},
                ),
                html.Div([
                    dcc.Dropdown(
                        id="path-start",
                        placeholder="Start function",
                        className="dropdown-control",
                        style={"zIndex": 1080},
                    ),
                    dcc.Dropdown(
                        id="path-end",
                        placeholder="Focus function",
                        className="dropdown-control",
                        style={"zIndex": 1070},
                    ),
                    dcc.Checklist(
                        id="path-mode",
                        options=[{"label": " Path only", "value": "path-only"}],
                        value=[],
                        className="path-mode-toggle",
                        inputStyle={"marginRight": "0.3rem"},
                        labelStyle={"display": "inline-flex", "alignItems": "center"},
                    ),
                ], className="path-controls"),
                html.Div(id="path-info", className="path-info"),
                html.Div(id="focus-info", className="path-info"),
                html.Div(id="path-table", className="path-table"),
            ], className="section"),

        ], className="sidebar"),

        # ── Graph canvas ─────────────────────────────────────────────────
        html.Div([
            dcc.Loading(
                id="call-graph-loader",
                type="circle",
                color="#38bdf8",
                children=cyto.Cytoscape(
                    id="call-graph",
                    style={"width": "100%", "height": "100vh", "minHeight": "400px"},
                    layout=LAYOUT_PRESETS["cose"],
                    elements=[],
                    stylesheet=[
                        {
                            "selector": "node",
                            "style": {
                                "label": "data(label)",
                                "background-color": "data(color)",
                                "color": "#0b1224",
                                "text-wrap": "wrap",
                                "text-max-width": "200px",
                                "text-overflow": "ellipsis",
                                "text-background-color": "rgba(248,250,252,0.9)",
                                "text-background-opacity": 0.9,
                                "text-background-padding": "3px",
                                "text-background-shape": "roundrectangle",
                                "font-size": "11px",
                                "min-zoomed-font-size": "9px",
                                "text-outline-width": "0px",
                                "width": "data(size)",
                                "height": "data(size)",
                                "border-width": "1.5px",
                                "border-color": "rgba(248,250,252,0.5)",
                                "transition-property": "background-color, border-color, border-width, opacity",
                                "transition-duration": "200ms",
                            },
                        },
                        {
                            "selector": "node[show_label = false]",
                            "style": {"label": "", "text-opacity": 0, "text-background-opacity": 0},
                        },
                        {
                            "selector": "node[is_external = True]",
                            "style": {"shape": "triangle", "opacity": 0.88},
                        },
                        {
                            "selector": "node[hub = true]",
                            "style": {"border-width": 3, "border-color": "#38bdf8"},
                        },
                        {
                            "selector": "node:selected",
                            "style": {
                                "border-width": 4,
                                "border-color": "#facc15",
                                "overlay-color": "#facc15",
                                "overlay-padding": 4,
                                "overlay-opacity": 0.12,
                            },
                        },
                        {
                            "selector": "node[path_highlight = true]",
                            "style": {"background-color": "#f97316", "border-color": "#fde68a"},
                        },
                        {
                            "selector": "node[path_focus = true]",
                            "style": {
                                "border-width": 4,
                                "border-color": "#f97316",
                                "background-color": "#fde68a",
                                "color": "#0f172a",
                            },
                        },
                        {
                            "selector": "node.jump-flash",
                            "style": {
                                "border-width": 6,
                                "border-color": "#facc15",
                                "background-color": "#fde68a",
                                "overlay-color": "#facc15",
                                "overlay-opacity": 0.2,
                            },
                        },
                        {
                            "selector": "edge",
                            "style": {
                                "line-color": "#334155",
                                "width": 1,
                                "curve-style": "bezier",
                                "target-arrow-color": "#475569",
                                "target-arrow-shape": "triangle",
                                "arrow-scale": 0.8,
                                "opacity": 0.4,
                                "transition-property": "opacity, line-color",
                                "transition-duration": "200ms",
                            },
                        },
                        {
                            "selector": "edge[perf = true]",
                            "style": {
                                "line-color": "#1e293b",
                                "curve-style": "haystack",
                                "width": 0.5,
                                "opacity": 0.18,
                                "target-arrow-shape": "none",
                            },
                        },
                        {
                            "selector": "edge:selected",
                            "style": {
                                "line-color": "#facc15",
                                "target-arrow-color": "#facc15",
                                "width": 3,
                                "opacity": 1,
                            },
                        },
                        {
                            "selector": "edge[kind = 'reaches']",
                            "style": {"line-color": "#4ade80", "target-arrow-color": "#4ade80", "opacity": 0.55},
                        },
                        {
                            "selector": "edge[kind = 'import']",
                            "style": {
                                "line-color": "#60a5fa", "target-arrow-color": "#60a5fa",
                                "line-style": "dashed", "opacity": 0.55,
                            },
                        },
                        {
                            "selector": "edge[kind = 'apiset']",
                            "style": {
                                "line-color": "#a855f7", "target-arrow-color": "#a855f7",
                                "line-style": "dotted", "opacity": 0.6,
                            },
                        },
                        {
                            "selector": "edge[kind = 'forwarder']",
                            "style": {
                                "line-color": "#f97316", "target-arrow-color": "#f97316",
                                "line-style": "dashed", "opacity": 0.6,
                            },
                        },
                        {
                            "selector": "edge[kind = 'projection']",
                            "style": {"line-color": "#22d3ee", "target-arrow-color": "#22d3ee", "opacity": 0.7},
                        },
                        {
                            "selector": "edge[kind = 'syscall']",
                            "style": {"line-color": "#f43f5e", "target-arrow-color": "#f43f5e", "opacity": 0.75},
                        },
                        {
                            "selector": "edge[path_highlight = true]",
                            "style": {
                                "line-color": "#f97316", "target-arrow-color": "#facc15",
                                "width": 2.5, "opacity": 0.9,
                            },
                        },
                    ],
                ),
            ),
        ], className="graph-panel"),

    ], className="page")

    # ── Callbacks ─────────────────────────────────────────────────────────

    @app.callback(
        Output("graph-file", "options"),
        Output("graph-file", "value"),
        Input("graph-index", "data"),
        Input("mode-filter", "value"),
        State("graph-file", "value"),
    )
    def update_graph_options(
        graph_index_data: list[dict] | None,
        mode_filter: list[str] | None,
        current_value: str | None,
    ) -> tuple[list[dict], str | None]:
        entries = graph_index_data or []
        active_modes = set(mode_filter or [])
        if not active_modes:
            active_modes = {"raw", "unified", "syscall", "projection"}
        options = [
            {"label": entry["label"], "value": entry["value"]}
            for entry in entries
            if entry.get("mode_filter") in active_modes or entry.get("mode_filter") == "unknown"
        ]
        if not options:
            return [], None
        values = {opt["value"] for opt in options}
        selected = current_value if current_value in values else options[0]["value"]
        return options, selected

    @app.callback(
        Output("call-graph", "elements"),
        Output("call-graph", "layout"),
        Output("path-info", "children"),
        Output("focus-info", "children"),
        Output("path-table", "children"),
        Output("graph-summary", "children"),
        Output("program-legend", "children"),
        Output("path-start", "options"),
        Output("path-end", "options"),
        Output("path-start", "value"),
        Output("path-end", "value"),
        Output("call-graph", "hideEdgesOnViewport"),
        Output("call-graph", "textureOnViewport"),
        Output("call-graph", "pixelRatio"),
        Input("graph-file", "value"),
        Input("node-limit", "value"),
        Input("node-limit-custom", "value"),
        Input("filters", "value"),
        Input("edge-kind-filter", "value"),
        Input("layout-mode", "value"),
        Input("node-size-mode", "value"),
        Input("perf-mode", "value"),
        Input("focus-depth", "value"),
        Input("path-start", "value"),
        Input("path-end", "value"),
        Input("path-mode", "value"),
        Input("pin-focus", "value"),
        Input("jump-target", "data"),
    )
    def update_graph(
        path_value: str,
        node_limit: int,
        node_limit_custom: int | None,
        filters: List[str],
        edge_kind_filter: List[str],
        layout_mode: str,
        size_mode: str,
        perf_mode: str,
        focus_depth: int,
        start_node: str | None,
        end_node: str | None,
        path_mode: List[str],
        pin_focus: List[str],
        jump_target: dict | None,
    ) -> Tuple[List[dict], dict, str, str, html.Div, list, list, List[dict], List[dict], str | None, str | None, bool, bool, int | str]:
        path_obj = Path(path_value)
        try:
            mtime = path_obj.stat().st_mtime
        except OSError:
            mtime = 0.0
        ig_graph, nx_graph = _load_graph_cached(str(path_obj), mtime)

        limit_value = node_limit
        if node_limit_custom not in (None, "", " "):
            limit_value = node_limit_custom
        try:
            limit_value = int(limit_value)
        except (TypeError, ValueError):
            limit_value = node_limit
        if limit_value <= 0:
            node_limit = ig_graph.vcount()
        else:
            node_limit = max(1, min(limit_value, ig_graph.vcount()))

        filtered_graph, filtered_node_ids = _filter_graph(ig_graph, filters or [])
        subset_graph, subset_nodes = _subset_graph(filtered_graph, node_limit)

        rendered_programs = sorted({_vertex_attr(v, "program", "unknown") for v in subset_graph.vs})
        all_programs = sorted({_vertex_attr(v, "program", "unknown") for v in ig_graph.vs})
        colors = _program_colors(rendered_programs)

        total_nodes = subset_graph.vcount()
        degree_values = subset_graph.degree() if total_nodes else []
        size_mode = size_mode or "fixed"
        size_map: Optional[Dict[str, float]] = None
        if total_nodes:
            if size_mode == "degree":
                min_deg = min(degree_values)
                max_deg = max(degree_values)
                if max_deg == min_deg:
                    size_map = {v["node_id"]: 28.0 for v in subset_graph.vs}
                else:
                    size_map = {}
                    for vertex, degree in zip(subset_graph.vs, degree_values):
                        norm = (degree - min_deg) / (max_deg - min_deg)
                        size_map[vertex["node_id"]] = 18.0 + norm * 28.0
            else:
                size_map = {v["node_id"]: 22.0 for v in subset_graph.vs}

        highlight_nodes: set[str] = set()
        highlight_edges: set[Tuple[str, str]] = set()
        vertex_index = {v["node_id"]: v.index for v in subset_graph.vs}
        filtered_vertex_index = {v["node_id"]: v.index for v in filtered_graph.vs}

        triggered_id = dash.callback_context.triggered_id
        jump_node = None
        if triggered_id == "jump-target" and isinstance(jump_target, dict):
            jump_node = jump_target.get("node_id")
            if jump_node:
                end_node = jump_node

        if start_node and start_node not in subset_nodes:
            start_node = None
        pin_focus_enabled = bool(pin_focus and "pin" in pin_focus)
        if end_node and end_node not in subset_nodes:
            if not pin_focus_enabled and end_node != jump_node:
                end_node = None

        path_text = "Select a start and focus function to view shortest paths."
        focus_info = "Select a focus function to inspect inbound callers."
        path_table_children: html.Div = html.Div(
            "Select a focus function to list inbound paths.", className="path-table-empty"
        )
        path_only = bool(path_mode and "path-only" in path_mode)
        path_node_ids: List[str] = []
        edge_kind_filter_set = set(edge_kind_filter or [])

        weights: List[float] | None = None
        if "min_hops" in subset_graph.es.attribute_names():
            raw_weights = subset_graph.es["min_hops"]
            weights = []
            for value in raw_weights:
                try:
                    weight = float(value)
                except (TypeError, ValueError):
                    weight = 1.0
                if weight <= 0:
                    weight = 1.0
                weights.append(weight)

        def _path_hops(vertex_path: list[int]) -> float:
            if not vertex_path or len(vertex_path) == 1:
                return 0.0
            if not weights:
                return float(len(vertex_path) - 1)
            total = 0.0
            for src_idx, dst_idx in zip(vertex_path[:-1], vertex_path[1:]):
                try:
                    edge_id = subset_graph.get_eid(src_idx, dst_idx)
                except Exception:
                    edge_id = None
                total += 1.0 if edge_id is None else weights[edge_id]
            return total

        if start_node and end_node and start_node in vertex_index and end_node in vertex_index:
            highlight_nodes.add(start_node)
            highlight_nodes.add(end_node)
            shortest = subset_graph.get_shortest_paths(
                vertex_index[start_node], to=vertex_index[end_node], mode="OUT", weights=weights
            )
            if shortest and shortest[0]:
                vertex_path = shortest[0]
                path_node_ids = [subset_graph.vs[idx]["node_id"] for idx in vertex_path]
                for src_idx, dst_idx in zip(vertex_path[:-1], vertex_path[1:]):
                    highlight_edges.add((subset_graph.vs[src_idx]["node_id"], subset_graph.vs[dst_idx]["node_id"]))
                labels = [
                    _vertex_attr(subset_graph.vs[vid], "name")
                    or _vertex_attr(subset_graph.vs[vid], "qualified_name")
                    or _vertex_attr(subset_graph.vs[vid], "address")
                    or subset_graph.vs[vid]["node_id"]
                    for vid in vertex_path
                ]
                unweighted_hops = len(vertex_path) - 1
                weighted_hops = _path_hops(vertex_path)
                if weighted_hops.is_integer():
                    weighted_hops = int(weighted_hops)
                path_text = f"Shortest path: {unweighted_hops} hops (weighted {weighted_hops})."
                table = html.Table([
                    html.Thead(html.Tr([
                        html.Th("Source", className="path-header"),
                        html.Th("Hops", className="path-header"),
                        html.Th("Weighted", className="path-header"),
                        html.Th("Path", className="path-header"),
                    ])),
                    html.Tbody([html.Tr([
                        html.Td(labels[0], className="path-cell path-cell--source"),
                        html.Td(str(unweighted_hops), className="path-cell path-cell--hops"),
                        html.Td(str(weighted_hops), className="path-cell path-cell--hops"),
                        html.Td(" → ".join(labels[:8]), className="path-cell path-cell--path"),
                    ])]),
                ], className="path-table-grid")
                path_table_children = html.Div(table)
            else:
                path_text = "No path found between start and focus."
                path_table_children = html.Div("No shortest path found.", className="path-table-empty")
        else:
            focus_candidates: list[tuple[int, float]] = []
            if end_node and end_node in vertex_index:
                highlight_nodes.add(end_node)
                reverse_graph = subset_graph.copy()
                reverse_graph.reverse_edges()
                distances = reverse_graph.shortest_paths(vertex_index[end_node], mode="OUT", weights=weights)[0]
                focus_vertex_indices = [
                    idx for idx, dist in enumerate(distances)
                    if not math.isinf(dist) and dist <= focus_depth
                ]
                if focus_vertex_indices:
                    focus_subgraph = subset_graph.subgraph(focus_vertex_indices)
                    focus_node_ids = focus_subgraph.vs["node_id"]
                    highlight_nodes.update(focus_node_ids)
                    for src_idx, dst_idx in focus_subgraph.get_edgelist():
                        highlight_edges.add((focus_subgraph.vs[src_idx]["node_id"], focus_subgraph.vs[dst_idx]["node_id"]))
                    target_vertex = subset_graph.vs[vertex_index[end_node]]
                    target_label = (
                        _vertex_attr(target_vertex, "name")
                        or _vertex_attr(target_vertex, "qualified_name")
                        or _vertex_attr(target_vertex, "address")
                        or end_node
                    )
                    focus_info = f"{len(focus_node_ids)} functions within {focus_depth} hops of {target_label}."
                    focus_candidates = [
                        (idx, distances[idx])
                        for idx in focus_vertex_indices
                        if idx != vertex_index[end_node] and not math.isinf(distances[idx])
                    ]
                else:
                    focus_info = "Focus function is currently filtered out."
            elif end_node:
                focus_info = "Focus function is currently filtered out."

            path_rows: list[html.Tr] = []
            if focus_candidates:
                focus_candidates.sort(key=lambda item: (item[1], item[0]))
                for idx, dist in focus_candidates[:12]:
                    vpath = subset_graph.get_shortest_paths(
                        idx, to=vertex_index[end_node], mode="OUT", weights=weights
                    )
                    if not vpath or not vpath[0]:
                        continue
                    vertex_path = vpath[0]
                    labels = [
                        _vertex_attr(subset_graph.vs[vid], "name")
                        or _vertex_attr(subset_graph.vs[vid], "qualified_name")
                        or _vertex_attr(subset_graph.vs[vid], "address")
                        or subset_graph.vs[vid]["node_id"]
                        for vid in vertex_path
                    ]
                    unweighted_hops = len(vertex_path) - 1
                    weighted_hops = _path_hops(vertex_path)
                    if weighted_hops.is_integer():
                        weighted_hops = int(weighted_hops)
                    path_rows.append(html.Tr([
                        html.Td(labels[0], className="path-cell path-cell--source"),
                        html.Td(str(unweighted_hops), className="path-cell path-cell--hops"),
                        html.Td(str(weighted_hops), className="path-cell path-cell--hops"),
                        html.Td(" → ".join(labels[:8]), className="path-cell path-cell--path"),
                    ]))
                if path_rows:
                    table = html.Table([
                        html.Thead(html.Tr([
                            html.Th("Source", className="path-header"),
                            html.Th("Hops", className="path-header"),
                            html.Th("Weighted", className="path-header"),
                            html.Th("Path", className="path-header"),
                        ])),
                        html.Tbody(path_rows),
                    ], className="path-table-grid")
                    path_table_children = html.Div(table)
                else:
                    path_table_children = html.Div("No paths found.", className="path-table-empty")
            elif end_node:
                path_table_children = html.Div("No paths found.", className="path-table-empty")

        if end_node and not start_node:
            path_text = "Select a start function to compute a path."

        pinned_nodes: set[str] = set()
        if pin_focus_enabled and end_node:
            pinned_nodes.add(end_node)
        if jump_node and isinstance(jump_node, str):
            pinned_nodes.add(jump_node)
        if pin_focus_enabled and end_node and end_node not in subset_nodes:
            focus_info = "Pinned focus node is outside the current node cap."

        legend_programs = list(rendered_programs)
        if pinned_nodes:
            pinned_programs = {
                _vertex_attr(filtered_graph.vs[filtered_vertex_index[nid]], "program", "unknown")
                for nid in pinned_nodes
                if nid in filtered_vertex_index
            }
            colors = _program_colors(set(rendered_programs) | pinned_programs)
            legend_programs = sorted(set(rendered_programs) | pinned_programs)

        render_nodes: set[str] = set(subset_nodes) if subset_nodes else {v["node_id"] for v in subset_graph.vs}
        render_nodes.update(path_node_ids)
        render_nodes.update(pinned_nodes)
        render_indices = [filtered_vertex_index[n] for n in render_nodes if n in filtered_vertex_index]
        graph_for_render = filtered_graph.subgraph(render_indices) if render_indices else filtered_graph.subgraph([])

        if path_node_ids:
            highlight_nodes.update(path_node_ids)
            highlight_edges.update((path_node_ids[i], path_node_ids[i + 1]) for i in range(len(path_node_ids) - 1))
        if pinned_nodes:
            highlight_nodes.update(pinned_nodes)

        focus_nodes_set = set(path_node_ids)

        if path_only and path_node_ids:
            indices = [filtered_vertex_index[n] for n in path_node_ids if n in filtered_vertex_index]
            graph_for_render = filtered_graph.subgraph(indices) if indices else filtered_graph.subgraph([])

        perf_mode_value = (perf_mode or "auto").lower()
        render_node_count = graph_for_render.vcount()
        perf_active = perf_mode_value == "on" or (
            perf_mode_value == "auto" and render_node_count >= PERF_NODE_THRESHOLD
        )

        nodes, edges = _create_elements(
            graph_for_render, colors, highlight_nodes, highlight_edges,
            size_map=size_map, focus_nodes=focus_nodes_set,
            prefix_program=True, edge_kind_filter=edge_kind_filter_set,
            perf_mode=perf_active,
        )

        filtered_node_ids_sorted = sorted(set(subset_nodes) | pinned_nodes)
        options = []
        prefix_dropdown = len(rendered_programs) > 1
        for node_id in filtered_node_ids_sorted:
            if node_id not in filtered_vertex_index:
                continue
            vertex = filtered_graph.vs[filtered_vertex_index[node_id]]
            label = (
                _vertex_attr(vertex, "name")
                or _vertex_attr(vertex, "qualified_name")
                or _vertex_attr(vertex, "address")
                or node_id
            )
            if prefix_dropdown:
                program = _vertex_attr(vertex, "program", "unknown")
                if program:
                    label = f"{program}:{label}"
            options.append({"label": label, "value": node_id})

        start_value = start_node if start_node in subset_nodes else None
        end_value = end_node if end_node in subset_nodes or end_node in pinned_nodes else None

        graph_mode_raw = _infer_mode_raw_from_file(path_obj)
        graph_mode = "projection" if graph_mode_raw == "syscall_projection" else graph_mode_raw
        rendered_nodes = graph_for_render.vcount()
        rendered_edges = graph_for_render.ecount()
        filtered_nodes_count = filtered_graph.vcount()
        filtered_edges_count = filtered_graph.ecount()
        total_nodes_full = ig_graph.vcount()
        total_edges_full = ig_graph.ecount()
        arch_value = nx_graph.graph.get("arch") or "mixed"
        machine_value = nx_graph.graph.get("machine") or "mixed"
        perf_label = "on" if perf_active else "off"
        if perf_mode_value == "auto":
            perf_label = f"auto ({perf_label})"

        graph_summary_children = [
            html.Div(
                html.Div([
                    html.Div([
                        html.Div("Mode", className="metric-title"),
                        html.Div(graph_mode, className="metric-value"),
                    ], className="metric"),
                    html.Div([
                        html.Div("Programs", className="metric-title"),
                        html.Div(str(len(all_programs)), className="metric-value"),
                    ], className="metric"),
                    html.Div([
                        html.Div("Nodes r/f/t", className="metric-title"),
                        html.Div(f"{rendered_nodes} / {filtered_nodes_count} / {total_nodes_full}", className="metric-value"),
                    ], className="metric"),
                    html.Div([
                        html.Div("Edges r/f/t", className="metric-title"),
                        html.Div(f"{rendered_edges} / {filtered_edges_count} / {total_edges_full}", className="metric-value"),
                    ], className="metric"),
                    html.Div([
                        html.Div("Perf", className="metric-title"),
                        html.Div(perf_label, className="metric-value"),
                    ], className="metric"),
                    html.Div([
                        html.Div("Arch", className="metric-title"),
                        html.Div(str(arch_value), className="metric-value"),
                    ], className="metric"),
                ], className="metrics"),
            ),
            html.Div(path_obj.name, className="footnote", style={"marginTop": "0.4rem"}),
        ]

        family_groups: dict[str, list[str]] = {}
        for program in legend_programs:
            family = _legend_family(program)
            family_groups.setdefault(family, []).append(program)

        legend_children = []
        for family in ["api-ms", "ext-ms", "ntdll", "syscall", "system32", "unknown"]:
            programs = family_groups.get(family)
            if not programs:
                continue
            items = [
                html.Div([
                    html.Span(
                        className="legend-chip",
                        style={"backgroundColor": colors.get(p, colors["unknown"])},
                    ),
                    html.Span(p),
                ], className="legend-item")
                for p in programs
            ]
            legend_children.append(html.Details([
                html.Summary(f"{family} ({len(programs)})"),
                html.Div(items, className="legend"),
            ], open=family in {"ntdll", "system32"}))
        if not legend_children:
            legend_children = [html.Div("No nodes to display.", className="footnote")]

        layout_config = dict(LAYOUT_PRESETS.get(layout_mode, LAYOUT_PRESETS["cose"]))
        layout_config.setdefault("padding", 30)
        if layout_config.get("name") == "cose":
            layout_config.setdefault("animate", False)
            layout_config.setdefault("randomize", False)

        return (
            nodes + edges, layout_config,
            path_text, focus_info, path_table_children,
            graph_summary_children, legend_children,
            options, options,
            start_value, end_value,
            perf_active, perf_active,
            1 if perf_active else "auto",
        )

    @app.callback(
        Output("graph-mode-label", "children"),
        Input("graph-file", "value"),
    )
    def update_graph_mode_label(path_value: str | None) -> str:
        if not path_value:
            return "unknown"
        mode_raw = _infer_mode_raw_from_file(Path(path_value))
        return "projection" if mode_raw == "syscall_projection" else mode_raw

    @app.callback(
        Output("hover-details", "children"),
        Input("call-graph", "mouseoverNodeData"),
        Input("call-graph", "mouseoverEdgeData"),
    )
    def update_hover_details(node_data: dict | None, edge_data: dict | None) -> list:
        if node_data:
            return [html.Div([
                html.Div([html.Div("Node", className="metric-title"), html.Div(node_data.get("label") or node_data.get("id"), className="metric-value")], className="metric"),
                html.Div([html.Div("Program", className="metric-title"), html.Div(node_data.get("program"), className="metric-value")], className="metric"),
                html.Div([html.Div("Address", className="metric-title"), html.Div(node_data.get("address"), className="metric-value")], className="metric"),
                html.Div([html.Div("Source", className="metric-title"), html.Div(node_data.get("source"), className="metric-value")], className="metric"),
                html.Div([html.Div("External", className="metric-title"), html.Div(str(node_data.get("is_external")), className="metric-value")], className="metric"),
                html.Div([html.Div("Degree", className="metric-title"), html.Div(str(node_data.get("degree")), className="metric-value")], className="metric"),
            ], className="metrics")]
        if edge_data:
            return [html.Div([
                html.Div([html.Div("Edge", className="metric-title"), html.Div(f"{edge_data.get('source')} → {edge_data.get('target')}", className="metric-value")], className="metric"),
                html.Div([html.Div("Kind", className="metric-title"), html.Div(edge_data.get("kind"), className="metric-value")], className="metric"),
                html.Div([html.Div("Min hops", className="metric-title"), html.Div(str(edge_data.get("min_hops")), className="metric-value")], className="metric"),
                html.Div([html.Div("Callsite", className="metric-title"), html.Div(edge_data.get("site"), className="metric-value")], className="metric"),
            ], className="metrics")]
        return [html.Div("Hover a node or edge to inspect.", className="footnote")]

    @app.callback(
        Output("jump-target", "data"),
        Output("search-status", "children"),
        Input("search-jump", "n_clicks"),
        State("search-query", "value"),
        State("graph-file", "value"),
        prevent_initial_call=True,
    )
    def jump_to_node(n_clicks: int | None, query: str | None, path_value: str | None) -> tuple[dict | None, str]:
        if not query or not path_value:
            return None, "Enter a search term to jump."
        path_obj = Path(path_value)
        try:
            mtime = path_obj.stat().st_mtime
        except OSError:
            mtime = 0.0
        ig_graph, _ = _load_graph_cached(str(path_obj), mtime)
        query_lower = query.strip().lower()
        if not query_lower:
            return None, "Enter a search term to jump."

        best = None
        best_score = 0.0
        best_label = None
        for vertex in ig_graph.vs:
            label = (
                _vertex_attr(vertex, "name")
                or _vertex_attr(vertex, "qualified_name")
                or _vertex_attr(vertex, "address")
                or vertex["node_id"]
            )
            if not label:
                continue
            label_lower = str(label).lower()
            score = difflib.SequenceMatcher(None, query_lower, label_lower).ratio()
            if query_lower in label_lower:
                score += 0.35
            if label_lower in query_lower:
                score += 0.15
            if score > best_score:
                best_score = score
                best = vertex["node_id"]
                best_label = label

        if not best:
            return None, f"No matches for '{query}'."
        payload = {"node_id": best, "label": best_label, "score": round(best_score, 3)}
        return payload, f"Jumped to {best_label} (score {payload['score']})."

    app.clientside_callback(
        """
        function(jump) {
            if (!jump || !jump.node_id || !window.cy) return window.dash_clientside.no_update;
            const cy = window.cy;
            const node = cy.getElementById(jump.node_id);
            if (!node || node.empty()) return window.dash_clientside.no_update;
            try { cy.animate({ center: { eles: node }, duration: 300 }); } catch(e) { cy.center(node); }
            node.addClass("jump-flash");
            setTimeout(() => node.removeClass("jump-flash"), 1200);
            return Date.now();
        }
        """,
        Output("jump-applied", "data"),
        Input("jump-target", "data"),
    )

    @app.callback(
        Output("call-graph", "generateImage"),
        Input("export-png", "n_clicks"),
        Input("export-svg", "n_clicks"),
        State("graph-file", "value"),
        prevent_initial_call=True,
    )
    def export_graph_image(png_clicks: int | None, svg_clicks: int | None, path_value: str | None) -> dict:
        triggered_id = dash.callback_context.triggered_id
        if not triggered_id or not path_value:
            raise dash.exceptions.PreventUpdate
        ext = "png" if triggered_id == "export-png" else "svg"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{Path(path_value).stem}_{stamp}.{ext}"
        return {"type": ext, "action": "download", "filename": filename, "options": {"bg": "#010b15", "full": True, "scale": 2}}

    app.index_string = """<!DOCTYPE html>
<html>
<head>
{%metas%}
<title>{%title%}</title>
{%favicon%}
{%css%}
<style>
  *, *::before, *::after { box-sizing: border-box; }

  body {
    margin: 0;
    background: #010b15;
    color: #e2e8f0;
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }

  /* ── Layout ── */
  .page {
    display: grid;
    grid-template-columns: 380px 1fr;
    height: 100vh;
    overflow: hidden;
  }

  .sidebar {
    padding: 1.1rem;
    background: rgba(6, 14, 26, 0.97);
    border-right: 1px solid rgba(148, 163, 184, 0.1);
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    overflow-y: auto;
    overflow-x: hidden;
  }

  .sidebar::-webkit-scrollbar { width: 3px; }
  .sidebar::-webkit-scrollbar-track { background: transparent; }
  .sidebar::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.2); border-radius: 99px; }

  .graph-panel {
    background: #010b15;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .graph-panel > div { width: 100%; flex: 1; }

  /* Slider mark labels need room below the track */
  .rc-slider { margin-bottom: 1.2rem; }
  .rc-slider-mark-text { color: #475569 !important; font-size: 0.7rem !important; }

  /* ── Header ── */
  .header {
    padding-bottom: 0.75rem;
    border-bottom: 1px solid rgba(148, 163, 184, 0.1);
  }

  .title {
    margin: 0;
    font-size: 1.05rem;
    font-weight: 700;
    color: #38bdf8;
    letter-spacing: -0.01em;
  }

  .subtitle {
    margin: 0.15rem 0 0;
    font-size: 0.75rem;
    color: #475569;
  }

  .header-meta { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; }

  .header-meta-label {
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #475569;
  }

  .header-meta-value {
    font-size: 0.68rem;
    font-weight: 600;
    padding: 0.15rem 0.55rem;
    border-radius: 9999px;
    background: rgba(56, 189, 248, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.3);
    color: #38bdf8;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  /* ── Controls ── */
  .control { display: flex; flex-direction: column; gap: 0.4rem; overflow: visible; }

  .control > label, .control label:first-child {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #475569;
    font-weight: 600;
  }

  /* Dash component label resets — prevent invisible text */
  .radio-control label,
  .checklist label,
  .path-mode-toggle label {
    color: #94a3b8 !important;
    font-size: 0.82rem !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
    font-weight: 400 !important;
  }

  /* ── Sections ── */
  .section {
    border-top: 1px solid rgba(148, 163, 184, 0.08);
    padding-top: 0.8rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .section-title {
    margin: 0;
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b;
    font-weight: 600;
  }

  /* ── Stats / hover panel ── */
  .stats {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 10px;
    padding: 0.65rem;
  }

  /* ── Metrics grid ── */
  .metrics {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.4rem;
  }

  .metric {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(148, 163, 184, 0.08);
    border-radius: 7px;
    padding: 0.35rem 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .metric-title {
    font-size: 0.6rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #475569;
  }

  .metric-value {
    font-size: 0.82rem;
    font-weight: 600;
    color: #e2e8f0;
    word-break: break-all;
  }

  /* ── Legend ── */
  .legend-container { display: flex; flex-direction: column; gap: 0.35rem; }

  .legend {
    display: grid;
    gap: 0.3rem 0.6rem;
    grid-template-columns: repeat(auto-fit, minmax(85px, 1fr));
    padding-top: 0.4rem;
  }

  .legend-item { display: flex; align-items: center; gap: 0.4rem; font-size: 0.78rem; color: #94a3b8; }

  .legend-chip {
    width: 9px; height: 9px;
    border-radius: 3px;
    flex-shrink: 0;
    border: 1px solid rgba(226, 232, 240, 0.4);
  }

  details {
    background: rgba(15, 23, 42, 0.4);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 8px;
    padding: 0.35rem 0.55rem;
  }

  summary {
    cursor: pointer;
    font-size: 0.75rem;
    color: #64748b;
    user-select: none;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }

  summary::before { content: '▸'; font-size: 0.65rem; transition: transform 0.15s; }
  details[open] summary::before { transform: rotate(90deg); }
  details[open] summary { color: #94a3b8; margin-bottom: 0.35rem; }

  /* ── Chips ── */
  .chip-group {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
  }

  .chip-group label {
    display: inline-flex !important;
    align-items: center;
    gap: 0.3rem;
    padding: 0.18rem 0.5rem;
    border-radius: 9999px;
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid rgba(148, 163, 184, 0.2);
    color: #94a3b8;
    cursor: pointer;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
    font-size: 0.75rem;
    text-transform: none !important;
    letter-spacing: 0 !important;
    font-weight: 400 !important;
  }

  .chip-group label:has(input:checked) {
    background: rgba(56, 189, 248, 0.12);
    border-color: rgba(56, 189, 248, 0.45);
    color: #bae6fd;
  }

  /* ── Checklist ── */
  .checklist { display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.82rem; color: #94a3b8; }

  /* ── Radio ── */
  .radio-control { display: flex; flex-wrap: wrap; gap: 0.5rem; color: #94a3b8; font-size: 0.82rem; }
  .radio-control input { accent-color: #38bdf8; }

  /* ── Dropdowns ── */
  .dropdown-control .Select-control {
    background: rgba(6, 14, 26, 0.98);
    border: 1px solid rgba(148, 163, 184, 0.28);
    border-radius: 7px;
    min-height: 38px;
  }
  .dropdown-control .Select-placeholder,
  .dropdown-control .Select-value-label { color: #e2e8f0 !important; font-size: 0.83rem; }
  .dropdown-control .Select-arrow { border-top-color: #64748b; }
  .dropdown-control .Select-menu-outer {
    background: rgba(6, 14, 26, 0.99);
    border: 1px solid rgba(148, 163, 184, 0.28);
    box-shadow: 0 20px 48px rgba(0, 0, 0, 0.7);
    border-radius: 8px;
    z-index: 3000;
  }
  .dropdown-control .Select-option { background-color: transparent; color: #94a3b8; font-size: 0.83rem; }
  .dropdown-control .Select-option.is-focused { background-color: rgba(56, 189, 248, 0.15); color: #e2e8f0; }
  .dropdown-control .Select-option.is-selected { background-color: rgba(74, 222, 128, 0.2); color: #4ade80; }

  /* ── Text inputs ── */
  .text-input {
    width: 100%;
    padding: 0.4rem 0.65rem;
    border-radius: 7px;
    border: 1px solid rgba(148, 163, 184, 0.25);
    background: rgba(6, 14, 26, 0.95);
    color: #e2e8f0;
    font-family: inherit;
    font-size: 0.83rem;
    outline: none;
    transition: border-color 0.15s;
  }

  .text-input:focus { border-color: rgba(56, 189, 248, 0.5); }
  .text-input::placeholder { color: #334155; }

  /* ── Buttons ── */
  .ui-button {
    border: 1px solid rgba(148, 163, 184, 0.22);
    background: rgba(30, 41, 59, 0.8);
    color: #94a3b8;
    padding: 0.35rem 0.7rem;
    border-radius: 7px;
    cursor: pointer;
    font-size: 0.75rem;
    font-weight: 500;
    font-family: inherit;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }

  .ui-button:hover {
    border-color: rgba(56, 189, 248, 0.5);
    background: rgba(56, 189, 248, 0.12);
    color: #e2e8f0;
  }

  .export-row { display: flex; gap: 0.4rem; flex-wrap: wrap; }

  /* ── Search ── */
  .search-row { display: flex; gap: 0.4rem; align-items: stretch; }
  .search-row .text-input { flex: 1; }

  /* ── Path inspector ── */
  .path-controls { display: grid; gap: 0.4rem; }
  .path-mode-toggle { font-size: 0.8rem; color: #64748b; }

  .path-info {
    font-size: 0.78rem;
    color: #64748b;
    line-height: 1.5;
    padding: 0.4rem 0.5rem;
    background: rgba(15, 23, 42, 0.5);
    border: 1px solid rgba(148, 163, 184, 0.08);
    border-radius: 7px;
  }

  .path-table-grid {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.74rem;
    background: rgba(6, 14, 26, 0.7);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 8px;
    overflow: hidden;
  }

  .path-header {
    text-align: left;
    padding: 0.4rem 0.5rem;
    font-size: 0.62rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #334155;
    background: rgba(15, 23, 42, 0.9);
  }

  .path-cell {
    padding: 0.38rem 0.5rem;
    border-top: 1px solid rgba(148, 163, 184, 0.08);
    vertical-align: top;
  }

  .path-cell--source { font-weight: 600; color: #7dd3fc; max-width: 110px; word-break: break-word; }
  .path-cell--hops { width: 2.8rem; text-align: center; font-variant-numeric: tabular-nums; color: #38bdf8; }
  .path-cell--path { color: #475569; font-size: 0.7rem; }

  .path-table-empty {
    font-size: 0.75rem;
    color: #334155;
    border: 1px dashed rgba(148, 163, 184, 0.15);
    padding: 0.55rem 0.7rem;
    border-radius: 8px;
  }

  .footnote { font-size: 0.7rem; color: #334155; }
</style>
</head>
<body>
{%app_entry%}
<footer>
{%config%}
{%scripts%}
{%renderer%}
</footer>
</body>
</html>"""

    return app
