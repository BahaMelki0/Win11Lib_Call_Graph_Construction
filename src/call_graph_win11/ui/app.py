"""Dash application offering a smooth single-page call graph explorer."""



from __future__ import annotations



from functools import lru_cache
import difflib
import json
import math

from pathlib import Path

from datetime import datetime
from typing import Dict, Iterable, List, Tuple, Optional



import dash

import dash_cytoscape as cyto

from dash import Dash, Input, Output, State, dcc, html

import networkx as nx
import igraph as ig

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
    # Cheap sniffing to support unified nodes/edges graphs in the UI.
    if "\"functions\"" in payload:
        nx_graph = load_call_graph(path_obj)
    else:
        nx_graph = load_generic_graph(path_obj)
    ig_graph = to_igraph(nx_graph)
    return ig_graph, nx_graph





def _subset_graph(graph: "ig.Graph", limit: int | None) -> Tuple["ig.Graph", set[str]]:
    if limit is None or graph.vcount() <= limit:
        return graph, set(graph.vs["node_id"])

    # Balance nodes across programs to avoid single-DLL dominance when limit is small.
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
        nodes.append(
            {
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
            }
        )

    for idx, (source_idx, target_idx) in enumerate(graph.get_edgelist()):
        source_id = graph.vs[source_idx]["node_id"]
        target_id = graph.vs[target_idx]["node_id"]
        edge = graph.es[idx]
        kind_value = _edge_attr(edge, "kind") or "unknown"
        if edge_kind_filter and kind_value not in edge_kind_filter:
            continue
        edges.append(
            {
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
            }
        )

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
        raise FileNotFoundError(f"No *.callgraph.json files found under {data_dir} for mode '{mode}'")

    graph_options = [
        {"label": str(path.relative_to(data_dir)), "value": str(path.resolve())} for path, _, _ in file_entries
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



    app.layout = html.Div(

        [
            dcc.Store(id="graph-index", data=graph_index),
            dcc.Store(id="jump-target"),
            dcc.Store(id="jump-applied", data=0),

            html.Div(

                [

                    html.Div(

                        [

                            html.H1("Windows Call Graph Explorer", className="title"),

                            html.P(

                                "Browse symbol-enriched call graphs exported from Ghidra.",

                                className="subtitle",

                            ),

                            html.Div(
                                [
                                    html.Span("Mode", className="header-meta-label"),
                                    html.Span(id="graph-mode-label", className="header-meta-value"),
                                ],
                                className="header-meta",
                            ),

                        ],

                        className="header",

                    ),

                    html.Div(

                        [

                            html.Label("Library"),

                            dcc.Dropdown(

                                id="graph-file",

                                options=graph_options,

                                value=graph_options[0]["value"],

                                clearable=False,

                                className="dropdown-control",

                                        style={"zIndex": 1100},

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(
                        [
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
                                inputStyle={"marginRight": "0.35rem"},
                                labelStyle={"display": "inline-flex", "alignItems": "center"},
                            ),
                        ],
                        className="control",
                    ),

                    html.Div(

                        [

                            html.Label("Max nodes"),

                            dcc.Slider(
                                id="node-limit",
                                min=100,
                                max=5000,
                                step=None,
                                marks={100: "100", 300: "300", 1000: "1k", 2500: "2.5k", 5000: "5k"},
                                value=100,
                                tooltip={"placement": "bottom", "always_visible": True},
                            ),

                            html.Label("Custom nodes"),
                            dcc.Input(
                                id="node-limit-custom",
                                type="number",
                                min=0,
                                step=50,
                                placeholder="Enter node cap (0 for all, e.g., 20000)",
                                debounce=True,
                                style={"marginTop": "6px", "width": "100%"},
                            ),

                        ],

                        className="control",

                    ),

                    html.Div(
                        [
                            html.Label("Graph layout"),
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
                                style={"zIndex": 1100},
                            ),
                        ],
                        className="control",
                    ),

                    html.Div(
                        [
                            html.Label("Node size"),
                            dcc.RadioItems(
                                id="node-size-mode",
                                options=[
                                    {"label": "Fixed", "value": "fixed"},
                                    {"label": "Degree scaled", "value": "degree"},
                                ],
                                value="fixed",
                                className="radio-control",
                                inputStyle={"marginRight": "0.35rem"},
                                labelStyle={
                                    "display": "inline-flex",
                                    "alignItems": "center",
                                    "marginRight": "0.75rem",
                                    "gap": "0.15rem",
                                },
                            ),
                        ],
                        className="control",
                    ),

                    html.Div(
                        [
                            html.Label("Performance"),
                            dcc.RadioItems(
                                id="perf-mode",
                                options=[
                                    {"label": "Auto (>= 1000 nodes)", "value": "auto"},
                                    {"label": "On", "value": "on"},
                                    {"label": "Off", "value": "off"},
                                ],
                                value="auto",
                                className="radio-control",
                                inputStyle={"marginRight": "0.35rem"},
                                labelStyle={
                                    "display": "inline-flex",
                                    "alignItems": "center",
                                    "marginRight": "0.75rem",
                                    "gap": "0.15rem",
                                },
                            ),
                        ],
                        className="control",
                    ),

                    html.Div(

                    [

                            html.Label("Filters"),

                            dcc.Checklist(

                                id="filters",

                                options=[

                                    {"label": "Only exported/imported APIs", "value": "apis_only"},
                                    {"label": "External nodes only", "value": "external"},

                                ],

                                value=[],

                                className="checklist",

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(
                        [
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
                                value=[
                                    "direct",
                                    "import",
                                    "forwarder",
                                    "apiset",
                                    "reaches",
                                    "projection",
                                    "syscall",
                                    "ref",
                                    "unknown",
                                ],
                                className="chip-group",
                                inputStyle={"marginRight": "0.35rem"},
                                labelStyle={"display": "inline-flex", "alignItems": "center"},
                            ),
                        ],
                        className="control",
                    ),

                    html.Div(
                        [
                            html.H3("Graph info", className="section-title"),
                            html.Div(
                                [
                                    html.Button("Export PNG", id="export-png", className="ui-button"),
                                    html.Button("Export SVG", id="export-svg", className="ui-button"),
                                ],
                                className="export-row",
                            ),
                            html.Div(id="graph-summary", className="stats"),
                            html.Div(id="program-legend", className="legend"),
                        ],
                        className="section",
                    ),

                    html.Div(
                        [
                            html.H3("Hover details", className="section-title"),
                            html.Div(id="hover-details", className="stats"),
                        ],
                        className="section",
                    ),

                    html.Div(

                        [

                            html.Label("Inbound depth"),

                            dcc.Slider(

                                id="focus-depth",

                                min=1,
                                max=6,
                                step=None,
                                marks={1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6"},
                                value=3,

                                tooltip={"placement": "bottom", "always_visible": True},

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(
                        [
                            html.Label("Search"),
                            html.Div(
                                [
                                    dcc.Input(
                                        id="search-query",
                                        type="text",
                                        placeholder="Find function name or address",
                                        debounce=True,
                                        className="search-input",
                                    ),
                                    html.Button("Jump", id="search-jump", className="ui-button"),
                                ],
                                className="search-row",
                            ),
                            html.Div(id="search-status", className="overview-footnote"),
                        ],
                        className="control",
                    ),

                    html.Div(

                        [

                            html.H3("Path inspector", className="section-title"),

                            dcc.Checklist(
                                id="pin-focus",
                                options=[{"label": " Pin focus node", "value": "pin"}],
                                value=[],
                                className="path-mode-toggle",
                                inputStyle={"marginRight": "0.35rem"},
                                labelStyle={"display": "inline-flex", "alignItems": "center", "gap": "0.2rem"},
                                style={"color": "#e2e8f0", "fontSize": "0.85rem"},
                            ),

                            html.Div(

                                [

                                    dcc.Dropdown(
                                        id="path-start",
                                        placeholder="Start function",
                                        className="dropdown-control",
                                        style={"zIndex": 1100},
                                    ),

                                    dcc.Dropdown(
                                        id="path-end",
                                        placeholder="Focus function",
                                        className="dropdown-control",
                                        style={"zIndex": 1100},
                                    ),
                                    dcc.Checklist(
                                        id="path-mode",
                                        options=[{"label": " Path only", "value": "path-only"}],
                                        value=[],
                                        className="path-mode-toggle",
                                        inputStyle={"marginRight": "0.35rem"},
                                        labelStyle={"display": "inline-flex", "alignItems": "center", "gap": "0.2rem"},
                                        style={"color": "#e2e8f0", "fontSize": "0.85rem"},
                                    ),

                                ],

                                className="path-controls",

                            ),

                            html.Div(id="path-info", className="path-info"),
                            html.Div(id="path-table", className="path-table"),

                            html.Div(id="focus-info", className="path-info"),

                        ],

                        className="section",

                    ),

                ],

                className="sidebar",

            ),

            html.Div(
                [
                    dcc.Loading(
                        id="call-graph-loader",
                        type="default",
                        children=cyto.Cytoscape(
                            id="call-graph",
                            style={"width": "100%", "height": "100%", "minHeight": "72vh"},
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
                                        "text-max-width": "220px",
                                        "text-overflow": "ellipsis",
                                        "text-background-color": "rgba(248,250,252,0.92)",
                                        "text-background-opacity": 0.92,
                                        "text-background-padding": "4px",
                                        "text-background-shape": "roundrectangle",
                                        "font-size": "12px",
                                        "min-zoomed-font-size": "10px",
                                        "text-outline-width": "0px",
                                        "width": "data(size)",
                                        "height": "data(size)",
                                        "border-width": "1px",
                                        "border-color": "rgba(248,250,252,0.6)",
                                        "transition-property": "background-color, border-color, border-width",
                                        "transition-duration": "300ms",
                                    },
                                },
                                {
                                    "selector": "node[show_label = false]",
                                    "style": {
                                        "label": "",
                                        "text-opacity": 0,
                                        "text-background-opacity": 0,
                                    },
                                },
                                {
                                    "selector": "node[is_external = True]",
                                    "style": {"shape": "triangle", "opacity": 0.92},
                                },
                                {
                                    "selector": "node[hub = true]",
                                    "style": {"border-width": 3, "border-color": "#38bdf8"},
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
                                },
                            },
                            {
                                "selector": "edge",
                                "style": {
                                    "line-color": "#475569",
                                    "width": 1,
                                        "curve-style": "bezier",
                                        "target-arrow-color": "#38bdf8",
                                        "target-arrow-shape": "triangle",
                                        "opacity": 0.35,
                                    },
                            },
                            {
                                "selector": "edge[perf = true]",
                                "style": {
                                    "line-color": "#334155",
                                    "curve-style": "haystack",
                                    "width": 0.5,
                                    "opacity": 0.2,
                                    "target-arrow-shape": "none",
                                },
                            },
                            {
                                "selector": "edge[kind = 'reaches']",
                                "style": {
                                    "line-color": "#4ade80",
                                    "target-arrow-color": "#4ade80",
                                    "opacity": 0.55,
                                },
                            },
                            {
                                "selector": "edge[kind = 'import']",
                                "style": {
                                    "line-color": "#60a5fa",
                                    "target-arrow-color": "#60a5fa",
                                    "line-style": "dashed",
                                    "opacity": 0.6,
                                },
                            },
                            {
                                "selector": "edge[kind = 'apiset']",
                                "style": {
                                    "line-color": "#a855f7",
                                    "target-arrow-color": "#a855f7",
                                    "line-style": "dotted",
                                    "opacity": 0.65,
                                },
                            },
                            {
                                "selector": "edge[kind = 'forwarder']",
                                "style": {
                                    "line-color": "#f97316",
                                    "target-arrow-color": "#f97316",
                                    "line-style": "dashed",
                                    "opacity": 0.65,
                                },
                            },
                            {
                                "selector": "edge[kind = 'projection']",
                                "style": {
                                    "line-color": "#22d3ee",
                                    "target-arrow-color": "#22d3ee",
                                    "line-style": "solid",
                                    "opacity": 0.75,
                                },
                            },
                            {
                                "selector": "edge[kind = 'syscall']",
                                "style": {
                                    "line-color": "#f43f5e",
                                    "target-arrow-color": "#f43f5e",
                                    "line-style": "solid",
                                    "opacity": 0.75,
                                },
                            },
                            {
                                "selector": "edge[path_highlight = true]",
                                "style": {"line-color": "#f97316", "target-arrow-color": "#facc15", "width": 2.5, "opacity": 0.8},
                            },
                        ],
                        ),
                    ),
                ],
                className="graph-panel",
            ),

        ],

        className="page",

    )



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
    ) -> Tuple[
        List[dict],
        dict,
        str,
        str,
        html.Div,
        list,
        list,
        List[dict],
        List[dict],
        str | None,
        str | None,
        bool,
        bool,
        int | str,
    ]:
        path_obj = Path(path_value)
        try:
            mtime = path_obj.stat().st_mtime
        except OSError:
            mtime = 0.0
        ig_graph, nx_graph = _load_graph_cached(str(path_obj), mtime)
        # Prefer custom node cap if provided (empty input is treated as unset)
        limit_value = node_limit
        if node_limit_custom not in (None, "", " "):
            limit_value = node_limit_custom
        try:
            limit_value = int(limit_value)
        except (TypeError, ValueError):
            limit_value = node_limit
        # Allow 0/None to mean "all nodes"; otherwise ensure at least one node and cap to graph size
        if limit_value <= 0:
            node_limit = ig_graph.vcount()
        else:
            node_limit = max(1, min(limit_value, ig_graph.vcount()))

        # Filter first, then subset for rendering
        filtered_graph, filtered_node_ids = _filter_graph(ig_graph, filters or [])
        subset_graph, subset_nodes = _subset_graph(filtered_graph, node_limit)

        rendered_programs = sorted({_vertex_attr(vertex, "program", "unknown") for vertex in subset_graph.vs})
        all_programs = sorted({_vertex_attr(vertex, "program", "unknown") for vertex in ig_graph.vs})
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
                    size_value = 28.0
                    size_map = {vertex["node_id"]: size_value for vertex in subset_graph.vs}
                else:
                    size_map = {}
                    for vertex, degree in zip(subset_graph.vs, degree_values):
                        norm = (degree - min_deg) / (max_deg - min_deg)
                        size_map[vertex["node_id"]] = 18.0 + norm * 28.0
            else:
                size_map = {vertex["node_id"]: 22.0 for vertex in subset_graph.vs}

        highlight_nodes: set[str] = set()
        highlight_edges: set[Tuple[str, str]] = set()
        vertex_index = {vertex["node_id"]: vertex.index for vertex in subset_graph.vs}
        filtered_vertex_index = {vertex["node_id"]: vertex.index for vertex in filtered_graph.vs}

        triggered_id = dash.callback_context.triggered_id
        jump_node = None
        if triggered_id == "jump-target" and isinstance(jump_target, dict):
            jump_node = jump_target.get("node_id")
            if jump_node:
                end_node = jump_node

        # Constrain path inputs to the rendered subset
        if start_node and start_node not in subset_nodes:
            start_node = None
        pin_focus_enabled = bool(pin_focus and "pin" in pin_focus)
        if end_node and end_node not in subset_nodes:
            if not pin_focus_enabled and end_node != jump_node:
                end_node = None

        path_text = "Select a start and focus function to view shortest paths."
        focus_info = "Select a focus function to inspect inbound callers."
        path_table_children: html.Div = html.Div(
            "Select a focus function to list inbound paths.", className="path-table path-table-empty"
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
                if edge_id is None:
                    total += 1.0
                else:
                    total += weights[edge_id]
            return total

        # If both start and end are selected, show shortest path between them
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
                labels = []
                for vid in vertex_path:
                    vertex = subset_graph.vs[vid]
                    labels.append(
                        _vertex_attr(vertex, "name")
                        or _vertex_attr(vertex, "qualified_name")
                        or _vertex_attr(vertex, "address")
                        or vertex["node_id"]
                    )
                unweighted_hops = len(vertex_path) - 1
                weighted_hops = _path_hops(vertex_path)
                if weighted_hops.is_integer():
                    weighted_hops = int(weighted_hops)
                path_text = f"Shortest path length: {unweighted_hops} hops (weighted {weighted_hops})."
                table = html.Table(
                    [
                        html.Thead(
                            html.Tr(
                                [
                                    html.Th("Source", className="path-header"),
                                    html.Th("Hops", className="path-header"),
                                    html.Th("Weighted", className="path-header"),
                                    html.Th("Path", className="path-header"),
                                ]
                            )
                        ),
                        html.Tbody(
                            [
                                html.Tr(
                                    [
                                        html.Td(labels[0], className="path-cell path-cell--source"),
                                        html.Td(f"{unweighted_hops}", className="path-cell path-cell--hops"),
                                        html.Td(f"{weighted_hops}", className="path-cell path-cell--hops"),
                                        html.Td(" -> ".join(labels[:8]), className="path-cell path-cell--path"),
                                    ]
                                )
                            ]
                        ),
                    ],
                    className="path-table-grid",
                )
                path_table_children = html.Div(table, className="path-table")
            else:
                path_text = "No path found between start and focus."
                path_table_children = html.Div("No shortest path found.", className="path-table path-table-empty")
        else:
            focus_candidates: list[tuple[int, float]] = []
            if end_node and end_node in vertex_index:
                highlight_nodes.add(end_node)
                reverse_graph = subset_graph.copy()
                reverse_graph.reverse_edges()
                distances = reverse_graph.shortest_paths(vertex_index[end_node], mode="OUT", weights=weights)[0]
                focus_vertex_indices = [
                    idx for idx, dist in enumerate(distances) if not math.isinf(dist) and dist <= focus_depth
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
                    focus_info = f"{len(focus_node_ids)} functions within {focus_depth} hops can reach {target_label}."
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
                max_rows = 12
                for idx, dist in focus_candidates[:max_rows]:
                    vpath = subset_graph.get_shortest_paths(
                        idx, to=vertex_index[end_node], mode="OUT", weights=weights
                    )
                    if not vpath or not vpath[0]:
                        continue
                    labels = []
                    vertex_path = vpath[0]
                    for vid in vertex_path:
                        vertex = subset_graph.vs[vid]
                        labels.append(
                            _vertex_attr(vertex, "name")
                            or _vertex_attr(vertex, "qualified_name")
                            or _vertex_attr(vertex, "address")
                            or vertex["node_id"]
                        )
                    source_label = labels[0]
                    unweighted_hops = len(vertex_path) - 1
                    weighted_hops = _path_hops(vertex_path)
                    if weighted_hops.is_integer():
                        weighted_hops = int(weighted_hops)
                    path_rows.append(
                        html.Tr(
                            [
                                html.Td(source_label, className="path-cell path-cell--source"),
                                html.Td(f"{unweighted_hops}", className="path-cell path-cell--hops"),
                                html.Td(f"{weighted_hops}", className="path-cell path-cell--hops"),
                                html.Td(" -> ".join(labels[:8]), className="path-cell path-cell--path"),
                            ]
                        )
                    )
                if path_rows:
                    table = html.Table(
                        [
                            html.Thead(
                                html.Tr(
                                    [
                                    html.Th("Source", className="path-header"),
                                    html.Th("Hops", className="path-header"),
                                    html.Th("Weighted", className="path-header"),
                                    html.Th("Path", className="path-header"),
                                    ]
                                )
                            ),
                            html.Tbody(path_rows),
                        ],
                        className="path-table-grid",
                    )
                    path_table_children = html.Div(table, className="path-table")
                else:
                    path_table_children = html.Div("No paths found for the selected focus.", className="path-table path-table-empty")
            elif end_node:
                path_table_children = html.Div("No paths found for the selected focus.", className="path-table path-table-empty")

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
                _vertex_attr(filtered_graph.vs[filtered_vertex_index[node_id]], "program", "unknown")
                for node_id in pinned_nodes
                if node_id in filtered_vertex_index
            }
            colors = _program_colors(set(rendered_programs) | pinned_programs)
            legend_programs = sorted(set(rendered_programs) | pinned_programs)

        # Render on subset nodes plus any path nodes to avoid hiding cross-DLL paths.
        render_nodes: set[str] = set(subset_nodes) if subset_nodes else {vertex["node_id"] for vertex in subset_graph.vs}
        render_nodes.update(path_node_ids)
        render_nodes.update(pinned_nodes)
        render_indices = [filtered_vertex_index[n] for n in render_nodes if n in filtered_vertex_index]
        graph_for_render = filtered_graph.subgraph(render_indices) if render_indices else filtered_graph.subgraph([])

        if path_node_ids:
            highlight_nodes.update(path_node_ids)
            highlight_edges.update((path_node_ids[i], path_node_ids[i + 1]) for i in range(len(path_node_ids) - 1))
        if pinned_nodes:
            highlight_nodes.update(pinned_nodes)

        focus_nodes = set(path_node_ids)

        if path_only and path_node_ids:
            indices = [filtered_vertex_index[n] for n in path_node_ids if n in filtered_vertex_index]
            graph_for_render = filtered_graph.subgraph(indices) if indices else filtered_graph.subgraph([])

        perf_mode_value = (perf_mode or "auto").lower()
        render_node_count = graph_for_render.vcount()
        perf_active = perf_mode_value == "on" or (
            perf_mode_value == "auto" and render_node_count >= PERF_NODE_THRESHOLD
        )

        # Always prefix program for clarity, especially when multiple DLLs are shown.
        prefix_program = True
        nodes, edges = _create_elements(
            graph_for_render,
            colors,
            highlight_nodes,
            highlight_edges,
            size_map=size_map,
            focus_nodes=focus_nodes,
            prefix_program=prefix_program,
            edge_kind_filter=edge_kind_filter_set,
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
        filtered_nodes = filtered_graph.vcount()
        filtered_edges = filtered_graph.ecount()
        total_nodes_full = ig_graph.vcount()
        total_edges_full = ig_graph.ecount()
        arch_value = nx_graph.graph.get("arch") or "mixed"
        machine_value = nx_graph.graph.get("machine") or "mixed"

        perf_label = "on" if perf_active else "off"
        if perf_mode_value == "auto":
            perf_label = f"auto ({perf_label})"

        graph_summary_children = [
            html.Div(
                [html.Div("Mode", className="metric-title"), html.Div(graph_mode, className="metric-value")],
                className="metric",
            ),
            html.Div(
                [html.Div("Programs", className="metric-title"), html.Div(str(len(all_programs)), className="metric-value")],
                className="metric",
            ),
            html.Div(
                [
                    html.Div("Nodes (r/f/t)", className="metric-title"),
                    html.Div(f"{rendered_nodes} / {filtered_nodes} / {total_nodes_full}", className="metric-value"),
                ],
                className="metric",
            ),
            html.Div(
                [
                    html.Div("Edges (r/f/t)", className="metric-title"),
                    html.Div(f"{rendered_edges} / {filtered_edges} / {total_edges_full}", className="metric-value"),
                ],
                className="metric",
            ),
            html.Div(
                [html.Div("Perf", className="metric-title"), html.Div(perf_label, className="metric-value")],
                className="metric",
            ),
            html.Div(
                [html.Div("Arch", className="metric-title"), html.Div(str(arch_value), className="metric-value")],
                className="metric",
            ),
            html.Div(
                [html.Div("Machine", className="metric-title"), html.Div(str(machine_value), className="metric-value")],
                className="metric",
            ),
        ]
        graph_summary = [
            html.Div(graph_summary_children, className="metrics"),
            html.Div(f"File: {path_obj.name}", className="overview-footnote"),
        ]

        family_groups: dict[str, list[str]] = {}
        for program in legend_programs:
            family = _legend_family(program)
            family_groups.setdefault(family, []).append(program)

        legend_children = []
        family_order = ["api-ms", "ext-ms", "ntdll", "syscall", "system32", "unknown"]
        for family in family_order:
            programs = family_groups.get(family)
            if not programs:
                continue
            items = [
                html.Div(
                    [
                        html.Span(
                            className="legend-chip",
                            style={"backgroundColor": colors.get(program, colors["unknown"])},
                        ),
                        html.Span(program),
                    ],
                    className="legend-item",
                )
                for program in programs
            ]
            legend_children.append(
                html.Details(
                    [
                        html.Summary(f"{family} ({len(programs)})"),
                        html.Div(items, className="legend"),
                    ],
                    open=family in {"ntdll", "system32"},
                )
            )
        if not legend_children:
            legend_children = [html.Div("No nodes to display.", className="overview-footnote")]

        layout_config = dict(LAYOUT_PRESETS.get(layout_mode, LAYOUT_PRESETS["cose"]))
        layout_config.setdefault("padding", 30)
        if layout_config.get("name") == "cose":
            layout_config.setdefault("animate", False)
            layout_config.setdefault("randomize", False)

        return (
            nodes + edges,
            layout_config,
            path_text,
            focus_info,
            path_table_children,
            graph_summary,
            legend_children,
            options,
            options,
            start_value,
            end_value,
            perf_active,
            perf_active,
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
            return [
                html.Div(
                    [
                        html.Div(
                            [
                                html.Div("Node", className="metric-title"),
                                html.Div(node_data.get("label") or node_data.get("id"), className="metric-value"),
                            ],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Program", className="metric-title"), html.Div(node_data.get("program"), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Address", className="metric-title"), html.Div(node_data.get("address"), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Source", className="metric-title"), html.Div(node_data.get("source"), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("External", className="metric-title"), html.Div(str(node_data.get("is_external")), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Degree", className="metric-title"), html.Div(str(node_data.get("degree")), className="metric-value")],
                            className="metric",
                        ),
                    ],
                    className="metrics",
                )
            ]
        if edge_data:
            return [
                html.Div(
                    [
                        html.Div(
                            [
                                html.Div("Edge", className="metric-title"),
                                html.Div(f"{edge_data.get('source')} -> {edge_data.get('target')}", className="metric-value"),
                            ],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Kind", className="metric-title"), html.Div(edge_data.get("kind"), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Min hops", className="metric-title"), html.Div(str(edge_data.get("min_hops")), className="metric-value")],
                            className="metric",
                        ),
                        html.Div(
                            [html.Div("Callsite", className="metric-title"), html.Div(edge_data.get("site"), className="metric-value")],
                            className="metric",
                        ),
                    ],
                    className="metrics",
                )
            ]
        return [html.Div("Hover a node or edge to inspect details.", className="overview-footnote")]

    @app.callback(
        Output("jump-target", "data"),
        Output("search-status", "children"),
        Input("search-jump", "n_clicks"),
        State("search-query", "value"),
        State("graph-file", "value"),
        prevent_initial_call=True,
    )
    def jump_to_node(
        n_clicks: int | None,
        query: str | None,
        path_value: str | None,
    ) -> tuple[dict | None, str]:
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
            if (!jump || !jump.node_id || !window.cy) {
                return window.dash_clientside.no_update;
            }
            const nodeId = jump.node_id;
            const cy = window.cy;
            const node = cy.getElementById(nodeId);
            if (!node || node.empty()) {
                return window.dash_clientside.no_update;
            }
            try {
                cy.animate({ center: { eles: node }, duration: 300 });
            } catch (err) {
                cy.center(node);
            }
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
    def export_graph_image(
        png_clicks: int | None,
        svg_clicks: int | None,
        path_value: str | None,
    ) -> dict:
        triggered_id = dash.callback_context.triggered_id
        if not triggered_id or not path_value:
            raise dash.exceptions.PreventUpdate

        extension = "png" if triggered_id == "export-png" else "svg"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(path_value).stem
        filename = f"{stem}_{stamp}.{extension}"
        return {
            "type": extension,
            "action": "download",
            "filename": filename,
            "options": {"bg": "#0f172a", "full": True, "scale": 2},
        }
    app.index_string = """

<!DOCTYPE html>

<html>

    <head>

        {%metas%}

        <title>{%title%}</title>

        {%favicon%}

        {%css%}

        <style>

            body {

                margin: 0;

                background: radial-gradient(circle at top left, rgba(30, 64, 175, 0.15), rgba(15, 23, 42, 0.95));

                background-size: 180% 180%;

                animation: heroGradient 22s ease infinite;

                color: #e2e8f0;

                font-family: 'Inter', sans-serif;

            }

            @keyframes heroGradient {

                0% { background-position: 0% 50%; }

                50% { background-position: 100% 50%; }

                100% { background-position: 0% 50%; }

            }

            .page {
                display: grid;
                grid-template-columns: 360px 1fr;
                height: 100vh;
            }

            .sidebar {
                padding: 1.35rem;
                background: rgba(15, 23, 42, 0.92);
                backdrop-filter: blur(12px);
                box-shadow: inset -1px 0 0 rgba(148, 163, 184, 0.12);
                display: flex;
                flex-direction: column;
                gap: 1.1rem;
                overflow-y: auto;
            }

            .graph-panel {
                padding: 1rem 1.7rem 1.7rem 1.5rem;
            }

            .graph-panel > div {

                width: 100%;

                height: 100%;

            }

            .header .title {

                margin: 0;

                font-size: 1.35rem;

                font-weight: 600;

                color: #38bdf8;

            }

            .header .subtitle {

                margin: 0.3rem 0 0;

                color: #94a3b8;

                font-size: 0.9rem;

            }

            .control {
                display: flex;
                flex-direction: column;
                gap: 0.55rem;
            }

            .control label {
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #94a3b8;
            }

            .section-title {
                margin: 0.4rem 0 0.2rem;
                font-size: 0.82rem;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #cbd5f5;
            }

            .header-meta {
                display: flex;
                gap: 0.4rem;
                align-items: baseline;
                margin-top: 0.4rem;
            }

            .header-meta-label {
                font-size: 0.7rem;
                letter-spacing: 0.12em;
                text-transform: uppercase;
                color: #94a3b8;
            }

            .header-meta-value {
                font-size: 0.85rem;
                font-weight: 600;
                color: #e2e8f0;
            }

            .chip-group {
                display: flex;
                flex-wrap: wrap;
                gap: 0.4rem;
                font-size: 0.8rem;
            }

            .chip-group label {
                display: inline-flex;
                align-items: center;
                gap: 0.35rem;
                padding: 0.25rem 0.5rem;
                border-radius: 9999px;
                background: rgba(30, 41, 59, 0.6);
                border: 1px solid rgba(148, 163, 184, 0.35);
                color: #e2e8f0;
            }

            .search-row {
                display: flex;
                gap: 0.5rem;
                align-items: center;
            }

            .search-input {
                flex: 1;
                min-height: 40px;
                padding: 0.35rem 0.6rem;
                border-radius: 8px;
                border: 1px solid rgba(148, 163, 184, 0.45);
                background: rgba(15, 23, 42, 0.9);
                color: #e2e8f0;
            }

            .ui-button {
                border: 1px solid rgba(148, 163, 184, 0.45);
                background: rgba(56, 189, 248, 0.15);
                color: #e2e8f0;
                padding: 0.35rem 0.75rem;
                border-radius: 8px;
                cursor: pointer;
                font-size: 0.8rem;
                font-weight: 600;
            }

            .ui-button:hover {
                border-color: rgba(56, 189, 248, 0.8);
                background: rgba(56, 189, 248, 0.25);
            }

            .export-row {
                display: flex;
                gap: 0.5rem;
                flex-wrap: wrap;
            }

            .dropdown-control .Select-control {
                background: rgba(15, 23, 42, 0.95);
                border: 1px solid rgba(148, 163, 184, 0.6);
                box-shadow: 0 10px 22px rgba(0, 0, 0, 0.4);
                min-height: 44px;
            }

            .dropdown-control .Select-placeholder,

            .dropdown-control .Select-value-label {

                color: #e2e8f0 !important;

                font-size: 0.9rem;

            }

            .dropdown-control .Select-arrow {

                border-top-color: #cbd5f5;

            }

            .dropdown-control .Select-menu-outer {
                background: rgba(15, 23, 42, 0.98);
                border: 1px solid rgba(148, 163, 184, 0.6);
                box-shadow: 0 22px 46px rgba(0, 0, 0, 0.55);
                z-index: 3000;
            }

            .dropdown-control .Select-option {
                background-color: rgba(15, 23, 42, 0.98);
                color: #e2e8f0;
            }

            .dropdown-control .Select-option.is-focused {
                background-color: rgba(56, 189, 248, 0.35);
            }

            .dropdown-control .Select-option.is-selected {
                background-color: rgba(74, 222, 128, 0.4);
            }

            .radio-control {
                display: flex;
                flex-wrap: wrap;
                gap: 0.75rem;
                color: #e2e8f0;
                font-size: 0.9rem;
            }

            .radio-control input {

                accent-color: #38bdf8;

            }

            .overview-grid {

                display: grid;

                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));

                gap: 1rem;

                margin-bottom: 1.25rem;

            }

            .overview-card {

                background: rgba(15, 23, 42, 0.7);

                border: 1px solid rgba(51, 65, 85, 0.5);

                border-radius: 14px;

                padding: 1.1rem 1.25rem;

                box-shadow: 0 18px 36px rgba(15, 23, 42, 0.4);

                display: flex;

                flex-direction: column;

                gap: 0.5rem;

                transition: transform 0.25s ease, box-shadow 0.25s ease;

            }

            .overview-card:hover {

                transform: translateY(-4px);

                box-shadow: 0 22px 40px rgba(15, 23, 42, 0.55);

            }

            .overview-card--primary {

                background: linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(59, 130, 246, 0.15));

                border-color: rgba(96, 165, 250, 0.5);

            }

            .overview-label {

                font-size: 0.7rem;

                letter-spacing: 0.1em;

                text-transform: uppercase;

                color: rgba(203, 213, 225, 0.85);

            }

            .overview-value {

                font-size: 1.4rem;

                font-weight: 600;

                color: #f8fafc;

            }

            .overview-subvalue {

                font-size: 0.9rem;

                color: rgba(226, 232, 240, 0.75);

            }

            .overview-footnote {

                font-size: 0.75rem;

                color: rgba(148, 163, 184, 0.8);

            }

            .dropdown-control .Select-control {
                background: rgba(15, 23, 42, 0.95);
                border: 1px solid rgba(148, 163, 184, 0.6);
                box-shadow: 0 10px 22px rgba(0, 0, 0, 0.4);
            }

            .dropdown-control .Select-placeholder,

            .dropdown-control .Select-value-label {

                color: #e2e8f0 !important;

            }

            .dropdown-control .Select-arrow {

                border-top-color: #e2e8f0;

            }

            .dropdown-control .Select-menu-outer {
                background: rgba(15, 23, 42, 0.95);
                border: 1px solid rgba(148, 163, 184, 0.35);
                box-shadow: 0 18px 40px rgba(15, 23, 42, 0.35);
                z-index: 1500;
            }

            .dropdown-control .Select-option {
                background-color: rgba(15, 23, 42, 0.95);
                color: #e2e8f0;
            }

            .dropdown-control .Select-option.is-focused {
                background-color: rgba(56, 189, 248, 0.25);
            }

            .dropdown-control .Select-option.is-selected {
                background-color: rgba(59, 130, 246, 0.45);
            }

            .radio-control {

                display: flex;

                flex-wrap: wrap;

                gap: 0.6rem;

                color: #e2e8f0;

                font-size: 0.84rem;

            }

            .radio-control input {

                accent-color: #38bdf8;

            }

            .checklist {
                display: flex;
                flex-direction: column;
                gap: 0.35rem;
                font-size: 0.86rem;
            }

            .stats, .legend, .top-list, .path-info, .hook-summary {

                background: rgba(30, 41, 59, 0.7);

                border: 1px solid rgba(148, 163, 184, 0.18);

                border-radius: 14px;

                padding: 0.85rem;

            }

            .hook-summary-grid {

                display: grid;

                gap: 0.6rem;

            }

            .path-table {
                margin-top: 0.35rem;
            }

            .path-table-grid {
                width: 100%;
                border-collapse: collapse;
                font-size: 0.78rem;
                background: rgba(15, 23, 42, 0.65);
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 10px;
                overflow: hidden;
            }

            .path-header {
                text-align: left;
                padding: 0.5rem;
                font-size: 0.7rem;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #94a3b8;
                background: rgba(30, 41, 59, 0.85);
            }

            .path-cell {
                padding: 0.45rem 0.55rem;
                border-top: 1px solid rgba(148, 163, 184, 0.15);
            }

            .path-cell--source {
                font-weight: 600;
                color: #e0f2fe;
            }

            .path-cell--hops {
                width: 3.5rem;
                text-align: center;
                font-variant-numeric: tabular-nums;
            }

            .path-cell--path {
                color: #cbd5f5;
            }

            .path-table-empty {
                font-size: 0.78rem;
                color: #94a3b8;
                background: rgba(30, 41, 59, 0.6);
                border: 1px dashed rgba(148, 163, 184, 0.4);
                padding: 0.65rem;
                border-radius: 10px;
            }

            @media (min-width: 720px) {

                .hook-summary-grid {

                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));

                }

            }

            .hook-block {

                background: rgba(15, 23, 42, 0.5);

                border: 1px solid rgba(148, 163, 184, 0.12);

                border-radius: 12px;

                padding: 0.75rem;

                display: flex;

                flex-direction: column;

                gap: 0.45rem;

            }

            .hook-subtitle {

                font-size: 0.72rem;

                letter-spacing: 0.08em;

                text-transform: uppercase;

                color: #94a3b8;

            }

            .hook-list {

                margin: 0;

                padding-left: 1.1rem;

                display: flex;

                flex-direction: column;

                gap: 0.4rem;

            }

            ul.hook-list {

                list-style: none;

                padding-left: 0;

            }

            .hook-item {

                color: #e2e8f0;

                font-size: 0.88rem;

                display: flex;

                align-items: center;

                justify-content: space-between;

                gap: 0.4rem;

                flex-wrap: wrap;

            }

            .hook-badge-row {

                display: flex;

                gap: 0.3rem;

            }

            .hook-badge {

                display: inline-flex;

                align-items: center;

                padding: 0.12rem 0.45rem;

                border-radius: 9999px;

                font-size: 0.7rem;

                font-weight: 500;

                letter-spacing: 0.05em;

                border: 1px solid rgba(148, 163, 184, 0.25);

                background: rgba(148, 163, 184, 0.18);

                color: #cbd5f5;

            }

            .hook-badge-top {

                background: rgba(34, 197, 94, 0.18);

                border-color: rgba(74, 222, 128, 0.5);

                color: #4ade80;

            }

            .hook-badge-low {

                background: rgba(248, 113, 113, 0.18);

                border-color: rgba(248, 113, 113, 0.4);

                color: #fca5a5;

            }

            .hook-badge-zero {

                background: rgba(148, 163, 184, 0.18);

                border-color: rgba(148, 163, 184, 0.35);

                color: #e2e8f0;

            }

            .hook-name {

                font-weight: 500;

            }

            .hook-count {

                color: #38bdf8;

                font-size: 0.78rem;

                margin-left: 0.35rem;

            }

            .hook-note {

                font-size: 0.75rem;

                color: #94a3b8;

            }

            .metrics {

                display: flex;

                gap: 0.75rem;

                flex-wrap: wrap;

            }

            .metric {

                flex: 1 1 90px;

                display: flex;

                flex-direction: column;

                gap: 0.2rem;

            }

            .metric-title {

                font-size: 0.7rem;

                letter-spacing: 0.05em;

                text-transform: uppercase;

                color: #94a3b8;

            }

            .metric-value {

                font-size: 1.15rem;

                font-weight: 600;

                color: #e2e8f0;

            }

            .legend {

                display: grid;

                gap: 0.4rem 0.8rem;

                grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));

            }

            details {
                background: rgba(15, 23, 42, 0.55);
                border: 1px solid rgba(148, 163, 184, 0.18);
                border-radius: 10px;
                padding: 0.45rem 0.6rem;
            }

            summary {
                cursor: pointer;
                font-size: 0.82rem;
                color: #e2e8f0;
                list-style: none;
            }

            .legend-item {

                display: flex;

                align-items: center;

                gap: 0.45rem;

                font-size: 0.84rem;

            }

            .legend-chip {

                width: 13px;

                height: 13px;

                border-radius: 4px;

                border: 1px solid rgba(226, 232, 240, 0.7);

            }

            .path-controls {

                display: grid;

                gap: 0.45rem;

            }

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

</html>

    """

    return app
