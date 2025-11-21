"""Dash application offering a smooth single-page call graph explorer."""



from __future__ import annotations



from functools import lru_cache
import math

from pathlib import Path

from typing import Dict, Iterable, List, Tuple, Optional



import dash

import dash_cytoscape as cyto

from dash import Dash, Input, Output, State, dcc, html

import networkx as nx
import igraph as ig

from call_graph_win11.analysis.graph_loader import load_call_graph, to_igraph



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


def _list_graph_files(base_dir: Path, excluded: set[Path] | None = None) -> List[Path]:

    base_dir = base_dir.expanduser().resolve()
    results: List[Path] = []
    excluded_resolved = {path.resolve() for path in excluded} if excluded else set()
    for path in base_dir.rglob("*.callgraph.json"):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in excluded_resolved:
            continue
        results.append(resolved)
    return sorted(results)





@lru_cache(maxsize=256)

def _load_graph(path: str) -> Tuple["ig.Graph", nx.DiGraph]:

    nx_graph = load_call_graph(Path(path))
    ig_graph = to_igraph(nx_graph)
    return ig_graph, nx_graph





def _subset_graph(graph: "ig.Graph", limit: int | None) -> Tuple["ig.Graph", set[str]]:
    if limit is None or graph.vcount() <= limit:
        return graph, set(graph.vs["node_id"])

    degrees = graph.degree()
    ranked_indices = sorted(range(len(degrees)), key=lambda idx: degrees[idx], reverse=True)[:limit]
    subgraph = graph.subgraph(ranked_indices)
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


def _create_elements(
    graph: "ig.Graph",
    colors: Dict[str, str],
    search_term: str,
    highlight_nodes: Iterable[str],
    highlight_edges: Iterable[Tuple[str, str]],
    size_map: Optional[Dict[str, float]] = None,
    focus_nodes: Optional[set[str]] = None,
    prefix_program: bool = False,
) -> Tuple[List[dict], List[dict]]:
    nodes: List[dict] = []
    edges: List[dict] = []
    term_lower = (search_term or "").strip().lower()
    highlight_node_set = set(highlight_nodes)
    highlight_edge_set = set(highlight_edges)
    size_lookup = size_map or {}
    focus_nodes = focus_nodes or set()

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
                    "calling_convention": _vertex_attr(vertex, "calling_convention"),
                    "is_external": bool(_vertex_attr(vertex, "is_external")),
                    "color": colors.get(program, colors["unknown"]),
                    "search_match": term_lower in label.lower() if term_lower else False,
                    "path_highlight": node_id in highlight_node_set,
                    "path_focus": node_id in focus_nodes,
                    "size": size_value,
                    "hub": is_hub,
                    "degree": vertex.degree(),
                }
            }
        )

    for idx, (source_idx, target_idx) in enumerate(graph.get_edgelist()):
        source_id = graph.vs[source_idx]["node_id"]
        target_id = graph.vs[target_idx]["node_id"]
        edges.append(
            {
                "data": {
                    "id": f"main-edge-{idx}",
                    "source": source_id,
                    "target": target_id,
                    "path_highlight": (source_id, target_id) in highlight_edge_set,
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
            vertex["node_id"]
            for vertex in graph.vs
            if _vertex_attr(vertex, "is_external")
        }
        nodes_to_keep &= external_nodes

    if not nodes_to_keep:
        return graph.subgraph([]), set()

    if nodes_to_keep == set(graph.vs["node_id"]):
        return graph, nodes_to_keep

    indices = [vertex.index for vertex in graph.vs if vertex["node_id"] in nodes_to_keep]
    subgraph = graph.subgraph(indices)
    return subgraph, set(subgraph.vs["node_id"])


def create_app(data_dir: Path, *, default_limit: int = 320, excluded_paths: set[Path] | None = None) -> Dash:

    data_dir = data_dir.expanduser().resolve()

    graph_files = _list_graph_files(data_dir, excluded=excluded_paths)

    if not graph_files:

        raise FileNotFoundError(f"No *.callgraph.json files found under {data_dir}")



    graph_options = [

        {"label": str(path.relative_to(data_dir)), "value": str(path.resolve())} for path in graph_files

    ]



    external_stylesheets = [
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
    ]
    app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

    app.title = "Windows Call Graph Explorer"



    app.layout = html.Div(

        [

            html.Div(

                [

                    html.Div(

                        [

                            html.H1("Windows Call Graph Explorer", className="title"),

                            html.P(

                                "Browse symbol-enriched call graphs exported from Ghidra.",

                                className="subtitle",

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

                            html.Label("Max nodes"),

                            dcc.Slider(

                                id="node-limit",

                                min=50,

                                max=1500,

                                step=50,

                                value=default_limit,

                                tooltip={"placement": "bottom", "always_visible": True},

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(

                        [

                            html.Label("Highlight"),

                            dcc.Input(

                                id="search-term",

                                type="text",

                                placeholder="Function name fragment...",

                                debounce=True,

                                style={"zIndex": 1100},

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

                            html.Label("Filters"),

                            dcc.Checklist(

                                id="filters",

                                options=[

                                    {"label": "Only exported APIs", "value": "external"},

                                ],

                                value=[],

                                className="checklist",

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(

                        [

                            html.Label("Inbound depth"),

                            dcc.Slider(

                                id="focus-depth",

                                min=1,

                                max=6,

                                step=1,

                                value=3,

                                tooltip={"placement": "bottom", "always_visible": True},

                            ),

                        ],

                        className="control",

                    ),

                    html.Div(

                        [

                            html.H3("Path inspector", className="section-title"),

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
                                        "color": "#e2e8f0",
                                        "text-outline-color": "rgba(15,23,42,0.85)",
                                        "text-outline-width": "2px",
                                        "font-size": "9px",
                                        "width": "data(size)",
                                        "height": "data(size)",
                                        "border-width": "1px",
                                        "border-color": "rgba(248,250,252,0.6)",
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
                                    "selector": "node[search_match = true]",
                                    "style": {
                                        "border-width": 4,
                                        "border-color": "#facc15",
                                        "shadow-blur": 16,
                                        "shadow-color": "rgba(250, 204, 21, 0.8)",
                                        "shadow-opacity": 1.0,
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
        Output("call-graph", "elements"),
        Output("call-graph", "layout"),
        Output("path-info", "children"),
        Output("focus-info", "children"),
        Output("path-table", "children"),
        Output("path-start", "options"),
        Output("path-end", "options"),
        Output("path-start", "value"),
        Output("path-end", "value"),
        Input("graph-file", "value"),
        Input("node-limit", "value"),
        Input("search-term", "value"),
        Input("filters", "value"),
        Input("layout-mode", "value"),
        Input("node-size-mode", "value"),
        Input("focus-depth", "value"),
        Input("path-start", "value"),
        Input("path-end", "value"),
        Input("path-mode", "value"),
    )
    def update_graph(
        path_value: str,
        node_limit: int,
        search_term: str,
        filters: List[str],
        layout_mode: str,
        size_mode: str,
        focus_depth: int,
        start_node: str | None,
        end_node: str | None,
        path_mode: List[str],
    ) -> Tuple[
        List[dict],
        dict,
        str,
        str,
        html.Div,
        List[dict],
        List[dict],
        str | None,
        str | None,
    ]:
        ig_graph, nx_graph = _load_graph(path_value)
        subset_graph, subset_nodes = _subset_graph(ig_graph, node_limit)
        filtered_graph, filtered_node_ids = _filter_graph(subset_graph, filters or [])

        colors = _program_colors(_vertex_attr(vertex, "program", "unknown") for vertex in filtered_graph.vs)

        total_nodes = filtered_graph.vcount()
        degree_values = filtered_graph.degree() if total_nodes else []
        size_mode = size_mode or "fixed"
        size_map: Optional[Dict[str, float]] = None
        if total_nodes:
            if size_mode == "degree":
                min_deg = min(degree_values)
                max_deg = max(degree_values)
                if max_deg == min_deg:
                    size_value = 28.0
                    size_map = {vertex["node_id"]: size_value for vertex in filtered_graph.vs}
                else:
                    size_map = {}
                    for vertex, degree in zip(filtered_graph.vs, degree_values):
                        norm = (degree - min_deg) / (max_deg - min_deg)
                        size_map[vertex["node_id"]] = 18.0 + norm * 28.0
            else:
                size_map = {vertex["node_id"]: 22.0 for vertex in filtered_graph.vs}

        highlight_nodes: set[str] = set()
        highlight_edges: set[Tuple[str, str]] = set()
        vertex_index = {vertex["node_id"]: vertex.index for vertex in filtered_graph.vs}

        path_text = "Select a start and focus function to view shortest paths."
        focus_info = "Select a focus function to inspect inbound callers."
        path_table_children: html.Div = html.Div(
            "Select a focus function to list inbound paths.", className="path-table path-table-empty"
        )
        path_only = "path-only" in (path_mode or [])
        path_node_ids: List[str] = []

        focus_candidates: list[tuple[int, float]] = []
        if end_node and end_node in vertex_index:
            highlight_nodes.add(end_node)
            reverse_graph = filtered_graph.copy()
            reverse_graph.reverse_edges()
            distances = reverse_graph.shortest_paths(vertex_index[end_node], mode="OUT")[0]
            focus_vertex_indices = [
                idx for idx, dist in enumerate(distances) if not math.isinf(dist) and dist <= focus_depth
            ]
            if focus_vertex_indices:
                focus_subgraph = filtered_graph.subgraph(focus_vertex_indices)
                focus_node_ids = focus_subgraph.vs["node_id"]
                highlight_nodes.update(focus_node_ids)
                for src_idx, dst_idx in focus_subgraph.get_edgelist():
                    highlight_edges.add((focus_subgraph.vs[src_idx]["node_id"], focus_subgraph.vs[dst_idx]["node_id"]))
                target_vertex = filtered_graph.vs[vertex_index[end_node]]
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
                vpath = filtered_graph.get_shortest_paths(idx, to=vertex_index[end_node], mode="OUT")
                if not vpath or not vpath[0]:
                    continue
                node_ids = [filtered_graph.vs[vid]["node_id"] for vid in vpath[0]]
                labels = []
                for vid in vpath[0]:
                    vertex = filtered_graph.vs[vid]
                    labels.append(
                        _vertex_attr(vertex, "name")
                        or _vertex_attr(vertex, "qualified_name")
                        or _vertex_attr(vertex, "address")
                        or vertex["node_id"]
                    )
                source_label = labels[0]
                hops = len(node_ids) - 1
                path_rows.append(
                    html.Tr(
                        [
                            html.Td(source_label, className="path-cell path-cell--source"),
                            html.Td(f"{hops}", className="path-cell path-cell--hops"),
                            html.Td(" → ".join(labels[:8]), className="path-cell path-cell--path"),
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
                                    html.Th("Path", className="path-header"),
                                ]
                            )
                        ),
                        html.Tbody(path_rows),
                    ],
                    className="path-table-grid",
                )
                path_table_children = html.Div(table, className="path-table")

        if start_node and end_node and start_node in vertex_index and end_node in vertex_index:
            highlight_nodes.add(start_node)
            if start_node == end_node:
                path_text = "Start and focus functions are identical."
                path_node_ids = [start_node]
            else:
                shortest = filtered_graph.get_shortest_paths(vertex_index[start_node], to=vertex_index[end_node], mode="OUT")
                if shortest and shortest[0]:
                    vertex_path = shortest[0]
                    path_node_ids = [filtered_graph.vs[idx]["node_id"] for idx in vertex_path]
                    path_text = f"Shortest path length: {len(path_node_ids) - 1} hops."
                else:
                    path_text = "No forward path found; showing inbound callers only."
        elif end_node:
            path_text = "Select a start function to compute a path."

        if path_node_ids:
            highlight_nodes.update(path_node_ids)
            highlight_edges.update((path_node_ids[i], path_node_ids[i + 1]) for i in range(len(path_node_ids) - 1))

        focus_nodes = set(path_node_ids)

        graph_for_render = filtered_graph
        if path_only and path_node_ids:
            indices = [vertex_index[n] for n in path_node_ids if n in vertex_index]
            graph_for_render = filtered_graph.subgraph(indices)

        prefix_program = len(colors.keys()) > 1
        nodes, edges = _create_elements(
            graph_for_render,
            colors,
            search_term or "",
            highlight_nodes,
            highlight_edges,
            size_map=size_map,
            focus_nodes=focus_nodes,
            prefix_program=prefix_program,
        )

        filtered_node_ids_sorted = sorted(filtered_node_ids)
        options = []
        for node_id in filtered_node_ids_sorted:
            if node_id not in vertex_index:
                continue
            vertex = filtered_graph.vs[vertex_index[node_id]]
            label = (
                _vertex_attr(vertex, "name")
                or _vertex_attr(vertex, "qualified_name")
                or _vertex_attr(vertex, "address")
                or node_id
            )
            options.append({"label": label, "value": node_id})

        start_value = start_node if start_node in filtered_node_ids else None
        end_value = end_node if end_node in filtered_node_ids else None

        layout_config = dict(LAYOUT_PRESETS.get(layout_mode, LAYOUT_PRESETS["cose"]))
        layout_config.setdefault("padding", 30)
        if layout_config.get("name") == "cose":
            layout_config.setdefault("animate", True)
            layout_config.setdefault("randomize", False)

        return (
            nodes + edges,
            layout_config,
            path_text,
            focus_info,
            path_table_children,
            options,
            options,
            start_value,
            end_value,
        )
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
