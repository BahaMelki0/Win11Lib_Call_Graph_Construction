# -*- coding: utf-8 -*-
#@category CallGraph
# Ghidra Jython script: export a per-binary call graph with better import/external handling.
#
# Output format (backward-compatible-ish):
# - functions[]: list of function nodes with metadata
# - edges[]: list of {caller, callee, site, kind}
#
# Key improvements vs original:
# 1) External/import nodes use stable IDs: "IMPORT:<lib>!<symbol>" (no collisions on fake external addresses)
# 2) Call target resolution falls back to instruction references when getFlows() is empty (common for IAT calls)
# 3) Thunks are resolved to their thunked function when possible
# 4) Edges include callsite address ("site") + a coarse "kind" label for debugging/unification

from __future__ import print_function

import json
import os


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)


def addr_hex(addr):
    if addr is None:
        return None
    try:
        return "0x%X" % addr.getOffset()
    except Exception:
        return str(addr)


def function_node_id(func):
    """
    Node identity for a function.

    - Regular/internal functions: entrypoint address ("0x..."), stable within a binary.
    - Imports/external stubs: stable synthetic id "IMPORT:<lib>!<symbol>" derived from the qualified name / namespace.
    """
    # Many imports show up as functions namespaced like:
    #   API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::_initterm
    # even when func.isExternal() is False.
    try:
        qualified = "{}".format(func.getName(True) or "")
    except Exception:
        qualified = ""
    if "::" in qualified:
        prefix = qualified.split("::", 1)[0].strip()
        if prefix and prefix.upper().endswith(".DLL"):
            return import_node_id(prefix, func.getName())

    try:
        namespace = func.getParentNamespace()
        ns_name = namespace.getName(True) if namespace else ""
    except Exception:
        ns_name = ""
    ns = "{}".format(ns_name) if ns_name is not None else ""
    if ns and ns.upper().endswith(".DLL"):
        return import_node_id(ns, func.getName())

    ep = func.getEntryPoint()
    return "0x%X" % ep.getOffset()


def import_node_id(library, symbol):
    lib = (library or "").strip()
    sym = (symbol or "").strip()
    return "IMPORT:{}!{}".format(lib, sym) if lib else "IMPORT:!{}".format(sym)


def function_payload(func):
    entry_point = func.getEntryPoint()
    namespace = func.getParentNamespace()
    ns_name = namespace.getName(True) if namespace else ""

    node_id = function_node_id(func)
    inferred_import = str(node_id).startswith("IMPORT:")

    return {
        "node_id": node_id,
        "entry_point": "0x%X" % entry_point.getOffset(),
        "address_space": entry_point.getAddressSpace().getName(),
        "name": func.getName(),
        "qualified_name": func.getName(True),
        "namespace": ns_name,
        "signature": func.getPrototypeString(True, True),
        "is_external": bool(func.isExternal()) or bool(inferred_import),
        "calling_convention": func.getCallingConventionName(),
        "source": "IMPORTED" if inferred_import else str(func.getSignatureSource()),
        "is_thunk": bool(func.isThunk()),
    }


def external_function_payload(ext_loc):
    """
    Build a stable payload for an imported/external symbol.

    ext_loc is a ghidra.program.model.symbol.ExternalLocation.
    """
    library = ext_loc.getLibraryName() or ""
    label = ext_loc.getLabel() or ""
    if not label:
        return None

    node_id = import_node_id(library, label)

    address = None
    try:
        address = ext_loc.getExternalAddress()
    except Exception:
        address = None

    qualified = "{}!{}".format(library, label) if library else label

    payload = {
        "node_id": node_id,
        "name": label,
        "qualified_name": qualified,
        "namespace": library,
        "signature": "",
        "is_external": True,
        "calling_convention": None,
        "source": "IMPORTED",
    }

    if address is not None:
        payload.update(
            {
                "entry_point": "0x%X" % address.getOffset(),
                "address_space": address.getAddressSpace().getName(),
            }
        )
    else:
        payload.update({"entry_point": None, "address_space": None})

    return payload


def resolve_thunk(func):
    try:
        if func and func.isThunk():
            thunked = func.getThunkedFunction(True)
            if thunked:
                return thunked
    except Exception:
        pass
    return func


def external_location_for_address(addr):
    try:
        ext_mgr = currentProgram.getExternalManager()
        ext_loc = ext_mgr.getExternalLocation(addr)
        if ext_loc:
            lib = ext_loc.getLibraryName() or ""
            lbl = ext_loc.getLabel() or ""
            if lbl:
                return lib, lbl
    except Exception:
        pass
    return None


def callee_id_from_destination(destination):
    if destination is None:
        return None, None

    callee = getFunctionAt(destination)
    if callee:
        callee_id = function_node_id(callee)
        if str(callee_id).startswith("IMPORT:"):
            return callee_id, "import"
        callee = resolve_thunk(callee)
        callee_id = function_node_id(callee)
        if str(callee_id).startswith("IMPORT:"):
            return callee_id, "import"
        return callee_id, "direct"

    ext = external_location_for_address(destination)
    if ext:
        lib, sym = ext
        return import_node_id(lib, sym), "import"

    return "0x%X" % destination.getOffset(), "unknown"


def collect_edges(func, listing):
    """
    Collect call edges for a function.
    Uses direct flow destinations when available, otherwise falls back to references from callsites.
    Returns list of dict edges: {callee, site, kind}
    """
    edges = []
    instructions = listing.getInstructions(func.getBody(), True)
    while instructions.hasNext():
        instruction = instructions.next()
        flow = instruction.getFlowType()
        if not flow.isCall():
            continue

        site = addr_hex(instruction.getAddress())

        destinations = None
        try:
            destinations = instruction.getFlows()
        except Exception:
            destinations = None

        seen = set()

        if destinations:
            for destination in destinations:
                callee_id, kind = callee_id_from_destination(destination)
                if not callee_id:
                    continue
                if callee_id in seen:
                    continue
                seen.add(callee_id)
                edges.append({"callee": callee_id, "site": site, "kind": kind or "direct"})
            continue

        try:
            refs = instruction.getReferencesFrom()
        except Exception:
            refs = []

        for ref in refs:
            try:
                to_addr = ref.getToAddress()
            except Exception:
                to_addr = None
            if to_addr is None:
                continue

            callee_id, kind = callee_id_from_destination(to_addr)
            if not callee_id:
                continue
            if callee_id in seen:
                continue
            seen.add(callee_id)
            if kind == "direct":
                kind = "direct_ref"
            elif kind == "unknown":
                kind = "ref"
            if str(callee_id).startswith("IMPORT:"):
                kind = "import"
            edges.append({"callee": callee_id, "site": site, "kind": kind or "ref"})

    return edges


def main():
    print("[GHIDRA] main() entered")
    args = getScriptArgs()
    print("[GHIDRA] args =", args)
    if not args or len(args) < 1:
        raise RuntimeError("Output path argument is required.")

    # Ghidra headless passes the file to import via the `-import` flag and
    # forwards only the remaining script args to the post script. Accept
    # either a single argument (output path) or two (binary, output).
    if len(args) == 1:
        binary_path = None
        output_path = args[0]
    else:
        binary_path = args[0]
        output_path = args[1]

    print("[GHIDRA] writing to:", output_path)

    try:
        listing = currentProgram.getListing()
        function_manager = currentProgram.getFunctionManager()

        functions = []
        edges = []

        seen_nodes = set()
        seen_import_keys = set()

        functions_iter = function_manager.getFunctions(True)
        while functions_iter.hasNext():
            func = functions_iter.next()

            payload = function_payload(func)
            node_id = payload.get("node_id")
            if node_id and node_id not in seen_nodes:
                seen_nodes.add(node_id)
                functions.append(payload)

            caller_id = node_id or function_node_id(func)
            for edge in collect_edges(func, listing):
                callee_id = edge.get("callee")
                if not callee_id:
                    continue

                if str(callee_id).startswith("IMPORT:") and callee_id not in seen_nodes:
                    try:
                        lib_sym = callee_id[len("IMPORT:") :]
                        lib, sym = lib_sym.split("!", 1) if "!" in lib_sym else ("", lib_sym)
                    except Exception:
                        lib, sym = "", callee_id

                    key = (lib.upper(), sym)
                    if key not in seen_import_keys:
                        seen_import_keys.add(key)
                        qualified = "{}!{}".format(lib, sym) if lib else sym
                        functions.append({
                            "node_id": callee_id,
                            "entry_point": None,
                            "address_space": None,
                            "name": sym,
                            "qualified_name": qualified,
                            "namespace": lib,
                            "signature": "",
                            "is_external": True,
                            "calling_convention": None,
                            "source": "IMPORTED",
                            "is_thunk": False,
                        })
                        seen_nodes.add(callee_id)

                edges.append({
                    "caller": caller_id,
                    "callee": callee_id,
                    "site": edge.get("site"),
                    "kind": edge.get("kind", "call"),
                })

        payload = {
            "schema_version": "1.1",
            "program": currentProgram.getName(),
            "functions": functions,
            "edges": edges,
        }

        ensure_parent(output_path)
        print("[DBG] Writing call graph to:", output_path)

        with open(output_path, "w") as f:
            json.dump(payload, f, indent=2)
            f.flush()

        print("[DBG] Write complete")

    except Exception as e:
        # This guarantees visibility when Ghidra silently fails
        ensure_parent(output_path)
        err_path = output_path + ".error.txt"
        with open(err_path, "w") as f:
            f.write(str(e))
        print("[ERROR] Exception during export:", e)
        raise



if __name__ == "__main__":
    main()
