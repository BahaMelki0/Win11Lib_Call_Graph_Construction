#@category CallGraph

from __future__ import print_function

import json
import os


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)


def function_payload(func):
    entry_point = func.getEntryPoint()
    namespace = func.getParentNamespace()
    if namespace:
        ns_name = namespace.getName(True)
    else:
        ns_name = ""

    return {
        "entry_point": "0x%X" % entry_point.getOffset(),
        "address_space": entry_point.getAddressSpace().getName(),
        "name": func.getName(),
        "qualified_name": func.getName(True),
        "namespace": ns_name,
        "signature": func.getPrototypeString(True, True),
        "is_external": bool(func.isExternal()),
        "calling_convention": func.getCallingConventionName(),
        "source": str(func.getSignatureSource()),
    }


def collect_edges(func, listing):
    edges = []
    instructions = listing.getInstructions(func.getBody(), True)
    while instructions.hasNext():
        instruction = instructions.next()
        flow = instruction.getFlowType()
        if not flow.isCall():
            continue

        destinations = instruction.getFlows()
        if not destinations:
            continue

        for destination in destinations:
            if destination is None:
                continue
            callee = getFunctionAt(destination)
            if callee:
                callee_id = "0x%X" % callee.getEntryPoint().getOffset()
            else:
                callee_id = "0x%X" % destination.getOffset()
            edges.append(callee_id)
    return edges


def main():
    args = getScriptArgs()
    if not args or len(args) < 1:
        raise RuntimeError("Output path argument is required.")

    output_path = args[0]
    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()

    functions = []
    edges = []

    functions_iter = function_manager.getFunctions(True)
    while functions_iter.hasNext():
        func = functions_iter.next()
        func_id = "0x%X" % func.getEntryPoint().getOffset()
        functions.append(function_payload(func))

        for callee_id in collect_edges(func, listing):
            edges.append({"caller": func_id, "callee": callee_id})

    payload = {
        "program": currentProgram.getName(),
        "language_id": str(currentProgram.getLanguageID()),
        "compiler_spec": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        "functions": functions,
        "edges": edges,
    }

    ensure_parent(output_path)
    with open(output_path, "w") as handle:
        json.dump(payload, handle, indent=2)

    print("Call graph exported to %s" % output_path)


if __name__ == "__main__":
    main()
