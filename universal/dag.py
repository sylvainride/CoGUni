"""Iterative graph validation independent of Python's recursion limit."""
from collections import deque


def topological_order(dependencies):
    nodes = set(dependencies)
    children = {node: [] for node in nodes}
    degrees = {}
    for node, parents in dependencies.items():
        parents = set(parents)
        if not parents <= nodes:
            raise ValueError("unknown dependency")
        degrees[node] = len(parents)
        for parent in parents:
            children[parent].append(node)
    queue = deque(sorted(node for node in nodes if degrees[node] == 0))
    order = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for child in children[node]:
            degrees[child] -= 1
            if degrees[child] == 0:
                queue.append(child)
    if len(order) != len(nodes):
        raise ValueError("dependency cycle")
    return order
