import ast
import sys

filename = sys.argv[1]

with open(filename, "r", encoding="utf-8-sig") as f:
    tree = ast.parse(f.read())

functions = [node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
print(f"Functions in {filename}: {functions}")