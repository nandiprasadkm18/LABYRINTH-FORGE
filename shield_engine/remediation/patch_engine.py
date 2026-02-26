import ast

class PatchEngine(ast.NodeTransformer):
    """
    Autonomously refactors insecure sinks into secure versions.
    """
    def __init__(self, code):
        self.code = code
        self.tree = ast.parse(code)
        self.remediations = []

    def remediate(self):
        self.visit(self.tree)
        # Use ast.unparse (Python 3.9+)
        try:
            return ast.unparse(self.tree), self.remediations
        except AttributeError:
            # Fallback for older python or if unparse is picky
            return self.code, ["AST Rewriting failed (unparse error)"]

    def visit_Call(self, node):
        # 1. SQL Injection Remediation (CWE-89)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                # Detect and refactor to parameterized query
                new_node = self._refactor_sql_execute(node)
                if new_node != node:
                    self.remediations.append(f"SQLi Fix: Parameterized line {node.lineno}")
                    return new_node

        # 2. Command Injection Remediation (CWE-78)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'system' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
            # os.system(cmd) -> subprocess.run([cmd], shell=False)
            self.remediations.append(f"CMDi Fix: Replaced os.system with subprocess.run at line {node.lineno}")
            return ast.Call(
                func=ast.Attribute(value=ast.Name(id='subprocess', ctx=ast.Load()), attr='run', ctx=ast.Load()),
                args=[ast.List(elts=[node.args[0]], ctx=ast.Load())],
                keywords=[ast.keyword(arg='check', value=ast.Constant(value=True))]
            )

        return self.generic_visit(node)

    def _refactor_sql_execute(self, node):
        """
        Attempts to transform f-string SQL into parameterized tuples.
        """
        query_arg = node.args[0]
        params = []
        
        if isinstance(query_arg, ast.JoinedStr):
            new_parts = []
            for part in query_arg.values:
                if isinstance(part, ast.FormattedValue):
                    new_parts.append("%s")
                    params.append(part.value)
                elif isinstance(part, ast.Constant):
                    new_parts.append(str(part.value))
            
            new_query = "".join(new_parts)
            return ast.Call(
                func=node.func,
                args=[
                    ast.Constant(value=new_query),
                    ast.Tuple(elts=params, ctx=ast.Load())
                ],
                keywords=node.keywords
            )
        return node
