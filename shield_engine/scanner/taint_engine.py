import ast

class TaintEngine:
    """
    Analyzes whether user-controlled data (sources) reaches dangerous sinks.
    """
    def __init__(self, tree):
        self.tree = tree
        self.user_sources = set()
        self.tainted_vars = set()

    def analyze(self):
        self._find_sources()
        self._track_taint()
        return self.tainted_vars

    def _find_sources(self):
        # Identify common sources of user input in Flask/Django
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == 'request':
                    if node.attr in ['args', 'form', 'json', 'values', 'cookies']:
                        # This is a source attribute access
                        pass
            
            if isinstance(node, ast.Assign):
                # Track assignments from request attributes
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        if isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'request':
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.user_sources.add(target.id)

    def _track_taint(self):
        self.tainted_vars = self.user_sources.copy()
        
        # Simple one-pass taint propagation
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                # If RHS has a tainted variable, mark LHS as tainted
                rhs_vars = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                if any(v in self.tainted_vars for v in rhs_vars):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)

    def is_tainted(self, node):
        """Checks if an AST node contains any tainted variables."""
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Name) and subnode.id in self.tainted_vars:
                return True
        return False
