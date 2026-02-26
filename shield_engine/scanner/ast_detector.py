import ast
import logging

class ASTDetector(ast.NodeVisitor):
    """
    Scans Python AST for dangerous sinks and maps them to CWE IDs.
    """
    def __init__(self, code):
        self.code = code
        self.tree = ast.parse(code)
        self.findings = []
        self.lines = code.split('\n')

    def detect(self):
        self.visit(self.tree)
        return self.findings

    def visit_Call(self, node):
        # 1. SQL Injection Sinks (cursor.execute with f-strings or concat)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    self.findings.append({
                        "id": "CWE-89",
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "line": node.lineno,
                        "vector": "Database Execute Sink",
                        "description": "User-controlled data is being concatenated into a SQL query.",
                        "snippet": self.lines[node.lineno-1].strip()
                    })

        # 2. Command Injection Sinks (os.system, subprocess.run with shell=True)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.findings.append({
                    "id": "CWE-78",
                    "type": "Command Injection",
                    "severity": "CRITICAL",
                    "line": node.lineno,
                    "vector": "os.system Sink",
                    "description": "Executing OS commands directly via shell with potentially untrusted input.",
                    "snippet": self.lines[node.lineno-1].strip()
                })
        
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.findings.append({
                "id": "CWE-95",
                "type": "Code Injection",
                "severity": "CRITICAL",
                "line": node.lineno,
                "vector": "eval() Sink",
                "description": "Evaluation of arbitrary strings as code can lead to remote code execution.",
                "snippet": self.lines[node.lineno-1].strip()
            })

        # 3. Insecure Deserialization (pickle.loads)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'loads':
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                self.findings.append({
                    "id": "CWE-502",
                    "type": "Insecure Deserialization",
                    "severity": "CRITICAL",
                    "line": node.lineno,
                    "vector": "pickle.loads Sink",
                    "description": "Deserializing untrusted data with pickle can lead to RCE.",
                    "snippet": self.lines[node.lineno-1].strip()
                })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # 4. Hardcoded Secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                key_names = ['api_key', 'password', 'secret', 'token', 'passwd']
                if any(k in target.id.lower() for k in key_names):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 8: # Avoid short false positives
                            self.findings.append({
                                "id": "CWE-798",
                                "type": "Hardcoded Credentials",
                                "severity": "HIGH",
                                "line": node.lineno,
                                "vector": "Static Assignment",
                                "description": f"Sensitive key '{target.id}' assigned a static string value.",
                                "snippet": self.lines[node.lineno-1].strip()
                            })
        
        # 5. Missing Input Validation (Checks if a variable from request attributes is used without validation)
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == 'request':
            self.findings.append({
                "id": "CWE-20",
                "type": "Missing Input Validation",
                "severity": "MEDIUM",
                "line": node.lineno,
                "vector": "Request Attribute Access",
                "description": "User-controlled data accessed without strict type or length validation.",
                "snippet": self.lines[node.lineno-1].strip()
            })
        self.generic_visit(node)

    def visit_withitem(self, node):
        # 6. Insecure File Access (lack of BASE_DIR or absolute path checks)
        if isinstance(node.context_expr, ast.Call) and isinstance(node.context_expr.func, ast.Name) and node.context_expr.func.id == 'open':
            if node.context_expr.args:
                arg = node.context_expr.args[0]
                if not self._is_wrapped_in_sandbox(arg):
                    self.findings.append({
                        "id": "CWE-22",
                        "type": "Improper Filesystem Sandbox",
                        "severity": "HIGH",
                        "line": node.context_expr.lineno,
                        "vector": "open() Sink",
                        "description": "File access detected without visible BASE_DIR or path traversal protection.",
                        "snippet": self.lines[node.context_expr.lineno-1].strip()
                    })
        self.generic_visit(node)

    def _is_wrapped_in_sandbox(self, node):
        """Checks if a path argument is wrapped in abspath or joined with a BASE_DIR."""
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Call):
                if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == 'abspath':
                    return True
            if isinstance(subnode, ast.Name) and "BASE_DIR" in subnode.id:
                return True
        return False
