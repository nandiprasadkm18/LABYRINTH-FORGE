import ast

DANGEROUS_SINKS = [
    "exec",
    "eval",
    "pickle.loads",
    "os.system"
]

class VulnerabilityScanner(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.issues = []
        self.source_lines = source_lines

    def get_snippet(self, lineno):
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno-1].strip()
        return "Unknown Context"

    def visit_Call(self, node):
        full_name = self.get_name(node.func)
        name = full_name.split('.')[-1] # Get 'execute' from 'cursor.execute'

        # 1. CRITICAL: Unsafe Sinks (Always Blocked)
        if full_name in DANGEROUS_SINKS or name in ["exec", "eval"]:
            self.issues.append({
                "line": node.lineno,
                "type": "CRITICAL",
                "sink": full_name or name,
                "snippet": self.get_snippet(node.lineno)
            })

        # 2. SQL Injection: Check any 'execute' call for f-strings
        if name in ["execute", "executemany"]:
            if any(isinstance(arg, ast.JoinedStr) for arg in node.args):
                self.issues.append({
                    "line": node.lineno,
                    "type": "CRITICAL",
                    "sink": f"SQL Injection ({full_name})",
                    "snippet": self.get_snippet(node.lineno)
                })

        # 3. XSS: Check render_template_string for direct injection
        if name == "render_template_string":
            # Check positional args AND keyword args for f-strings
            unsafe = any(isinstance(arg, ast.JoinedStr) for arg in node.args)
            unsafe = unsafe or any(isinstance(kw.value, ast.JoinedStr) for kw in node.keywords)
            
            if unsafe:
                self.issues.append({
                    "line": node.lineno,
                    "type": "HIGH",
                    "sink": "Potential XSS (Template Injection)",
                    "snippet": self.get_snippet(node.lineno)
                })

        # 4. Command Injection: Only flag subprocess if shell=True is present
        if name in ["run", "call", "Popen", "check_output"]:
            # Only check if it looks like a subprocess call
            if full_name.startswith("subprocess.") or full_name == name:
                is_unsafe = False
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        is_unsafe = True
                
                if is_unsafe:
                    self.issues.append({
                        "line": node.lineno,
                        "type": "CRITICAL",
                        "sink": f"{full_name} (shell=True detected)",
                        "snippet": self.get_snippet(node.lineno)
                    })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # f-strings are allowed in assignments (logs, etc.), so we no longer flag them globally.
        self.generic_visit(node)

    def get_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self.get_name(node.value)}.{node.attr}"
        return ""
        

def scan(code):
    try:
        source_lines = code.splitlines()
        tree = ast.parse(code)
        scanner = VulnerabilityScanner(source_lines)
        scanner.visit(tree)
        return scanner.issues
    except Exception as e:
        return [{"type": "PARSE_ERROR", "line": 0, "sink": str(e), "snippet": "File parsing failed"}]
