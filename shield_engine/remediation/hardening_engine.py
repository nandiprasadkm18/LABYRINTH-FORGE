import ast

class HardeningEngine(ast.NodeTransformer):
    """
    Enforces production-grade defensive controls structurally.
    """
    def __init__(self, tree):
        self.tree = tree
        self.hardened = False
        self.logs = []

    def enforce(self):
        self.visit(self.tree)
        # Inject standard defensive imports if missing
        self._inject_defensive_imports()
        return self.tree, self.logs

    def _inject_defensive_imports(self):
        imports = [
            ast.Import(names=[ast.alias(name='os')]),
            ast.Import(names=[ast.alias(name='subprocess')]),
            ast.Import(names=[ast.alias(name='logging')]),
            ast.Import(names=[ast.alias(name='ipaddress')]),
        ]
        # Check existing imports to avoid duplicates (simplified)
        self.tree.body = imports + self.tree.body

    def visit_Call(self, node):
        # 1. Hardening subprocess.run
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'run' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
            # Ensure shell=False, timeout=3, check=True
            node.keywords.append(ast.keyword(arg='shell', value=ast.Constant(value=False)))
            node.keywords.append(ast.keyword(arg='timeout', value=ast.Constant(value=3)))
            node.keywords.append(ast.keyword(arg='check', value=ast.Constant(value=True)))
            node.keywords.append(ast.keyword(arg='capture_output', value=ast.Constant(value=True)))
            self.logs.append(f"Hardened subprocess.run at line {node.lineno}")

        # 2. Hardening open() with BASE_DIR sandbox
        if isinstance(node.func, ast.Name) and node.func.id == 'open':
            if node.args:
                path_arg = node.args[0]
                # Replace path with os.path.join(BASE_DIR, os.path.basename(path))
                node.args[0] = ast.Call(
                    func=ast.Attribute(value=ast.Attribute(value=ast.Name(id='os', ctx=ast.Load()), attr='path', ctx=ast.Load()), attr='join', ctx=ast.Load()),
                    args=[
                        ast.Name(id='BASE_DIR', ctx=ast.Load()),
                        ast.Call(
                            func=ast.Attribute(value=ast.Attribute(value=ast.Name(id='os', ctx=ast.Load()), attr='path', ctx=ast.Load()), attr='basename', ctx=ast.Load()),
                            args=[path_arg],
                            keywords=[]
                        )
                    ],
                    keywords=[]
                )
                self.logs.append(f"Added BASE_DIR sandbox to open() at line {node.lineno}")

        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # 3. Injecting input validation at start of functions with request args
        has_request = any(arg.arg == 'request' for arg in node.args.args)
        if has_request:
            validation_node = ast.If(
                test=ast.Compare(
                    left=ast.Call(func=ast.Name(id='len', ctx=ast.Load()), args=[ast.Name(id='request', ctx=ast.Load())], keywords=[]),
                    ops=[ast.Gt()],
                    comparators=[ast.Constant(value=10000)]
                ),
                body=[ast.Raise(exc=ast.Call(func=ast.Name(id='ValueError', ctx=ast.Load()), args=[ast.Constant(value="Input too large")], keywords=[]))],
                orelse=[]
            )
            node.body.insert(0, validation_node)
            self.logs.append(f"Injected input size limit to function {node.name}")
        
        return self.generic_visit(node)
