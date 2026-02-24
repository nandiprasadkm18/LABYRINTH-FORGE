import { useMemo } from 'react';
import {
    Shield, Brain, Network, Eye, Bug, Layers, BarChart3,
    ChevronDown, Zap, Lock, Server, Cpu, Activity, Terminal
} from 'lucide-react';

/* ── Matrix rain characters ── */
function MatrixRain() {
    const cols = useMemo(() => {
        return Array.from({ length: 40 }, (_, i) => ({
            left: `${(i / 40) * 100}%`,
            delay: `${Math.random() * 5}s`,
            duration: `${3 + Math.random() * 5}s`,
            chars: Array.from({ length: 20 }, () =>
                String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96))
            ).join('\n'),
        }));
    }, []);
    return (
        <div className="matrix-rain">
            {cols.map((c, i) => (
                <span key={i} style={{ left: c.left, animationDelay: c.delay, animationDuration: c.duration, whiteSpace: 'pre' }}>
                    {c.chars}
                </span>
            ))}
        </div>
    );
}

/* ── Feature card ── */
function FeatureCard({ icon: Icon, title, desc, color }) {
    const colorMap = {
        blue: 'text-neon-blue border-neon-blue/30 hover:border-neon-blue/60 hover:shadow-[0_0_30px_rgba(59,130,246,0.15)]',
        green: 'text-neon-green border-neon-green/30 hover:border-neon-green/60 hover:shadow-[0_0_30px_rgba(16,185,129,0.15)]',
        purple: 'text-neon-purple border-neon-purple/30 hover:border-neon-purple/60 hover:shadow-[0_0_30px_rgba(139,92,246,0.15)]',
        cyan: 'text-neon-cyan border-neon-cyan/30 hover:border-neon-cyan/60 hover:shadow-[0_0_30px_rgba(6,182,212,0.15)]',
        pink: 'text-neon-pink border-neon-pink/30 hover:border-neon-pink/60 hover:shadow-[0_0_30px_rgba(236,72,153,0.15)]',
        amber: 'text-neon-amber border-neon-amber/30 hover:border-neon-amber/60 hover:shadow-[0_0_30px_rgba(245,158,11,0.15)]',
    };
    return (
        <div className={`glass-card p-6 border ${colorMap[color]} transition-all duration-300 opacity-0 animate-slide-up`}>
            <Icon className={`w-10 h-10 mb-4 ${colorMap[color].split(' ')[0]}`} />
            <h3 className="font-[Orbitron] text-base font-semibold text-white mb-2">{title}</h3>
            <p className="text-gray-400 text-sm leading-relaxed">{desc}</p>
        </div>
    );
}

export default function LandingPage({ onNavigate }) {
    return (
        <div className="relative">
            {/* ═══ Hero ═══ */}
            <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
                <MatrixRain />
                {/* Radial gradient overlay */}
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyber-bg/50 to-cyber-bg pointer-events-none z-[1]" />

                <div className="relative z-[2] text-center px-6 max-w-5xl mx-auto">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-neon-green/30 bg-neon-green/5 mb-8 animate-fade-in">
                        <Activity className="w-4 h-4 text-neon-green animate-pulse" />
                        <span className="text-neon-green text-sm font-mono">SYSTEM ACTIVE — ALL DEFENSES ONLINE</span>
                    </div>

                    <h1 className="font-[Orbitron] text-5xl sm:text-7xl font-black text-white mb-6 leading-tight animate-slide-up">
                        <span className="text-glow-blue">LABYRINTH</span>{' '}
                        <span className="text-glow-purple">FORGE</span>
                    </h1>

                    <p className="text-xl sm:text-2xl text-gray-300 mb-4 font-light animate-slide-up" style={{ animationDelay: '0.2s' }}>
                        AI-Powered Active Defense Engine
                    </p>
                    <p className="text-gray-500 max-w-2xl mx-auto mb-10 animate-slide-up" style={{ animationDelay: '0.3s' }}>
                        Lure, deceive, and neutralize cyber threats with generative AI honeypots,
                        polymorphic deception, and real-time attacker profiling.
                    </p>

                    <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-slide-up" style={{ animationDelay: '0.4s' }}>
                        <button className="btn-neon" onClick={() => onNavigate('warroom')}>
                            <span className="flex items-center gap-2"><Zap className="w-4 h-4" /> Enter War Room</span>
                        </button>
                        <button className="btn-neon btn-neon-green" onClick={() => onNavigate('devsecops')}>
                            <span className="flex items-center gap-2"><Bug className="w-4 h-4" /> DevSecOps Shield</span>
                        </button>
                    </div>

                    {/* Scroll hint */}
                    <div className="absolute bottom-10 left-1/2 -translate-x-1/2 animate-float">
                        <ChevronDown className="w-6 h-6 text-gray-500" />
                    </div>
                </div>
            </section>

            {/* ═══ Problem Statement ═══ */}
            <section className="relative z-10 py-24 px-6">
                <div className="max-w-6xl mx-auto">
                    <div className="text-center mb-16">
                        <h2 className="font-[Orbitron] text-3xl font-bold text-white mb-4 text-glow-blue">THE PROBLEM</h2>
                        <p className="text-gray-400 max-w-3xl mx-auto text-lg">
                            Traditional cybersecurity is reactive — by the time you detect a breach, the damage is done.
                            Attackers dwell undetected for an average of <span className="text-neon-red font-semibold">197 days</span>.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        {[
                            { val: '197', label: 'Avg days to detect a breach', c: 'text-neon-red' },
                            { val: '$4.5M', label: 'Avg cost of a data breach', c: 'text-neon-amber' },
                            { val: '83%', label: 'Companies breached more than once', c: 'text-neon-purple' },
                        ].map((s, i) => (
                            <div key={i} className="glass-card p-8 text-center">
                                <div className={`font-[Orbitron] text-4xl font-black ${s.c} mb-2`}>{s.val}</div>
                                <div className="text-gray-400 text-sm">{s.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══ Solution ═══ */}
            <section className="relative z-10 py-24 px-6">
                <div className="max-w-6xl mx-auto">
                    <div className="text-center mb-16">
                        <h2 className="font-[Orbitron] text-3xl font-bold text-white mb-4 text-glow-green">THE SOLUTION</h2>
                        <p className="text-gray-400 max-w-3xl mx-auto text-lg">
                            Labyrinth Forge flips the script — using generative AI to build intelligent deception environments
                            that trap, profile, and neutralize attackers in real-time.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 stagger-children">
                        <FeatureCard icon={Brain} title="AI Honeypot Engine" desc="Generative AI creates hyper-realistic fake systems that adapt to attacker behavior in real-time." color="blue" />
                        <FeatureCard icon={Eye} title="Attacker Profiling" desc="Psychological analysis of attacker typing patterns, command sequences, and frustration levels." color="green" />
                        <FeatureCard icon={Network} title="Network Deception" desc="Dynamic topology that moves, morphs, and expands the deception surface with every attacker action." color="purple" />
                        <FeatureCard icon={Layers} title="Polymorphic Hosts" desc="Switch between Ubuntu, Windows Server, and IoT device simulations on the fly." color="cyan" />
                        <FeatureCard icon={Lock} title="Honey Tokens" desc="Deploy convincing fake credentials, AWS keys, and config files that trigger alerts on use." color="pink" />
                        <FeatureCard icon={BarChart3} title="DevSecOps Shield" desc="AI-powered vulnerability scanning that detects flaws, simulates exploits, and generates patches." color="amber" />
                    </div>
                </div>
            </section>

            {/* ═══ Architecture Diagram ═══ */}
            <section className="relative z-10 py-24 px-6">
                <div className="max-w-5xl mx-auto">
                    <h2 className="font-[Orbitron] text-3xl font-bold text-white mb-12 text-center text-glow-purple">ARCHITECTURE</h2>
                    <div className="glass-card p-8 font-mono text-sm text-gray-300 overflow-x-auto">
                        <pre className="leading-relaxed">{`
  ┌──────────────────────────────────────────────────────────────┐
  │                    LABYRINTH FORGE PLATFORM                  │
  ├──────────────────────────────────────────────────────────────┤
  │                                                              │
  │   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
  │   │   ATTACKER   │───▶│   HONEYPOT    │───▶│  AI ENGINE   │   │
  │   │   (SSH/Web)  │    │   Gateway     │    │  (Mock LLM)  │   │
  │   └─────────────┘    └──────────────┘    └──────────────┘   │
  │          │                   │                    │          │
  │          ▼                   ▼                    ▼          │
  │   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
  │   │  KEYSTROKE   │    │   DECEPTION   │    │   PROFILER   │   │
  │   │  CAPTURE     │    │   SURFACE     │    │   & TURING   │   │
  │   └─────────────┘    └──────────────┘    └──────────────┘   │
  │          │                   │                    │          │
  │          ▼                   ▼                    ▼          │
  │   ┌────────────────────────────────────────────────────┐    │
  │   │              WAR ROOM DASHBOARD (React)             │    │
  │   │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐   │    │
  │   │  │Terminal │  │Network │  │Profile │  │Capture │   │    │
  │   │  │  View   │  │Topology│  │Analysis│  │ Panel  │   │    │
  │   │  └────────┘  └────────┘  └────────┘  └────────┘   │    │
  │   └────────────────────────────────────────────────────┘    │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
            `}</pre>
                    </div>
                </div>
            </section>

            {/* ═══ Business Model ═══ */}
            <section className="relative z-10 py-24 px-6">
                <div className="max-w-6xl mx-auto">
                    <h2 className="font-[Orbitron] text-3xl font-bold text-white mb-12 text-center text-glow-blue">BUSINESS MODEL</h2>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        {[
                            {
                                tier: 'Starter',
                                price: '$499/mo',
                                features: ['1 Honeypot Instance', 'Basic Profiling', 'Email Alerts', '5 Decoy Files'],
                                color: 'neon-cyan',
                            },
                            {
                                tier: 'Professional',
                                price: '$1,499/mo',
                                features: ['5 Honeypot Instances', 'Advanced AI Profiling', 'Real-time Dashboard', 'Hydra Mode', 'DevSecOps Shield'],
                                color: 'neon-blue',
                                popular: true,
                            },
                            {
                                tier: 'Enterprise',
                                price: 'Custom',
                                features: ['Unlimited Instances', 'Custom Deception Playbooks', 'SIEM Integration', 'Dedicated Support', 'On-Prem Deployment'],
                                color: 'neon-purple',
                            },
                        ].map((plan, i) => (
                            <div key={i} className={`glass-card p-8 border ${plan.popular ? `border-${plan.color}/50 shadow-[0_0_40px_rgba(59,130,246,0.15)]` : `border-${plan.color}/20`} relative`}>
                                {plan.popular && (
                                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 py-1 bg-neon-blue rounded-full text-xs font-[Orbitron] font-bold tracking-wider">
                                        MOST POPULAR
                                    </div>
                                )}
                                <h3 className={`font-[Orbitron] text-lg font-bold text-${plan.color} mb-2`}>{plan.tier}</h3>
                                <div className="font-[Orbitron] text-3xl font-black text-white mb-6">{plan.price}</div>
                                <ul className="space-y-3 mb-8">
                                    {plan.features.map((f, j) => (
                                        <li key={j} className="flex items-center gap-2 text-gray-400 text-sm">
                                            <Zap className={`w-4 h-4 text-${plan.color}`} />
                                            {f}
                                        </li>
                                    ))}
                                </ul>
                                <button className={`btn-neon w-full ${plan.popular ? '' : 'btn-neon-purple'}`}>
                                    Get Started
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══ CTA ═══ */}
            <section className="relative z-10 py-24 px-6">
                <div className="max-w-3xl mx-auto text-center">
                    <div className="glass-card p-12 border border-neon-blue/30">
                        <Terminal className="w-12 h-12 text-neon-blue mx-auto mb-6" />
                        <h2 className="font-[Orbitron] text-2xl font-bold text-white mb-4">See It In Action</h2>
                        <p className="text-gray-400 mb-8">
                            Launch the War Room and watch a live attack simulation — from intrusion to isolation.
                        </p>
                        <button className="btn-neon btn-neon-green text-lg" onClick={() => onNavigate('warroom')}>
                            <span className="flex items-center gap-2"><Zap className="w-5 h-5" /> Launch War Room</span>
                        </button>
                    </div>
                </div>
            </section>

            {/* ═══ Footer ═══ */}
            <footer className="relative z-10 py-8 border-t border-white/5 text-center text-gray-600 text-sm font-mono">
                <p>LABYRINTH FORGE © 2024 — AI-Powered Active Defense Platform</p>
            </footer>
        </div>
    );
}
