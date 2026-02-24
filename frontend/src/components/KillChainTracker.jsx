import { useState } from 'react';
import { Crosshair, ChevronRight, Shield, Zap, Lock, Key, Database, Eye, X } from 'lucide-react';

const PHASE_ICONS = {
    recon: Eye,
    initial_access: Zap,
    execution: Zap,
    persistence: Lock,
    priv_esc: Shield,
    credential_access: Key,
    collection: Database,
};

export default function KillChainTracker({ attackIntel }) {
    const [expandedPhase, setExpandedPhase] = useState(null);
    const killChain = attackIntel?.kill_chain || [];
    const totalTechniques = attackIntel?.total_techniques || 0;
    const activeCount = killChain.filter(p => p.active).length;

    return (
        <div className="glass-card overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-neon-red" />
                <span className="font-[Orbitron] text-xs font-semibold text-neon-red tracking-wider">
                    MITRE ATT&CK KILL CHAIN
                </span>
                <div className="ml-auto flex items-center gap-3 text-[10px] font-mono">
                    <span className="text-gray-500">
                        PHASES: <span className="text-neon-red font-bold">{activeCount}/{killChain.length}</span>
                    </span>
                    <span className="text-gray-500">
                        TTPs: <span className="text-neon-amber font-bold">{totalTechniques}</span>
                    </span>
                </div>
            </div>

            {/* Kill Chain Progress Bar */}
            <div className="p-4">
                <div className="flex items-stretch gap-1">
                    {killChain.map((phase, i) => {
                        const Icon = PHASE_ICONS[phase.id] || Eye;
                        const isActive = phase.active;
                        const isExpanded = expandedPhase === phase.id;

                        return (
                            <div key={phase.id} className="flex items-stretch flex-1">
                                <button
                                    onClick={() => setExpandedPhase(isExpanded ? null : phase.id)}
                                    className={`
                                        relative flex-1 flex flex-col items-center justify-center p-2 rounded-lg
                                        transition-all duration-500 cursor-pointer group min-h-[72px]
                                        ${isActive
                                            ? 'border border-opacity-60'
                                            : 'border border-white/5 bg-white/[0.02]'
                                        }
                                    `}
                                    style={isActive ? {
                                        background: `linear-gradient(135deg, ${phase.color}15, ${phase.color}08)`,
                                        borderColor: `${phase.color}60`,
                                        boxShadow: `0 0 20px ${phase.color}20, inset 0 0 20px ${phase.color}05`,
                                    } : {}}
                                >
                                    {/* Pulse ring for active */}
                                    {isActive && (
                                        <div
                                            className="absolute inset-0 rounded-lg animate-pulse-neon opacity-30"
                                            style={{ border: `1px solid ${phase.color}` }}
                                        />
                                    )}

                                    <Icon
                                        className="w-4 h-4 mb-1 transition-all duration-300"
                                        style={{ color: isActive ? phase.color : '#4b5563' }}
                                    />
                                    <span
                                        className="text-[9px] font-[Orbitron] font-bold tracking-wider text-center leading-tight"
                                        style={{ color: isActive ? phase.color : '#6b7280' }}
                                    >
                                        {phase.name.split(' ').slice(0, 2).join(' ')}
                                    </span>
                                    {isActive && phase.technique_count > 0 && (
                                        <span
                                            className="mt-1 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-full"
                                            style={{
                                                background: `${phase.color}25`,
                                                color: phase.color,
                                            }}
                                        >
                                            {phase.technique_count} TTP{phase.technique_count > 1 ? 's' : ''}
                                        </span>
                                    )}
                                </button>
                                {i < killChain.length - 1 && (
                                    <div className="flex items-center px-0.5">
                                        <ChevronRight className="w-3 h-3 text-gray-700" />
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>

                {/* Expanded Technique Details */}
                {expandedPhase && (() => {
                    const phase = killChain.find(p => p.id === expandedPhase);
                    if (!phase || !phase.techniques?.length) return null;
                    return (
                        <div className="mt-3 p-3 rounded-xl bg-black/40 border border-white/5 animate-fade-in">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-[10px] font-[Orbitron] font-bold tracking-wider" style={{ color: phase.color }}>
                                    {phase.name} — TECHNIQUES OBSERVED
                                </span>
                                <button onClick={() => setExpandedPhase(null)} className="text-gray-500 hover:text-white cursor-pointer">
                                    <X className="w-3 h-3" />
                                </button>
                            </div>
                            <div className="space-y-1">
                                {phase.techniques.map((t, i) => (
                                    <div key={i} className="flex items-center gap-2 text-xs font-mono p-1.5 rounded bg-white/[0.03]">
                                        <span className="font-bold shrink-0" style={{ color: phase.color }}>
                                            {t.technique_id}
                                        </span>
                                        <span className="text-gray-400">{t.technique_name}</span>
                                        <span className="ml-auto text-gray-600 text-[10px] truncate max-w-[120px]">
                                            {t.command}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    );
                })()}
            </div>
        </div>
    );
}
