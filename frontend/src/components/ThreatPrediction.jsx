import { BrainCircuit, TrendingUp, ShieldAlert, ChevronRight, Loader2 } from 'lucide-react';

const RISK_COLORS = {
    LOW: '#10b981',
    MEDIUM: '#f59e0b',
    HIGH: '#ef4444',
    CRITICAL: '#dc2626',
};

const RISK_BG = {
    LOW: 'rgba(16, 185, 129, 0.1)',
    MEDIUM: 'rgba(245, 158, 11, 0.1)',
    HIGH: 'rgba(239, 68, 68, 0.1)',
    CRITICAL: 'rgba(220, 38, 38, 0.15)',
};

export default function ThreatPrediction({ prediction, active }) {
    const predictions = prediction?.predictions || [];
    const currentPhase = prediction?.current_phase_name || 'Unknown';
    const cmdCount = prediction?.commands_analyzed || 0;

    return (
        <div className="glass-card overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-neon-purple" />
                <span className="font-[Orbitron] text-xs font-semibold text-neon-purple tracking-wider">
                    AI THREAT PREDICTION
                </span>
                {active && <Loader2 className="w-3 h-3 text-neon-purple animate-spin ml-auto" />}
            </div>

            <div className="p-3">
                {/* Current Phase Indicator */}
                <div className="flex items-center gap-2 mb-3 p-2 rounded-lg bg-neon-purple/5 border border-neon-purple/20">
                    <TrendingUp className="w-3.5 h-3.5 text-neon-purple" />
                    <span className="text-[10px] font-mono text-gray-400">
                        CURRENT PHASE:
                    </span>
                    <span className="text-[10px] font-[Orbitron] font-bold text-neon-purple">
                        {currentPhase.toUpperCase()}
                    </span>
                    <span className="ml-auto text-[10px] font-mono text-gray-600">
                        {cmdCount} cmds analyzed
                    </span>
                </div>

                {/* Predictions */}
                {predictions.length === 0 ? (
                    <div className="text-center py-4 text-gray-600 text-xs font-mono">
                        <BrainCircuit className="w-6 h-6 mx-auto mb-2 opacity-30" />
                        <p>Awaiting attacker activity...</p>
                    </div>
                ) : (
                    <div className="space-y-2">
                        {predictions.map((pred, i) => {
                            const riskColor = RISK_COLORS[pred.risk_level] || RISK_COLORS.MEDIUM;
                            const riskBg = RISK_BG[pred.risk_level] || RISK_BG.MEDIUM;

                            return (
                                <div
                                    key={i}
                                    className={`p-2.5 rounded-xl border transition-all duration-500 animate-fade-in ${i === 0 && pred.risk_level === 'CRITICAL'
                                            ? 'animate-pulse-neon'
                                            : ''
                                        }`}
                                    style={{
                                        background: riskBg,
                                        borderColor: `${riskColor}30`,
                                    }}
                                >
                                    <div className="flex items-center gap-2 mb-1.5">
                                        <ChevronRight className="w-3 h-3" style={{ color: riskColor }} />
                                        <span className="text-xs font-semibold text-white flex-1">
                                            {pred.phase_name}
                                        </span>
                                        <span
                                            className="text-[9px] font-[Orbitron] font-bold px-2 py-0.5 rounded-full"
                                            style={{
                                                color: riskColor,
                                                background: `${riskColor}20`,
                                                border: `1px solid ${riskColor}40`,
                                            }}
                                        >
                                            {pred.risk_level}
                                        </span>
                                    </div>

                                    {/* Confidence Bar */}
                                    <div className="flex items-center gap-2 mb-1.5">
                                        <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
                                            <div
                                                className="h-full rounded-full transition-all duration-1000 ease-out"
                                                style={{
                                                    width: `${pred.confidence}%`,
                                                    background: `linear-gradient(90deg, ${riskColor}80, ${riskColor})`,
                                                    boxShadow: `0 0 8px ${riskColor}60`,
                                                }}
                                            />
                                        </div>
                                        <span className="text-[10px] font-mono font-bold shrink-0" style={{ color: riskColor }}>
                                            {pred.confidence}%
                                        </span>
                                    </div>

                                    <p className="text-[10px] text-gray-400 mb-1">{pred.description}</p>

                                    {/* Countermeasure */}
                                    <div className="flex items-start gap-1.5 mt-1 p-1.5 rounded bg-black/30">
                                        <ShieldAlert className="w-3 h-3 text-neon-cyan shrink-0 mt-0.5" />
                                        <span className="text-[10px] text-neon-cyan/80 font-mono">
                                            {pred.countermeasure}
                                        </span>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
}
