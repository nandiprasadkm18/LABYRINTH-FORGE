import { ShieldCheck, ShieldAlert, FileText, Clock, Activity } from 'lucide-react';

export default function SystemCapture({ isolated, profile }) {
    return (
        <div className={`glass-card overflow-hidden transition-all duration-500 ${isolated ? 'border-neon-green/50 shadow-[0_0_30px_rgba(16,185,129,0.2)]' : ''}`}>
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                {isolated ? (
                    <ShieldCheck className="w-4 h-4 text-neon-green" />
                ) : (
                    <ShieldAlert className="w-4 h-4 text-gray-500" />
                )}
                <span className={`font-[Orbitron] text-xs font-semibold tracking-wider ${isolated ? 'text-neon-green' : 'text-gray-500'}`}>
                    SYSTEM CAPTURE
                </span>
            </div>

            <div className="p-4">
                {isolated ? (
                    <div className="animate-slide-up">
                        {/* Isolation Alert */}
                        <div className="text-center mb-4 p-4 rounded-xl bg-neon-green/10 border border-neon-green/30">
                            <ShieldCheck className="w-10 h-10 text-neon-green mx-auto mb-2" />
                            <div className="font-[Orbitron] text-lg font-bold text-neon-green text-glow-green">HACKER ISOLATED</div>
                            <div className="text-sm text-gray-400 mt-1">Threat Neutralized • Logs Captured</div>
                        </div>

                        {/* Session Stats */}
                        <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                                <Activity className="w-3.5 h-3.5 text-neon-blue" />
                                <span className="text-gray-400">Commands: <span className="text-white font-semibold">{profile.commands_executed}</span></span>
                            </div>
                            <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                                <Clock className="w-3.5 h-3.5 text-neon-cyan" />
                                <span className="text-gray-400">Duration: <span className="text-white font-semibold">{profile.session_duration}s</span></span>
                            </div>
                            <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3 col-span-2">
                                <FileText className="w-3.5 h-3.5 text-neon-purple" />
                                <span className="text-gray-400">Data exfiltrated: <span className="text-neon-green font-semibold">0 bytes (all decoy)</span></span>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="text-center py-6 text-gray-600 text-sm font-mono">
                        <ShieldAlert className="w-8 h-8 mx-auto mb-2 opacity-30" />
                        <p>No active capture</p>
                        <p className="text-xs mt-1">Waiting for threat isolation...</p>
                    </div>
                )}
            </div>
        </div>
    );
}
