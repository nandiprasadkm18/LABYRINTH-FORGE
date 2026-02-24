import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from 'recharts';
import { UserX, Brain, Flame, Clock, AlertTriangle, Terminal } from 'lucide-react';

function GaugeMini({ value, max, color, label }) {
    const data = [{ value, fill: color }];
    return (
        <div className="flex flex-col items-center">
            <div className="w-20 h-20 relative">
                <ResponsiveContainer width="100%" height="100%">
                    <RadialBarChart
                        innerRadius="70%"
                        outerRadius="100%"
                        data={data}
                        startAngle={210}
                        endAngle={-30}
                        barSize={6}
                    >
                        <PolarAngleAxis type="number" domain={[0, max]} tick={false} angleAxisId={0} />
                        <RadialBar
                            className="gauge-ring"
                            dataKey="value"
                            cornerRadius={10}
                            background={{ fill: 'rgba(255,255,255,0.05)' }}
                            angleAxisId={0}
                        />
                    </RadialBarChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex items-center justify-center">
                    <span className="font-[Orbitron] text-sm font-bold text-white">{value}</span>
                </div>
            </div>
            <span className="text-[10px] text-gray-500 mt-1 font-mono">{label}</span>
        </div>
    );
}

export default function HackerProfile({ profile }) {
    const { threat_level, skill_level, frustration_index, commands_executed, session_duration, suspicious_commands } = profile;

    const threatColor = threat_level > 70 ? '#ef4444' : threat_level > 40 ? '#f59e0b' : '#10b981';
    const frustColor = frustration_index > 60 ? '#ef4444' : frustration_index > 30 ? '#f59e0b' : '#3b82f6';

    return (
        <div className="glass-card overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                <UserX className="w-4 h-4 text-neon-red" />
                <span className="font-[Orbitron] text-xs font-semibold text-neon-red tracking-wider">HACKER PROFILE</span>
            </div>

            <div className="p-4">
                {/* Gauges Row */}
                <div className="flex items-center justify-around mb-4">
                    <GaugeMini value={threat_level} max={100} color={threatColor} label="THREAT" />
                    <GaugeMini value={frustration_index} max={100} color={frustColor} label="FRUSTRATION" />
                    <GaugeMini value={commands_executed} max={50} color="#8b5cf6" label="COMMANDS" />
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                        <Brain className="w-3.5 h-3.5 text-neon-purple" />
                        <div>
                            <div className="text-gray-500">Skill Level</div>
                            <div className="text-white font-semibold">{skill_level}</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                        <Clock className="w-3.5 h-3.5 text-neon-cyan" />
                        <div>
                            <div className="text-gray-500">Duration</div>
                            <div className="text-white font-semibold">{session_duration}s</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                        <AlertTriangle className="w-3.5 h-3.5 text-neon-amber" />
                        <div>
                            <div className="text-gray-500">Suspicious</div>
                            <div className="text-white font-semibold">{suspicious_commands} cmds</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-white/3">
                        <Flame className="w-3.5 h-3.5 text-neon-red" />
                        <div>
                            <div className="text-gray-500">Threat</div>
                            <div className="font-semibold" style={{ color: threatColor }}>{threat_level > 70 ? 'CRITICAL' : threat_level > 40 ? 'MODERATE' : 'LOW'}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
