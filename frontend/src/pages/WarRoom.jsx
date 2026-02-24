import { useState, useRef, useCallback } from 'react';
import AttackerTerminal from '../components/AttackerTerminal';
import NetworkTopology from '../components/NetworkTopology';
import HackerProfile from '../components/HackerProfile';
import DeceptionStatus from '../components/DeceptionStatus';
import SystemCapture from '../components/SystemCapture';
import DecoyFiles from '../components/DecoyFiles';
import HydraMode from '../components/HydraMode';
import KillChainTracker from '../components/KillChainTracker';
import ThreatPrediction from '../components/ThreatPrediction';
import IncidentReport from '../components/IncidentReport';
import { Zap, Radio, Wifi, WifiOff } from 'lucide-react';

export default function WarRoom() {
    const [demoActive, setDemoActive] = useState(false);
    const [liveActive, setLiveActive] = useState(false);
    const [profile, setProfile] = useState({
        threat_level: 0,
        skill_level: 'Unknown',
        frustration_index: 0,
        commands_executed: 0,
        session_duration: 0,
        suspicious_commands: 0,
    });
    const [deceptionPhase, setDeceptionPhase] = useState('');
    const [isolated, setIsolated] = useState(false);
    const [attackerIp, setAttackerIp] = useState(null);
    const [activeNodes, setActiveNodes] = useState(['entry']);
    const [hydraMode, setHydraMode] = useState('ubuntu');
    const [attackIntel, setAttackIntel] = useState(null);
    const [prediction, setPrediction] = useState(null);
    const [reportData, setReportData] = useState(null);
    const wsRef = useRef(null);
    const termRef = useRef(null);

    /* ── Start Live Monitor ── */
    const startLiveMonitor = useCallback(() => {
        if (liveActive || demoActive) return;
        setLiveActive(true);
        setIsolated(false);
        setReportData(null);
        setAttackIntel(null);
        setPrediction(null);
        setDeceptionPhase('🛰️ Awaiting connection from local CLI...');
        setActiveNodes(['entry']);

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(`${protocol}://${window.location.host}/ws/monitor`);
        wsRef.current = ws;

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);

            if (msg.type === 'init') {
                setAttackerIp(msg.attacker_ip);
                termRef.current?.writeln(`\n\x1b[1;36m${'═'.repeat(50)}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;36m  ${msg.message}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;36m${'═'.repeat(50)}\x1b[0m\n`);
                setDeceptionPhase('🟢 Live data stream established');
            }

            if (msg.type === 'command') {
                termRef.current?.writeln(`\x1b[1;32m${msg.prompt}\x1b[0m${msg.command}`);
                if (msg.output) termRef.current?.writeln(msg.output);
                termRef.current?.writeln('');
                if (msg.profile) setProfile(msg.profile);
                if (msg.attack_intel) setAttackIntel(msg.attack_intel);
                if (msg.prediction) setPrediction(msg.prediction);

                if (msg.risk_event) {
                    setDeceptionPhase(`⚠ HIGH RISK COMMAND: ${msg.command.substring(0, 20)}...`);
                }

                // Progress nodes
                const cmdCount = msg.profile?.commands_executed || 0;
                if (cmdCount >= 3) setActiveNodes(prev => [...new Set([...prev, 'honeypot'])]);
                if (cmdCount >= 6) setActiveNodes(prev => [...new Set([...prev, 'fakedb'])]);
                if (cmdCount >= 10) setActiveNodes(prev => [...new Set([...prev, 'internal'])]);
            }

            if (msg.type === 'isolated') {
                setIsolated(true);
                if (msg.report) setReportData(msg.report);
                if (msg.attack_intel) setAttackIntel(msg.attack_intel);
                termRef.current?.writeln(`\n\x1b[1;31m${'═'.repeat(50)}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;31m  ${msg.message}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;31m${'═'.repeat(50)}\x1b[0m\n`);
                setLiveActive(false);
                setDeceptionPhase('🔌 Connection lost');
            }
        };

        ws.onclose = () => {
            setLiveActive(false);
            setDeceptionPhase('🔌 Monitor disconnected');
        };
    }, [liveActive, demoActive]);

    /* ── Start demo simulation ── */
    const startDemo = useCallback(() => {
        if (demoActive) return;
        setDemoActive(true);
        setIsolated(false);
        setReportData(null);
        setAttackIntel(null);
        setPrediction(null);
        setDeceptionPhase('');
        setActiveNodes(['entry']);

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(`${protocol}://${window.location.host}/ws/demo`);
        wsRef.current = ws;

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);

            if (msg.type === 'init') {
                setAttackerIp(msg.attacker_ip);
                termRef.current?.writeln(`\x1b[1;31m⚠  ${msg.message}\x1b[0m\n`);
            }

            if (msg.type === 'command') {
                termRef.current?.writeln(`\x1b[1;32m${msg.prompt}\x1b[0m${msg.command}`);
                if (msg.output) termRef.current?.writeln(msg.output);
                termRef.current?.writeln('');
                if (msg.profile) setProfile(msg.profile);
                if (msg.attack_intel) setAttackIntel(msg.attack_intel);
                if (msg.prediction) setPrediction(msg.prediction);

                // Progress nodes
                const cmdCount = msg.profile?.commands_executed || 0;
                if (cmdCount >= 3) setActiveNodes(prev => [...new Set([...prev, 'honeypot'])]);
                if (cmdCount >= 6) setActiveNodes(prev => [...new Set([...prev, 'fakedb'])]);
                if (cmdCount >= 10) setActiveNodes(prev => [...new Set([...prev, 'internal'])]);
            }

            if (msg.type === 'deception') {
                setDeceptionPhase(msg.message);
            }

            if (msg.type === 'dave') {
                termRef.current?.writeln(`\x1b[1;33m${msg.message}\x1b[0m`);
                if (msg.profile) setProfile(msg.profile);
            }

            if (msg.type === 'isolated') {
                setIsolated(true);
                if (msg.report) setReportData(msg.report);
                if (msg.attack_intel) setAttackIntel(msg.attack_intel);
                termRef.current?.writeln(`\n\x1b[1;31m${'═'.repeat(50)}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;31m  ${msg.message}\x1b[0m`);
                termRef.current?.writeln(`\x1b[1;31m${'═'.repeat(50)}\x1b[0m\n`);
                if (msg.profile) setProfile(msg.profile);
                setDemoActive(false);
            }
        };

        ws.onerror = () => {
            termRef.current?.writeln('\x1b[1;31m[CONNECTION ERROR] Could not reach backend. Make sure the FastAPI server is running on port 8000.\x1b[0m');
            setDemoActive(false);
        };

        ws.onclose = () => {
            setDemoActive(false);
        };
    }, [demoActive]);

    return (
        <div className="max-w-[1600px] mx-auto px-4 py-6">
            {/* ── Header ── */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${demoActive ? 'bg-neon-red animate-pulse' : isolated ? 'bg-neon-green' : 'bg-gray-600'}`} />
                    <h1 className="font-[Orbitron] text-2xl font-bold text-white text-glow-blue">WAR ROOM</h1>
                    {attackerIp && (
                        <span className="font-mono text-sm text-neon-red ml-4">
                            <Wifi className="w-4 h-4 inline mr-1" />
                            Attacker: {attackerIp}
                        </span>
                    )}
                </div>

                <div className="flex items-center gap-3">
                    <HydraMode mode={hydraMode} onModeChange={setHydraMode} />

                    <button
                        className={`btn-neon ${liveActive ? 'btn-neon-blue active' : 'btn-neon-blue'} flex items-center gap-2`}
                        onClick={startLiveMonitor}
                        disabled={liveActive || demoActive}
                    >
                        <Radio className={`w-4 h-4 ${liveActive ? 'animate-pulse' : ''}`} />
                        {liveActive ? 'Monitor Connected' : 'Connect Local CLI'}
                    </button>

                    <button
                        className={`btn-neon ${demoActive ? 'btn-neon-red' : 'btn-neon-green'} flex items-center gap-2`}
                        onClick={startDemo}
                        disabled={demoActive || liveActive}
                    >
                        {demoActive ? (
                            <><Radio className="w-4 h-4 animate-pulse" /> Simulation Running...</>
                        ) : (
                            <><Zap className="w-4 h-4" /> Start Demo Simulation</>
                        )}
                    </button>
                </div>
            </div>

            {/* ── Kill Chain Tracker (Full Width) ── */}
            {attackIntel && (
                <div className="mb-4 animate-slide-up">
                    <KillChainTracker attackIntel={attackIntel} />
                </div>
            )}

            {/* ── Dashboard Grid ── */}
            <div className="grid grid-cols-12 gap-4">
                {/* Left: Terminal */}
                <div className="col-span-12 lg:col-span-7">
                    <AttackerTerminal ref={termRef} mode={hydraMode} />
                </div>

                {/* Right: Panels */}
                <div className="col-span-12 lg:col-span-5 space-y-4">
                    <HackerProfile profile={profile} />
                    <ThreatPrediction prediction={prediction} active={demoActive || liveActive} />
                    <DeceptionStatus phase={deceptionPhase} active={demoActive} />
                    <SystemCapture isolated={isolated} profile={profile} />
                </div>

                {/* Bottom: Network + Decoys / Report */}
                <div className="col-span-12 lg:col-span-7">
                    <NetworkTopology activeNodes={activeNodes} />
                </div>

                <div className="col-span-12 lg:col-span-5">
                    {isolated && reportData ? (
                        <IncidentReport report={reportData} />
                    ) : (
                        <DecoyFiles />
                    )}
                </div>
            </div>
        </div>
    );
}
