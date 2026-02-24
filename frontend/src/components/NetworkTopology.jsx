import { useMemo, useCallback } from 'react';
import {
    ReactFlow,
    Background,
    Controls,
    Handle,
    Position,
    useNodesState,
    useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Server, Database, Shield, Globe, MonitorSmartphone } from 'lucide-react';

/* ── Custom Node ── */
function CyberNode({ data }) {
    const Icon = data.icon;
    const isActive = data.active;
    const colors = {
        entry: { border: '#ef4444', shadow: 'rgba(239,68,68,0.4)', text: '#fca5a5' },
        honeypot: { border: '#f59e0b', shadow: 'rgba(245,158,11,0.4)', text: '#fcd34d' },
        fakedb: { border: '#8b5cf6', shadow: 'rgba(139,92,246,0.4)', text: '#c4b5fd' },
        internal: { border: '#10b981', shadow: 'rgba(16,185,129,0.4)', text: '#6ee7b7' },
    };
    const c = colors[data.nodeType] || colors.honeypot;

    return (
        <div
            className="px-4 py-3 rounded-xl border text-center min-w-[140px]"
            style={{
                background: isActive ? 'rgba(17,24,39,0.9)' : 'rgba(17,24,39,0.5)',
                borderColor: isActive ? c.border : 'rgba(75,85,99,0.4)',
                boxShadow: isActive ? `0 0 20px ${c.shadow}` : 'none',
                transition: 'all 0.5s ease',
            }}
        >
            <Handle type="target" position={Position.Left} style={{ background: c.border, width: 8, height: 8 }} />
            <Handle type="source" position={Position.Right} style={{ background: c.border, width: 8, height: 8 }} />
            <Icon className="w-6 h-6 mx-auto mb-1" style={{ color: isActive ? c.border : '#6b7280' }} />
            <div className="font-[Orbitron] text-xs font-semibold" style={{ color: isActive ? c.text : '#9ca3af' }}>
                {data.label}
            </div>
            {isActive && (
                <div className="text-[10px] mt-1 font-mono" style={{ color: c.border }}>
                    ● ACTIVE
                </div>
            )}
        </div>
    );
}

const nodeTypes = { cyber: CyberNode };

export default function NetworkTopology({ activeNodes = [] }) {
    const initialNodes = useMemo(() => [
        { id: 'entry', type: 'cyber', position: { x: 50, y: 120 }, data: { label: 'Entry Node', icon: Globe, nodeType: 'entry', active: activeNodes.includes('entry') } },
        { id: 'honeypot', type: 'cyber', position: { x: 280, y: 50 }, data: { label: 'Honeypot', icon: Shield, nodeType: 'honeypot', active: activeNodes.includes('honeypot') } },
        { id: 'fakedb', type: 'cyber', position: { x: 280, y: 190 }, data: { label: 'Fake DB', icon: Database, nodeType: 'fakedb', active: activeNodes.includes('fakedb') } },
        { id: 'internal', type: 'cyber', position: { x: 520, y: 120 }, data: { label: 'Internal Server', icon: Server, nodeType: 'internal', active: activeNodes.includes('internal') } },
    ], [activeNodes]);

    const initialEdges = useMemo(() => [
        { id: 'e1', source: 'entry', target: 'honeypot', animated: activeNodes.includes('honeypot'), style: { stroke: activeNodes.includes('honeypot') ? '#f59e0b' : '#374151', strokeWidth: 2 } },
        { id: 'e2', source: 'entry', target: 'fakedb', animated: activeNodes.includes('fakedb'), style: { stroke: activeNodes.includes('fakedb') ? '#8b5cf6' : '#374151', strokeWidth: 2 } },
        { id: 'e3', source: 'honeypot', target: 'internal', animated: activeNodes.includes('internal'), style: { stroke: activeNodes.includes('internal') ? '#10b981' : '#374151', strokeWidth: 2 } },
        { id: 'e4', source: 'fakedb', target: 'internal', animated: activeNodes.includes('internal'), style: { stroke: activeNodes.includes('internal') ? '#10b981' : '#374151', strokeWidth: 2 } },
    ], [activeNodes]);

    return (
        <div className="glass-card overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                <MonitorSmartphone className="w-4 h-4 text-neon-purple" />
                <span className="font-[Orbitron] text-xs font-semibold text-neon-purple tracking-wider">NETWORK TOPOLOGY</span>
            </div>
            <div className="h-[300px]">
                <ReactFlow
                    nodes={initialNodes}
                    edges={initialEdges}
                    nodeTypes={nodeTypes}
                    fitView
                    proOptions={{ hideAttribution: true }}
                    panOnDrag={false}
                    zoomOnScroll={false}
                    zoomOnDoubleClick={false}
                    nodesDraggable={false}
                    nodesConnectable={false}
                >
                    <Background color="#1e293b" gap={20} size={1} />
                </ReactFlow>
            </div>
        </div>
    );
}
