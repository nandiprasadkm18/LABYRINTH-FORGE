import { FileText, Table, Image, Key, Shield, Database, FolderOpen } from 'lucide-react';

const ICON_MAP = {
    'file-text': FileText,
    'table': Table,
    'image': Image,
    'key': Key,
    'shield': Shield,
    'database': Database,
};

const STATUS_COLORS = {
    'deployed': 'text-neon-blue bg-neon-blue/10 border-neon-blue/30',
    'active-lure': 'text-neon-amber bg-neon-amber/10 border-neon-amber/30 animate-pulse-neon',
};

const decoys = [
    { name: 'Q3_Financials.pdf', type: 'pdf', size: '2.4 MB', status: 'deployed', icon: 'file-text' },
    { name: 'passwords.xlsx', type: 'excel', size: '156 KB', status: 'deployed', icon: 'table' },
    { name: 'network_diagram.png', type: 'image', size: '890 KB', status: 'deployed', icon: 'image' },
    { name: 'aws_credentials.bak', type: 'config', size: '512 B', status: 'active-lure', icon: 'key' },
    { name: 'prod.env', type: 'config', size: '1.1 KB', status: 'active-lure', icon: 'shield' },
    { name: 'db_dump_2024.sql.gz', type: 'database', size: '234 MB', status: 'deployed', icon: 'database' },
];

export default function DecoyFiles() {
    return (
        <div className="glass-card overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 bg-black/30 flex items-center gap-2">
                <FolderOpen className="w-4 h-4 text-neon-amber" />
                <span className="font-[Orbitron] text-xs font-semibold text-neon-amber tracking-wider">MULTI-MODAL DECOYS</span>
            </div>

            <div className="p-3 space-y-1.5 max-h-[280px] overflow-y-auto">
                {decoys.map((file, i) => {
                    const Icon = ICON_MAP[file.icon] || FileText;
                    return (
                        <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg bg-white/3 hover:bg-white/5 transition-colors">
                            <div className="p-1.5 rounded-lg bg-white/5">
                                <Icon className="w-4 h-4 text-gray-400" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="text-sm text-white font-mono truncate">{file.name}</div>
                                <div className="text-[10px] text-gray-500">{file.type.toUpperCase()} • {file.size}</div>
                            </div>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${STATUS_COLORS[file.status]}`}>
                                {file.status === 'active-lure' ? '🎣 LURE' : '✓ DEPLOYED'}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
