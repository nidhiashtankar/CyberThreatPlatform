import React, { useState, useMemo } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, Info } from 'lucide-react';

export default function GraphVisualizer({ graphData, isLoading }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [zoom, setZoom] = useState(1);

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  // Compute 2D node coordinates in a circular/force layout
  const layoutNodes = useMemo(() => {
    if (!nodes.length) return [];
    const width = 700;
    const height = 450;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.38;

    return nodes.map((node, index) => {
      // Position central hubs closer to center, entities along circle
      const isAlert = node.type === 'alert';
      const angle = (2 * Math.PI * index) / nodes.length;
      const r = isAlert ? radius * 0.65 : radius;
      const x = centerX + r * Math.cos(angle);
      const y = centerY + r * Math.sin(angle);

      return {
        ...node,
        x: Math.round(x),
        y: Math.round(y),
      };
    });
  }, [nodes]);

  const nodeMap = useMemo(() => {
    const map = {};
    layoutNodes.forEach(n => { map[n.id] = n; });
    return map;
  }, [layoutNodes]);

  if (isLoading) {
    return (
      <div className="h-80 flex flex-col items-center justify-center bg-slate-50 border border-slate-200 rounded-xl text-slate-500">
        <Network className="w-8 h-8 text-blue-500 animate-spin mb-2" />
        <span className="text-sm font-medium">Synthesizing NetworkX intelligence graph...</span>
      </div>
    );
  }

  if (!nodes.length) {
    return (
      <div className="h-72 flex flex-col items-center justify-center bg-slate-50 border border-slate-200 rounded-xl text-slate-500 p-6 text-center">
        <Info className="w-8 h-8 text-slate-400 mb-2" />
        <p className="text-sm font-medium text-slate-700">No Relationship Graph Available</p>
        <p className="text-xs text-slate-500 mt-1 max-w-sm">
          Link alerts with source IPs, user accounts, or deception tokens to generate multi-hop entity relationships.
        </p>
      </div>
    );
  }

  const getNodeColor = (type) => {
    switch (type) {
      case 'ip': return { bg: '#fee2e2', border: '#ef4444', text: '#991b1b', dot: '#dc2626' }; // Red
      case 'user': return { bg: '#ede9fe', border: '#8b5cf6', text: '#5b21b6', dot: '#7c3aed' }; // Purple
      case 'honeytoken': return { bg: '#ffe4e6', border: '#f43f5e', text: '#9f1239', dot: '#e11d48' }; // Rose
      case 'target': return { bg: '#e0f2fe', border: '#0284c7', text: '#0369a1', dot: '#0284c7' }; // Sky
      case 'url': return { bg: '#fef3c7', border: '#d97706', text: '#92400e', dot: '#b45309' }; // Amber
      case 'alert': return { bg: '#f1f5f9', border: '#64748b', text: '#334155', dot: '#475569' }; // Slate
      default: return { bg: '#f8fafc', border: '#94a3b8', text: '#1e293b', dot: '#64748b' };
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
      {/* Controls Header */}
      <div className="px-4 py-3 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-blue-600" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">
            NetworkX Entity-Relationship Graph ({nodes.length} nodes, {edges.length} edges)
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setZoom(z => Math.min(1.5, z + 0.1))}
            className="p-1.5 rounded bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 shadow-2xs"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom(z => Math.max(0.6, z - 0.1))}
            className="p-1.5 rounded bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 shadow-2xs"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => { setZoom(1); setSelectedNode(null); }}
            className="p-1.5 rounded bg-white border border-slate-200 hover:bg-slate-100 text-slate-600 shadow-2xs"
            title="Reset View"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* SVG Canvas Area */}
      <div className="relative bg-slate-50/40 p-2 overflow-auto" style={{ minHeight: '440px' }}>
        <svg
          viewBox="0 0 700 450"
          className="w-full h-auto max-h-[460px] mx-auto transition-transform duration-150"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
        >
          {/* Edges */}
          <g className="edges">
            {edges.map((edge, i) => {
              const src = nodeMap[edge.source];
              const tgt = nodeMap[edge.target];
              if (!src || !tgt) return null;

              const midX = (src.x + tgt.x) / 2;
              const midY = (src.y + tgt.y) / 2;

              return (
                <g key={`edge-${i}`} className="group">
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke="#cbd5e1"
                    strokeWidth="1.8"
                    strokeDasharray={edge.relationship === 'COMMUNICATED_WITH' ? '4,3' : 'none'}
                    className="group-hover:stroke-blue-500 transition-colors"
                  />
                  {/* Relationship pill */}
                  <rect
                    x={midX - 35}
                    y={midY - 8}
                    width="70"
                    height="16"
                    rx="8"
                    fill="#ffffff"
                    stroke="#e2e8f0"
                    strokeWidth="1"
                    className="shadow-2xs"
                  />
                  <text
                    x={midX}
                    y={midY + 3}
                    textAnchor="middle"
                    fill="#64748b"
                    fontSize="8.5"
                    fontWeight="600"
                    className="select-none pointer-events-none"
                  >
                    {edge.relationship}
                  </text>
                </g>
              );
            })}
          </g>

          {/* Nodes */}
          <g className="nodes">
            {layoutNodes.map((node) => {
              const colors = getNodeColor(node.type);
              const isSelected = selectedNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNode(node)}
                  className="cursor-pointer group"
                >
                  {/* Outer circle badge */}
                  <circle
                    r={isSelected ? 24 : 20}
                    fill={colors.bg}
                    stroke={isSelected ? '#2563eb' : colors.border}
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-all duration-150 shadow-xs group-hover:filter group-hover:brightness-95"
                  />
                  <circle
                    r="4"
                    fill={colors.dot}
                  />
                  {/* Node Label */}
                  <text
                    y="32"
                    textAnchor="middle"
                    fill="#1e293b"
                    fontSize="10"
                    fontWeight="600"
                    className="select-none pointer-events-none"
                  >
                    {node.label.length > 22 ? `${node.label.slice(0, 20)}...` : node.label}
                  </text>
                  <text
                    y="43"
                    textAnchor="middle"
                    fill="#64748b"
                    fontSize="8"
                    fontWeight="500"
                    className="select-none uppercase tracking-wider"
                  >
                    {node.type}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:max-w-xs bg-white border border-slate-200 rounded-lg p-3 shadow-md text-xs">
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
              <span className="font-semibold text-slate-800">Node Inspector</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-600 font-bold"
              >
                ×
              </button>
            </div>
            <div className="mt-2 space-y-1">
              <div><span className="text-slate-500 font-medium">Identifier:</span> <span className="font-mono text-slate-900">{selectedNode.id}</span></div>
              <div><span className="text-slate-500 font-medium">Type:</span> <span className="capitalize text-slate-900 font-semibold">{selectedNode.type}</span></div>
              <div><span className="text-slate-500 font-medium">Role:</span> <span className="text-slate-700">{selectedNode.role}</span></div>
              <div><span className="text-slate-500 font-medium">Label:</span> <span className="text-slate-900">{selectedNode.label}</span></div>
              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div className="mt-1 pt-1 border-t border-slate-100">
                  <span className="text-slate-500">Metadata:</span>
                  <pre className="mt-0.5 bg-slate-50 p-1 rounded text-[10px] text-slate-700 overflow-x-auto">
                    {JSON.stringify(selectedNode.metadata, null, 1)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Legend Footer */}
      <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center gap-3 text-xs text-slate-600">
        <span className="font-semibold text-slate-700">Node Legend:</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500" /> Attacker IP
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> User Account
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Honeytoken Decoy
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-sky-500" /> Target Host
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-slate-500" /> Detector Alert
        </span>
      </div>
    </div>
  );
}
