import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, AlertTriangle, Activity, Bell, RefreshCw, ArrowRight, CheckCircle2 } from 'lucide-react';
import api from '../services/api';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import RiskTierBadge from '../components/RiskTierBadge';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      setRefreshing(true);
      const data = await api.getStats();
      setStats(data);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Failed to load dashboard statistics:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // Controlled polling interval (10 seconds)
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-slate-500">
        <Activity className="w-8 h-8 text-blue-600 animate-spin mb-3" />
        <p className="text-sm font-medium">Loading Security Operations Center Telemetry...</p>
      </div>
    );
  }

  const tierDist = stats?.risk_tier_distribution || { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const totalTierIncidents = Object.values(tierDist).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">SOC Command Center</h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Real-time security events, automated correlation, risk scoring, and multi-vector threat detection.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">
            Last updated: <span className="font-mono text-slate-700">{lastUpdated || 'Never'}</span>
          </span>
          <button
            onClick={fetchStats}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 shadow-2xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-blue-600' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Correlated Incidents"
          value={stats?.total_incidents || 0}
          subtitle="Aggregated multi-vector campaigns"
          icon={Shield}
          color="blue"
        />
        <StatCard
          title="Active Open Incidents"
          value={stats?.active_incidents || 0}
          subtitle="Currently open or under investigation"
          icon={Activity}
          color="amber"
        />
        <StatCard
          title="High / Critical Threats"
          value={stats?.high_critical_incidents || 0}
          subtitle="Prioritized for automated response"
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Ingested Alert Stream"
          value={stats?.total_alerts || 0}
          subtitle={`Across ${stats?.total_events || 0} security events`}
          icon={Bell}
          color="indigo"
        />
      </div>

      {/* Two Column Layout: Risk Distribution & Detector Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Card */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
          <h2 className="text-base font-semibold text-slate-900 mb-1">Incident Risk Tier Distribution</h2>
          <p className="text-xs text-slate-500 mb-6">Current breakdown of categorized incidents</p>

          <div className="space-y-4">
            {[
              { label: 'Critical Risk', count: tierDist.Critical, color: 'bg-red-500', barBg: 'bg-red-100', text: 'text-red-700' },
              { label: 'High Risk', count: tierDist.High, color: 'bg-orange-500', barBg: 'bg-orange-100', text: 'text-orange-700' },
              { label: 'Medium Risk', count: tierDist.Medium, color: 'bg-amber-500', barBg: 'bg-amber-100', text: 'text-amber-700' },
              { label: 'Low Risk', count: tierDist.Low, color: 'bg-emerald-500', barBg: 'bg-emerald-100', text: 'text-emerald-700' },
            ].map((tier) => {
              const pct = Math.round((tier.count / totalTierIncidents) * 100);
              return (
                <div key={tier.label}>
                  <div className="flex justify-between items-center text-xs mb-1">
                    <span className="font-medium text-slate-700">{tier.label}</span>
                    <span className="font-semibold text-slate-900">{tier.count} ({pct}%)</span>
                  </div>
                  <div className={`h-2 rounded-full overflow-hidden ${tier.barBg}`}>
                    <div
                      className={`h-full rounded-full ${tier.color} transition-all duration-300`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Deterministic Scoring Algorithm</span>
            <span className="font-semibold text-blue-600">0 - 100 Scale</span>
          </div>
        </div>

        {/* Contributing Detectors Activity */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Detection Modules Breakdown</h2>
              <p className="text-xs text-slate-500">Alert yield per active cybersecurity sensor</p>
            </div>
            <Link
              to="/simulator"
              className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              Test Modules <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { id: 'phishing', name: 'Phishing URL', desc: 'Random Forest + Heuristics', count: stats?.detector_distribution?.phishing || 0 },
              { id: 'login', name: 'Login Threat', desc: 'Sliding Window + Sequences', count: stats?.detector_distribution?.login || 0 },
              { id: 'port_scan', name: 'Port Scan', desc: 'Distinct Ports Recon', count: stats?.detector_distribution?.port_scan || 0 },
              { id: 'web_attack', name: 'Web Exploits', desc: 'SQLi, XSS, Path Traversal', count: stats?.detector_distribution?.web_attack || 0 },
              { id: 'honeytoken', name: 'Honeytoken', desc: 'Canary Deception Traps', count: stats?.detector_distribution?.honeytoken || 0 },
              { id: 'graph', name: 'Graph Analysis', desc: 'NetworkX Entity Links', count: 'Active' },
            ].map((module) => (
              <div key={module.id} className="p-3.5 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-900">{module.name}</span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">{module.desc}</p>
                <div className="mt-3 text-lg font-bold text-slate-800">
                  {module.count}
                  {typeof module.count === 'number' && (
                    <span className="text-[11px] font-normal text-slate-500 ml-1">alerts</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Section: Recent Incidents & Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Incidents Table */}
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/50">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Recent Correlated Incidents</h2>
              <p className="text-xs text-slate-500">Multi-alert incidents grouped by entity links</p>
            </div>
            <Link to="/incidents" className="text-xs font-semibold text-blue-600 hover:text-blue-700">
              View All →
            </Link>
          </div>

          {(!stats?.recent_incidents || stats.recent_incidents.length === 0) ? (
            <div className="p-8 text-center text-slate-500">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
              <p className="text-sm font-medium text-slate-700">No Incidents Reported</p>
              <p className="text-xs text-slate-500 mt-1">Use the Threat Simulator to ingest attack sequences.</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {stats.recent_incidents.map((inc) => (
                <Link
                  key={inc.id}
                  to={`/incidents/${inc.id}`}
                  className="p-4 block hover:bg-slate-50 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-blue-600">{inc.id}</span>
                    <RiskTierBadge tier={inc.risk_tier} score={inc.risk_score} />
                  </div>
                  <h3 className="text-sm font-medium text-slate-900 mt-1 line-clamp-1">{inc.title}</h3>
                  <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
                    <span>{inc.alert_count} linked alert(s)</span>
                    <span className="capitalize px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-medium text-[11px]">
                      {inc.status}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts Feed */}
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/50">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Recent Alerts Stream</h2>
              <p className="text-xs text-slate-500">Latest standardized detector triggers</p>
            </div>
            <Link to="/alerts" className="text-xs font-semibold text-blue-600 hover:text-blue-700">
              View All →
            </Link>
          </div>

          {(!stats?.recent_alerts || stats.recent_alerts.length === 0) ? (
            <div className="p-8 text-center text-slate-500">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
              <p className="text-sm font-medium text-slate-700">Clean Horizon</p>
              <p className="text-xs text-slate-500 mt-1">No anomalous alerts triggered yet.</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {stats.recent_alerts.map((alt) => (
                <div key={alt.id} className="p-4 hover:bg-slate-50/50 transition-colors">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-slate-500 uppercase tracking-wider font-mono">
                      {alt.detector}
                    </span>
                    <SeverityBadge severity={alt.severity} />
                  </div>
                  <p className="text-sm font-medium text-slate-900 mt-1 line-clamp-1">{alt.title}</p>
                  <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
                    <span className="font-mono text-slate-600">IP: {alt.source_ip || 'N/A'}</span>
                    <span>Confidence: {(alt.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
