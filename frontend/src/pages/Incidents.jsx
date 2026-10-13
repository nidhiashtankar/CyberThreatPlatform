import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Filter, Search, RefreshCw, ArrowRight, Layers } from 'lucide-react';
import api from '../services/api';
import RiskTierBadge from '../components/RiskTierBadge';

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [tierFilter, setTierFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (tierFilter) params.risk_tier = tierFilter;
      const data = await api.getIncidents(params);
      setIncidents(data);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter, tierFilter]);

  const filteredIncidents = incidents.filter(inc => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      inc.incident_id?.toLowerCase().includes(q) ||
      inc.title?.toLowerCase().includes(q) ||
      inc.summary?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Security Incidents</h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Correlated multi-vector security threats prioritized by deterministic risk scoring.
          </p>
        </div>
        <button
          onClick={fetchIncidents}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 shadow-2xs self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Toolbar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search incidents by ID, title, or summary..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 text-slate-900"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Risk Tier Filter */}
          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            className="px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none"
          >
            <option value="">All Risk Tiers</option>
            <option value="Critical">Critical Risk</option>
            <option value="High">High Risk</option>
            <option value="Medium">Medium Risk</option>
            <option value="Low">Low Risk</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>

          {(tierFilter || statusFilter || searchQuery) && (
            <button
              onClick={() => {
                setTierFilter('');
                setStatusFilter('');
                setSearchQuery('');
              }}
              className="text-xs text-blue-600 hover:text-blue-700 px-2 font-medium"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Incidents Table / Cards */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
        {loading ? (
          <div className="p-12 text-center text-slate-500">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-600 mb-2" />
            <p className="text-sm">Loading security incident ledger...</p>
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <Shield className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-800">No Incidents Found</p>
            <p className="text-xs text-slate-500 mt-1">Try resetting filters or generating activity in the Simulator.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-600">
              <thead className="bg-slate-50/80 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-3.5">Incident ID</th>
                  <th className="px-6 py-3.5">Title & Summary</th>
                  <th className="px-6 py-3.5">Risk Tier & Score</th>
                  <th className="px-6 py-3.5">Status</th>
                  <th className="px-6 py-3.5">Linked Alerts</th>
                  <th className="px-6 py-3.5">Last Seen</th>
                  <th className="px-6 py-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-normal">
                {filteredIncidents.map((inc) => (
                  <tr key={inc.incident_id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="px-6 py-4 font-mono text-xs font-bold text-blue-600">
                      {inc.incident_id}
                    </td>
                    <td className="px-6 py-4 max-w-md">
                      <div className="font-semibold text-slate-900 line-clamp-1">{inc.title}</div>
                      <div className="text-xs text-slate-500 line-clamp-1 mt-0.5">{inc.summary}</div>
                    </td>
                    <td className="px-6 py-4">
                      <RiskTierBadge tier={inc.risk_tier} score={inc.risk_score} />
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${
                        inc.status === 'contained' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                        inc.status === 'investigating' ? 'bg-purple-50 text-purple-700 border border-purple-200' :
                        inc.status === 'closed' ? 'bg-slate-100 text-slate-700 border border-slate-200' :
                        'bg-blue-50 text-blue-700 border border-blue-200'
                      }`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs font-semibold text-slate-700">
                      <span className="inline-flex items-center gap-1">
                        <Layers className="w-3.5 h-3.5 text-slate-400" />
                        {inc.alert_ids?.length || inc.linked_alerts?.length || 0}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-500 whitespace-nowrap">
                      {new Date(inc.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <Link
                        to={`/incidents/${inc.incident_id}`}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 transition-colors"
                      >
                        Inspect
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
