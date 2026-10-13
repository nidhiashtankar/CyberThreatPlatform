import React, { useState, useEffect } from 'react';
import { Search, Filter, AlertTriangle, Eye, Shield, RefreshCw } from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/SeverityBadge';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [detectorFilter, setDetectorFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const params = {};
      if (severityFilter) params.severity = severityFilter;
      if (detectorFilter) params.detector = detectorFilter;
      const data = await api.getAlerts(params);
      setAlerts(data);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter, detectorFilter]);

  const filteredAlerts = alerts.filter(a => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.title?.toLowerCase().includes(q) ||
      a.alert_id?.toLowerCase().includes(q) ||
      a.source_ip?.toLowerCase().includes(q) ||
      a.user_id?.toLowerCase().includes(q) ||
      a.detector?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Security Alerts</h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Normalized and validated alerts output by the five detection modules.
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 shadow-2xs self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Alerts
        </button>
      </div>

      {/* Filter and Search Toolbar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search alerts by title, IP, user, or alert ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 text-slate-900"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Detector Filter */}
          <select
            value={detectorFilter}
            onChange={(e) => setDetectorFilter(e.target.value)}
            className="px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
          >
            <option value="">All Detectors</option>
            <option value="phishing">Phishing URL</option>
            <option value="login">Login Threat</option>
            <option value="port_scan">Port Scan</option>
            <option value="web_attack">Web Attack</option>
            <option value="honeytoken">Honeytoken</option>
          </select>

          {(severityFilter || detectorFilter || searchQuery) && (
            <button
              onClick={() => {
                setSeverityFilter('');
                setDetectorFilter('');
                setSearchQuery('');
              }}
              className="text-xs text-blue-600 hover:text-blue-700 px-2 font-medium"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
        {loading ? (
          <div className="p-12 text-center text-slate-500">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-600 mb-2" />
            <p className="text-sm">Fetching standardized security alerts...</p>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <AlertTriangle className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-800">No matching alerts found</p>
            <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or search keywords.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-600">
              <thead className="bg-slate-50/80 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-3.5">Severity</th>
                  <th className="px-6 py-3.5">Detector</th>
                  <th className="px-6 py-3.5">Alert Title</th>
                  <th className="px-6 py-3.5">Entity / Target</th>
                  <th className="px-6 py-3.5">Confidence</th>
                  <th className="px-6 py-3.5">Timestamp</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-normal">
                {filteredAlerts.map((alert) => (
                  <tr key={alert.alert_id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="px-6 py-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <span className="font-mono text-xs font-semibold uppercase px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                        {alert.detector}
                      </span>
                    </td>
                    <td className="px-6 py-4 max-w-xs">
                      <div className="font-semibold text-slate-900 truncate">{alert.title}</div>
                      <div className="text-xs text-slate-500 capitalize">{alert.category?.replace('_', ' ')}</div>
                    </td>
                    <td className="px-6 py-4 text-xs font-mono">
                      <div>IP: <span className="text-slate-800 font-semibold">{alert.source_ip || 'N/A'}</span></div>
                      {alert.user_id && <div className="text-slate-500">User: {alert.user_id}</div>}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 bg-slate-200 h-1.5 rounded-full overflow-hidden">
                          <div
                            className="bg-blue-600 h-full rounded-full"
                            style={{ width: `${alert.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono font-semibold text-slate-700">
                          {Math.round(alert.confidence * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-500 whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Alert Evidence Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-slate-900/30 backdrop-blur-2xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-slate-200 max-w-2xl w-full p-6 shadow-xl max-h-[85vh] overflow-y-auto space-y-5 animate-in fade-in duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={selectedAlert.severity} />
                <span className="font-mono text-xs text-slate-500">{selectedAlert.alert_id}</span>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-slate-600 font-bold text-lg leading-none"
              >
                ✕
              </button>
            </div>

            <div>
              <h2 className="text-lg font-bold text-slate-900">{selectedAlert.title}</h2>
              <p className="text-xs text-slate-500 mt-1">
                Detector: <span className="font-semibold text-slate-700 uppercase">{selectedAlert.detector}</span> | Category: <span className="font-semibold text-slate-700 capitalize">{selectedAlert.category}</span>
              </p>
            </div>

            {/* Recommended Action */}
            <div className="p-4 rounded-xl bg-blue-50/70 border border-blue-200 text-xs text-blue-900">
              <span className="font-bold block mb-1">Recommended Response Action:</span>
              <p>{selectedAlert.recommended_action}</p>
            </div>

            {/* Evidence Payload */}
            <div>
              <h3 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">Sanitized Evidence Context</h3>
              <pre className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 font-mono overflow-x-auto max-h-60">
                {JSON.stringify(selectedAlert.evidence, null, 2)}
              </pre>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
