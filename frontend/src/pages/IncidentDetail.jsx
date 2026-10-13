import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield, AlertTriangle, Network, Clock, CheckCircle2,
  FileText, Send, Lock, UserX, ShieldAlert, RotateCcw,
  RefreshCw, HelpCircle, ArrowLeft, Terminal, AlertOctagon
} from 'lucide-react';
import api from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import RiskTierBadge from '../components/RiskTierBadge';
import GraphVisualizer from '../components/GraphVisualizer';

export default function IncidentDetail() {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [graphLoading, setGraphLoading] = useState(true);
  const [applyDecay, setApplyDecay] = useState(false);

  // Analyst feedback form state
  const [feedbackVerdict, setFeedbackVerdict] = useState('true_positive');
  const [feedbackNotes, setFeedbackNotes] = useState('');
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [feedbackSuccessMsg, setFeedbackSuccessMsg] = useState('');

  // Simulated response form state
  const [selectedAction, setSelectedAction] = useState('SIMULATE_BLOCK_IP');
  const [actionReason, setActionReason] = useState('');
  const [confirmingAction, setConfirmingAction] = useState(false);
  const [submittingAction, setSubmittingAction] = useState(false);
  const [actionResult, setActionResult] = useState(null);

  const fetchIncidentData = async () => {
    try {
      setLoading(true);
      const data = await api.getIncidentDetail(id, applyDecay);
      setIncident(data);
    } catch (err) {
      console.error('Error fetching incident:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchGraphData = async () => {
    try {
      setGraphLoading(true);
      const g = await api.getIncidentGraph(id);
      setGraphData(g);
    } catch (err) {
      console.error('Error fetching graph:', err);
    } finally {
      setGraphLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentData();
    fetchGraphData();
  }, [id, applyDecay]);

  const handleFeedbackSubmit = async (e) => {
    e.preventDefault();
    try {
      setSubmittingFeedback(true);
      await api.submitFeedback(id, {
        verdict: feedbackVerdict,
        notes: feedbackNotes,
        analyst_id: 'analyst_swanandi',
      });
      setFeedbackSuccessMsg('Analyst feedback persisted to audit log.');
      fetchIncidentData();
      setTimeout(() => setFeedbackSuccessMsg(''), 4000);
    } catch (err) {
      console.error('Feedback submission failed:', err);
    } finally {
      setSubmittingFeedback(false);
    }
  };

  const handleExecuteResponse = async () => {
    try {
      setSubmittingAction(true);
      const res = await api.submitResponse(id, {
        action_type: selectedAction,
        reason: actionReason || 'Analyst defensive response triggered via SOC console.',
        analyst_id: 'analyst_radhika',
        parameters: {
          ip: incident?.related_entities?.ips?.[0] || '198.51.100.45',
          user: incident?.related_entities?.users?.[0] || 'admin_svc',
        }
      });
      setActionResult(res);
      setConfirmingAction(false);
      setActionReason('');
      fetchIncidentData();
    } catch (err) {
      console.error('Response action failed:', err);
    } finally {
      setSubmittingAction(false);
    }
  };

  if (loading && !incident) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-slate-500">
        <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mb-3" />
        <p className="text-sm font-medium">Aggregating incident narrative and timeline...</p>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 text-center">
        <AlertOctagon className="w-12 h-12 text-slate-400 mx-auto mb-3" />
        <h2 className="text-lg font-bold text-slate-800">Incident Not Found</h2>
        <p className="text-sm text-slate-500 mt-1">The requested incident ID does not exist in the database.</p>
        <Link to="/incidents" className="mt-4 inline-flex items-center text-sm font-semibold text-blue-600">
          ← Return to Incidents
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Back button & Incident Header */}
      <div>
        <Link to="/incidents" className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-800 mb-3">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Incidents Ledger
        </Link>
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-sm font-bold bg-blue-50 text-blue-700 px-2.5 py-1 rounded-md border border-blue-200">
                {incident.incident_id}
              </span>
              <RiskTierBadge tier={incident.risk_tier} score={incident.risk_score} />
              <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium uppercase tracking-wider ${
                incident.status === 'contained' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                incident.status === 'investigating' ? 'bg-purple-50 text-purple-700 border border-purple-200' :
                'bg-blue-50 text-blue-700 border border-blue-200'
              }`}>
                {incident.status}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
              {incident.title}
            </h1>
            <p className="text-sm text-slate-600 max-w-3xl">
              {incident.summary}
            </p>
          </div>

          {/* Quick Metrics Badge */}
          <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-100 gap-2 shrink-0">
            <div className="text-right">
              <span className="text-xs text-slate-500 block">First Seen</span>
              <span className="text-xs font-medium text-slate-800 font-mono">
                {new Date(incident.first_seen).toLocaleString()}
              </span>
            </div>
            <div className="text-right">
              <span className="text-xs text-slate-500 block">Last Seen</span>
              <span className="text-xs font-medium text-slate-800 font-mono">
                {new Date(incident.last_seen).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* NetworkX Relationship Graph Section */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-600" />
            Graph Intelligence & Entity Linkage
          </h2>
          <span className="text-xs text-slate-500">
            NetworkX multi-hop entity correlation
          </span>
        </div>
        <GraphVisualizer graphData={graphData} isLoading={graphLoading} />
      </div>

      {/* Two Column Section: Narrative & Risk Scoring */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Narrative Section (Swanandi's ownership) */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-blue-600" />
              <h2 className="text-base font-bold text-slate-900">Chronological Incident Narrative</h2>
            </div>
            <span className="text-[11px] bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono">
              7-Section Factual Synthesis
            </span>
          </div>

          <div className="prose prose-slate max-w-none text-xs sm:text-sm text-slate-700 space-y-4 whitespace-pre-line leading-relaxed">
            {incident.incident_narrative || 'Generating incident narrative from stored event evidence...'}
          </div>
        </div>

        {/* Risk Score Derivation & Decay Simulator (Aastha's ownership) */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-blue-600" />
              Risk Derivation
            </h2>
            <div className="text-right">
              <span className="text-2xl font-black text-slate-900">{incident.risk_score}</span>
              <span className="text-xs text-slate-400 font-mono">/100</span>
            </div>
          </div>

          {/* Time Decay Simulation Toggle */}
          <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-slate-800 block">Simulate Half-Life Risk Decay</span>
                <span className="text-[11px] text-slate-500">Decays stale alerts (24h half-life) with evidence protection floor</span>
              </div>
              <button
                onClick={() => setApplyDecay(!applyDecay)}
                className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                  applyDecay ? 'bg-blue-600 text-white' : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
                }`}
              >
                {applyDecay ? 'Decay Active' : 'Apply Decay'}
              </button>
            </div>
          </div>

          {/* Itemized Score Contributors */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2">
              Scoring Contributors
            </h3>
            <div className="space-y-2">
              {(incident.risk_score_explanation || []).map((item, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-50/70 border border-slate-100 text-xs flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono text-blue-600 uppercase block font-semibold">
                      {item.category || 'Score Factor'}
                    </span>
                    <span className="text-slate-700">{item.reason}</span>
                  </div>
                  {item.points !== undefined && (
                    <span className="font-mono font-bold text-slate-900 shrink-0">
                      +{item.points}
                    </span>
                  )}
                  {item.decay_factor !== undefined && (
                    <span className="font-mono font-semibold text-slate-500 text-[11px] shrink-0">
                      ×{item.decay_factor}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Linked Alerts & Timeline */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-50/50">
          <h2 className="text-base font-bold text-slate-900">
            Linked Alerts & Evidence Timeline ({incident.linked_alerts?.length || 0})
          </h2>
          <p className="text-xs text-slate-500">Chronological detector outputs correlated into this incident</p>
        </div>

        <div className="divide-y divide-slate-100">
          {(incident.linked_alerts || []).map((alert, idx) => (
            <div key={alert.alert_id} className="p-4 sm:p-5 hover:bg-slate-50/50 transition-colors">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-600 text-xs font-bold flex items-center justify-center">
                    {idx + 1}
                  </span>
                  <span className="font-mono text-xs font-semibold text-blue-700 uppercase">
                    [{alert.detector}]
                  </span>
                  <SeverityBadge severity={alert.severity} />
                </div>
                <div className="text-xs font-mono text-slate-500">
                  {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </div>
              </div>

              <h3 className="text-sm font-bold text-slate-900 mb-1">{alert.title}</h3>
              <p className="text-xs text-slate-600 mb-3">{alert.recommended_action}</p>

              {/* Collapsible evidence snippet */}
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 font-mono text-[11px] text-slate-800 overflow-x-auto">
                {JSON.stringify(alert.evidence, null, 1)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Two Column: Analyst Feedback & Simulated Response Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Analyst Feedback Box */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-600" />
              Analyst Validation & Feedback
            </h2>
            <span className="text-[11px] text-slate-500">Continuous Assessment</span>
          </div>

          {incident.analyst_feedback && (
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold">Current Verdict: <span className="uppercase">{incident.analyst_feedback.verdict}</span></span>
                <span className="text-[10px] text-emerald-700 font-mono">By {incident.analyst_feedback.analyst_id}</span>
              </div>
              <p className="italic">"{incident.analyst_feedback.notes || 'No analyst notes.'}"</p>
            </div>
          )}

          <form onSubmit={handleFeedbackSubmit} className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Analyst Verdict</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'true_positive', label: 'True Positive', color: 'border-emerald-300 text-emerald-800' },
                  { id: 'false_positive', label: 'False Positive', color: 'border-rose-300 text-rose-800' },
                  { id: 'needs_review', label: 'Needs Review', color: 'border-amber-300 text-amber-800' },
                ].map(opt => (
                  <button
                    type="button"
                    key={opt.id}
                    onClick={() => setFeedbackVerdict(opt.id)}
                    className={`py-2 text-xs font-semibold rounded-lg border text-center transition-all ${
                      feedbackVerdict === opt.id
                        ? 'bg-blue-50 border-blue-600 text-blue-700 ring-1 ring-blue-600'
                        : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Investigation Notes</label>
              <textarea
                rows={3}
                value={feedbackNotes}
                onChange={(e) => setFeedbackNotes(e.target.value)}
                placeholder="Document verification findings, false-positive context, or follow-up tasks..."
                className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 text-slate-900"
              />
            </div>

            {feedbackSuccessMsg && (
              <p className="text-xs text-emerald-600 font-medium">{feedbackSuccessMsg}</p>
            )}

            <button
              type="submit"
              disabled={submittingFeedback}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              {submittingFeedback ? 'Persisting...' : 'Submit Analyst Feedback'}
            </button>
          </form>
        </div>

        {/* Manual Simulated Response Controls (Radhika's ownership) */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Lock className="w-5 h-5 text-blue-600" />
              Audited Response Actions (Simulated)
            </h2>
            <span className="text-[11px] bg-amber-50 text-amber-700 px-2 py-0.5 rounded border border-amber-200 font-semibold">
              Dry-Run Safe
            </span>
          </div>

          <p className="text-xs text-slate-600">
            Execute containment measures in non-destructive dry-run mode. Generates immutable audit records in the database.
          </p>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Select Response Action</label>
              <select
                value={selectedAction}
                onChange={(e) => setSelectedAction(e.target.value)}
                className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-800 font-medium"
              >
                <option value="SIMULATE_BLOCK_IP">Simulate Blocking Attacker Source IP</option>
                <option value="SIMULATE_DISABLE_ACCOUNT">Simulate Disabling Targeted User Account</option>
                <option value="CONTAIN_INCIDENT">Mark Incident as Contained</option>
                <option value="INVESTIGATE_INCIDENT">Mark Incident for Deep Forensics</option>
                <option value="RESET_HONEYTOKEN">Simulate Rotating Decoy Canary Secret</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Justification Reason</label>
              <input
                type="text"
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
                placeholder="e.g. Adversary observed actively probing internal decoy token..."
                className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
              />
            </div>

            {!confirmingAction ? (
              <button
                type="button"
                onClick={() => setConfirmingAction(true)}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors"
              >
                <Lock className="w-3.5 h-3.5" />
                Initiate Simulated Action
              </button>
            ) : (
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl space-y-2">
                <p className="text-xs font-semibold text-amber-900">
                  Confirm Simulated Execution of: {selectedAction}?
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExecuteResponse}
                    disabled={submittingAction}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-bold"
                  >
                    {submittingAction ? 'Executing...' : 'Confirm Dry-Run'}
                  </button>
                  <button
                    onClick={() => setConfirmingAction(false)}
                    className="px-3 py-1.5 bg-slate-200 text-slate-700 rounded text-xs font-semibold"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {actionResult && (
              <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-xs text-blue-900 mt-2">
                <span className="font-bold block">Simulation Result ({actionResult.simulation_status}):</span>
                <p className="font-mono mt-0.5">{actionResult.outcome}</p>
              </div>
            )}
          </div>

          {/* Audit History Log */}
          {incident.response_actions && incident.response_actions.length > 0 && (
            <div className="pt-3 border-t border-slate-100">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2">Response Audit History</h3>
              <div className="space-y-1.5 max-h-36 overflow-y-auto">
                {incident.response_actions.map(act => (
                  <div key={act.action_id} className="p-2 rounded bg-slate-50 border border-slate-200 text-[11px] flex items-center justify-between">
                    <div>
                      <span className="font-bold text-slate-800">{act.action_type}</span>
                      <span className="text-slate-500 block truncate max-w-xs">{act.outcome}</span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {new Date(act.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
