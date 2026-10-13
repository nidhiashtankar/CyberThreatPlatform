import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import Simulator from './pages/Simulator';

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 font-sans selection:bg-blue-100 selection:text-blue-900">
        <Navbar />

        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/simulator" element={<Simulator />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>

        <footer className="bg-white border-t border-slate-200 mt-12 py-6 text-xs text-slate-500">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-700">AI Cyber Threat Intelligence & Automated Response Platform</span>
            </div>
            <div className="flex items-center gap-4 text-slate-500 text-[11px]">
              <span className="font-mono text-emerald-600 font-semibold">● Realtime Connected</span>
            </div>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
}
