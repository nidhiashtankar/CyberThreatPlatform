import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, AlertTriangle, Layers, Activity, Terminal } from 'lucide-react';

export default function Navbar() {
  const navItems = [
    { name: 'Dashboard', path: '/', icon: Activity },
    { name: 'Incidents', path: '/incidents', icon: Shield },
    { name: 'Alerts', path: '/alerts', icon: AlertTriangle },
    { name: 'Event Simulator', path: '/simulator', icon: Terminal },
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-900 text-base tracking-tight">AI Cyber Threat Platform</span>
                <span className="bg-blue-50 text-blue-700 text-[10px] font-semibold px-2 py-0.5 rounded border border-blue-200">
                  SOC v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-500 hidden sm:block">Automated Correlation & Incident Intelligence</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex space-x-1 sm:space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    `inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 border border-blue-200 font-semibold shadow-2xs'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/70 border border-transparent'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </NavLink>
              );
            })}
          </nav>

          {/* System Status */}
          <div className="hidden lg:flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs text-slate-600 bg-slate-50 px-3 py-1.5 rounded-full border border-slate-200">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-medium text-slate-700">SOC Online</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
