"use client";

import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Upload, 
  Search, 
  Activity, 
  FileText, 
  Lock, 
  ChevronRight, 
  Loader2, 
  X,
  Image as ImageIcon,
  Info
} from 'lucide-react';
import { analyzeThreat, ThreatAnalysisResult } from '../services/threat-engine';

export default function Home() {
  const [input, setInput] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ThreatAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setImageFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const removeImage = () => {
    setImageFile(null);
    setImagePreview(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalyze = async () => {
    if (!input.trim() && !imageFile) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      let base64Data: string | undefined;
      let mimeType: string | undefined;

      if (imageFile) {
        base64Data = imagePreview?.split(',')[1];
        mimeType = imageFile.type;
      }

      const analysis = await analyzeThreat(input, base64Data, mimeType);
      setResult(analysis);
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : 'An error occurred during analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'Safe': return 'text-[var(--color-safe)]';
      case 'Low': return 'text-blue-400';
      case 'Medium': return 'text-[var(--color-warning)]';
      case 'High': return 'text-orange-500';
      case 'Critical': return 'text-[var(--color-danger)]';
      default: return 'text-gray-400';
    }
  };

  const getRiskBg = (level: string) => {
    switch (level) {
      case 'Safe': return 'bg-[var(--color-safe)]/10 border-[var(--color-safe)]/30';
      case 'Low': return 'bg-blue-400/10 border-blue-400/30';
      case 'Medium': return 'bg-[var(--color-warning)]/10 border-[var(--color-warning)]/30';
      case 'High': return 'bg-orange-500/10 border-orange-500/30';
      case 'Critical': return 'bg-[var(--color-danger)]/10 border-[var(--color-danger)]/30';
      default: return 'bg-gray-400/10 border-gray-400/30';
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'Safe': return <ShieldCheck className="w-8 h-8 text-[var(--color-safe)]" />;
      case 'Critical':
      case 'High': return <ShieldAlert className="w-8 h-8 text-[var(--color-danger)]" />;
      default: return <AlertTriangle className="w-8 h-8 text-[var(--color-warning)]" />;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--color-bg-base)] text-slate-200">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[var(--color-border)] glass-panel flex flex-col hidden md:flex z-10">
        <div className="p-6 flex items-center gap-3 border-b border-[var(--color-border)]">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[var(--color-primary)] to-indigo-800 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">Aegis<span className="text-[var(--color-primary)]">AI</span></h1>
        </div>
        
        <nav className="flex-1 p-4 space-y-2">
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg bg-[var(--color-primary)]/10 text-[var(--color-primary)] font-medium border border-[var(--color-primary)]/20 transition-colors">
            <Search className="w-5 h-5" />
            Scanner
          </a>
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors">
            <Activity className="w-5 h-5" />
            Dashboard
          </a>
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors">
            <FileText className="w-5 h-5" />
            Reports
          </a>
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors">
            <Lock className="w-5 h-5" />
            Policies
          </a>
        </nav>
        
        <div className="p-4 border-t border-[var(--color-border)]">
          <div className="glass-panel rounded-lg p-4 text-sm">
            <div className="flex items-center gap-2 mb-2 text-slate-300">
              <Activity className="w-4 h-4 text-[var(--color-accent)]" />
              <span>Engine Status</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Gemini 1.5 Pro</span>
              <span className="flex items-center gap-1.5 text-[var(--color-accent)] text-xs font-medium bg-[var(--color-accent)]/10 px-2 py-1 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] animate-pulse"></span>
                Online
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        {/* Mobile Header */}
        <header className="md:hidden p-4 border-b border-[var(--color-border)] glass-panel flex items-center gap-3 z-10">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[var(--color-primary)] to-indigo-800 flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <h1 className="text-lg font-bold text-white">Aegis<span className="text-[var(--color-primary)]">AI</span></h1>
        </header>

        <div className="flex-1 overflow-y-auto p-4 md:p-8 lg:p-10 z-0">
          <div className="max-w-5xl mx-auto space-y-8">
            
            {/* Header Section */}
            <header className="space-y-2">
              <h2 className="text-3xl font-bold text-white tracking-tight">Threat Scanner</h2>
              <p className="text-slate-400 max-w-2xl">
                Analyze URLs, emails, code snippets, or images for potential security threats. 
                Our multi-agent engine provides explainable reasoning for every assessment.
              </p>
            </header>

            {/* Input Section */}
            <section className="glass-panel rounded-2xl p-1 overflow-hidden">
              <div className="bg-[#151822] rounded-xl p-4 md:p-6 flex flex-col gap-4">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Paste a suspicious URL, email content, prompt, or code snippet here..."
                  className="w-full h-32 bg-transparent border-none resize-none focus:ring-0 text-slate-200 placeholder-slate-500 text-lg"
                />
                
                {/* Image Preview */}
                <AnimatePresence>
                  {imagePreview && (
                    <motion.div 
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="relative inline-block w-fit"
                    >
                      <img src={imagePreview} alt="Upload preview" className="h-32 rounded-lg border border-[var(--color-border)] object-cover" />
                      <button 
                        onClick={removeImage}
                        className="absolute -top-2 -right-2 bg-slate-800 text-white p-1 rounded-full border border-[var(--color-border)] hover:bg-slate-700 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>

                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pt-4 border-t border-[var(--color-border)]">
                  <div className="flex items-center gap-3">
                    <input 
                      type="file" 
                      ref={fileInputRef} 
                      onChange={handleImageUpload} 
                      accept="image/*" 
                      className="hidden" 
                    />
                    <button 
                      onClick={() => fileInputRef.current?.click()}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors text-sm font-medium border border-[var(--color-border)]"
                    >
                      <ImageIcon className="w-4 h-4" />
                      Attach Image
                    </button>
                    <span className="text-xs text-slate-500 hidden md:inline-block">
                      Supports screenshots of phishing emails or suspicious sites
                    </span>
                  </div>
                  
                  <button
                    onClick={handleAnalyze}
                    disabled={isAnalyzing || (!input.trim() && !imageFile)}
                    className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-white font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-indigo-500/25"
                  >
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        Scan Threat
                      </>
                    )}
                  </button>
                </div>
              </div>
            </section>

            {/* Error Message */}
            <AnimatePresence>
              {error && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-3 text-red-400"
                >
                  <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                  <p>{error}</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Results Section */}
            <AnimatePresence>
              {result && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                      <Activity className="w-5 h-5 text-[var(--color-primary)]" />
                      Analysis Results
                    </h3>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Verified by 3 AI Experts
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Risk Score Card */}
                    <div className={`glass-panel rounded-2xl p-6 border ${getRiskBg(result.riskLevel)} flex flex-col items-center justify-center text-center relative overflow-hidden`}>
                      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-current to-transparent opacity-50"></div>
                      {getRiskIcon(result.riskLevel)}
                      <h4 className="text-sm font-medium text-slate-400 mt-4 uppercase tracking-wider">Risk Level</h4>
                      <p className={`text-4xl font-bold mt-1 ${getRiskColor(result.riskLevel)}`}>{result.riskLevel}</p>
                      
                      <div className="mt-6 w-full bg-black/20 rounded-full h-2 overflow-hidden">
                        <motion.div 
                          initial={{ width: 0 }}
                          animate={{ width: `${result.confidenceScore}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className={`h-full ${result.riskLevel === 'Safe' ? 'bg-[var(--color-safe)]' : result.riskLevel === 'Low' ? 'bg-blue-400' : result.riskLevel === 'Medium' ? 'bg-[var(--color-warning)]' : result.riskLevel === 'High' ? 'bg-orange-500' : 'bg-[var(--color-danger)]'}`}
                        />
                      </div>
                      <p className="text-xs text-slate-500 mt-2">{result.confidenceScore}% Confidence</p>
                    </div>

                    {/* Threat Type & Explanation */}
                    <div className="md:col-span-2 glass-panel rounded-2xl p-6 flex flex-col">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <h4 className="text-sm font-medium text-slate-400 uppercase tracking-wider">Threat Classification</h4>
                          <p className="text-xl font-semibold text-white mt-1">{result.threatType}</p>
                        </div>
                        <div className="p-2 bg-[var(--color-primary)]/10 rounded-lg">
                          <Info className="w-5 h-5 text-[var(--color-primary)]" />
                        </div>
                      </div>
                      
                      <div className="flex-1">
                        <h4 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-2">Explainable Reasoning</h4>
                        <p className="text-slate-300 leading-relaxed text-sm">
                          {result.explanation}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Indicators of Compromise */}
                    <div className="glass-panel rounded-2xl p-6">
                      <h4 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Search className="w-4 h-4" />
                        Key Indicators
                      </h4>
                      <ul className="space-y-3">
                        {result.indicators.map((indicator, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-sm text-slate-300">
                            <ChevronRight className="w-4 h-4 text-[var(--color-primary)] shrink-0 mt-0.5" />
                            <span>{indicator}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Recommendations */}
                    <div className="glass-panel rounded-2xl p-6">
                      <h4 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4" />
                        Recommended Actions
                      </h4>
                      <ul className="space-y-3">
                        {result.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-sm text-slate-300">
                            <div className="w-5 h-5 rounded-full bg-[var(--color-accent)]/10 text-[var(--color-accent)] flex items-center justify-center shrink-0 mt-0.5 border border-[var(--color-accent)]/20 text-xs font-bold">
                              {idx + 1}
                            </div>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

          </div>
        </div>
        
        {/* Background decorative elements */}
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-primary)]/5 blur-[120px] pointer-events-none"></div>
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-[var(--color-accent)]/5 blur-[120px] pointer-events-none"></div>
      </main>
    </div>
  );
}
