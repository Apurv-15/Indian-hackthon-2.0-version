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
import { analyzeThreat, ThreatAnalysisResult } from '../../services/threat-engine';
import { saveScan } from '../../services/scan-history';

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
      
      // If it's a text file, read the content and put it in the input area
      if (file.type === 'text/plain' || file.name.endsWith('.txt')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          const content = event.target?.result as string;
          setInput(prev => prev ? `${prev}\n\n[File Content: ${file.name}]\n${content}` : content);
          setImagePreview("data:text/plain;base64," + btoa(content.slice(0, 50))); // Minimal text preview
        };
        reader.readAsText(file);
      } else {
        const reader = new FileReader();
        reader.onloadend = () => {
          setImagePreview(reader.result as string);
        };
        reader.readAsDataURL(file);
      }
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
      saveScan(input, !!imageFile, analysis);
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
    <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        {/* Mobile Header */}
        <header className="md:hidden px-4 py-3 bg-white/60 backdrop-blur-md border-b border-slate-200 flex items-center gap-3 z-10 sticky top-0">
          <div className="w-8 h-8 rounded-xl bg-white border border-slate-200 shadow-sm flex items-center justify-center">
            <Shield className="w-4 h-4 text-[var(--color-primary)]" />
          </div>
          <h1 className="text-lg font-bold text-slate-800">Aegis<span className="text-[var(--color-primary)]">AI</span></h1>
        </header>

        <div className="flex-1 overflow-y-auto p-4 md:p-8 z-0">
          <div className="max-w-4xl mx-auto space-y-6 flex flex-col items-center">
            
            {/* Header Section */}
            <header className="flex flex-col items-center text-center mt-4 md:mt-12 mb-4 space-y-3">
              <div className="w-16 h-16 bg-white shadow-sm border border-slate-200/60 rounded-3xl flex items-center justify-center mb-1">
                <Shield className="w-8 h-8 text-[var(--color-primary)]" />
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-slate-900 tracking-tight">
                Hey, I'm AegisAI.
              </h2>
              <h3 className="text-lg md:text-xl text-slate-600 font-medium max-w-lg">
                Upload media or paste context below to begin the forensic analysis.
              </h3>
            </header>

            {/* Input Section */}
            <section className="bg-white rounded-[2.5rem] p-4 overflow-hidden shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-white/50 w-full max-w-3xl">
              <div className="flex flex-col gap-2">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="How can I help you today?"
                  className="w-full h-24 bg-transparent border-none resize-none focus:ring-0 text-slate-700 placeholder-slate-400 text-base p-2 px-3 outline-none"
                />
                
                {/* Image/Media Preview */}
                <AnimatePresence>
                  {imagePreview && (
                    <motion.div 
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="relative inline-block w-fit px-3"
                    >
                      {imageFile?.type.startsWith('video') ? (
                        <video src={imagePreview} className="h-40 rounded-xl border border-slate-200 shadow-sm" controls />
                      ) : imageFile?.type.startsWith('audio') ? (
                        <audio src={imagePreview} className="w-full max-w-md rounded-xl border border-slate-200 shadow-sm p-2 bg-slate-50" controls />
                      ) : imageFile?.type === 'text/plain' || imageFile?.name.endsWith('.txt') ? (
                        <div className="h-24 w-24 rounded-xl border border-slate-200 shadow-sm bg-slate-50 flex flex-col items-center justify-center gap-1">
                          <FileText className="w-8 h-8 text-blue-500" />
                          <span className="text-[10px] font-bold text-slate-400 uppercase truncate px-2 w-full text-center">{imageFile.name}</span>
                        </div>
                      ) : (
                        <img src={imagePreview} alt="Upload preview" className="h-24 rounded-xl border border-slate-200 shadow-sm object-cover" />
                      )}
                      <button 
                        onClick={removeImage}
                        className="absolute -top-2 -right-2 bg-white text-slate-500 p-1 rounded-full border border-slate-200 shadow-sm hover:text-red-500 transition-colors z-20"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>

                <div className="flex justify-between items-center gap-4 pt-2">
                  <div className="flex items-center gap-2">
                    <input 
                      type="file" 
                      ref={fileInputRef} 
                      onChange={handleImageUpload} 
                      accept="image/*,audio/*,video/*" 
                      className="hidden" 
                    />
                    <button 
                      onClick={() => fileInputRef.current?.click()}
                      className="flex items-center gap-2 px-3 py-2 rounded-xl text-slate-500 hover:text-slate-700 hover:bg-slate-50 transition-colors text-sm font-medium"
                      title="Attach file"
                    >
                      <Upload className="w-5 h-5" />
                    </button>
                  </div>
                  
                  <button
                    onClick={handleAnalyze}
                    disabled={isAnalyzing || (!input.trim() && !imageFile)}
                    className="flex items-center justify-center w-10 h-10 rounded-full bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isAnalyzing ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                      <ChevronRight className="w-5 h-5" />
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
                    <h3 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                      <Activity className="w-5 h-5 text-[var(--color-primary)]" />
                      Analysis Results
                    </h3>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-100 border border-slate-200 text-slate-600 text-xs font-semibold">
                      <ShieldCheck className="w-3.5 h-3.5 text-[var(--color-primary)]" />
                      Verified by AI Forensics
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Risk Score Card */}
                    <div className={`rounded-[2.5rem] p-8 border ${getRiskBg(result.riskLevel)} bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] flex flex-col items-center justify-center text-center relative overflow-hidden`}>
                      {getRiskIcon(result.riskLevel)}
                      <h4 className="text-sm font-medium text-slate-500 mt-4 uppercase tracking-wider">Risk Level</h4>
                      <p className={`text-4xl font-bold mt-1 ${getRiskColor(result.riskLevel)}`}>{result.riskLevel}</p>
                      
                      <div className="mt-6 w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                        <motion.div 
                          initial={{ width: 0 }}
                          animate={{ width: `${result.confidenceScore}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className={`h-full ${result.riskLevel === 'Safe' ? 'bg-[var(--color-safe)]' : result.riskLevel === 'Low' ? 'bg-blue-400' : result.riskLevel === 'Medium' ? 'bg-[var(--color-warning)]' : result.riskLevel === 'High' ? 'bg-orange-500' : 'bg-[var(--color-danger)]'}`}
                        />
                      </div>
                      <p className="text-xs text-slate-500 mt-2 font-medium">{result.confidenceScore}% Confidence</p>
                    </div>

                    {/* Threat Type & Explanation */}
                    <div className="md:col-span-2 bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-white/50 rounded-[2.5rem] p-8 flex flex-col">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <h4 className="text-sm font-medium text-slate-500 uppercase tracking-wider">Threat Classification</h4>
                          <p className="text-xl font-semibold text-slate-800 mt-1">{result.threatType}</p>
                        </div>
                        <div className="p-2 bg-slate-50 border border-slate-100 rounded-xl">
                          <Info className="w-5 h-5 text-[var(--color-primary)]" />
                        </div>
                      </div>
                      
                      <div className="flex-1">
                        <h4 className="text-sm font-medium text-slate-500 uppercase tracking-wider mb-2">Explainable Reasoning</h4>
                        <p className="text-slate-600 leading-relaxed text-sm">
                          {result.explanation}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Detailed Intelligence Section */}
                  {result.detailedScores && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                      <div className="bg-white px-6 py-5 rounded-[2rem] border border-slate-100 shadow-sm flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Phishing Prob</span>
                        <div className="flex items-end gap-2">
                          <span className="text-2xl font-bold text-slate-800">{(result.detailedScores.phishingProb * 100).toFixed(0)}%</span>
                          <div className="flex-1 h-1.5 bg-slate-100 rounded-full mb-2 overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${result.detailedScores.phishingProb * 100}%` }}
                              className="h-full bg-red-400" 
                            />
                          </div>
                        </div>
                      </div>
                      <div className="bg-white px-6 py-5 rounded-[2rem] border border-slate-100 shadow-sm flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Spam Signal</span>
                        <div className="flex items-end gap-2">
                          <span className="text-2xl font-bold text-slate-800">{(result.detailedScores.spamProb * 100).toFixed(0)}%</span>
                          <div className="flex-1 h-1.5 bg-slate-100 rounded-full mb-2 overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${result.detailedScores.spamProb * 100}%` }}
                              className="h-full bg-blue-400" 
                            />
                          </div>
                        </div>
                      </div>
                      <div className="bg-white px-6 py-5 rounded-[2rem] border border-slate-100 shadow-sm flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Prompt Injection</span>
                        <div className="flex items-end gap-2">
                          <span className="text-2xl font-bold text-slate-800">{(result.detailedScores.promptInjectionScore * 100).toFixed(0)}%</span>
                          <div className="flex-1 h-1.5 bg-slate-100 rounded-full mb-2 overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${result.detailedScores.promptInjectionScore * 100}%` }}
                              className="h-full bg-purple-400" 
                            />
                          </div>
                        </div>
                      </div>
                      <div className="bg-white px-6 py-5 rounded-[2rem] border border-slate-100 shadow-sm flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Tone Analysis</span>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase ${result.detailedScores.sentimentLabel === 'NEGATIVE' ? 'bg-orange-100 text-orange-600' : 'bg-green-100 text-green-600'}`}>
                            {result.detailedScores.sentimentLabel}
                          </span>
                          <span className="text-xs font-semibold text-slate-500">{(result.detailedScores.sentimentScore * 100).toFixed(0)}% intensity</span>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pb-20">
                    {/* Indicators of Compromise */}
                    <div className="bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-white/50 rounded-[2.5rem] p-8">
                      <h4 className="text-sm font-medium text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Search className="w-4 h-4" />
                        Key Indicators
                      </h4>
                      <ul className="space-y-3">
                        {result.indicators.map((indicator, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-sm text-slate-600">
                            <ChevronRight className="w-4 h-4 text-[var(--color-primary)] shrink-0 mt-0.5" />
                            <span>{indicator}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Recommendations */}
                    <div className="bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-white/50 rounded-[2.5rem] p-8">
                      <h4 className="text-sm font-medium text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4" />
                        Recommended Actions
                      </h4>
                      <ul className="space-y-3">
                        {result.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-sm text-slate-600">
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
        
        {/* Removing the harsh blob backgrounds since the layout has a mesh */}
    </main>
  );
}
