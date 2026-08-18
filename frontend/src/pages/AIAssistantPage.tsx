import { useState } from 'react';
import { analyzePrompt } from '../services/api';
import type { AnalyzeResponse } from '../services/api';
import { Bot, Send, ShieldAlert, CheckCircle, Loader2 } from 'lucide-react';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  analysis?: AnalyzeResponse;
}

export default function AIAssistantPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'assistant',
      text: 'Hello! I am Sentinel AI Assistant. Enter any network payload, suspicious command, or log line to evaluate threat risk.',
    },
  ]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    const textToSend = input;
    setInput('');
    setMessages((prev) => [...prev, { sender: 'user', text: textToSend }]);
    setLoading(true);

    try {
      const response = await analyzePrompt(textToSend);
      const isSafe = response.safe ?? (response.decision !== 'BLOCK');
      const score = response.score ?? response.confidence ?? 0.0;
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `Analysis complete. Result: ${isSafe ? 'SAFE' : 'POTENTIAL THREAT'} (Score: ${score.toFixed(2)})`,
          analysis: response,
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `Analysis failed: ${err.message || 'Unknown error occurred'}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full h-[calc(100vh-2rem)] gap-4 p-6 text-slate-100 font-mono">
      <div className="bg-[#111625] p-4 rounded-xl border border-slate-800 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">Sentinel AI Copilot</h1>
            <p className="text-xs text-slate-400">Interactive threat triage & security reasoning assistant</p>
          </div>
        </div>
      </div>

      <div className="flex-1 bg-[#111625] rounded-xl border border-slate-800 p-4 overflow-y-auto space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-xl p-3.5 rounded-xl text-xs ${
                msg.sender === 'user'
                  ? 'bg-blue-600 text-white rounded-br-none'
                  : 'bg-[#161c2e] border border-slate-800 text-slate-200 rounded-bl-none'
              }`}
            >
              <p>{msg.text}</p>
              {msg.analysis && (
                <div className="mt-2.5 pt-2.5 border-t border-slate-700/60 text-[11px] space-y-1">
                  <div className="flex items-center gap-1.5 font-bold">
                    {msg.analysis.safe ? (
                      <span className="text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" /> ✓ SAFE</span>
                    ) : (
                      <span className="text-red-400 flex items-center gap-1"><ShieldAlert className="w-3.5 h-3.5" /> ⚠ THREAT DETECTED</span>
                    )}
                  </div>
                  <p className="text-slate-400">Decision: <span className="text-slate-200">{msg.analysis.decision}</span></p>
                  <p className="text-slate-400">Reason: <span className="text-slate-300">{msg.analysis.reason}</span></p>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-[#111625] p-3 rounded-xl border border-slate-800 flex items-center gap-3">
        <input
          type="text"
          placeholder="Type a PowerShell command, suspicious IP, or payload to analyze..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          className="flex-1 bg-[#161c2e] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Analyze
        </button>
      </div>
    </div>
  );
}
