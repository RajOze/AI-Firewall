import { useState } from "react";
import { analyzePrompt } from "../services/api";
import type { AnalyzeResponse } from "../services/api";

interface TerminalMessage {
  id: string;
  type: "user" | "ai" | "system";
  text: string;
  timestamp: string;
  analysis?: AnalyzeResponse;
}

export default function AIAssistantPage() {
  const [inputText, setInputText] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [messages, setMessages] = useState<TerminalMessage[]>([
    {
      id: "msg-1",
      type: "system",
      text: "Sentinel AI Neural Engine initialized. Deep Packet Inspection & Prompt Analysis online.",
      timestamp: "13:00:00",
    },
    {
      id: "msg-2",
      type: "ai",
      text: "Hello, Administrator. Submit any prompt, command payload, or log string below for real-time security score and threat category classification.",
      timestamp: "13:00:01",
    },
  ]);

  const handleAnalyze = async (textToAnalyze?: string) => {
    const prompt = textToAnalyze || inputText;
    if (!prompt.trim() || loading) return;

    const userMsg: TerminalMessage = {
      id: `user-${Date.now()}`,
      type: "user",
      text: prompt,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev: TerminalMessage[]) => [...prev, userMsg]);
    if (!textToAnalyze) setInputText("");
    setLoading(true);

    try {
      const response = await analyzePrompt(prompt);

      const aiMsg: TerminalMessage = {
        id: `ai-${Date.now()}`,
        type: "ai",
        text: `Analysis complete. Result: ${response.safe ? "SAFE" : "POTENTIAL THREAT"} (Score: ${response.score.toFixed(2)})`,
        timestamp: new Date().toLocaleTimeString(),
        analysis: response,
      };

      setMessages((prev: TerminalMessage[]) => [...prev, aiMsg]);
    } catch (err: any) {
      const errorMsg: TerminalMessage = {
        id: `sys-${Date.now()}`,
        type: "system",
        text: `Error contacting AI Backend: ${err.message || "Failed to analyze prompt"}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev: TerminalMessage[]) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="flex flex-col w-full gap-gutter h-[calc(100vh-100px)]">
      {/* Header Banner */}
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="font-headline-lg text-on-surface flex items-center gap-2">
            <span className="material-symbols-outlined text-secondary text-[28px]">smart_toy</span>
            AI Assistant Terminal
          </h1>
          <p className="font-body-sm text-outline mt-1">
            Real-time payload inspection, prompt injection detection, and AI threat analysis.
          </p>
        </div>
        <div className="flex items-center gap-xs px-md py-xs bg-secondary-container/10 border border-secondary/20 rounded-full text-secondary font-label-caps">
          <span className="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
          FASTAPI MODEL BACKEND
        </div>
      </div>

      {/* Preset Prompt Shortcuts */}
      <div className="flex items-center gap-sm flex-shrink-0">
        <span className="font-label-caps text-outline">Quick Presets:</span>
        <button
          onClick={() => handleAnalyze("SELECT * FROM users WHERE admin = 1 OR '1'='1'")}
          className="px-md py-xs bg-surface-container-high hover:bg-surface-container-highest text-on-surface-variant text-[12px] font-code-sm rounded border border-outline-variant/30 transition-colors"
        >
          SQL Injection Payload
        </button>
        <button
          onClick={() => handleAnalyze("powershell -ExecutionPolicy Bypass -NoProfile -Enc QmFzaDY0...")}
          className="px-md py-xs bg-surface-container-high hover:bg-surface-container-highest text-on-surface-variant text-[12px] font-code-sm rounded border border-outline-variant/30 transition-colors"
        >
          Encoded PowerShell
        </button>
        <button
          onClick={() => handleAnalyze("GET /index.html HTTP/1.1 User-Agent: Mozilla/5.0")}
          className="px-md py-xs bg-surface-container-high hover:bg-surface-container-highest text-on-surface-variant text-[12px] font-code-sm rounded border border-outline-variant/30 transition-colors"
        >
          Standard HTTP Request
        </button>
      </div>

      {/* Terminal View Container */}
      <div className="flex-1 bg-surface-container-lowest border border-outline-variant/40 rounded p-lg overflow-y-auto flex flex-col gap-md font-code-sm text-[13px]">
        {messages.map((msg) => (
          <div key={msg.id} className="flex flex-col gap-xs">
            <div className="flex items-center gap-md text-[11px] text-outline">
              <span className="uppercase font-bold tracking-wider">
                [{msg.type === "user" ? "ADMIN" : msg.type === "ai" ? "SENTINEL-AI" : "SYSTEM"}]
              </span>
              <span>{msg.timestamp}</span>
            </div>

            <div
              className={`p-md rounded ${
                msg.type === "user"
                  ? "bg-surface-container text-on-surface border border-outline-variant/30"
                  : msg.type === "ai"
                  ? "bg-surface-container-low text-on-surface border border-primary/30"
                  : "bg-surface-container-highest/20 text-outline border border-outline-variant/10"
              }`}
            >
              <p className="whitespace-pre-wrap">{msg.text}</p>

              {msg.analysis && (
                <div className="mt-md pt-md border-t border-outline-variant/30 grid grid-cols-1 md:grid-cols-3 gap-md">
                  <div className="flex flex-col">
                    <span className="font-label-caps text-outline">Safety Verdict</span>
                    <span
                      className={`font-headline-sm text-[16px] font-bold ${
                        msg.analysis.safe ? "text-secondary" : "text-error"
                      }`}
                    >
                      {msg.analysis.safe ? "✓ SAFE" : "⚠ THREAT DETECTED"}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="font-label-caps text-outline">Threat Score</span>
                    <span className="font-headline-sm text-[16px] text-primary">
                      {msg.analysis.score.toFixed(3)}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="font-label-caps text-outline">Category / Reason</span>
                    <span className="font-body-sm text-on-surface-variant truncate">
                      {msg.analysis.category || msg.analysis.reason || "General Payload"}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-md text-secondary animate-pulse p-sm">
            <span className="material-symbols-outlined">hourglass_empty</span>
            <span>Sentinel AI is analyzing payload...</span>
          </div>
        )}
      </div>

      {/* Input Bar */}
      <div className="flex items-center gap-md flex-shrink-0">
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
          placeholder="Type or paste payload string for AI security analysis..."
          className="flex-1 bg-surface-container-low border border-outline-variant rounded px-lg py-md text-body-md font-code-sm text-on-surface focus:outline-none focus:border-primary transition-colors"
        />
        <button
          onClick={() => handleAnalyze()}
          disabled={loading || !inputText.trim()}
          className="px-xl py-md bg-primary text-on-primary font-headline-sm text-[14px] rounded hover:bg-primary-container transition-colors disabled:opacity-50 flex items-center gap-xs"
        >
          <span className="material-symbols-outlined text-[18px]">send</span>
          Analyze
        </button>
      </div>
    </div>
  );
}
