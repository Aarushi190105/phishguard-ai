import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:8000";

function RiskGauge({ value }) {
  const normalized = Math.max(0, Math.min(100, value || 0));
  const strokeDashoffset = 439.82 - (439.82 * normalized) / 100;
  const color = normalized >= 65 ? "#ef4444" : normalized >= 35 ? "#3b82f6" : "#22c55e";

  return (
    <div className="relative w-44 h-44 mx-auto">
      <svg className="w-44 h-44 -rotate-90" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="70" stroke="#1e293b" strokeWidth="12" fill="none" />
        <circle
          cx="80"
          cy="80"
          r="70"
          stroke={color}
          strokeWidth="12"
          fill="none"
          strokeLinecap="round"
          strokeDasharray="439.82"
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{normalized.toFixed(1)}%</span>
        <span className="text-xs uppercase tracking-[0.2em] text-slate-400">Risk</span>
      </div>
    </div>
  );
}

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const statusColor = useMemo(() => {
    if (!result) return "text-blue-400";
    return result.label === "Phishing" ? "text-red-400" : "text-green-400";
  }, [result]);

  const onScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) throw new Error("Scan failed");
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError("Unable to analyze URL right now. Try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-white p-6 md:p-12">
      <div className="max-w-6xl mx-auto space-y-8">
        <motion.header initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-center text-4xl md:text-6xl font-black tracking-tight bg-gradient-to-r from-blue-400 to-cyan-200 bg-clip-text text-transparent">
            Cyber-Security Command Center
          </h1>
          <p className="text-center text-slate-400 mt-3">AI-powered phishing threat analysis in real time</p>
        </motion.header>

        <motion.form
          onSubmit={onScan}
          className="backdrop-blur-md bg-white/5 border border-blue-400/20 rounded-2xl p-4 md:p-6 shadow-[0_0_30px_rgba(59,130,246,0.15)]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="flex flex-col md:flex-row gap-3">
            <input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-domain.example/login"
              className="flex-1 bg-slate-900/80 border border-blue-400/40 rounded-xl p-4 outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              className="px-6 py-4 rounded-xl font-semibold bg-blue-500 hover:bg-blue-400 transition disabled:opacity-50"
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan URL"}
            </button>
          </div>
        </motion.form>

        {loading && (
          <div className="flex justify-center">
            <motion.div
              className="w-28 h-28 rounded-full border-4 border-blue-400/20 border-t-blue-400"
              animate={{ rotate: 360, scale: [1, 1.08, 1] }}
              transition={{ repeat: Infinity, duration: 1.1, ease: "linear" }}
            />
          </div>
        )}

        {error && <p className="text-center text-red-400">{error}</p>}

        <AnimatePresence>
          {result && !loading && (
            <motion.section
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="grid lg:grid-cols-3 gap-6"
            >
              <div className="lg:col-span-1 backdrop-blur-md bg-white/5 border border-slate-700 rounded-2xl p-6">
                <h2 className="text-xl font-semibold mb-4">Risk Gauge</h2>
                <RiskGauge value={result.phishing_probability} />
                <p className={`text-center mt-4 font-bold ${statusColor}`}>{result.label}</p>
              </div>

              <div className="backdrop-blur-md bg-white/5 border border-slate-700 rounded-2xl p-6">
                <h2 className="text-xl font-semibold mb-4">Threat Map</h2>
                <ul className="space-y-2 text-slate-300">
                  <li><strong>IP:</strong> {result.geolocation?.ip || "Unknown"}</li>
                  <li><strong>City:</strong> {result.geolocation?.city || "Unknown"}</li>
                  <li><strong>Country:</strong> {result.geolocation?.country || "Unknown"}</li>
                  <li><strong>Domain Age:</strong> {result.domain_age_days ?? "Unknown"} days</li>
                </ul>
              </div>

              <div className="backdrop-blur-md bg-white/5 border border-slate-700 rounded-2xl p-6">
                <h2 className="text-xl font-semibold mb-4">Technical Breakdown</h2>
                <ul className="space-y-3 text-slate-300 list-disc pl-6">
                  {result.threat_indicators?.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </motion.section>
          )}
        </AnimatePresence>
      </div>
    </main>
  );
}
