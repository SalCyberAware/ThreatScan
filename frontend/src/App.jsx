import { useState, useRef, useEffect } from "react";

const Styles = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:#07090f; --surface:#0d1017; --surface2:#111520;
      --border:#1a2035; --border2:#232c42;
      --green:#00ff88; --red:#ff3355; --yellow:#ffd700; --blue:#4fa3ff;
      --text:#dde4f0; --text2:#7a8aaa; --text3:#3d4a66;
      --mono:'Space Mono',monospace; --sans:'DM Sans',sans-serif;
    }
    body { background:var(--bg); color:var(--text); font-family:var(--sans); }
    @keyframes pulse   { 0%,100%{opacity:1} 50%{opacity:.4} }
    @keyframes fadeUp  { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
    @keyframes fadeIn  { from{opacity:0} to{opacity:1} }
    @keyframes spin    { to{transform:rotate(360deg)} }
    @keyframes countUp { from{opacity:0;transform:scale(.8)} to{opacity:1;transform:scale(1)} }
    @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
    @keyframes borderGlow {
      0%,100%{border-color:var(--border2);box-shadow:none}
      50%{border-color:var(--green);box-shadow:0 0 12px rgba(0,255,136,.15)}
    }
    @keyframes scanPulse {
      0%,100%{box-shadow:0 0 0 0 rgba(0,255,136,0)}
      50%{box-shadow:0 0 0 6px rgba(0,255,136,.1)}
    }
    input:focus { outline:none; }
    button:focus-visible { outline:2px solid var(--green); outline-offset:2px; }
  `}</style>
);

const BACKEND = import.meta.env.VITE_API_URL || "/api";

const ENGINE_META = {
  virustotal:    { name:"VirusTotal",        icon:"🔬" },
  abuseipdb:     { name:"AbuseIPDB",         icon:"🛡"  },
  urlscan:       { name:"URLScan.io",        icon:"🔍" },
  malwarebazaar: { name:"MalwareBazaar",     icon:"☣"  },
  otx:           { name:"AlienVault OTX",   icon:"👽" },
  greynoise:     { name:"GreyNoise",         icon:"📡" },
  ipinfo:        { name:"IPInfo",            icon:"🌐" },
  phishtank:     { name:"PhishTank",         icon:"🎣" },
  safebrowsing:  { name:"Google SafeBrowse", icon:"🔒" },
  threatfox:     { name:"ThreatFox",         icon:"🦊" },
};

const ENGINE_ORDER = Object.keys(ENGINE_META);

const TYPES = [
  { id:"auto",   label:"Auto-detect",  placeholder:"Paste anything — URL, IP, hash, domain…" },
  { id:"url",    label:"URL",          placeholder:"https://suspicious-site.example.com"      },
  { id:"ip",     label:"IP / Host",    placeholder:"192.168.1.1"                              },
  { id:"hash",   label:"File Hash",    placeholder:"SHA256 / MD5 / SHA1"                      },
  { id:"domain", label:"Domain",       placeholder:"malware-domain.example"                   },
];

// ─── FIX: Client-side type detection (mirrors backend detect.js) ──────────────
// This runs on every keystroke so the correct tab is always highlighted,
// and more importantly, the correct type is sent to the backend on scan.
const IP_RE      = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const MD5_RE     = /^[a-fA-F0-9]{32}$/;
const SHA1_RE    = /^[a-fA-F0-9]{40}$/;
const SHA256_RE  = /^[a-fA-F0-9]{64}$/;
const URL_RE     = /^https?:\/\/.+/i;
const DOMAIN_RE  = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function detectInputType(q) {
  if (!q || !q.trim()) return "auto";
  const s = q.trim();
  if (URL_RE.test(s))    return "url";
  if (IP_RE.test(s))     return "ip";
  if (MD5_RE.test(s) || SHA1_RE.test(s) || SHA256_RE.test(s)) return "hash";
  if (DOMAIN_RE.test(s)) return "domain";
  return "auto";
}
// ─────────────────────────────────────────────────────────────────────────────

const Badge = ({ verdict, size="sm" }) => {
  const MAP = {
    malicious:  { bg:"#ff335515", border:"#ff3355", text:"#ff3355", label:"MALICIOUS"  },
    suspicious: { bg:"#ffd70015", border:"#ffd700", text:"#ffd700", label:"SUSPICIOUS" },
    clean:      { bg:"#00ff8815", border:"#00ff88", text:"#00ff88", label:"CLEAN"      },
    info:       { bg:"#4fa3ff15", border:"#4fa3ff", text:"#4fa3ff", label:"INFO"       },
    skipped:    { bg:"#3d4a6620", border:"#3d4a66", text:"#3d4a66", label:"SKIPPED"    },
    error:      { bg:"#ff335510", border:"#553333", text:"#996666", label:"ERROR"      },
    scanning:   { bg:"#9b72ff15", border:"#9b72ff", text:"#9b72ff", label:"SCANNING…"  },
  };
  const c = MAP[verdict] || MAP.info;
  return (
    <span style={{ background:c.bg, border:`1px solid ${c.border}`, color:c.text,
      padding: size==="lg" ? "6px 14px":"3px 8px",
      fontSize: size==="lg" ? 13:10,
      borderRadius:4, fontFamily:"var(--mono)", fontWeight:700,
      letterSpacing:1, display:"inline-flex", alignItems:"center", gap:5
    }}>
      {verdict==="scanning" && (
        <span style={{ width:7, height:7, borderRadius:"50%", background:c.text,
          animation:"pulse 1s infinite", flexShrink:0 }}/>
      )}
      {c.label}
    </span>
  );
};

const Spinner = ({ size=18, color="var(--green)" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    style={{ animation:"spin .8s linear infinite", flexShrink:0 }}>
    <circle cx="12" cy="12" r="10" stroke={color} strokeOpacity=".2" strokeWidth="3"/>
    <path d="M12 2 A10 10 0 0 1 22 12" stroke={color} strokeWidth="3" strokeLinecap="round"/>
  </svg>
);

const ThreatGauge = ({ score }) => {
  const color = score>=70?"#ff3355":score>=30?"#ffd700":"#00ff88";
  const label = score>=70?"HIGH RISK":score>=30?"MODERATE":"LOW RISK";
  return (
    <div style={{ textAlign:"center" }}>
      <svg width="160" height="90" viewBox="0 0 160 90">
        <defs>
          <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor="#00ff88"/>
            <stop offset="50%"  stopColor="#ffd700"/>
            <stop offset="100%" stopColor="#ff3355"/>
          </linearGradient>
        </defs>
        <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke="#1a2035" strokeWidth="14" strokeLinecap="round"/>
        <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke="url(#g)"
          strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${(score/100)*188} 188`}
          style={{ transition:"stroke-dasharray .6s ease" }}/>
        <g transform={`rotate(${-90+(score/100)*180},80,80)`}
          style={{ transition:"transform .6s ease" }}>
          <line x1="80" y1="80" x2="80" y2="28" stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
          <circle cx="80" cy="80" r="5" fill={color}/>
        </g>
        <text x="80" y="72" textAnchor="middle" fontSize="20" fontWeight="700"
          fontFamily="var(--mono)" fill={color}>{score}</text>
      </svg>
      <div style={{ fontFamily:"var(--mono)", fontSize:11, color, letterSpacing:2, marginTop:-4 }}>{label}</div>
    </div>
  );
};

const EngineCard = ({ engineId, data, status }) => {
  const meta = ENGINE_META[engineId] || { name: engineId, icon:"🔧" };
  const isScanning = status === "scanning";
  const borderColor = isScanning ? "#9b72ff40"
    : data?.verdict==="malicious"  ? "#ff3355"
    : data?.verdict==="suspicious" ? "#ffd700"
    : data?.verdict==="clean"      ? "#00ff8840"
    : "#1a2035";

  return (
    <div style={{
      background:"var(--surface2)", border:`1px solid ${borderColor}`,
      borderRadius:8, padding:"14px 16px",
      transition:"border-color .4s, box-shadow .4s",
      animation:"slideIn .25s ease both",
      boxShadow: isScanning ? "none"
        : data?.verdict==="malicious" ? "0 0 16px rgba(255,51,85,.07)" : "none",
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:18 }}>{meta.icon}</span>
          <span style={{ fontSize:13, fontWeight:600 }}>{meta.name}</span>
        </div>
        {isScanning ? <Badge verdict="scanning"/> : <Badge verdict={data?.verdict || "info"}/>}
      </div>
      {!isScanning && data && (
        <div style={{ fontSize:11, color:"var(--text2)", fontFamily:"var(--mono)",
          display:"flex", flexWrap:"wrap", gap:"5px 14px", marginTop:4 }}>
          {data.engines     !== undefined && <span>Engines: <b style={{color:"var(--text)"}}>{data.flagged}/{data.engines}</b></span>}
          {data.confidence  !== undefined && <span>Confidence: <b style={{color:"var(--text)"}}>{data.confidence}%</b></span>}
          {data.reports     !== undefined && <span>Reports: <b style={{color:"var(--text)"}}>{data.reports}</b></span>}
          {data.pulses      !== undefined && <span>Pulses: <b style={{color:"var(--text)"}}>{data.pulses}</b></span>}
          {data.type        && <span>Type: <b style={{color:"#ff3355"}}>{data.type}</b></span>}
          {data.malware     && <span>Malware: <b style={{color:"#ff3355"}}>{data.malware}</b></span>}
          {data.org         && <span>Org: <b style={{color:"var(--text)"}}>{data.org}</b></span>}
          {data.city        && <span>Location: <b style={{color:"var(--text)"}}>{data.city}, {data.country}</b></span>}
          {data.classification && <span>Class: <b style={{color:"var(--text)"}}>{data.classification}</b></span>}
          {data.detail      && <span style={{color:"var(--text3)"}}>{data.detail}</span>}
          {data.tags?.length    > 0 && <span>Tags: <b style={{color:"#ff3355"}}>{data.tags.join(", ")}</b></span>}
          {data.threats?.length > 0 && <span>Threats: <b style={{color:"#ff3355"}}>{data.threats.join(", ")}</b></span>}
          {data.brands?.length  > 0 && <span>Brands: <b style={{color:"#ffd700"}}>{data.brands.join(", ")}</b></span>}
          {data.indicators?.length > 0 && <span>IOCs: <b style={{color:"#ff3355"}}>{data.indicators.join(", ")}</b></span>}
        </div>
      )}
    </div>
  );
};

export default function App() {
  const [query,      setQuery]      = useState("");
  const [type,       setType]       = useState("auto");
  const [userPickedType, setUserPickedType] = useState(false); // tracks manual tab selection
  const [scanning,   setScanning]   = useState(false);
  const [engineData, setEngineData] = useState({});
  const [engineStatus, setEngineStatus] = useState({});
  const [summary,    setSummary]    = useState(null);
  const [progress,   setProgress]   = useState(0);
  const [total,      setTotal]      = useState(10);
  const [error,      setError]      = useState(null);
  const [history,    setHistory]    = useState(() => {
    try { return JSON.parse(localStorage.getItem("ts_history") || "[]"); } catch { return []; }
  });
  const [tab, setTab] = useState("scan");
  const inputRef = useRef();
  const esSrc    = useRef(null);

  // ─── FIX: Auto-detect type as user types ────────────────────────────────────
  // Only auto-switch if the user hasn't manually clicked a type tab.
  // Resets to auto when the input is cleared.
  useEffect(() => {
    if (userPickedType) return; // user explicitly chose a type — respect that
    if (!query.trim()) {
      setType("auto");
      return;
    }
    const detected = detectInputType(query.trim());
    setType(detected);
  }, [query, userPickedType]);
  // ─────────────────────────────────────────────────────────────────────────────

  const handleTypeClick = (typeId) => {
    setType(typeId);
    setUserPickedType(typeId !== "auto"); // clicking Auto-detect re-enables auto-switching
  };

  const handleQueryChange = (e) => {
    setQuery(e.target.value);
    // If the user starts typing something new, let auto-detect take over again
    if (userPickedType && !e.target.value.trim()) {
      setUserPickedType(false);
    }
  };

  const handleScan = () => {
    if (!query.trim() || scanning) return;

    // ── FIX: Always resolve the true type at scan time ───────────────────────
    // Even if auto-detect lagged or userPickedType is set to something wrong,
    // we re-detect here so the backend always gets the correct type.
    const resolvedType = (type === "auto" || !type)
      ? detectInputType(query.trim())
      : type;
    // ─────────────────────────────────────────────────────────────────────────

    setScanning(true);
    setEngineData({});
    setEngineStatus({});
    setSummary(null);
    setProgress(0);
    setError(null);

    const initStatus = {};
    ENGINE_ORDER.forEach(id => { initStatus[id] = "scanning"; });
    setEngineStatus(initStatus);

    if (esSrc.current) esSrc.current.close();

    const params = new URLSearchParams({
      query: query.trim(),
      type: resolvedType,   // always send explicit resolved type — never "auto"
    });

    const url = `${BACKEND}/scan/stream?${params}`;
    const es  = new EventSource(url);
    esSrc.current = es;

    es.addEventListener("start", (e) => {
      const data = JSON.parse(e.data);
      setTotal(data.total || 10);
    });

    es.addEventListener("engine", (e) => {
      const data = JSON.parse(e.data);
      setEngineData(prev => ({ ...prev, [data.id]: data }));
      setEngineStatus(prev => ({ ...prev, [data.id]: "done" }));
      setProgress(prev => prev + 1);
    });

    es.addEventListener("done", (e) => {
      const data = JSON.parse(e.data);
      setSummary(data);
      setScanning(false);
      es.close();

      const newHistory = [
        { query: query.trim(), type: resolvedType, verdict: data.verdict,
          score: data.score, time: new Date().toLocaleTimeString() },
        ...history.slice(0, 19)
      ];
      setHistory(newHistory);
      try { localStorage.setItem("ts_history", JSON.stringify(newHistory)); } catch {}
    });

    es.onerror = () => {
      setError("Connection error — please try again.");
      setScanning(false);
      es.close();
    };
  };

  const doneCount = Object.values(engineStatus).filter(s => s === "done").length;
  const progressPct = total > 0 ? Math.round((doneCount / total) * 100) : 0;

  const malCount   = Object.values(engineData).filter(r => r.verdict === "malicious").length;
  const suspCount  = Object.values(engineData).filter(r => r.verdict === "suspicious").length;
  const cleanCount = Object.values(engineData).filter(r => r.verdict === "clean").length;

  // Derive the label shown in the tab for display purposes
  const displayedType = query.trim() ? type : "auto";

  return (
    <>
      <Styles/>
      <div style={{ minHeight:"100vh", background:"var(--bg)" }}>
        <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0,
          background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.012) 2px,rgba(0,255,136,.012) 4px)"
        }}/>

        {/* Header */}
        <header style={{ borderBottom:"1px solid var(--border)", padding:"0 32px",
          position:"sticky", top:0, zIndex:100,
          background:"rgba(7,9,15,.92)", backdropFilter:"blur(12px)" }}>
          <div style={{ maxWidth:1200, margin:"0 auto", height:60,
            display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12 }}>
              <div style={{ width:32, height:32, borderRadius:8,
                background:"linear-gradient(135deg,#00ff88,#00cc6a)",
                display:"flex", alignItems:"center", justifyContent:"center",
                fontSize:18, boxShadow:"0 0 20px rgba(0,255,136,.3)" }}>⚔</div>
              <div>
                <div style={{ fontFamily:"var(--mono)", fontSize:15, fontWeight:700, letterSpacing:1 }}>
                  THREAT<span style={{color:"var(--green)"}}>SCAN</span>
                </div>
                <div style={{ fontSize:9, color:"var(--text3)", fontFamily:"var(--mono)", letterSpacing:2 }}>
                  OPEN SOURCE · MULTI-ENGINE
                </div>
              </div>
            </div>
            <nav style={{ display:"flex", gap:4 }}>
              {["scan","history","about"].map(t => (
                <button key={t} onClick={() => setTab(t)} style={{
                  background: tab===t ? "var(--surface2)":"none",
                  border:`1px solid ${tab===t?"var(--border2)":"transparent"}`,
                  color: tab===t ? "var(--green)":"var(--text2)",
                  padding:"6px 14px", borderRadius:6, cursor:"pointer",
                  fontFamily:"var(--mono)", fontSize:11, letterSpacing:1,
                  textTransform:"uppercase", transition:"all .2s"
                }}>{t}</button>
              ))}
            </nav>
          </div>
        </header>

        <main style={{ maxWidth:1200, margin:"0 auto", padding:"32px 24px", position:"relative", zIndex:1 }}>

          {tab === "scan" && <>
            <div style={{ textAlign:"center", marginBottom:36 }}>
              <h1 style={{ fontFamily:"var(--mono)", fontSize:"clamp(22px,4vw,40px)",
                fontWeight:700, letterSpacing:-1, lineHeight:1.1, marginBottom:10 }}>
                Multi-Engine <span style={{
                  background:"linear-gradient(90deg,var(--green),#00ccff)",
                  WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent"
                }}>Threat Intelligence</span>
              </h1>
              <p style={{ color:"var(--text2)", fontSize:14, maxWidth:500, margin:"0 auto" }}>
                Results stream live as each engine responds — no waiting for all engines to finish.
              </p>
            </div>

            {/* Type selector */}
            <div style={{ display:"flex", gap:6, justifyContent:"center", flexWrap:"wrap", marginBottom:16 }}>
              {TYPES.map(t => {
                const isActive = displayedType === t.id;
                const isAutoDetected = !userPickedType && t.id === displayedType && t.id !== "auto";
                return (
                  <button key={t.id} onClick={() => handleTypeClick(t.id)} style={{
                    background: isActive ? "var(--green)":"var(--surface2)",
                    color:      isActive ? "#000":"var(--text2)",
                    border:`1px solid ${isActive ? "var(--green)" : isAutoDetected ? "var(--green)40" : "var(--border2)"}`,
                    padding:"6px 14px", borderRadius:6, cursor:"pointer",
                    fontFamily:"var(--mono)", fontSize:11, letterSpacing:1,
                    fontWeight:isActive?700:400, transition:"all .15s",
                    // Subtle pulse on auto-detected tab to signal it switched automatically
                    boxShadow: isAutoDetected ? "0 0 8px rgba(0,255,136,.15)" : "none",
                  }}>
                    {t.label}
                    {/* Show a small dot when this tab was auto-detected */}
                    {isAutoDetected && (
                      <span style={{ marginLeft:5, fontSize:8, opacity:.7 }}>●</span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Search bar */}
            <div style={{ marginBottom:16 }}>
              <div style={{ display:"flex", border:"1px solid var(--border2)", borderRadius:10,
                overflow:"hidden", background:"var(--surface)",
                animation: scanning ? "borderGlow 2s ease-in-out infinite":"none" }}>
                <input ref={inputRef} value={query}
                  onChange={handleQueryChange}
                  onKeyDown={e => e.key==="Enter" && handleScan()}
                  placeholder={TYPES.find(t => t.id === displayedType)?.placeholder || TYPES[0].placeholder}
                  style={{ flex:1, background:"none", border:"none", padding:"16px",
                    color:"var(--text)", fontSize:14, fontFamily:"var(--mono)" }}
                />
                <button onClick={handleScan} disabled={!query.trim()||scanning} style={{
                  background: scanning ? "var(--surface2)":"var(--green)",
                  color: scanning ? "var(--text3)":"#000",
                  border:"none", padding:"0 28px", cursor:scanning?"not-allowed":"pointer",
                  fontFamily:"var(--mono)", fontSize:13, fontWeight:700, letterSpacing:1,
                  display:"flex", alignItems:"center", gap:8, minWidth:140, transition:"all .2s"
                }}>
                  {scanning ? <><Spinner color="#666" size={16}/> SCANNING…</> : "⚔ SCAN NOW"}
                </button>
              </div>
            </div>

            {/* Progress bar */}
            {(scanning || summary) && (
              <div style={{ marginBottom:20, animation:"fadeUp .3s ease" }}>
                <div style={{ display:"flex", justifyContent:"space-between",
                  fontFamily:"var(--mono)", fontSize:11, color:"var(--text2)", marginBottom:6 }}>
                  <span>{scanning ? `SCANNING ${doneCount}/${total} ENGINES…` : `COMPLETE — ${total} ENGINES`}</span>
                  <span>{progressPct}%</span>
                </div>
                <div style={{ height:3, background:"var(--surface2)", borderRadius:4, overflow:"hidden" }}>
                  <div style={{
                    height:"100%", width:`${progressPct}%`,
                    background:"linear-gradient(90deg,var(--green),#00ccff)",
                    borderRadius:4, transition:"width .3s ease",
                    boxShadow:"0 0 8px rgba(0,255,136,.4)"
                  }}/>
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div style={{ background:"#ff335510", border:"1px solid #ff335540",
                borderRadius:8, padding:"12px 16px", marginBottom:20,
                color:"#ff3355", fontFamily:"var(--mono)", fontSize:12 }}>
                ⚠ {error}
              </div>
            )}

            {/* Summary card */}
            {(scanning || summary) && doneCount > 0 && (
              <div style={{ background:"var(--surface)", borderRadius:12, padding:28,
                border:`1px solid ${
                  summary?.verdict==="malicious" ? "#ff335540" :
                  summary?.verdict==="suspicious"? "#ffd70040" :
                  summary?.verdict==="clean"     ? "#00ff8840" : "var(--border2)"
                }`,
                marginBottom:24, animation:"fadeUp .4s ease",
                transition:"border-color .5s"
              }}>
                <div style={{ display:"flex", flexWrap:"wrap", gap:24,
                  alignItems:"center", justifyContent:"space-between" }}>
                  <div>
                    <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)",
                      letterSpacing:2, marginBottom:10 }}>
                      {summary ? "FINAL VERDICT" : "LIVE VERDICT"}
                    </div>
                    {summary
                      ? <Badge verdict={summary.verdict} size="lg"/>
                      : <Badge verdict="scanning" size="lg"/>
                    }
                    <div style={{ marginTop:12, fontSize:13, color:"var(--text2)" }}>
                      <b style={{color:"var(--text)", fontFamily:"var(--mono)"}}>{query}</b>
                    </div>
                  </div>
                  <ThreatGauge score={summary?.score ?? 0}/>
                  <div style={{ display:"flex", gap:20 }}>
                    {[
                      { label:"MALICIOUS",  val:malCount,   color:"#ff3355" },
                      { label:"SUSPICIOUS", val:suspCount,  color:"#ffd700" },
                      { label:"CLEAN",      val:cleanCount, color:"#00ff88" },
                    ].map(({ label, val, color }) => (
                      <div key={label} style={{ textAlign:"center" }}>
                        <div style={{ fontFamily:"var(--mono)", fontSize:32, fontWeight:700,
                          color, transition:"all .3s" }}>{val}</div>
                        <div style={{ fontFamily:"var(--mono)", fontSize:9,
                          color:"var(--text3)", letterSpacing:1.5 }}>{label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Engine grid */}
            {Object.keys(engineStatus).length > 0 && (
              <div style={{ display:"grid",
                gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))", gap:12 }}>
                {ENGINE_ORDER.map(id => (
                  <EngineCard
                    key={id}
                    engineId={id}
                    data={engineData[id]}
                    status={engineStatus[id] || "scanning"}
                  />
                ))}
              </div>
            )}

            {/* Empty state */}
            {!scanning && !summary && Object.keys(engineStatus).length === 0 && (
              <div style={{ textAlign:"center", padding:"60px 0", color:"var(--text3)" }}>
                <div style={{ fontSize:48, marginBottom:16, opacity:.3 }}>⚔</div>
                <div style={{ fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>
                  ENTER A URL, IP, HASH OR DOMAIN TO BEGIN
                </div>
                <div style={{ marginTop:20, display:"flex", gap:10,
                  justifyContent:"center", flexWrap:"wrap" }}>
                  {["https://example.com","8.8.8.8","44d88612fea8a8f36de82e1278abb02f","malware.xyz"].map(ex => (
                    <button key={ex} onClick={() => {
                      setQuery(ex);
                      setUserPickedType(false); // let auto-detect pick the type
                      inputRef.current?.focus();
                    }} style={{
                      background:"var(--surface)", border:"1px solid var(--border2)",
                      color:"var(--text2)", padding:"7px 12px", borderRadius:6,
                      cursor:"pointer", fontFamily:"var(--mono)", fontSize:10
                    }}>{ex}</button>
                  ))}
                </div>
              </div>
            )}
          </>}

          {/* History tab */}
          {tab === "history" && (
            <div style={{ animation:"fadeUp .3s ease" }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:24, display:"flex",
                justifyContent:"space-between", alignItems:"center" }}>
                <span>📋 SCAN HISTORY</span>
                {history.length > 0 && (
                  <button onClick={() => { setHistory([]); localStorage.removeItem("ts_history"); }} style={{
                    background:"none", border:"1px solid var(--border2)", color:"var(--text3)",
                    padding:"4px 10px", borderRadius:4, cursor:"pointer",
                    fontFamily:"var(--mono)", fontSize:10 }}>CLEAR</button>
                )}
              </div>
              {history.length === 0 ? (
                <div style={{ textAlign:"center", padding:60, color:"var(--text3)",
                  fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>NO SCANS YET</div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {history.map((h, i) => (
                    <div key={i} onClick={() => {
                      setQuery(h.query);
                      setType(h.type || "auto");
                      setUserPickedType(h.type && h.type !== "auto");
                      setTab("scan");
                    }} style={{ background:"var(--surface)", border:"1px solid var(--border2)",
                        borderRadius:8, padding:"12px 16px", cursor:"pointer",
                        display:"flex", alignItems:"center", justifyContent:"space-between",
                        flexWrap:"wrap", gap:8 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                        <Badge verdict={h.verdict}/>
                        <span style={{ fontFamily:"var(--mono)", fontSize:12 }}>{h.query}</span>
                      </div>
                      <div style={{ display:"flex", gap:14, alignItems:"center" }}>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>
                          {(h.type||"auto").toUpperCase()}</span>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>{h.time}</span>
                        <span style={{ fontFamily:"var(--mono)", fontSize:11,
                          color:h.score>=50?"#ff3355":h.score>=20?"#ffd700":"#00ff88" }}>
                          {h.score}/100</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* About tab */}
          {tab === "about" && (
            <div style={{ animation:"fadeUp .3s ease", maxWidth:720 }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:24 }}>ℹ ABOUT THREATSCAN</div>
              <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
                {[
                  ["🔍 What is ThreatScan?","An open-source, multi-engine threat intelligence platform. Simultaneously queries 10 free and open threat intelligence APIs and streams results live as each engine responds."],
                  ["⚡ Streaming Results","Results appear engine-by-engine as they arrive using Server-Sent Events — no waiting for all engines to finish before seeing data."],
                  ["🔒 Privacy & Security","API keys are stored server-side in environment variables. ThreatScan logs nothing and has no database. Results are cached for 5 minutes for speed."],
                  ["📦 Contributing","Open source under MIT license. Add new engines by creating a file in backend/engines/ and registering it in server.js."],
                ].map(([title, body]) => (
                  <div key={title} style={{ background:"var(--surface)",
                    border:"1px solid var(--border2)", borderRadius:8, padding:20 }}>
                    <div style={{ fontFamily:"var(--mono)", fontSize:12, fontWeight:700, marginBottom:8 }}>{title}</div>
                    <div style={{ fontSize:13, color:"var(--text2)", lineHeight:1.75 }}>{body}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        <footer style={{ borderTop:"1px solid var(--border)", padding:"16px 32px",
          textAlign:"center", fontFamily:"var(--mono)", fontSize:10,
          color:"var(--text3)", letterSpacing:1 }}>
          THREATSCAN · OPEN SOURCE · MIT LICENSE · MULTI-ENGINE THREAT INTELLIGENCE
        </footer>
      </div>
    </>
  );
}
