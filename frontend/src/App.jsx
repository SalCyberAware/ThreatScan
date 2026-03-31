import { useState, useRef } from "react";

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
    @keyframes spin    { to{transform:rotate(360deg)} }
    @keyframes countUp { from{opacity:0;transform:scale(.8)} to{opacity:1;transform:scale(1)} }
    @keyframes borderGlow {
      0%,100%{border-color:var(--border2);box-shadow:none}
      50%{border-color:var(--green);box-shadow:0 0 12px rgba(0,255,136,.15)}
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

const TYPES = [
  { id:"auto",   label:"Auto-detect",  placeholder:"Paste anything — URL, IP, hash, domain…" },
  { id:"url",    label:"URL",          placeholder:"https://suspicious-site.example.com"      },
  { id:"ip",     label:"IP / Host",    placeholder:"192.168.1.1"                              },
  { id:"hash",   label:"File Hash",    placeholder:"SHA256 / MD5 / SHA1"                      },
  { id:"domain", label:"Domain",       placeholder:"malware-domain.example"                   },
];

const Badge = ({ verdict, size="sm" }) => {
  const MAP = {
    malicious:  { bg:"#ff335515", border:"#ff3355", text:"#ff3355", label:"MALICIOUS"  },
    suspicious: { bg:"#ffd70015", border:"#ffd700", text:"#ffd700", label:"SUSPICIOUS" },
    clean:      { bg:"#00ff8815", border:"#00ff88", text:"#00ff88", label:"CLEAN"      },
    info:       { bg:"#4fa3ff15", border:"#4fa3ff", text:"#4fa3ff", label:"INFO"       },
    skipped:    { bg:"#3d4a6620", border:"#3d4a66", text:"#3d4a66", label:"SKIPPED"    },
    error:      { bg:"#ff335510", border:"#553333", text:"#996666", label:"ERROR"      },
  };
  const c = MAP[verdict] || MAP.info;
  return (
    <span style={{ background:c.bg, border:`1px solid ${c.border}`, color:c.text,
      padding: size==="lg" ? "6px 14px":"3px 8px",
      fontSize: size==="lg" ? 13:10,
      borderRadius:4, fontFamily:"var(--mono)", fontWeight:700,
      letterSpacing:1, display:"inline-flex", alignItems:"center", gap:5
    }}>
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
          strokeDasharray={`${(score/100)*188} 188`}/>
        <g transform={`rotate(${-90+(score/100)*180},80,80)`}>
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

const EngineCard = ({ engineId, data }) => {
  const meta = ENGINE_META[engineId] || { name: engineId, icon:"🔧" };
  const borderColor = data.verdict==="malicious"  ? "#ff3355"
                    : data.verdict==="suspicious" ? "#ffd700"
                    : data.verdict==="clean"      ? "#00ff8840"
                    : "#1a2035";
  return (
    <div style={{ background:"var(--surface2)", border:`1px solid ${borderColor}`,
      borderRadius:8, padding:"14px 16px", transition:"border-color .4s",
      animation:"fadeUp .3s ease both",
      boxShadow: data.verdict==="malicious" ? "0 0 16px rgba(255,51,85,.07)":"none"
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:18 }}>{meta.icon}</span>
          <span style={{ fontSize:13, fontWeight:600 }}>{meta.name}</span>
        </div>
        <Badge verdict={data.verdict}/>
      </div>
      <div style={{ fontSize:11, color:"var(--text2)", fontFamily:"var(--mono)",
        display:"flex", flexWrap:"wrap", gap:"5px 14px" }}>
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
    </div>
  );
};

export default function App() {
  const [query,   setQuery]   = useState("");
  const [type,    setType]    = useState("auto");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState(null);
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem("ts_history") || "[]"); } catch { return []; }
  });
  const [tab, setTab] = useState("scan");
  const inputRef = useRef();

  const handleScan = async () => {
    if (!query.trim() || loading) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await fetch(`${BACKEND}/scan`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ query: query.trim(), type: type === "auto" ? undefined : type }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error || `HTTP ${res.status}`); }
      const data = await res.json();
      setResult(data);
      const newHistory = [{ query: data.query, type: data.type, verdict: data.verdict,
        score: data.score, time: new Date().toLocaleTimeString() }, ...history.slice(0, 19)];
      setHistory(newHistory);
      try { localStorage.setItem("ts_history", JSON.stringify(newHistory)); } catch {}
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Styles/>
      <div style={{ minHeight:"100vh", background:"var(--bg)" }}>
        <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0,
          background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.012) 2px,rgba(0,255,136,.012) 4px)"
        }}/>
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
                Scan URLs, IPs, file hashes & domains across {Object.keys(ENGINE_META).length} live security engines simultaneously.
              </p>
            </div>
            <div style={{ display:"flex", gap:6, justifyContent:"center", flexWrap:"wrap", marginBottom:16 }}>
              {TYPES.map(t => (
                <button key={t.id} onClick={() => setType(t.id)} style={{
                  background: type===t.id ? "var(--green)":"var(--surface2)",
                  color:      type===t.id ? "#000":"var(--text2)",
                  border:`1px solid ${type===t.id?"var(--green)":"var(--border2)"}`,
                  padding:"6px 14px", borderRadius:6, cursor:"pointer",
                  fontFamily:"var(--mono)", fontSize:11, letterSpacing:1,
                  fontWeight:type===t.id?700:400, transition:"all .15s"
                }}>{t.label}</button>
              ))}
            </div>
            <div style={{ marginBottom:24 }}>
              <div style={{ display:"flex", border:"1px solid var(--border2)", borderRadius:10,
                overflow:"hidden", background:"var(--surface)",
                animation: loading ? "borderGlow 2s ease-in-out infinite":"none" }}>
                <input ref={inputRef} value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => e.key==="Enter" && handleScan()}
                  placeholder={TYPES.find(t=>t.id===type)?.placeholder}
                  style={{ flex:1, background:"none", border:"none", padding:"16px",
                    color:"var(--text)", fontSize:14, fontFamily:"var(--mono)" }}
                />
                <button onClick={handleScan} disabled={!query.trim()||loading} style={{
                  background: loading ? "var(--surface2)":"var(--green)",
                  color: loading ? "var(--text3)":"#000",
                  border:"none", padding:"0 28px", cursor:loading?"not-allowed":"pointer",
                  fontFamily:"var(--mono)", fontSize:13, fontWeight:700, letterSpacing:1,
                  display:"flex", alignItems:"center", gap:8, minWidth:140, transition:"all .2s"
                }}>
                  {loading ? <><Spinner color="#666" size={16}/> SCANNING…</> : "⚔ SCAN NOW"}
                </button>
              </div>
            </div>
            {error && (
              <div style={{ background:"#ff335510", border:"1px solid #ff335540",
                borderRadius:8, padding:"12px 16px", marginBottom:20,
                color:"#ff3355", fontFamily:"var(--mono)", fontSize:12 }}>⚠ {error}</div>
            )}
            {result && (
              <div style={{ animation:"fadeUp .4s ease" }}>
                <div style={{ background:"var(--surface)", borderRadius:12, padding:28,
                  border:`1px solid ${result.verdict==="malicious"?"#ff335540":result.verdict==="suspicious"?"#ffd70040":"#00ff8840"}`,
                  marginBottom:24 }}>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:24,
                    alignItems:"center", justifyContent:"space-between" }}>
                    <div>
                      <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)",
                        letterSpacing:2, marginBottom:10 }}>FINAL VERDICT</div>
                      <Badge verdict={result.verdict} size="lg"/>
                      <div style={{ marginTop:12, fontSize:13, color:"var(--text2)" }}>
                        <b style={{color:"var(--text)", fontFamily:"var(--mono)"}}>{result.query}</b>
                        <span style={{ marginLeft:10, fontFamily:"var(--mono)", fontSize:10,
                          color:"var(--text3)" }}>{result.type.toUpperCase()}</span>
                      </div>
                    </div>
                    <ThreatGauge score={result.score}/>
                    <div style={{ display:"flex", gap:20 }}>
                      {[
                        { label:"MALICIOUS",  val:result.malicious,  color:"#ff3355" },
                        { label:"SUSPICIOUS", val:result.suspicious, color:"#ffd700" },
                        { label:"CLEAN",      val:result.clean,      color:"#00ff88" },
                      ].map(({ label, val, color }) => (
                        <div key={label} style={{ textAlign:"center" }}>
                          <div style={{ fontFamily:"var(--mono)", fontSize:32,
                            fontWeight:700, color, animation:"countUp .5s ease" }}>{val}</div>
                          <div style={{ fontFamily:"var(--mono)", fontSize:9,
                            color:"var(--text3)", letterSpacing:1.5 }}>{label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div style={{ display:"grid",
                  gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))", gap:12 }}>
                  {result.engines.map(engine => (
                    <EngineCard key={engine.id} engineId={engine.id} data={engine}/>
                  ))}
                </div>
              </div>
            )}
            {!result && !loading && !error && (
              <div style={{ textAlign:"center", padding:"60px 0", color:"var(--text3)" }}>
                <div style={{ fontSize:48, marginBottom:16, opacity:.3 }}>⚔</div>
                <div style={{ fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>
                  ENTER A URL, IP, HASH OR DOMAIN TO BEGIN
                </div>
                <div style={{ marginTop:20, display:"flex", gap:10,
                  justifyContent:"center", flexWrap:"wrap" }}>
                  {["https://example.com","8.8.8.8","44d88612fea8a8f36de82e1278abb02f","malware.xyz"].map(ex => (
                    <button key={ex} onClick={() => { setQuery(ex); inputRef.current?.focus(); }} style={{
                      background:"var(--surface)", border:"1px solid var(--border2)",
                      color:"var(--text2)", padding:"7px 12px", borderRadius:6,
                      cursor:"pointer", fontFamily:"var(--mono)", fontSize:10
                    }}>{ex}</button>
                  ))}
                </div>
              </div>
            )}
          </>}

          {tab === "history" && (
            <div style={{ animation:"fadeUp .3s ease" }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:24 }}>📋 SCAN HISTORY</div>
              {history.length === 0 ? (
                <div style={{ textAlign:"center", padding:60, color:"var(--text3)",
                  fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>NO SCANS YET</div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {history.map((h, i) => (
                    <div key={i} onClick={() => { setQuery(h.query); setType(h.type); setTab("scan"); }}
                      style={{ background:"var(--surface)", border:"1px solid var(--border2)",
                        borderRadius:8, padding:"12px 16px", cursor:"pointer",
                        display:"flex", alignItems:"center", justifyContent:"space-between",
                        flexWrap:"wrap", gap:8 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                        <Badge verdict={h.verdict}/>
                        <span style={{ fontFamily:"var(--mono)", fontSize:12 }}>{h.query}</span>
                      </div>
                      <div style={{ display:"flex", gap:14, alignItems:"center" }}>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10,
                          color:"var(--text3)" }}>{h.type.toUpperCase()}</span>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10,
                          color:"var(--text3)" }}>{h.time}</span>
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

          {tab === "about" && (
            <div style={{ animation:"fadeUp .3s ease", maxWidth:720 }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:24 }}>ℹ ABOUT THREATSCAN</div>
              <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
                {[
                  ["🔍 What is ThreatScan?","An open-source, multi-engine threat intelligence platform. Simultaneously queries 10 free and open threat intelligence APIs for a comprehensive security verdict on any URL, IP, file hash, or domain."],
                  ["🔒 Privacy & Security","API keys are stored server-side in environment variables and never exposed to the browser. ThreatScan logs nothing and has no database."],
                  ["🛠 Self-Hosting","Node.js backend + React frontend. Deploy on any VPS, Railway, Render, or Vercel/Netlify. See the README for full setup instructions."],
                  ["📦 Contributing","Open source under MIT license. Add new engines by creating a file in backend/engines/ and registering it in server.js."],
                ].map(([title, body]) => (
                  <div key={title} style={{ background:"var(--surface)",
                    border:"1px solid var(--border2)", borderRadius:8, padding:20 }}>
                    <div style={{ fontFamily:"var(--mono)", fontSize:12,
                      fontWeight:700, marginBottom:8 }}>{title}</div>
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
