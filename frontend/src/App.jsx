import { useState, useRef, useEffect, useCallback } from "react";

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
    @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
    @keyframes borderGlow {
      0%,100%{border-color:var(--border2);box-shadow:none}
      50%{border-color:var(--green);box-shadow:0 0 12px rgba(0,255,136,.15)}
    }
    @keyframes dropPulse {
      0%,100%{border-color:#00ff8860;box-shadow:0 0 0 0 rgba(0,255,136,0)}
      50%{border-color:var(--green);box-shadow:0 0 20px rgba(0,255,136,.2)}
    }
    input:focus, textarea:focus { outline:none; }
    button:focus-visible { outline:2px solid var(--green); outline-offset:2px; }

    .ts-header-inner {
      max-width:1200px; margin:0 auto; height:60px;
      display:flex; align-items:center; justify-content:space-between; padding:0 24px;
    }
    .ts-nav { display:flex; gap:4px; }
    .ts-nav button { padding:6px 10px; font-size:10px; }
    .ts-main { max-width:1200px; margin:0 auto; padding:32px 24px; position:relative; z-index:1; }
    .ts-search-bar {
      display:flex; border:1px solid var(--border2); border-radius:10px;
      overflow:hidden; background:var(--surface);
    }
    .ts-search-bar input {
      flex:1; background:none; border:none; padding:16px;
      color:var(--text); font-size:14px; font-family:var(--mono); min-width:0;
    }
    .ts-scan-btn {
      background:var(--green); color:#000; border:none; padding:0 24px;
      cursor:pointer; font-family:var(--mono); font-size:13px; font-weight:700;
      letter-spacing:1px; display:flex; align-items:center; gap:8px;
      white-space:nowrap; flex-shrink:0; transition:all .2s;
    }
    .ts-scan-btn:disabled { background:var(--surface2); color:var(--text3); cursor:not-allowed; }
    .ts-summary-inner {
      display:flex; flex-wrap:wrap; gap:24px;
      align-items:center; justify-content:space-between;
    }
    .ts-counts { display:flex; gap:20px; }
    .ts-engine-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:12px; }
    .ts-history-item { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px; }
    .ts-history-meta { display:flex; gap:14px; align-items:center; }
    .ts-dropzone {
      border:2px dashed var(--border2); border-radius:10px; padding:28px;
      text-align:center; cursor:pointer; transition:all .2s; background:var(--surface); margin-bottom:12px;
    }
    .ts-dropzone:hover, .ts-dropzone.drag-over { animation:dropPulse 1.5s ease-in-out infinite; background:#00ff8808; }
    .ts-dropzone.drag-over { border-color:var(--green); }

    /* Bulk scan table */
    .ts-bulk-table { width:100%; border-collapse:collapse; font-family:var(--mono); font-size:12px; }
    .ts-bulk-table th {
      text-align:left; padding:10px 12px; color:var(--text3);
      border-bottom:1px solid var(--border); font-size:10px; letter-spacing:1px;
    }
    .ts-bulk-table td { padding:10px 12px; border-bottom:1px solid var(--border2); vertical-align:middle; }
    .ts-bulk-table tr:hover td { background:var(--surface2); }
    .ts-bulk-row-scanning td { opacity:.5; }

    @media (max-width:768px) {
      .ts-header-inner { padding:0 16px; height:52px; }
      .ts-logo-sub { display:none; }
      .ts-main { padding:24px 16px; }
      .ts-engine-grid { grid-template-columns:1fr; }
      .ts-summary-inner { gap:16px; justify-content:center; text-align:center; }
      .ts-counts { justify-content:center; }
      .ts-bulk-table th:nth-child(3), .ts-bulk-table td:nth-child(3) { display:none; }
    }
    @media (max-width:480px) {
      .ts-header-inner { height:48px; }
      .ts-nav button { padding:4px 8px; font-size:9px; }
      .ts-search-bar { flex-direction:column; border-radius:10px; }
      .ts-search-bar input { padding:14px 16px; border-bottom:1px solid var(--border2); }
      .ts-scan-btn { width:100%; justify-content:center; padding:14px; border-radius:0 0 10px 10px; }
      .ts-main { padding:16px 12px; }
      .ts-counts { gap:12px; }
      .ts-history-item { flex-direction:column; align-items:flex-start; }
    }
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
  urlhaus:       { name:"URLhaus",           icon:"🕷" },
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

const IP_RE     = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const MD5_RE    = /^[a-fA-F0-9]{32}$/;
const SHA1_RE   = /^[a-fA-F0-9]{40}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const URL_RE    = /^https?:\/\/.+/i;
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function detectInputType(q) {
  if (!q || !q.trim()) return "auto";
  const s = q.trim();
  if (URL_RE.test(s))    return "url";
  if (IP_RE.test(s))     return "ip";
  if (MD5_RE.test(s) || SHA1_RE.test(s) || SHA256_RE.test(s)) return "hash";
  if (DOMAIN_RE.test(s)) return "domain";
  return "auto";
}

async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,"0")).join("");
}

const VERDICT_COLOR = { malicious:"#ff3355", suspicious:"#ffd700", clean:"#00ff88", error:"#996666", skipped:"#3d4a66" };

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
      padding: size==="lg" ? "6px 14px":"3px 8px", fontSize: size==="lg" ? 13:10,
      borderRadius:4, fontFamily:"var(--mono)", fontWeight:700, letterSpacing:1,
      display:"inline-flex", alignItems:"center", gap:5 }}>
      {verdict==="scanning" && <span style={{ width:7, height:7, borderRadius:"50%",
        background:c.text, animation:"pulse 1s infinite", flexShrink:0 }}/>}
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
      <svg width="140" height="80" viewBox="0 0 160 90">
        <defs>
          <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#00ff88"/><stop offset="50%" stopColor="#ffd700"/>
            <stop offset="100%" stopColor="#ff3355"/>
          </linearGradient>
        </defs>
        <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke="#1a2035" strokeWidth="14" strokeLinecap="round"/>
        <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke="url(#g)" strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${(score/100)*188} 188`} style={{ transition:"stroke-dasharray .6s ease" }}/>
        <g transform={`rotate(${-90+(score/100)*180},80,80)`} style={{ transition:"transform .6s ease" }}>
          <line x1="80" y1="80" x2="80" y2="28" stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
          <circle cx="80" cy="80" r="5" fill={color}/>
        </g>
        <text x="80" y="72" textAnchor="middle" fontSize="20" fontWeight="700" fontFamily="var(--mono)" fill={color}>{score}</text>
      </svg>
      <div style={{ fontFamily:"var(--mono)", fontSize:11, color, letterSpacing:2, marginTop:-4 }}>{label}</div>
    </div>
  );
};

const EngineCard = ({ engineId, data, status }) => {
  const meta = ENGINE_META[engineId] || { name:engineId, icon:"🔧" };
  const isScanning = status === "scanning";
  const borderColor = isScanning ? "#9b72ff40"
    : data?.verdict==="malicious"  ? "#ff3355"
    : data?.verdict==="suspicious" ? "#ffd700"
    : data?.verdict==="clean"      ? "#00ff8840" : "#1a2035";
  return (
    <div style={{ background:"var(--surface2)", border:`1px solid ${borderColor}`, borderRadius:8,
      padding:"14px 16px", transition:"border-color .4s", animation:"slideIn .25s ease both",
      boxShadow: data?.verdict==="malicious" ? "0 0 16px rgba(255,51,85,.07)":"none" }}>
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
          {data.engines    !== undefined && <span>Engines: <b style={{color:"var(--text)"}}>{data.flagged}/{data.engines}</b></span>}
          {data.confidence !== undefined && <span>Confidence: <b style={{color:"var(--text)"}}>{data.confidence}%</b></span>}
          {data.reports    !== undefined && <span>Reports: <b style={{color:"var(--text)"}}>{data.reports}</b></span>}
          {data.pulses     !== undefined && <span>Pulses: <b style={{color:"var(--text)"}}>{data.pulses}</b></span>}
          {data.type       && <span>Type: <b style={{color:"#ff3355"}}>{data.type}</b></span>}
          {data.malware    && <span>Malware: <b style={{color:"#ff3355"}}>{data.malware}</b></span>}
          {data.org        && <span>Org: <b style={{color:"var(--text)"}}>{data.org}</b></span>}
          {data.city       && <span>Location: <b style={{color:"var(--text)"}}>{data.city}, {data.country}</b></span>}
          {data.classification && <span>Class: <b style={{color:"var(--text)"}}>{data.classification}</b></span>}
          {data.detail     && <span style={{color:"var(--text3)"}}>{data.detail}</span>}
          {data.tags?.length     > 0 && <span>Tags: <b style={{color:"#ff3355"}}>{data.tags.join(", ")}</b></span>}
          {data.threats?.length  > 0 && <span>Threats: <b style={{color:"#ff3355"}}>{data.threats.join(", ")}</b></span>}
          {data.brands?.length   > 0 && <span>Brands: <b style={{color:"#ffd700"}}>{data.brands.join(", ")}</b></span>}
          {data.indicators?.length > 0 && <span>IOCs: <b style={{color:"#ff3355"}}>{data.indicators.join(", ")}</b></span>}
          {data.registrar   && <span style={{width:"100%"}}>Registrar: <b style={{color:"var(--text)"}}>{data.registrar}</b></span>}
          {data.created     && <span>Created: <b style={{color:"var(--text)"}}>{data.created}</b></span>}
          {data.expires     && <span>Expires: <b style={{color:"var(--text)"}}>{data.expires}</b></span>}
          {data.aRecords?.length   > 0 && <span style={{width:"100%"}}>A Records: <b style={{color:"var(--text)"}}>{data.aRecords.join(", ")}</b></span>}
          {data.mxRecords?.length  > 0 && <span style={{width:"100%"}}>MX: <b style={{color:"var(--text)"}}>{data.mxRecords.join(", ")}</b></span>}
          {data.nameservers?.length > 0 && <span style={{width:"100%"}}>NS: <b style={{color:"var(--text)"}}>{data.nameservers.join(", ")}</b></span>}
          {data.screenshot && (
            <a href={data.screenshot} target="_blank" rel="noopener noreferrer"
              style={{ width:"100%", marginTop:8, display:"block" }}>
              <img src={data.screenshot} alt="URLScan screenshot"
                style={{ width:"100%", borderRadius:6, border:"1px solid var(--border2)",
                  maxHeight:160, objectFit:"cover", cursor:"pointer",
                  transition:"opacity .2s", opacity:.85 }}
                onMouseOver={e => e.target.style.opacity=1}
                onMouseOut={e => e.target.style.opacity=.85}
              />
              <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text3)",
                marginTop:4, textAlign:"center" }}>Click to open full screenshot ↗</div>
            </a>
          )}
        </div>
      )}
    </div>
  );
};

// ── Bulk Scan UI ──────────────────────────────────────────────────────────────
const BulkScan = () => {
  const [input,    setInput]    = useState("");
  const [scanning, setScanning] = useState(false);
  const [results,  setResults]  = useState([]);
  const [summary,  setSummary]  = useState(null);
  const [error,    setError]    = useState(null);
  const esSrc = useRef(null);

  const lineCount = input.split("\n").filter(l => l.trim()).length;
  const overLimit = lineCount > 20;

  const startBulk = () => {
    if (!input.trim() || scanning || overLimit) return;
    setScanning(true);
    setResults([]);
    setSummary(null);
    setError(null);

    if (esSrc.current) esSrc.current.close();

    const params = new URLSearchParams({ queries: input.trim() });
    const es = new EventSource(`${BACKEND}/scan/bulk?${params}`);
    esSrc.current = es;

    es.addEventListener("start", (e) => {
      const d = JSON.parse(e.data);
      // Pre-populate table with scanning state
      setResults(d.queries.map((q, i) => ({ index:i, query:q, status:"scanning" })));
    });

    es.addEventListener("result", (e) => {
      const d = JSON.parse(e.data);
      setResults(prev => prev.map(r => r.index === d.index ? { ...r, ...d, status:"done" } : r));
    });

    es.addEventListener("done", (e) => {
      const d = JSON.parse(e.data);
      setSummary(d);
      setScanning(false);
      es.close();
    });

    es.onerror = () => {
      setError("Connection error — please try again.");
      setScanning(false);
      es.close();
    };
  };

  const exportCSV = () => {
    if (!results.length) return;
    const rows = [["Query","Type","Verdict","Score","Malicious","Suspicious","Clean","Cached"]];
    results.forEach(r => {
      if (r.status === "done") {
        rows.push([r.query, r.type, r.verdict, r.score, r.malicious, r.suspicious, r.clean, r.cached]);
      }
    });
    const csv = rows.map(r => r.join(",")).join("\n");
    const blob = new Blob([csv], { type:"text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `threatscan-bulk-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ animation:"fadeUp .3s ease" }}>
      <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
        letterSpacing:2, marginBottom:8 }}>⚡ BULK SCAN</div>
      <div style={{ fontSize:13, color:"var(--text2)", marginBottom:20 }}>
        Paste up to 20 URLs, IPs, domains, or hashes — one per line. Each is auto-detected and scanned across all engines.
      </div>

      {/* Input */}
      <div style={{ position:"relative", marginBottom:12 }}>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={"https://malicious-site.com\n8.8.8.8\nmalware.xyz\n44d88612fea8a8f36de82e1278abb02f"}
          rows={8}
          style={{ width:"100%", background:"var(--surface)", border:`1px solid ${overLimit?"#ff3355":"var(--border2)"}`,
            borderRadius:10, padding:16, color:"var(--text)", fontFamily:"var(--mono)",
            fontSize:13, resize:"vertical", lineHeight:1.6 }}
        />
        <div style={{ position:"absolute", bottom:12, right:12,
          fontFamily:"var(--mono)", fontSize:10,
          color: overLimit ? "#ff3355" : "var(--text3)" }}>
          {lineCount}/20
        </div>
      </div>

      {overLimit && (
        <div style={{ color:"#ff3355", fontFamily:"var(--mono)", fontSize:11,
          marginBottom:12 }}>⚠ Maximum 20 queries — remove {lineCount - 20} line{lineCount-20>1?"s":""}</div>
      )}

      <div style={{ display:"flex", gap:10, marginBottom:24, flexWrap:"wrap" }}>
        <button onClick={startBulk} disabled={!input.trim() || scanning || overLimit} style={{
          background: scanning||overLimit ? "var(--surface2)":"var(--green)",
          color: scanning||overLimit ? "var(--text3)":"#000",
          border:"none", borderRadius:8, padding:"12px 24px", cursor: scanning||overLimit?"not-allowed":"pointer",
          fontFamily:"var(--mono)", fontSize:13, fontWeight:700, letterSpacing:1,
          display:"flex", alignItems:"center", gap:8 }}>
          {scanning ? <><Spinner color="#666" size={16}/> SCANNING…</> : "⚡ SCAN ALL"}
        </button>
        {results.length > 0 && !scanning && (
          <button onClick={exportCSV} style={{
            background:"var(--surface2)", color:"var(--green)",
            border:"1px solid var(--green)", borderRadius:8, padding:"12px 20px",
            cursor:"pointer", fontFamily:"var(--mono)", fontSize:12, fontWeight:700 }}>
            ⬇ EXPORT CSV
          </button>
        )}
      </div>

      {error && (
        <div style={{ background:"#ff335510", border:"1px solid #ff335540", borderRadius:8,
          padding:"12px 16px", marginBottom:20, color:"#ff3355", fontFamily:"var(--mono)", fontSize:12 }}>
          ⚠ {error}
        </div>
      )}

      {/* Summary bar */}
      {summary && (
        <div style={{ background:"var(--surface)", border:"1px solid var(--border2)", borderRadius:10,
          padding:"16px 20px", marginBottom:16, display:"flex", gap:24, flexWrap:"wrap",
          alignItems:"center", animation:"fadeUp .3s ease" }}>
          <span style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text3)" }}>
            SCAN COMPLETE — {summary.total} QUERIES
          </span>
          {[
            { label:"MALICIOUS",  val:summary.malicious,  color:"#ff3355" },
            { label:"SUSPICIOUS", val:summary.suspicious, color:"#ffd700" },
            { label:"CLEAN",      val:summary.clean,      color:"#00ff88" },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ display:"flex", alignItems:"center", gap:6 }}>
              <span style={{ fontFamily:"var(--mono)", fontSize:18, fontWeight:700, color }}>{val}</span>
              <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text3)" }}>{label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Results table */}
      {results.length > 0 && (
        <div style={{ background:"var(--surface)", border:"1px solid var(--border2)",
          borderRadius:10, overflow:"hidden", animation:"fadeUp .3s ease" }}>
          <table className="ts-bulk-table">
            <thead>
              <tr>
                <th>#</th>
                <th>QUERY</th>
                <th>TYPE</th>
                <th>VERDICT</th>
                <th>SCORE</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} className={r.status === "scanning" ? "ts-bulk-row-scanning":""}>
                  <td style={{ color:"var(--text3)", width:32 }}>{i+1}</td>
                  <td style={{ fontFamily:"var(--mono)", fontSize:11,
                    maxWidth:300, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {r.query}
                  </td>
                  <td style={{ color:"var(--text3)", fontSize:10 }}>
                    {r.type ? r.type.toUpperCase() : "—"}
                  </td>
                  <td>
                    {r.status === "scanning"
                      ? <Badge verdict="scanning"/>
                      : <Badge verdict={r.verdict}/>
                    }
                  </td>
                  <td style={{ fontFamily:"var(--mono)", fontSize:13, fontWeight:700,
                    color: r.score >= 50 ? "#ff3355" : r.score >= 20 ? "#ffd700" : "#00ff88" }}>
                    {r.status === "scanning" ? "—" : `${r.score ?? 0}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const [query,        setQuery]        = useState("");
  const [detectedType, setDetectedType] = useState("auto");
  const [manualType,   setManualType]   = useState(null);
  const [scanning,     setScanning]     = useState(false);
  const [engineData,   setEngineData]   = useState({});
  const [engineStatus, setEngineStatus] = useState({});
  const [summary,      setSummary]      = useState(null);
  const [total,        setTotal]        = useState(10);
  const [error,        setError]        = useState(null);
  const [dragOver,     setDragOver]     = useState(false);
  const [fileInfo,     setFileInfo]     = useState(null);
  const [hashing,      setHashing]      = useState(false);
  const [history,      setHistory]      = useState(() => {
    try { return JSON.parse(localStorage.getItem("ts_history") || "[]"); } catch { return []; }
  });
  const [tab, setTab] = useState("scan");
  const inputRef = useRef();
  const fileRef  = useRef();
  const esSrc    = useRef(null);

  useEffect(() => {
    setDetectedType(detectInputType(query));
    setManualType(null);
    setFileInfo(null);
  }, [query]);

  const activeType = manualType || detectedType;

  const processFile = useCallback(async (file) => {
    if (!file) return;
    setHashing(true); setError(null);
    try {
      const hash = await hashFile(file);
      const size = (file.size / 1024).toFixed(1);
      setFileInfo({ name: file.name, size, hash });
      setQuery(hash);
      setManualType("hash");
    } catch { setError("Could not hash file — try a different file."); }
    finally { setHashing(false); }
  }, []);

  const handleDrop      = useCallback((e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) processFile(f); }, [processFile]);
  const handleDragOver  = (e) => { e.preventDefault(); setDragOver(true); };
  const handleDragLeave = () => setDragOver(false);
  const handleFileInput = (e) => { const f = e.target.files[0]; if (f) processFile(f); };

  const handleScan = () => {
    if (!query.trim() || scanning) return;
    const resolvedType = activeType === "auto" ? detectInputType(query.trim()) : activeType;
    setScanning(true); setEngineData({}); setEngineStatus({}); setSummary(null); setError(null);
    const initStatus = {};
    ENGINE_ORDER.forEach(id => { initStatus[id] = "scanning"; });
    setEngineStatus(initStatus);
    if (esSrc.current) esSrc.current.close();
    const params = new URLSearchParams({ query: query.trim(), type: resolvedType });
    const es = new EventSource(`${BACKEND}/scan/stream?${params}`);
    esSrc.current = es;
    es.addEventListener("start", (e) => { const d = JSON.parse(e.data); setTotal(d.total || 10); });
    es.addEventListener("engine", (e) => {
      const d = JSON.parse(e.data);
      setEngineData(prev => ({ ...prev, [d.id]: d }));
      setEngineStatus(prev => ({ ...prev, [d.id]: "done" }));
    });
    es.addEventListener("done", (e) => {
      const d = JSON.parse(e.data); setSummary(d); setScanning(false); es.close();
      const label = fileInfo ? fileInfo.name : query.trim();
      const newHistory = [
        { query: query.trim(), label, type: resolvedType, verdict: d.verdict,
          score: d.score, time: new Date().toLocaleTimeString() },
        ...history.slice(0, 19)
      ];
      setHistory(newHistory);
      try { localStorage.setItem("ts_history", JSON.stringify(newHistory)); } catch {}
    });
    es.onerror = () => { setError("Connection error — please try again."); setScanning(false); es.close(); };
  };

  const doneCount   = Object.values(engineStatus).filter(s => s === "done").length;
  const progressPct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
  const malCount    = Object.values(engineData).filter(r => r.verdict === "malicious").length;
  const suspCount   = Object.values(engineData).filter(r => r.verdict === "suspicious").length;
  const cleanCount  = Object.values(engineData).filter(r => r.verdict === "clean").length;

  // ── Export single scan results as JSON ────────────────────────────────────
  const exportJSON = () => {
    if (!summary) return;
    const output = {
      query:      query.trim(),
      fileName:   fileInfo?.name || null,
      type:       detectInputType(query.trim()),
      verdict:    summary.verdict,
      score:      summary.score,
      scannedAt:  summary.scannedAt || new Date().toISOString(),
      engines:    Object.entries(engineData).map(([id, data]) => ({ id, ...data })),
    };
    const blob = new Blob([JSON.stringify(output, null, 2)], { type:"application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    const name = fileInfo ? fileInfo.name : query.trim().replace(/[^a-z0-9]/gi, "_").slice(0, 40);
    a.href = url; a.download = `threatscan-${name}-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <>
      <Styles/>
      <div style={{ minHeight:"100vh", background:"var(--bg)" }}>
        <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0,
          background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.012) 2px,rgba(0,255,136,.012) 4px)"
        }}/>

        <header style={{ borderBottom:"1px solid var(--border)", position:"sticky", top:0, zIndex:100,
          background:"rgba(7,9,15,.92)", backdropFilter:"blur(12px)" }}>
          <div className="ts-header-inner">
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <div style={{ width:32, height:32, borderRadius:8, flexShrink:0,
                background:"linear-gradient(135deg,#00ff88,#00cc6a)",
                display:"flex", alignItems:"center", justifyContent:"center",
                fontSize:18, boxShadow:"0 0 20px rgba(0,255,136,.3)" }}>⚔</div>
              <div>
                <div style={{ fontFamily:"var(--mono)", fontSize:15, fontWeight:700, letterSpacing:1 }}>
                  THREAT<span style={{color:"var(--green)"}}>SCAN</span>
                </div>
                <div className="ts-logo-sub" style={{ fontSize:9, color:"var(--text3)", fontFamily:"var(--mono)", letterSpacing:2 }}>
                  OPEN SOURCE · MULTI-ENGINE
                </div>
              </div>
            </div>
            <nav className="ts-nav">
              {["scan","bulk","trends","history","about"].map(t => (
                <button key={t} onClick={() => setTab(t)} style={{
                  background: tab===t ? "var(--surface2)":"none",
                  border:`1px solid ${tab===t?"var(--border2)":"transparent"}`,
                  color: tab===t ? "var(--green)":"var(--text2)",
                  borderRadius:6, cursor:"pointer", fontFamily:"var(--mono)",
                  letterSpacing:1, textTransform:"uppercase", transition:"all .2s"
                }}>{t}</button>
              ))}
            </nav>
          </div>
        </header>

        <main className="ts-main">
          {tab === "scan" && <>
            <div style={{ textAlign:"center", marginBottom:32 }}>
              <h1 style={{ fontFamily:"var(--mono)", fontSize:"clamp(20px,4vw,40px)",
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

            <div style={{ display:"flex", gap:6, justifyContent:"center", flexWrap:"wrap", marginBottom:16 }}>
              {TYPES.map(t => {
                const isActive = activeType === t.id;
                return (
                  <button key={t.id} onClick={() => setManualType(t.id === "auto" ? null : t.id)} style={{
                    background: isActive ? "var(--green)":"var(--surface2)",
                    color:      isActive ? "#000":"var(--text2)",
                    border:`1px solid ${isActive ? "var(--green)":"var(--border2)"}`,
                    padding:"5px 12px", borderRadius:6, cursor:"pointer",
                    fontFamily:"var(--mono)", fontSize:10, letterSpacing:1,
                    fontWeight:isActive?700:400, transition:"all .15s",
                  }}>{t.label}</button>
                );
              })}
            </div>

            <div style={{ marginBottom:8 }}>
              <div className="ts-search-bar" style={{ animation: scanning ? "borderGlow 2s ease-in-out infinite":"none" }}>
                <input ref={inputRef} value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => e.key==="Enter" && handleScan()}
                  placeholder={TYPES.find(t => t.id === activeType)?.placeholder || TYPES[0].placeholder}
                />
                <button className="ts-scan-btn" onClick={handleScan} disabled={!query.trim()||scanning}>
                  {scanning ? <><Spinner color="#666" size={16}/> SCANNING…</> : "⚔ SCAN NOW"}
                </button>
              </div>
            </div>

            <div className={`ts-dropzone${dragOver ? " drag-over":""}`}
              onDrop={handleDrop} onDragOver={handleDragOver} onDragLeave={handleDragLeave}
              onClick={() => fileRef.current?.click()} style={{ marginBottom:16 }}>
              <input ref={fileRef} type="file" style={{ display:"none" }} onChange={handleFileInput}/>
              {hashing ? (
                <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:10,
                  fontFamily:"var(--mono)", fontSize:12, color:"var(--green)" }}>
                  <Spinner size={16}/> HASHING FILE…
                </div>
              ) : fileInfo ? (
                <div style={{ fontFamily:"var(--mono)", fontSize:11 }}>
                  <div style={{ color:"var(--green)", marginBottom:4 }}>📄 {fileInfo.name} ({fileInfo.size} KB)</div>
                  <div style={{ color:"var(--text3)", wordBreak:"break-all" }}>SHA256: {fileInfo.hash}</div>
                  <div style={{ color:"var(--text3)", marginTop:6, fontSize:10 }}>Click or drop another file to replace</div>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize:28, marginBottom:8 }}>📁</div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:12, color:"var(--text2)", marginBottom:4 }}>DROP A FILE TO SCAN</div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>
                    File is hashed locally (SHA256) — never uploaded to any server
                  </div>
                </div>
              )}
            </div>

            {(scanning || summary) && (
              <div style={{ marginBottom:20, animation:"fadeUp .3s ease" }}>
                <div style={{ display:"flex", justifyContent:"space-between",
                  fontFamily:"var(--mono)", fontSize:11, color:"var(--text2)", marginBottom:6 }}>
                  <span>{scanning ? `SCANNING ${doneCount}/${total} ENGINES…` : `COMPLETE — ${total} ENGINES`}</span>
                  <span>{progressPct}%</span>
                </div>
                <div style={{ height:3, background:"var(--surface2)", borderRadius:4, overflow:"hidden" }}>
                  <div style={{ height:"100%", width:`${progressPct}%`,
                    background:"linear-gradient(90deg,var(--green),#00ccff)",
                    borderRadius:4, transition:"width .3s ease", boxShadow:"0 0 8px rgba(0,255,136,.4)" }}/>
                </div>
              </div>
            )}

            {error && (
              <div style={{ background:"#ff335510", border:"1px solid #ff335540", borderRadius:8,
                padding:"12px 16px", marginBottom:20, color:"#ff3355", fontFamily:"var(--mono)", fontSize:12 }}>
                ⚠ {error}
              </div>
            )}

            {(scanning || summary) && doneCount > 0 && (
              <div style={{ background:"var(--surface)", borderRadius:12, padding:"20px 24px",
                border:`1px solid ${summary?.verdict==="malicious"?"#ff335540":summary?.verdict==="suspicious"?"#ffd70040":"#00ff8840"}`,
                marginBottom:24, animation:"fadeUp .4s ease", transition:"border-color .5s" }}>
                <div className="ts-summary-inner">
                  <div>
                    <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)", letterSpacing:2, marginBottom:10 }}>
                      {summary ? "FINAL VERDICT" : "LIVE VERDICT"}
                    </div>
                    {summary ? <Badge verdict={summary.verdict} size="lg"/> : <Badge verdict="scanning" size="lg"/>}
                    <div style={{ marginTop:12, fontSize:12, color:"var(--text2)", wordBreak:"break-all" }}>
                      {fileInfo
                        ? <><b style={{color:"var(--green)"}}>{fileInfo.name}</b><br/>
                            <span style={{color:"var(--text3)",fontSize:10}}>{query}</span></>
                        : <b style={{color:"var(--text)",fontFamily:"var(--mono)"}}>{query}</b>}
                    </div>
                    {summary && (
                      <button onClick={exportJSON} style={{
                        marginTop:14, background:"none", border:"1px solid var(--border2)",
                        color:"var(--green)", borderRadius:6, padding:"5px 12px",
                        cursor:"pointer", fontFamily:"var(--mono)", fontSize:10,
                        fontWeight:700, letterSpacing:1,
                      }}>⬇ EXPORT JSON</button>
                    )}
                  </div>
                  <ThreatGauge score={summary?.score ?? 0}/>
                  <div className="ts-counts">
                    {[
                      { label:"MALICIOUS",  val:malCount,   color:"#ff3355" },
                      { label:"SUSPICIOUS", val:suspCount,  color:"#ffd700" },
                      { label:"CLEAN",      val:cleanCount, color:"#00ff88" },
                    ].map(({ label, val, color }) => (
                      <div key={label} style={{ textAlign:"center" }}>
                        <div style={{ fontFamily:"var(--mono)", fontSize:32, fontWeight:700, color, transition:"all .3s" }}>{val}</div>
                        <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text3)", letterSpacing:1.5 }}>{label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {Object.keys(engineStatus).length > 0 && (
              <div className="ts-engine-grid">
                {ENGINE_ORDER.map(id => (
                  <EngineCard key={id} engineId={id} data={engineData[id]} status={engineStatus[id] || "scanning"}/>
                ))}
              </div>
            )}

            {!scanning && !summary && Object.keys(engineStatus).length === 0 && (
              <div style={{ textAlign:"center", padding:"40px 0", color:"var(--text3)" }}>
                <div style={{ fontSize:48, marginBottom:16, opacity:.3 }}>⚔</div>
                <div style={{ fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>
                  ENTER A URL, IP, HASH OR DOMAIN — OR DROP A FILE ABOVE
                </div>
                <div style={{ marginTop:20, display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap" }}>
                  {["https://example.com","8.8.8.8","44d88612fea8a8f36de82e1278abb02f","malware.xyz"].map(ex => (
                    <button key={ex} onClick={() => { setQuery(ex); inputRef.current?.focus(); }} style={{
                      background:"var(--surface)", border:"1px solid var(--border2)",
                      color:"var(--text2)", padding:"7px 12px", borderRadius:6,
                      cursor:"pointer", fontFamily:"var(--mono)", fontSize:10 }}>{ex}</button>
                  ))}
                </div>
              </div>
            )}
          </>}

          {tab === "bulk" && <BulkScan/>}

          {tab === "history" && (
            <div style={{ animation:"fadeUp .3s ease" }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:24, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                <span>📋 SCAN HISTORY</span>
                {history.length > 0 && (
                  <button onClick={() => { setHistory([]); localStorage.removeItem("ts_history"); }} style={{
                    background:"none", border:"1px solid var(--border2)", color:"var(--text3)",
                    padding:"4px 10px", borderRadius:4, cursor:"pointer", fontFamily:"var(--mono)", fontSize:10 }}>CLEAR</button>
                )}
              </div>
              {history.length === 0 ? (
                <div style={{ textAlign:"center", padding:60, color:"var(--text3)", fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>NO SCANS YET</div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {history.map((h, i) => (
                    <div key={i} onClick={() => { setQuery(h.query); setManualType(null); setTab("scan"); }}
                      style={{ background:"var(--surface)", border:"1px solid var(--border2)",
                        borderRadius:8, padding:"12px 16px", cursor:"pointer" }}>
                      <div className="ts-history-item">
                        <div style={{ display:"flex", alignItems:"center", gap:10, minWidth:0 }}>
                          <Badge verdict={h.verdict}/>
                          <span style={{ fontFamily:"var(--mono)", fontSize:12,
                            overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{h.label || h.query}</span>
                        </div>
                        <div className="ts-history-meta">
                          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>{(h.type||"auto").toUpperCase()}</span>
                          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>{h.time}</span>
                          <span style={{ fontFamily:"var(--mono)", fontSize:11,
                            color:h.score>=50?"#ff3355":h.score>=20?"#ffd700":"#00ff88" }}>{h.score}/100</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

{tab === "trends" && (
            <div style={{ animation:"fadeUp .3s ease" }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)",
                letterSpacing:2, marginBottom:8 }}>🔥 TRENDING THREATS</div>
              <div style={{ fontSize:13, color:"var(--text2)", marginBottom:24 }}>
                Top threats from your current session, ranked by score.
              </div>
              {history.length === 0 ? (
                <div style={{ textAlign:"center", padding:60, color:"var(--text3)",
                  fontFamily:"var(--mono)", fontSize:12, letterSpacing:2 }}>NO SCANS YET — RUN SOME SCANS FIRST</div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {[...history].sort((a,b) => (b.score||0)-(a.score||0)).map((h, i) => (
                    <div key={i} onClick={() => { setQuery(h.query); setManualType(null); setTab("scan"); }}
                      style={{ background:"var(--surface)", border:`1px solid ${
                        h.verdict==="malicious"?"#ff335540":h.verdict==="suspicious"?"#ffd70040":"var(--border2)"
                      }`, borderRadius:8, padding:"14px 16px", cursor:"pointer",
                        display:"flex", alignItems:"center", gap:16, flexWrap:"wrap",
                        transition:"border-color .2s" }}>
                      <div style={{ fontFamily:"var(--mono)", fontSize:22, fontWeight:700, minWidth:52, textAlign:"center",
                        color: h.score>=50?"#ff3355":h.score>=20?"#ffd700":"#00ff88" }}>
                        {h.score||0}
                      </div>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                          <Badge verdict={h.verdict}/>
                          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)" }}>
                            {(h.type||"auto").toUpperCase()}
                          </span>
                        </div>
                        <div style={{ fontFamily:"var(--mono)", fontSize:12,
                          overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                          color:"var(--text)" }}>{h.label||h.query}</div>
                      </div>
                      <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)", flexShrink:0 }}>
                        {h.time}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

                    {tab === "about" && (
            <div style={{ animation:"fadeUp .3s ease", maxWidth:720 }}>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, color:"var(--green)", letterSpacing:2, marginBottom:24 }}>ℹ ABOUT THREATSCAN</div>
              <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
                {[
                  ["🔍 What is ThreatScan?","An open-source, multi-engine threat intelligence platform. Simultaneously queries 10 free and open threat intelligence APIs and streams results live as each engine responds."],
                  ["📁 File Scanning","Drop any file onto the scan page — ThreatScan hashes it locally using SHA256 (the file never leaves your device) and scans the hash across all engines."],
                  ["⚡ Bulk Scanning","Paste up to 20 URLs, IPs, domains, or hashes and scan them all at once. Results stream in live and can be exported as CSV."],
                  ["🔒 Privacy & Security","API keys are stored server-side in environment variables. ThreatScan logs nothing and has no database. Files are never uploaded — only their hash is scanned."],
                  ["📦 Contributing","Open source under MIT license. Add new engines by creating a file in backend/engines/ and registering it in server.js."],
                ].map(([title, body]) => (
                  <div key={title} style={{ background:"var(--surface)", border:"1px solid var(--border2)", borderRadius:8, padding:20 }}>
                    <div style={{ fontFamily:"var(--mono)", fontSize:12, fontWeight:700, marginBottom:8 }}>{title}</div>
                    <div style={{ fontSize:13, color:"var(--text2)", lineHeight:1.75 }}>{body}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        <footer style={{ borderTop:"1px solid var(--border)", padding:"16px 24px",
          textAlign:"center", fontFamily:"var(--mono)", fontSize:10, color:"var(--text3)", letterSpacing:1 }}>
          THREATSCAN · OPEN SOURCE · MIT LICENSE · MULTI-ENGINE THREAT INTELLIGENCE
        </footer>
      </div>
    </>
  );
}
