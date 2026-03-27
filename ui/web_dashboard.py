"""MacSentry Web Dashboard - Flask UI"""

import json
import subprocess
import sys
from pathlib import Path

from flask import Flask, Response

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent.parent


@app.route("/")
def home():
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>MacSentry</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1c1c1e;color:#f5f5f7;font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:30px;min-height:100vh}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:30px}
h1{color:#007AFF;font-size:28px}
.version{color:#666;font-size:14px}
.btn{background:#007AFF;color:#fff;border:none;padding:14px 28px;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.85}
.btn:disabled{background:#444;cursor:not-allowed}
#output{background:#2c2c2e;border-radius:12px;padding:20px;margin-top:20px;font-family:monospace;font-size:13px;line-height:1.6;max-height:70vh;overflow-y:auto}
.step{margin:8px 0;padding:10px;border-left:3px solid #007AFF;background:#1c1c1e;border-radius:4px}
.critical{border-left-color:#FF3B30;background:#2a1a1a}
.high{border-left-color:#FF9500;background:#2a2216}
.medium{border-left-color:#FFCC00;background:#2a2a16}
.safe{border-left-color:#34C759;background:#1a2a1a}
.step-name{font-weight:700;color:#fff;margin-bottom:4px}
.step-detail{color:#999;font-size:12px}
.progress{color:#007AFF}
.summary{background:#2c2c2e;border-radius:12px;padding:20px;margin-top:20px;border:2px solid #007AFF}
.summary h2{color:#007AFF;margin-bottom:15px;font-size:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-top:15px}
.stat{background:#1c1c1e;padding:15px;border-radius:8px;text-align:center}
.stat-num{font-size:32px;font-weight:800;margin-bottom:5px}
.stat-label{color:#999;font-size:12px;text-transform:uppercase}
</style>
</head>
<body>
<div class="header">
<h1>🛡️ MacSentry Security Scanner</h1>
<span class="version">v1.0</span>
</div>
<button class="btn" id="scanBtn" onclick="startScan()">▶ Start Full Scan</button>
<div id="output"><div class="step progress">Ready to scan. Click the button above to begin.</div></div>
<div id="summary" style="display:none"></div>

<script>
let scanning=false;
function startScan(){
  if(scanning) return;
  scanning=true;
  const btn=document.getElementById('scanBtn');
  const out=document.getElementById('output');
  const sum=document.getElementById('summary');
  btn.disabled=true;
  btn.textContent='⏳ Scanning...';
  out.innerHTML='<div class="step progress">Starting security scan...</div>';
  sum.style.display='none';
  
  let stepData={};
  fetch('/scan').then(r=>r.body.getReader()).then(reader=>{
    const decoder=new TextDecoder();
    function read(){
      reader.read().then(({done,value})=>{
        if(done){
          scanning=false;
          btn.disabled=false;
          btn.textContent='▶ Start Full Scan';
          showSummary(stepData);
          return;
        }
        const lines=decoder.decode(value).split('\\n');
        lines.forEach(line=>{
          if(!line.trim()) return;
          try{
            const d=JSON.parse(line);
            if(d.step_number){
              stepData[d.step_number]=d;
              let cls='step';
              if(d.risk_level==='CRITICAL') cls+=' critical';
              else if(d.risk_level==='HIGH') cls+=' high';
              else if(d.risk_level==='MEDIUM') cls+=' medium';
              else if(d.risk_level==='SAFE') cls+=' safe';
              else cls+=' progress';
              
              const existing=document.getElementById('step'+d.step_number);
              const html=`<div class="${cls}" id="step${d.step_number}">
                <div class="step-name">Step ${d.step_number}: ${d.step_name}</div>
                <div class="step-detail">${d.description}</div>
                <div class="step-detail">Progress: ${Math.round(d.completion_pct)}% | Risk: ${d.risk_level} | Findings: ${d.findings.length}</div>
              </div>`;
              
              if(existing) existing.outerHTML=html;
              else out.innerHTML+=html;
              out.scrollTop=out.scrollHeight;
            }
          }catch(e){}
        });
        read();
      });
    }
    read();
  }).catch(e=>{
    scanning=false;
    btn.disabled=false;
    btn.textContent='▶ Start Full Scan';
    out.innerHTML+='<div class="step critical"><div class="step-name">Error</div><div class="step-detail">'+e+'</div></div>';
  });
}

function showSummary(data){
  const steps=Object.values(data);
  if(steps.length===0) return;
  
  let critical=0,high=0,medium=0,low=0,safe=0;
  steps.forEach(s=>{
    s.findings.forEach(f=>{
      if(f.severity==='CRITICAL') critical++;
      else if(f.severity==='HIGH') high++;
      else if(f.severity==='MEDIUM') medium++;
      else if(f.severity==='LOW') low++;
      else if(f.severity==='SAFE') safe++;
    });
  });
  
  const total=critical+high+medium+low+safe;
  const score=Math.round(Math.max(0,100-((critical*10+high*7+medium*4+low*1)/(total*10)*100)));
  
  document.getElementById('summary').innerHTML=`
    <h2>Scan Complete ✅</h2>
    <div class="stats">
      <div class="stat"><div class="stat-num" style="color:#007AFF">${score}%</div><div class="stat-label">Security Score</div></div>
      <div class="stat"><div class="stat-num" style="color:#FF3B30">${critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat"><div class="stat-num" style="color:#FF9500">${high}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-num" style="color:#FFCC00">${medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-num" style="color:#34C759">${safe}</div><div class="stat-label">Safe</div></div>
    </div>
  `;
  document.getElementById('summary').style.display='block';
}
</script>
</body></html>"""


@app.route("/scan")
def scan():
    def generate():
        cmd = [
            sys.executable,
            str(ROOT / "core/scanner_engine.py"),
            "--mode",
            "full",
            "--no-cve",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in proc.stdout:
            if line.strip():
                yield line

    return Response(generate(), mimetype="text/plain")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🛡️  MacSentry Web Dashboard")
    print("=" * 60)
    print("Dashboard URL: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000, use_reloader=False)
