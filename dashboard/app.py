"""
NetTwin Analyser — Streamlit Dashboard v2.1
ROOT FIX: All HTML panels rendered via components.html() — never st.markdown() for HTML.
st.markdown() is ONLY used for the global <style> tag (Streamlit elements).
components.html() is an iframe — CSS inside it ALWAYS works, always renders correctly.
"""

import os, sys, json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import streamlit.components.v1 as components

try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=5000, key="dashboard_refresh")
except ImportError:
    pass

st.set_page_config(
    page_title="NetTwin Analyser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Only style Streamlit's own chrome here — NOT custom panel classes
st.markdown("""<style>
html,body,[data-testid="stAppViewContainer"],[data-testid="stMain"],.main,.block-container{
  background:#0b0f1a!important;color:#e2e8f0!important;
  font-family:'Inter','Segoe UI',sans-serif!important;}
[data-testid="stSidebar"]{background:#0d1526!important;border-right:1px solid #1a3050!important;}
[data-testid="stSidebar"] *{color:#94a3b8!important;}
#MainMenu,footer,header,[data-testid="stToolbar"],[data-testid="stDecoration"]{display:none!important;}
.block-container{padding-top:1rem!important;}
[data-testid="stSidebar"] .stButton>button{
  background:#b91c1c!important;color:#fff!important;border:none!important;
  border-radius:8px!important;font-weight:700!important;width:100%!important;padding:10px!important;}
[data-testid="stSidebar"] .stButton>button:hover{background:#991b1b!important;}
</style>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# DATA
# ─────────────────────────────────────────────────────────────────────────────

def get_metrics(sc, tr):
    base = {
        "Normal Operation":     dict(health=96,latency=18, loss=0.3, threat=0, bw=34),
        "Simulate DDoS Attack": dict(health=41,latency=187,loss=12.4,threat=94,bw=98),
        "Link Failure":         dict(health=63,latency=54, loss=4.8, threat=12,bw=67),
        "VLAN Mismatch":        dict(health=78,latency=31, loss=2.1, threat=30,bw=55),
        "Routing Instability":  dict(health=55,latency=98, loss=7.2, threat=45,bw=72),
        "ACL Violation":        dict(health=70,latency=28, loss=1.5, threat=80,bw=48),
    }
    d = base.get(sc, base["Normal Operation"]).copy()
    d["latency"] = int(d["latency"]*(0.5+tr/100))
    d["bw"]      = min(100,int(d["bw"]*(0.6+tr/100)))
    return d

def get_routers(sc):
    fail = "Link Failure" in sc or "Routing" in sc
    return [
        dict(id="R1",role="Core Router",   ip="10.0.0.1",   status="up",      proto=["OSPF","BGP"],vlans=[10,20,30]),
        dict(id="R2",role="Edge Router",   ip="192.168.1.1", status="up",      proto=["OSPF"],      vlans=[10,20]),
        dict(id="R3",role="Firewall",      ip="192.168.2.1", status="degraded" if fail else "up",proto=["BGP"],vlans=[30]),
        dict(id="R4",role="Access Switch", ip="10.0.1.1",    status="down"     if fail else "up",proto=["RIP"],vlans=[20,40]),
    ]

def get_logs(sc, tr):
    base = [
        ("info",    f"OSPF adjacency stable on R1-R3 · uptime 14d 6h"),
        ("info",    "BGP peer 10.0.0.2 established · prefixes: 12"),
        ("warning", f"Traffic load at {tr}% utilization"),
        ("critical","ACL rule #7 triggered on R3 Gi0/1 inbound"),
        ("alert",   "Unauthorized access attempt: 10.99.0.44:4422"),
    ]
    extra = {
        "Simulate DDoS Attack":[("critical","DDoS flood: 94 Gbps inbound on R1"),
                                 ("critical","Rate-limit: 10.0.0.0/8 blocked"),
                                 ("alert",   "Scrubbing center activated")],
        "Link Failure":        [("critical","Link R1 ↔ R2 DOWN — physical failure"),
                                 ("warning", "OSPF adjacency lost on R1 Gi0/0"),
                                 ("info",    "Failover: R1→R3→R2 activated")],
        "ACL Violation":       [("alert",   "Unauthorized: 192.168.100.5→10.0.0.1:22"),
                                 ("critical","ACL DENY: 47 packets dropped /10s")],
        "VLAN Mismatch":       [("warning", "VLAN 20 trunk mismatch on R2 Gi0/2"),
                                 ("warning", "802.1Q tagging error — frames dropped")],
        "Routing Instability": [("critical","BGP route flap: R4 withdrew 10.0.0.0/8"),
                                 ("warning", "OSPF LSA storm area 0 — 340 updates/s")],
    }
    return base + extra.get(sc, [])

# ─────────────────────────────────────────────────────────────────────────────
# SHARED CSS — injected into EVERY components.html() iframe
# ─────────────────────────────────────────────────────────────────────────────

BASE = """<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#0b0f1a;font-family:'Inter','Segoe UI',sans-serif;color:#e2e8f0;font-size:13px;}
.panel{background:#0f1e33;border:1px solid #1e3a5f;border-radius:10px;overflow:hidden;}
.ph{background:#0d1a2e;border-bottom:1px solid #1e3a5f;padding:11px 16px;
  display:flex;align-items:center;gap:8px;}
.pt{font-size:11px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1.5px;}
.pb{padding:14px 16px;}
.row{display:flex;justify-content:space-between;align-items:center;
  padding:9px 0;border-bottom:1px solid #0d1f35;}
.row:last-child{border-bottom:none;}
.lbl{font-size:11px;color:#475569;}
.val{font-size:13px;font-weight:600;}
</style>"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def make_header(sc, tr):
    badges = {
        "Normal Operation":    ("#22c55e","NOMINAL"),
        "Simulate DDoS Attack":("#ef4444","CRITICAL"),
        "Link Failure":        ("#f59e0b","WARNING"),
        "VLAN Mismatch":       ("#f59e0b","WARNING"),
        "Routing Instability": ("#f59e0b","WARNING"),
        "ACL Violation":       ("#a855f7","HIGH RISK"),
    }
    c,l = badges.get(sc,("#22c55e","NOMINAL"))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{BASE}</head><body>
<div style="background:linear-gradient(135deg,#0f2744,#0a1628);border:1px solid #1e3a5f;
  border-radius:12px;padding:18px 26px;position:relative;overflow:hidden;">
  <div style="position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,#00d4ff,#0066ff,#7c3aed,#00d4ff);"></div>
  <div style="display:flex;align-items:center;justify-content:space-between;">
    <div>
      <div style="font-size:21px;font-weight:800;color:#f0f9ff;">🛡 NetTwin Analyser</div>
      <div style="font-size:11px;color:#4a9fd4;text-transform:uppercase;letter-spacing:1px;margin-top:3px;">
        Enterprise Network Monitoring &amp; Cybersecurity Simulation Platform</div>
    </div>
    <div style="text-align:right;">
      <div style="background:{c}22;border:1px solid {c}55;color:{c};font-size:11px;
        font-weight:700;padding:4px 14px;border-radius:20px;letter-spacing:1px;margin-bottom:5px;">● {l}</div>
      <div style="font-size:11px;color:#334155;">Traffic Load: {tr}%</div>
    </div>
  </div>
</div></body></html>"""


def make_metrics(m):
    def color(v,g,w): return "#22c55e" if v<=g else("#f59e0b" if v<=w else "#ef4444")
    def rcolor(v,g,w): return "#22c55e" if v>=g else("#f59e0b" if v>=w else "#ef4444")
    hc=rcolor(m["health"],85,60); lc=color(m["latency"],40,100)
    pc=color(m["loss"],2,8); bc=color(m["bw"],60,85); tc=color(m["threat"],20,60)
    def card(lbl,val,sub,col,pct):
        return f"""<div style="background:#0d1a2e;border:1px solid #1e3a5f;border-radius:10px;
          padding:14px 16px;text-align:center;position:relative;overflow:hidden;flex:1;min-width:0;">
          <div style="position:absolute;bottom:0;left:0;right:0;height:2px;background:{col};"></div>
          <div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;
            letter-spacing:1px;margin-bottom:7px;">{lbl}</div>
          <div style="font-size:20px;font-weight:800;color:{col};line-height:1;">{val}</div>
          <div style="font-size:10px;color:#334155;margin-top:3px;">{sub}</div>
          <div style="height:3px;background:#1e3a5f;border-radius:2px;margin-top:7px;overflow:hidden;">
            <div style="height:100%;width:{pct}%;background:{col};border-radius:2px;"></div></div>
        </div>"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{BASE}</head><body>
<div style="display:flex;gap:10px;">{
    card("Network Health",f"{m['health']}%","Overall",hc,m['health'])
  }{card("Avg Latency",f"{m['latency']} ms","Round trip",lc,min(100,m['latency']))
  }{card("Packet Loss",f"{m['loss']}%","Drop rate",pc,min(100,m['loss']*5))
  }{card("Bandwidth",f"{m['bw']}%","Utilization",bc,m['bw'])
  }{card("Threat Score",str(m['threat']),"Risk /100",tc,m['threat'])
}</div></body></html>"""


def make_topology(sc, tr):
    ddos  = "DDoS"    in sc
    fail  = "Link"    in sc
    route = "Routing" in sc
    acl   = "ACL"     in sc
    vlan  = "VLAN"    in sc

    nodes = json.dumps([
        dict(id="R1",role="Core",   ip="10.0.0.1",   x=310,y=200,status="up",       proto=["OSPF","BGP"]),
        dict(id="R2",role="Edge",   ip="192.168.1.1", x=130,y=100,status="up",       proto=["OSPF"]),
        dict(id="R3",role="FW",     ip="192.168.2.1", x=490,y=100,status="degraded" if (fail or route) else "up",proto=["BGP"]),
        dict(id="R4",role="Access", ip="10.0.1.1",    x=310,y=340,status="down"     if (fail or route) else "up",proto=["RIP"]),
    ])
    edges = json.dumps([
        dict(a="R1",b="R2",fail=fail),
        dict(a="R1",b="R3",fail=False),
        dict(a="R1",b="R4",fail=route),
        dict(a="R2",b="R3",fail=False),
    ])
    note = json.dumps(
        "DDoS flood — volumetric attack in progress on all nodes" if ddos else
        "Link R1 ↔ R2 DOWN — failover active"                    if fail else
        "ACL violation detected on R3 inbound"                   if acl  else
        "VLAN 20 mismatch on R2 trunk port"                      if vlan else
        "BGP route flap on R4 — convergence in progress"         if route else ""
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#080e1a;overflow:hidden;font-family:'Inter','Segoe UI',sans-serif;}}
canvas{{display:block;}}
#tip{{position:absolute;top:10px;left:10px;background:rgba(13,26,46,.95);
  border:1px solid #1e3a5f;border-radius:8px;padding:10px 14px;font-size:11px;
  color:#94a3b8;display:none;min-width:180px;line-height:1.8;pointer-events:none;}}
#tip .tid{{font-size:14px;font-weight:800;color:#00d4ff;}}
#note{{position:absolute;bottom:10px;left:50%;transform:translateX(-50%);
  background:rgba(239,68,68,.12);border:1px solid #ef444455;border-radius:6px;
  padding:5px 16px;font-size:11px;color:#fca5a5;white-space:nowrap;display:none;}}
#leg{{position:absolute;top:10px;right:10px;background:rgba(13,26,46,.88);
  border:1px solid #1e3a5f;border-radius:8px;padding:8px 12px;font-size:10px;color:#475569;}}
#leg div{{display:flex;align-items:center;gap:6px;margin-bottom:4px;}}
#leg div:last-child{{margin-bottom:0;}}
#leg span{{width:8px;height:8px;border-radius:50%;flex-shrink:0;}}
</style></head><body>
<canvas id="c" width="620" height="420"></canvas>
<div id="tip"></div><div id="note"></div>
<div id="leg">
  <div><span style="background:#22c55e"></span>Operational</div>
  <div><span style="background:#f59e0b"></span>Degraded</div>
  <div><span style="background:#ef4444"></span>Down</div>
</div>
<script>
const NODES={nodes},EDGES={edges},NOTE={note},TR={tr},DDOS={'true' if ddos else 'false'};
const C=document.getElementById('c'),ctx=C.getContext('2d');
const tip=document.getElementById('tip'),noteEl=document.getElementById('note');
if(NOTE){{noteEl.textContent=NOTE;noteEl.style.display='block';}}
const nm={{}};NODES.forEach(n=>nm[n.id]=n);
const SC={{up:'#22c55e',degraded:'#f59e0b',down:'#ef4444'}};
let hov=null,t=0;
function edge(e){{
  const a=nm[e.a],b=nm[e.b];ctx.save();
  if(e.fail){{ctx.setLineDash([7,5]);ctx.strokeStyle='#ef4444';ctx.lineWidth=1.5;ctx.globalAlpha=.55;}}
  else{{
    ctx.setLineDash([]);
    const ld=TR/100,r=Math.round(59+140*ld),g=Math.round(130-60*ld),bv=Math.round(246-200*ld);
    ctx.strokeStyle=`rgb(${{r}},${{g}},${{bv}})`;ctx.lineWidth=1.2+ld*2;ctx.globalAlpha=.75;
  }}
  ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();ctx.restore();
  if(!e.fail){{
    [[t*.012%1,'#00d4ff',3],[(t*.012+.5)%1,'#7c3aed',2]].forEach(([f,col,r])=>{{
      ctx.save();ctx.beginPath();
      ctx.arc(a.x+(b.x-a.x)*f,a.y+(b.y-a.y)*f,r,0,Math.PI*2);
      ctx.fillStyle=col;ctx.globalAlpha=.9;ctx.fill();ctx.restore();
    }});
  }}
  const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-10;
  const lat=e.fail?'FAIL':(Math.round(8+TR*1.4+Math.sin(t*.05)*4))+'ms';
  ctx.save();ctx.font='10px Inter,sans-serif';ctx.fillStyle=e.fail?'#ef4444':'#334155';
  ctx.textAlign='center';ctx.fillText(lat,mx,my);ctx.restore();
}}
function node(n){{
  const isH=hov===n.id,col=SC[n.status],rad=isH?30:25;
  if(DDOS){{const p=Math.sin(t*.08)*.5+.5;ctx.save();ctx.beginPath();
    ctx.arc(n.x,n.y,rad+10+p*10,0,Math.PI*2);ctx.fillStyle=`rgba(239,68,68,${{.05+p*.07}})`;
    ctx.fill();ctx.restore();}}
  ctx.save();ctx.beginPath();ctx.arc(n.x,n.y,rad+7,0,Math.PI*2);
  ctx.fillStyle=col+'18';ctx.fill();ctx.restore();
  ctx.save();ctx.beginPath();ctx.arc(n.x,n.y,rad,0,Math.PI*2);
  ctx.fillStyle='#0d1a2e';ctx.strokeStyle=col;ctx.lineWidth=isH?2.5:1.5;
  ctx.fill();ctx.stroke();ctx.restore();
  ctx.save();ctx.beginPath();ctx.arc(n.x,n.y,rad*.4,0,Math.PI*2);
  ctx.fillStyle=col+'44';ctx.fill();ctx.restore();
  ctx.save();ctx.font='bold 13px Inter,monospace';ctx.fillStyle='#f0f9ff';
  ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(n.id,n.x,n.y);ctx.restore();
  ctx.save();ctx.font='10px Inter,sans-serif';ctx.fillStyle=col;
  ctx.textAlign='center';ctx.fillText(n.role,n.x,n.y+rad+14);ctx.restore();
  if(n.status!=='up'){{ctx.save();ctx.beginPath();ctx.arc(n.x+rad-5,n.y-rad+5,6,0,Math.PI*2);
    ctx.fillStyle=col;ctx.fill();ctx.restore();}}
}}
function frame(){{
  ctx.clearRect(0,0,620,420);
  ctx.save();ctx.strokeStyle='#0c1a2c';ctx.lineWidth=.5;
  for(let x=0;x<620;x+=40){{ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,420);ctx.stroke();}}
  for(let y=0;y<420;y+=40){{ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(620,y);ctx.stroke();}}
  ctx.restore();
  EDGES.forEach(edge);NODES.forEach(node);t++;requestAnimationFrame(frame);
}}
requestAnimationFrame(frame);
C.addEventListener('mousemove',ev=>{{
  const rc=C.getBoundingClientRect(),mx=ev.clientX-rc.left,my=ev.clientY-rc.top;
  let f=null;NODES.forEach(n=>{{const dx=mx-n.x,dy=my-n.y;if(Math.sqrt(dx*dx+dy*dy)<32)f=n;}});
  hov=f?f.id:null;
  if(f){{tip.style.display='block';const col=SC[f.status];
    tip.innerHTML=`<div class="tid">${{f.id}}</div><div>Role: ${{f.role}}</div>
      <div>IP: ${{f.ip}}</div><div>Status: <span style="color:${{col}};font-weight:700;">
      ${{f.status.toUpperCase()}}</span></div><div>Protocols: ${{f.proto.join(', ')}}</div>`;
  }}else{{tip.style.display='none';}}
}});
</script></body></html>"""


def make_telemetry(m):
    def c(v,g,w): return "#22c55e" if v<=g else("#f59e0b" if v<=w else "#ef4444")
    def rc(v,g,w): return "#22c55e" if v>=g else("#f59e0b" if v>=w else "#ef4444")
    hc=rc(m["health"],85,60); lc=c(m["latency"],40,100)
    bc=c(m["bw"],60,85); tc=c(m["threat"],20,60)
    def brow(lbl,val,pct,col):
        return f"""<div style="padding:8px 0;border-bottom:1px solid #0d1f35;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:11px;color:#475569;">{lbl}</span>
            <span style="font-size:13px;font-weight:600;color:{col};">{val}</span>
          </div>
          <div style="height:4px;background:#0d1f35;border-radius:2px;overflow:hidden;">
            <div style="height:100%;width:{pct}%;background:{col};border-radius:2px;"></div>
          </div></div>"""
    def srow(lbl,val,col="#e2e8f0"):
        return f"""<div style="display:flex;justify-content:space-between;align-items:center;
          padding:8px 0;border-bottom:1px solid #0d1f35;">
          <span style="font-size:11px;color:#475569;">{lbl}</span>
          <span style="font-size:13px;font-weight:600;color:{col};">{val}</span></div>"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{BASE}</head>
<body><div class="panel"><div class="ph">
  <span style="font-size:14px;">📡</span><span class="pt">Telemetry</span>
</div><div class="pb">
  {brow("Network Health",f"{m['health']}%",m['health'],hc)}
  {brow("Bandwidth",f"{m['bw']}%",m['bw'],bc)}
  {brow("Latency",f"{m['latency']} ms",min(100,m['latency']),lc)}
  {srow("Packet Loss",f"{m['loss']}%")}
  {srow("Threat Score",f"{m['threat']} / 100",tc)}
  {srow("Active Nodes","4 / 4")}
  {srow("Protocols","OSPF · BGP · RIP")}
  {srow("Uptime","14d 6h 22m")}
</div></div></body></html>"""


def make_logs(logs):
    cfg = {
        "info":    ("#3b82f6","#0f2744","#93c5fd","INFO"),
        "warning": ("#f59e0b","#1f1800","#fcd34d","WARN"),
        "critical":("#ef4444","#1f0a0a","#fca5a5","CRIT"),
        "alert":   ("#a855f7","#1a0a2e","#c4b5fd","ALRT"),
    }
    rows = ""
    for lv,msg in logs[-9:]:
        col,bg,txt,badge = cfg.get(lv,cfg["info"])
        rows += f"""<div style="background:{bg};border-left:3px solid {col};border-radius:5px;
          padding:7px 10px;margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;">
          <span style="background:{col}22;color:{col};font-size:9px;font-weight:800;
            padding:2px 6px;border-radius:4px;flex-shrink:0;letter-spacing:.5px;">{badge}</span>
          <span style="font-size:11px;font-family:'Courier New',monospace;
            color:{txt};line-height:1.5;">{msg}</span></div>"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{BASE}</head>
<body><div class="panel"><div class="ph">
  <span style="font-size:14px;">⚠</span><span class="pt">Security Event Log</span>
  <span style="font-size:10px;color:#334155;margin-left:auto;">{len(logs)} events</span>
</div><div class="pb">{rows}</div></div></body></html>"""


def make_routers(routers):
    sc = {"up":"#22c55e","degraded":"#f59e0b","down":"#ef4444"}
    lbl = {"up":"UP","degraded":"DEGRADED","down":"DOWN"}
    rows=""
    for r in routers:
        col=sc[r["status"]]; lab=lbl[r["status"]]
        rows += f"""<div style="padding:10px 0;border-bottom:1px solid #0d1f35;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="width:9px;height:9px;border-radius:50%;background:{col};flex-shrink:0;"></div>
              <span style="font-size:13px;font-weight:700;color:#f0f9ff;">{r["id"]}</span>
              <span style="font-size:10px;color:#475569;">{r["role"]}</span>
            </div>
            <span style="background:{col}22;border:1px solid {col}55;color:{col};font-size:9px;
              font-weight:800;padding:2px 8px;border-radius:10px;letter-spacing:.5px;">{lab}</span>
          </div>
          <div style="font-size:10px;color:#334155;padding-left:17px;line-height:1.8;">
            <span style="color:#3b5270;">{r["ip"]}</span>
            &nbsp;·&nbsp;{' · '.join(r["proto"])}
            &nbsp;·&nbsp;VLANs: {', '.join(map(str,r["vlans"]))}
          </div></div>"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">{BASE}</head>
<body><div class="panel"><div class="ph">
  <span style="font-size:14px;">⬡</span><span class="pt">Router Status</span>
  <span style="font-size:10px;color:#334155;margin-left:auto;">4 devices</span>
</div><div class="pb">{rows}</div></div></body></html>"""


def make_alert(sc):
    cfg = {
        "Normal Operation":    ("#22c55e","#0a2010","✅ All systems operational — no active threats detected."),
        "Simulate DDoS Attack":("#ef4444","#1f0505","🔴 CRITICAL — Volumetric DDoS in progress on all edge nodes. Scrubbing center active."),
        "Link Failure":        ("#f59e0b","#1f1200","🟡 WARNING — Link R1 ↔ R2 is DOWN. Failover path via R3 activated."),
        "ACL Violation":       ("#a855f7","#130a1f","🟣 HIGH RISK — ACL violation on R3. Unauthorized traffic blocked and logged."),
        "Routing Instability": ("#f59e0b","#1f1200","🟡 WARNING — BGP route flap on R4. OSPF reconvergence in progress."),
        "VLAN Mismatch":       ("#f59e0b","#1f1200","🟡 WARNING — VLAN 20 mismatch on R2. Trunk port misconfigured."),
    }
    col,bg,msg = cfg.get(sc,cfg["Normal Operation"])
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0b0f1a;font-family:'Inter','Segoe UI',sans-serif;}}</style></head>
<body><div style="background:{bg};border:1px solid {col}44;border-radius:8px;
  padding:11px 18px;font-size:13px;color:{col};font-weight:500;">{msg}</div></body></html>"""

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        '<p style="font-size:13px;font-weight:800;color:#00d4ff;text-transform:uppercase;'
        'letter-spacing:1.5px;border-bottom:1px solid #1a3050;padding-bottom:12px;'
        'margin-bottom:16px;">🛡 Simulation Controls</p>',
        unsafe_allow_html=True,
    )
    scenario = st.selectbox(
        "Active Scenario",
        ["Normal Operation","Simulate DDoS Attack","Link Failure",
         "VLAN Mismatch","Routing Instability","ACL Violation"],
    )
    st.markdown("<br>", unsafe_allow_html=True)
    traffic_load = st.slider("Traffic Load (%)", 0, 100, 50)
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔴 Emergency Reset", use_container_width=True):
        st.toast("System restored.", icon="✅")
    st.markdown(
        '<p style="font-size:10px;color:#1e3a5f;text-align:center;margin-top:24px;">'
        'NetTwin Analyser v2.1</p>',
        unsafe_allow_html=True,
    )

# ─────────────────────────────────────────────────────────────────────────────
# RESOLVE DATA
# ─────────────────────────────────────────────────────────────────────────────

metrics     = get_metrics(scenario, traffic_load)
routers_data= get_routers(scenario)
logs_data   = get_logs(scenario, traffic_load)

# ─────────────────────────────────────────────────────────────────────────────
# RENDER — every panel via components.html()
# ─────────────────────────────────────────────────────────────────────────────

components.html(make_header(scenario, traffic_load), height=96)
st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

components.html(make_metrics(metrics), height=112)
st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

col_l, col_r = st.columns([3,1], gap="small")
with col_l:
    components.html(make_topology(scenario, traffic_load), height=440)
with col_r:
    components.html(make_telemetry(metrics), height=440)

st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

log_height = min(80 + len(logs_data) * 46, 500)
col_b1, col_b2 = st.columns([3,2], gap="small")
with col_b1:
    components.html(make_logs(logs_data), height=log_height)
with col_b2:
    components.html(make_routers(routers_data), height=log_height)

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
components.html(make_alert(scenario), height=54)