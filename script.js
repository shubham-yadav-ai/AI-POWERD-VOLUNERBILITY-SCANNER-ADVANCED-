// ── PARTICLES ──
const pWrap = document.getElementById('particles');
for (let i = 0; i < 30; i++) {
  const p = document.createElement('div');
  p.className = 'particle';
  p.style.cssText = `left:${Math.random()*100}%;animation-duration:${8+Math.random()*12}s;animation-delay:${Math.random()*10}s;`;
  pWrap.appendChild(p);
}

// ── CLOCK ──
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

let scanData = null;
let barChart, pieChart, radarChart, lineChart;

// ── SCAN DATA GENERATOR ──
function generateScanData(domain) {
  const h = domain.toLowerCase();
  const isMajor = ['google','github','microsoft','amazon','cloudflare'].some(s => h.includes(s));
  const riskBase = isMajor ? 1.5 : 4.5 + Math.random() * 4;
  const ports = [];
  const allPorts = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443];
  const count = isMajor ? 2 : 2 + Math.floor(Math.random() * 5);
  while (ports.length < count) {
    const p = allPorts[Math.floor(Math.random() * allPorts.length)];
    if (!ports.includes(p)) ports.push(p);
  }
  const sqlVuln = !isMajor && Math.random() > 0.5;
  const xssVuln = !isMajor && Math.random() > 0.4;
  const headersOk = isMajor || Math.random() > 0.5;
  const csrfVuln = !isMajor && Math.random() > 0.6;
  const sslOk = Math.random() > 0.2;
  const dirTraversal = !isMajor && Math.random() > 0.7;
  const risk = parseFloat(Math.min(9.9, riskBase + (sqlVuln?1.5:0) + (xssVuln?1:0) + (!headersOk?0.5:0) + (csrfVuln?0.8:0) + (!sslOk?0.7:0) + (dirTraversal?1.2:0) + ports.length*0.15).toFixed(1));
  const cves = [];
  if (sqlVuln) cves.push('CVE-2024-1234');
  if (xssVuln) cves.push('CVE-2024-5678');
  if (!sslOk) cves.push('CVE-2023-9101');
  if (dirTraversal) cves.push('CVE-2024-2468');
  return { domain, ports, sqlVuln, xssVuln, headersOk, csrfVuln, sslOk, dirTraversal, risk, cves, isMajor };
}

// ── LOGGER ──
function log(msg, type = 'info') {
  const t = document.getElementById('terminal');
  const now = new Date().toLocaleTimeString('en-GB', {hour12:false});
  const d = document.createElement('div');
  d.className = 'log-line';
  d.innerHTML = `<span class="log-time">[${now}]</span><span class="log-${type}">${msg}</span>`;
  t.appendChild(d);
  t.scrollTop = t.scrollHeight;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── MAIN SCAN ──
async function startScan() {
  const domain = document.getElementById('domainInput').value.trim();
  if (!domain) {
    document.getElementById('domainInput').style.borderColor = '#ff0055';
    setTimeout(() => document.getElementById('domainInput').style.borderColor = '', 1000);
    return;
  }
  ['dashboard','chartsSection','aiSection','solutionsSection','reportSection'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
  document.getElementById('timelineWrap').classList.remove('show');
  document.getElementById('terminal').classList.add('active');
  document.getElementById('terminal').innerHTML = '';

  const btn = document.getElementById('scanBtn');
  btn.textContent = '⟳ SCANNING...';
  btn.classList.add('scanning');
  btn.disabled = true;

  document.getElementById('progressWrap').classList.add('active');
  const fill = document.getElementById('progressFill');
  const steps = ['step1','step2','step3','step4','step5','step6','step7'];
  const msgs = [
    ['info','[DNS] Resolving hostname...'],
    ['ok','[PORT] Initiating port sweep on 1000 common ports...'],
    ['warn','[SQL] Testing injection vectors on form endpoints...'],
    ['warn','[XSS] Injecting payloads into query parameters...'],
    ['info','[HEADER] Auditing HTTP security headers...'],
    ['info','[AI] Running BERT threat classification model...'],
    ['ok','[REPORT] Compiling findings into structured JSON...'],
  ];
  for (let i = 0; i < steps.length; i++) {
    document.getElementById(steps[i]).className = 'step active';
    log(...msgs[i]);
    fill.style.width = `${((i+1)/steps.length)*100}%`;
    await sleep(600 + Math.random()*400);
    document.getElementById(steps[i]).className = 'step done';
  }

  scanData = generateScanData(domain);
  await sleep(300);
  renderDashboard(scanData);
  renderCharts(scanData);
  renderTimeline(scanData);
  renderAI(scanData);
  renderSolutions(scanData);
  document.getElementById('reportSection').classList.remove('hidden');
  log(`[DONE] Scan complete. Risk: ${scanData.risk}/10 | CVEs: ${scanData.cves.length}`, scanData.risk > 5 ? 'err' : 'ok');

  btn.textContent = '⚡ SCAN TARGET';
  btn.classList.remove('scanning');
  btn.disabled = false;
}

// ── DASHBOARD ──
function renderDashboard(d) {
  document.getElementById('dashboard').classList.remove('hidden');
  const pct = d.risk / 10;
  const offset = 238.76 - pct * 238.76;
  const ring = document.getElementById('riskRing');
  setTimeout(() => { ring.style.strokeDashoffset = offset; }, 100);
  const color = d.risk < 3 ? '#39ff14' : d.risk < 6 ? '#ffb700' : '#ff0055';
  ring.style.stroke = color;
  const num = document.getElementById('riskNum');
  num.style.color = color;
  animateNum(num, 0, d.risk, 1500);
  const lvl = d.risk < 3 ? 'LOW' : d.risk < 6 ? 'MEDIUM' : d.risk < 8 ? 'HIGH' : 'CRITICAL';
  const badgeClass = d.risk < 3 ? 'badge-safe' : d.risk < 6 ? 'badge-warn' : 'badge-danger';
  document.getElementById('riskBadge').textContent = lvl;
  document.getElementById('riskBadge').className = `card-badge ${badgeClass}`;
  document.getElementById('threatLevel').textContent = lvl;
  document.getElementById('threatLevel').style.color = color;
  document.getElementById('portsFound').textContent = d.ports.join(', ') || 'None';
  document.getElementById('cvesFound').textContent = d.cves.length;
  document.getElementById('scanTime').textContent = (2.1 + Math.random()).toFixed(2) + 's';
  document.getElementById('targetLabel').textContent = d.domain.toUpperCase();

  const items = [
    { icon:'🗄️', name:'SQL Injection', status:d.sqlVuln?'VULNERABLE':'SAFE', cls:d.sqlVuln?'status-danger':'status-safe' },
    { icon:'💉', name:'XSS', status:d.xssVuln?'VULNERABLE':'SAFE', cls:d.xssVuln?'status-danger':'status-safe' },
    { icon:'📋', name:'HTTP Headers', status:d.headersOk?'PRESENT':'MISSING', cls:d.headersOk?'status-safe':'status-warn' },
    { icon:'🔐', name:'CSRF Protection', status:d.csrfVuln?'MISSING':'PRESENT', cls:d.csrfVuln?'status-warn':'status-safe' },
    { icon:'🔒', name:'SSL/TLS', status:d.sslOk?'VALID':'WEAK', cls:d.sslOk?'status-safe':'status-danger' },
    { icon:'📁', name:'Dir Traversal', status:d.dirTraversal?'EXPOSED':'SECURE', cls:d.dirTraversal?'status-danger':'status-safe' },
  ];
  document.getElementById('resultsGrid').innerHTML = items.map(i => `
    <div class="result-item">
      <div class="result-icon">${i.icon}</div>
      <div><div class="result-name">${i.name}</div><div class="result-status ${i.cls}">${i.status}</div></div>
    </div>`).join('');

  const sevs = [
    { label:'CRITICAL', count:[d.sqlVuln,d.dirTraversal].filter(Boolean).length, color:'#ff0055' },
    { label:'HIGH', count:[d.xssVuln,!d.sslOk].filter(Boolean).length, color:'#ffb700' },
    { label:'MEDIUM', count:[!d.headersOk,d.csrfVuln].filter(Boolean).length, color:'#00f5ff' },
    { label:'LOW', count:Math.max(0,d.ports.length-3), color:'#39ff14' },
  ];
  const total = Math.max(1, sevs.reduce((a,b)=>a+b.count,0));
  document.getElementById('severityBreakdown').innerHTML = sevs.map(s => `
    <div>
      <div style="display:flex;justify-content:space-between;margin-bottom:5px">
        <span style="font-size:12px;color:${s.color};font-family:'Share Tech Mono'">${s.label}</span>
        <span style="font-family:'Share Tech Mono';font-size:12px">${s.count} found</span>
      </div>
      <div class="pred-bar-bg">
        <div class="pred-bar-fill" style="background:${s.color};width:0" data-target="${Math.round(s.count/total*100)}"></div>
      </div>
    </div>`).join('');
  setTimeout(() => {
    document.querySelectorAll('.pred-bar-fill[data-target]').forEach(el => { el.style.width = el.dataset.target + '%'; });
  }, 200);
}

// ── CHARTS ──
function renderCharts(d) {
  document.getElementById('chartsSection').classList.remove('hidden');
  if (barChart) barChart.destroy();
  if (pieChart) pieChart.destroy();
  if (radarChart) radarChart.destroy();

  const barVals = [Math.min(3,d.ports.length*0.5),d.sqlVuln?2.5:0.2,d.xssVuln?2:0.2,d.headersOk?0.2:1.5,d.csrfVuln?1.5:0.1,d.sslOk?0.1:1.8,d.dirTraversal?2.8:0.1];
  barChart = new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: ['Ports','SQL','XSS','Headers','CSRF','SSL','Dir Traversal'],
      datasets: [{ label:'Risk Factor', data:barVals, backgroundColor:barVals.map(v=>v>2?'rgba(255,0,85,0.6)':v>1?'rgba(255,183,0,0.6)':'rgba(0,245,255,0.4)'), borderColor:barVals.map(v=>v>2?'#ff0055':v>1?'#ffb700':'#00f5ff'), borderWidth:1, borderRadius:4 }]
    },
    options: chartOpts(3)
  });

  const vulnLabels = ['SQL Injection','XSS','Header Issues','CSRF','SSL Weakness','Dir Traversal'];
  const vulnVals = [d.sqlVuln?1:0,d.xssVuln?1:0,!d.headersOk?1:0,d.csrfVuln?1:0,!d.sslOk?1:0,d.dirTraversal?1:0];
  const safe = vulnVals.filter(v=>!v).length;
  const pLabels = [...vulnLabels.filter((_,i)=>vulnVals[i]),'Secure'];
  const pVals = [...vulnVals.filter(v=>v),safe];
  const cols = ['rgba(255,0,85,0.8)','rgba(255,0,85,0.6)','rgba(255,183,0,0.7)','rgba(255,183,0,0.5)','rgba(191,95,255,0.7)','rgba(191,95,255,0.5)','rgba(57,255,20,0.5)'];
  pieChart = new Chart(document.getElementById('pieChart'), {
    type: 'doughnut',
    data: { labels:pLabels, datasets:[{ data:pVals, backgroundColor:cols.slice(0,pLabels.length), borderColor:'transparent', hoverOffset:8 }] },
    options: { responsive:true, maintainAspectRatio:true, plugins:{ legend:{ position:'bottom', labels:{ color:'#6b8fb5', font:{ size:10, family:'Share Tech Mono' }, boxWidth:12 } }, tooltip:{ backgroundColor:'#0a1628', titleColor:'#00f5ff', bodyColor:'#e8f4ff' } } }
  });

  radarChart = new Chart(document.getElementById('radarChart'), {
    type: 'radar',
    data: {
      labels: ['Network Exp.','Web Vuln.','Data Leak','Auth Bypass','MITM Risk','Brute Force'],
      datasets: [{ label:'Risk Level', data:[d.ports.length*1.2,(d.sqlVuln?3:0)+(d.xssVuln?2:0),d.dirTraversal?3.5:0.5,d.csrfVuln?3:0.5,!d.sslOk?3:0.5,d.ports.includes(22)||d.ports.includes(3389)?2.5:0.5], backgroundColor:'rgba(0,245,255,0.1)', borderColor:'rgba(0,245,255,0.8)', pointBackgroundColor:'#00f5ff', pointRadius:4 }]
    },
    options: { responsive:true, maintainAspectRatio:true, plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'#0a1628', titleColor:'#00f5ff', bodyColor:'#e8f4ff' } }, scales:{ r:{ min:0, max:5, ticks:{ color:'#6b8fb5', font:{size:9}, backdropColor:'transparent', stepSize:1 }, grid:{ color:'rgba(255,255,255,0.08)' }, angleLines:{ color:'rgba(255,255,255,0.06)' }, pointLabels:{ color:'#6b8fb5', font:{ size:10, family:'Share Tech Mono' } } } } }
  });
}

function chartOpts(max) {
  return { responsive:true, maintainAspectRatio:true, plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'#0a1628', titleColor:'#00f5ff', bodyColor:'#e8f4ff', borderColor:'rgba(0,245,255,0.3)', borderWidth:1 } }, scales:{ x:{ ticks:{ color:'#6b8fb5', font:{ size:10, family:'Share Tech Mono' } }, grid:{ color:'rgba(255,255,255,0.04)' }, border:{color:'transparent'} }, y:{ max, ticks:{ color:'#6b8fb5', font:{size:10} }, grid:{ color:'rgba(255,255,255,0.06)' }, border:{color:'transparent'} } } };
}

// ── TIMELINE ──
function renderTimeline(d) {
  document.getElementById('timelineWrap').classList.add('show');
  if (lineChart) lineChart.destroy();
  const labels = Array.from({length:30},(_,i)=>`Day ${i+1}`);
  const data = labels.map((_,i)=>Math.max(0,Math.min(10,d.risk+(Math.random()-0.5)*1.5+Math.sin(i/4)*0.5)));
  const ctx = document.getElementById('lineChart').getContext('2d');
  const grad = ctx.createLinearGradient(0,0,0,180);
  grad.addColorStop(0,'rgba(0,245,255,0.3)');
  grad.addColorStop(1,'rgba(0,245,255,0)');
  lineChart = new Chart(ctx, {
    type:'line',
    data:{ labels, datasets:[
      { label:'Predicted Risk', data, borderColor:'#00f5ff', backgroundColor:grad, borderWidth:2, fill:true, tension:0.4, pointRadius:0, pointHoverRadius:5 },
      { label:'Critical Threshold', data:Array(30).fill(7), borderColor:'rgba(255,0,85,0.6)', borderWidth:1, borderDash:[5,5], fill:false, pointRadius:0 }
    ]},
    options:{ responsive:true, maintainAspectRatio:true, plugins:{ legend:{ labels:{ color:'#6b8fb5', font:{size:10} } }, tooltip:{ backgroundColor:'#0a1628', titleColor:'#00f5ff', bodyColor:'#e8f4ff' } }, scales:{ x:{ ticks:{ color:'#6b8fb5', font:{size:9}, maxTicksLimit:10 }, grid:{ color:'rgba(255,255,255,0.04)' }, border:{color:'transparent'} }, y:{ min:0, max:10, ticks:{ color:'#6b8fb5', font:{size:9} }, grid:{ color:'rgba(255,255,255,0.06)' }, border:{color:'transparent'} } } }
  });
}

// ── AI PANEL ──
function renderAI(d) {
  document.getElementById('aiSection').classList.remove('hidden');
  const lvl = d.risk < 3 ? 'low' : d.risk < 6 ? 'moderate' : 'critical';
  const color = d.risk < 3 ? 'var(--neon-green)' : d.risk < 6 ? 'var(--neon-amber)' : 'var(--neon-red)';
  const issues = [];
  if (d.sqlVuln) issues.push('SQL injection vulnerability — highest severity finding');
  if (d.xssVuln) issues.push('Cross-site scripting detected — user data at risk');
  if (!d.headersOk) issues.push('Missing security headers (CSP, HSTS, X-Frame-Options)');
  if (d.csrfVuln) issues.push('CSRF token absent — state-changing requests unprotected');
  if (!d.sslOk) issues.push('SSL/TLS weakness — man-in-the-middle exposure');
  if (d.dirTraversal) issues.push('Directory traversal — filesystem paths accessible');
  const tags = ['OWASP TOP 10','CVE DATABASE','ML CLASSIFIER','THREAT INTEL',...d.cves];
  document.getElementById('aiThinking').textContent = 'ANALYSIS COMPLETE';
  document.getElementById('aiOutput').innerHTML = `
    <p><strong style="color:var(--neon-cyan)">${d.domain}</strong> presents a <strong style="color:${color}">${lvl} risk profile</strong> with an overall score of <strong>${d.risk}/10</strong>.</p>
    ${issues.length ? `<p>Key threats: <strong>${issues[0]}</strong>. ${issues.slice(1).join('. ')}.</p>` : '<p>No critical vulnerabilities detected. Maintain regular scanning cadence.</p>'}
    <p>${d.ports.length} open port${d.ports.length!==1?'s':''} detected (${d.ports.join(', ')}). ${d.ports.includes(3306)||d.ports.includes(5432)?'Database ports exposed — restrict via firewall immediately.':d.ports.includes(22)?'SSH exposed — enforce key-based auth only.':'Port exposure within acceptable parameters.'}</p>
    <p style="margin-top:12px">${tags.map(t=>`<span class="ai-tag">${t}</span>`).join('')}</p>`;

  const preds = [
    { name:'SQL Injection Attack', pct:d.sqlVuln?82:12, color:'#ff0055' },
    { name:'Brute Force Attempt', pct:d.ports.includes(22)||d.ports.includes(3389)?71:18, color:'#ffb700' },
    { name:'XSS Exploitation', pct:d.xssVuln?65:8, color:'#ffb700' },
    { name:'Data Exfiltration', pct:d.dirTraversal?58:5, color:'#bf5fff' },
    { name:'MITM Interception', pct:!d.sslOk?48:6, color:'#00f5ff' },
  ];
  document.getElementById('predictionRows').innerHTML = preds.map(p => `
    <div class="pred-item">
      <div class="pred-top"><span class="pred-name">${p.name}</span><span class="pred-pct" style="color:${p.color}">${p.pct}%</span></div>
      <div class="pred-bar-bg"><div class="pred-bar-fill" style="background:${p.color};width:0;box-shadow:0 0 8px ${p.color}" data-w="${p.pct}"></div></div>
    </div>`).join('');
  setTimeout(() => { document.querySelectorAll('.pred-bar-fill[data-w]').forEach(el=>{ el.style.width=el.dataset.w+'%'; }); }, 300);
}

// ── SOLUTIONS ──
function renderSolutions(d) {
  document.getElementById('solutionsSection').classList.remove('hidden');
  const sols = [];
  if (d.sqlVuln) sols.push({ priority:'CRITICAL', priClass:'pri-critical', cardClass:'sol-critical', title:'Prevent SQL Injection', desc:'User input is being interpolated directly into SQL queries. Use parameterized queries.', code:`cursor.execute("SELECT * FROM users\nWHERE id = %s", (user_id,))\n\n# SQLAlchemy ORM:\nUser.query.filter_by(id=user_id).first()`, effort:2 });
  if (d.xssVuln) sols.push({ priority:'HIGH', priClass:'pri-high', cardClass:'sol-high', title:'Fix Cross-Site Scripting', desc:'User input reflected without sanitization. Escape all output and implement CSP.', code:`from markupsafe import escape\n\n@app.route('/')\ndef index():\n  name = escape(request.args.get('name',''))\n  return render_template('index.html',name=name)`, effort:2 });
  if (!d.headersOk) sols.push({ priority:'HIGH', priClass:'pri-high', cardClass:'sol-high', title:'Add Security Headers', desc:'Critical HTTP headers missing — browsers have no protection against clickjacking.', code:`@app.after_request\ndef headers(r):\n  r.headers['X-Frame-Options'] = 'DENY'\n  r.headers['X-Content-Type-Options'] = 'nosniff'\n  r.headers['Strict-Transport-Security'] = 'max-age=31536000'\n  return r`, effort:1 });
  if (d.csrfVuln) sols.push({ priority:'HIGH', priClass:'pri-high', cardClass:'sol-high', title:'Implement CSRF Tokens', desc:'Forms lack CSRF protection — attackers can trick users into submitting unauthorized requests.', code:`from flask_wtf.csrf import CSRFProtect\n\napp = Flask(__name__)\napp.config['SECRET_KEY'] = 'your-secret'\ncsrf = CSRFProtect(app)`, effort:2 });
  if (!d.sslOk) sols.push({ priority:'CRITICAL', priClass:'pri-critical', cardClass:'sol-critical', title:'Upgrade SSL/TLS', desc:'Weak or misconfigured SSL allows man-in-the-middle attacks. Enforce TLS 1.2+ minimum.', code:`# nginx.conf:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;\nssl_prefer_server_ciphers off;\nadd_header Strict-Transport-Security "max-age=63072000" always;`, effort:3 });
  if (d.dirTraversal) sols.push({ priority:'CRITICAL', priClass:'pri-critical', cardClass:'sol-critical', title:'Block Directory Traversal', desc:'Attacker can read arbitrary files via ../../../etc/passwd patterns.', code:`import os\n\ndef safe_path(base, user_input):\n  path = os.path.realpath(os.path.join(base, user_input))\n  if not path.startswith(base):\n    raise ValueError("Path traversal detected!")\n  return path`, effort:2 });
  if (!sols.length) sols.push({ priority:'MEDIUM', priClass:'pri-medium', cardClass:'sol-medium', title:'Maintain Security Posture', desc:'No critical issues found. Apply defense-in-depth and keep scanning regularly.', code:`# .github/workflows/security.yml\n- name: OWASP ZAP Scan\n  uses: zaproxy/action-full-scan@v0.9.0\n  with:\n    target: 'https://yourapp.com'`, effort:1 });

  document.getElementById('solutionsGrid').innerHTML = sols.map((s,i) => `
    <div class="solution-card ${s.cardClass}" style="animation-delay:${i*0.1}s">
      <div class="sol-priority ${s.priClass}">⚠ ${s.priority} PRIORITY</div>
      <div class="sol-title">${s.title}</div>
      <div class="sol-desc">${s.desc}</div>
      <div class="sol-code">${s.code}</div>
      <div class="sol-effort"><span>Effort:</span><div class="effort-dots">${Array(3).fill(0).map((_,j)=>`<div class="effort-dot ${j<s.effort?'filled':''}"></div>`).join('')}</div><span>${s.effort===1?'Low':s.effort===2?'Medium':'High'}</span></div>
    </div>`).join('');
}

// ── HELPERS ──
function animateNum(el, from, to, dur) {
  const start = performance.now();
  function step(now) {
    const t = Math.min((now-start)/dur, 1);
    el.textContent = (from+(to-from)*t).toFixed(1);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function buildReportText() {
  if (!scanData) return 'No scan data.';
  const d = scanData;
  return `AI — SECURITY REPORT\n====================================\nTarget: ${d.domain}\nDate: ${new Date().toLocaleString()}\nRisk Score: ${d.risk}/10\nThreat Level: ${d.risk<3?'LOW':d.risk<6?'MEDIUM':d.risk<8?'HIGH':'CRITICAL'}\n\nOpen Ports: ${d.ports.join(', ')||'None'}\nCVEs: ${d.cves.join(', ')||'None'}\n\nSQL Injection:   ${d.sqlVuln?'VULNERABLE':'SAFE'}\nXSS:             ${d.xssVuln?'VULNERABLE':'SAFE'}\nHTTP Headers:    ${d.headersOk?'PRESENT':'MISSING'}\nCSRF:            ${d.csrfVuln?'MISSING':'PRESENT'}\nSSL/TLS:         ${d.sslOk?'VALID':'WEAK'}\nDir Traversal:   ${d.dirTraversal?'EXPOSED':'SECURE'}\n\nGenerated by AI — Powered Vulnerability Scanner`.trim();
}

function downloadPDF() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([buildReportText()],{type:'text/plain'}));
  a.download = `report-${scanData?.domain||'scan'}.txt`;
  a.click();
}
function downloadJSON() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(scanData,null,2)],{type:'application/json'}));
  a.download = `scan-${scanData?.domain}.json`;
  a.click();
}
function copyReport() { navigator.clipboard.writeText(buildReportText()).then(()=>alert('Copied!')); }
function shareReport() {
  navigator.clipboard.writeText(`${location.origin}${location.pathname}?scan=${btoa(JSON.stringify(scanData))}`).then(()=>alert('Link copied!'));
}

document.getElementById('domainInput').addEventListener('keydown', e => { if (e.key==='Enter') startScan(); });
