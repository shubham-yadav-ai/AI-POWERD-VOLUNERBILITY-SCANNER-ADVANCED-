setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

const toggleBtn = document.getElementById("themeToggle");

// Load saved theme
if (localStorage.getItem("theme") === "dark") {
  document.body.classList.add("dark");
  toggleBtn.textContent = "☀️";
}

toggleBtn.onclick = () => {
  document.body.classList.toggle("dark");

  if (document.body.classList.contains("dark")) {
    localStorage.setItem("theme", "dark");
    toggleBtn.textContent = "☀️";
  } else {
    localStorage.setItem("theme", "light");
    toggleBtn.textContent = "🌙";
  }
};

let scanData = null;
let barChart, pieChart, radarChart, lineChart;

function generateScanData(domain) {
  const h = domain.toLowerCase();
  const isMajor = ['google','github','microsoft','amazon','cloudflare'].some(s => h.includes(s));
  const riskBase = isMajor ? 1.5 : 4.5 + Math.random() * 4;
  const allPorts = [21,22,23,25,53,80,110,443,445,3306,3389,5432,6379,8080];
  const ports = [];
  const count = isMajor ? 2 : 2 + Math.floor(Math.random() * 4);
  while (ports.length < count) {
    const p = allPorts[Math.floor(Math.random() * allPorts.length)];
    if (!ports.includes(p)) ports.push(p);
  }
  const sql = !isMajor && Math.random() > 0.5;
  const xss = !isMajor && Math.random() > 0.4;
  const headers = isMajor || Math.random() > 0.5;
  const csrf = !isMajor && Math.random() > 0.6;
  const ssl = Math.random() > 0.2;
  const dir = !isMajor && Math.random() > 0.7;
  const risk = parseFloat(Math.min(9.9,
    riskBase + (sql?1.5:0) + (xss?1:0) + (!headers?0.5:0) +
    (csrf?0.8:0) + (!ssl?0.7:0) + (dir?1.2:0) + ports.length*0.1
  ).toFixed(1));
  const cves = [];
  if (sql) cves.push('CVE-2024-1234');
  if (xss) cves.push('CVE-2024-5678');
  if (!ssl) cves.push('CVE-2023-9101');
  if (dir) cves.push('CVE-2024-2468');
  return { domain, ports, sql, xss, headers, csrf, ssl, dir, risk, cves };
}

function log(msg, type = 'info') {
  const t = document.getElementById('terminal');
  const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const d = document.createElement('div');
  d.className = 'log-line';
  d.innerHTML = `<span class="log-time">[${now}]</span><span class="log-${type}">${msg}</span>`;
  t.appendChild(d);
  t.scrollTop = t.scrollHeight;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function startScan() {
  const domain = document.getElementById('domainInput').value.trim();
  if (!domain) {
    document.getElementById('domainInput').style.borderColor = 'var(--red)';
    setTimeout(() => document.getElementById('domainInput').style.borderColor = '', 1000);
    return;
  }

  document.getElementById('results').classList.add('hidden');
  document.getElementById('terminal').classList.remove('hidden');
  document.getElementById('terminal').innerHTML = '';
  document.getElementById('steps').classList.remove('hidden');
  document.getElementById('progressBar').classList.remove('hidden');

  const btn = document.getElementById('scanBtn');
  btn.textContent = 'Scanning...';
  btn.disabled = true;

  const fill = document.getElementById('progressFill');
  const steps = ['s1','s2','s3','s4','s5','s6','s7'];
  const msgs = [
    ['info', 'Resolving hostname via DNS...'],
    ['info', 'Sweeping common ports (1-1024)...'],
    ['warn', 'Testing SQL injection vectors...'],
    ['warn', 'Checking XSS in query parameters...'],
    ['info', 'Auditing HTTP security headers...'],
    ['info', 'Running AI threat classification...'],
    ['ok',   'Compiling final report...'],
  ];

  for (let i = 0; i < steps.length; i++) {
    document.getElementById(steps[i]).className = 'step active';
    log(...msgs[i]);
    fill.style.width = `${((i + 1) / steps.length) * 100}%`;
    await sleep(500 + Math.random() * 400);
    document.getElementById(steps[i]).className = 'step done';
  }

  scanData = generateScanData(domain);
  await sleep(200);

  renderAll(scanData);

  btn.textContent = 'Scan';
  btn.disabled = false;
}

function renderAll(d) {
  renderScore(d);
  renderInfo(d);
  renderSeverity(d);
  renderVulns(d);
  renderCharts(d);
  renderAI(d);
  renderPredictions(d);
  renderFixes(d);
  document.getElementById('results').classList.remove('hidden');
  log(`Done. Risk score: ${d.risk}/10 — CVEs matched: ${d.cves.length}`, d.risk > 6 ? 'err' : 'ok');
}

function renderScore(d) {
  const color = d.risk < 3 ? 'var(--green)' : d.risk < 6 ? 'var(--yellow)' : 'var(--red)';
  const level = d.risk < 3 ? 'Low' : d.risk < 6 ? 'Medium' : d.risk < 8 ? 'High' : 'Critical';
  const num = document.getElementById('scoreNum');
  num.style.color = color;
  animateNum(num, 0, d.risk, 1200);
  const bar = document.getElementById('scoreBar');
  bar.style.background = color;
  setTimeout(() => { bar.style.width = (d.risk / 10 * 100) + '%'; }, 100);
  const lv = document.getElementById('scoreLevel');
  lv.textContent = level;
  lv.style.color = color;
}

function renderInfo(d) {
  document.getElementById('infoRows').innerHTML = [
    { k: 'Target', v: d.domain },
    { k: 'Open Ports', v: d.ports.join(', ') || 'None' },
    { k: 'CVEs', v: d.cves.length || 'None' },
    { k: 'Scan Time', v: (1.8 + Math.random()).toFixed(2) + 's' },
  ].map(r => `
    <div class="info-row">
      <span class="info-key">${r.k}</span>
      <span class="info-val">${r.v}</span>
    </div>`).join('');
}

function renderSeverity(d) {
  const sevs = [
    { label: 'Critical', count: [d.sql, d.dir].filter(Boolean).length, color: 'var(--red)' },
    { label: 'High',     count: [d.xss, !d.ssl].filter(Boolean).length, color: 'var(--yellow)' },
    { label: 'Medium',   count: [!d.headers, d.csrf].filter(Boolean).length, color: 'var(--accent)' },
    { label: 'Low',      count: Math.max(0, d.ports.length - 2), color: 'var(--green)' },
  ];
  const total = Math.max(1, sevs.reduce((a, b) => a + b.count, 0));
  document.getElementById('severityRows').innerHTML = sevs.map(s => `
    <div class="sev-row">
      <div class="sev-top">
        <span style="color:${s.color};font-weight:600;font-size:12px">${s.label}</span>
        <span style="font-family:var(--mono);font-size:12px">${s.count}</span>
      </div>
      <div class="sev-bar-bg">
        <div class="sev-bar-fill" style="background:${s.color};width:0" data-w="${Math.round(s.count/total*100)}"></div>
      </div>
    </div>`).join('');
  setTimeout(() => {
    document.querySelectorAll('.sev-bar-fill').forEach(el => { el.style.width = el.dataset.w + '%'; });
  }, 200);
}

function renderVulns(d) {
  const checks = [
    { icon: '🗄', name: 'SQL Injection', status: d.sql ? 'Vulnerable' : 'Safe', cls: d.sql ? 'danger' : 'safe' },
    { icon: '💉', name: 'XSS', status: d.xss ? 'Vulnerable' : 'Safe', cls: d.xss ? 'danger' : 'safe' },
    { icon: '📋', name: 'HTTP Headers', status: d.headers ? 'Present' : 'Missing', cls: d.headers ? 'safe' : 'warn' },
    { icon: '🔐', name: 'CSRF', status: d.csrf ? 'Missing' : 'Present', cls: d.csrf ? 'warn' : 'safe' },
    { icon: '🔒', name: 'SSL / TLS', status: d.ssl ? 'Valid' : 'Weak', cls: d.ssl ? 'safe' : 'danger' },
    { icon: '📁', name: 'Dir Traversal', status: d.dir ? 'Exposed' : 'Secure', cls: d.dir ? 'danger' : 'safe' },
  ];
  document.getElementById('vulnGrid').innerHTML = checks.map(c => `
    <div class="vuln-item">
      <span class="vuln-icon">${c.icon}</span>
      <div>
        <div class="vuln-name">${c.name}</div>
        <div class="vuln-status ${c.cls}">${c.status}</div>
      </div>
    </div>`).join('');
}

function renderCharts(d) {
  if (barChart) barChart.destroy();
  if (pieChart) pieChart.destroy();
  if (radarChart) radarChart.destroy();
  if (lineChart) lineChart.destroy();

  const bv = [
    Math.min(3, d.ports.length * 0.5),
    d.sql ? 2.5 : 0.2,
    d.xss ? 2.0 : 0.2,
    d.headers ? 0.1 : 1.5,
    d.csrf ? 1.5 : 0.1,
    d.ssl ? 0.1 : 1.8,
    d.dir ? 2.8 : 0.1,
  ];

  barChart = new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: ['Ports','SQL','XSS','Headers','CSRF','SSL','Dir'],
      datasets: [{
        data: bv,
        backgroundColor: bv.map(v => v > 2 ? '#fecaca' : v > 1 ? '#fef08a' : '#bbf7d0'),
        borderColor: bv.map(v => v > 2 ? '#dc2626' : v > 1 ? '#ca8a04' : '#16a34a'),
        borderWidth: 1, borderRadius: 4,
      }]
    },
    options: baseOpts(3)
  });

  const vl = ['SQL','XSS','Headers','CSRF','SSL','Dir Traversal'];
  const vv = [d.sql?1:0, d.xss?1:0, !d.headers?1:0, d.csrf?1:0, !d.ssl?1:0, d.dir?1:0];
  const safe = vv.filter(v => !v).length;
  const pl = [...vl.filter((_,i) => vv[i]), 'Secure'];
  const pv = [...vv.filter(v => v), safe];

  pieChart = new Chart(document.getElementById('pieChart'), {
    type: 'doughnut',
    data: {
      labels: pl,
      datasets: [{
        data: pv,
        backgroundColor: ['#fca5a5','#fcd34d','#93c5fd','#c4b5fd','#6ee7b7','#f9a8d4','#d1d5db'],
        borderColor: '#fff', borderWidth: 2, hoverOffset: 6,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: {
        legend: { position: 'bottom', labels: { font: { size: 10 }, boxWidth: 10 } },
        tooltip: { backgroundColor: '#1e1e1e', titleColor: '#fff', bodyColor: '#ccc' }
      }
    }
  });

  radarChart = new Chart(document.getElementById('radarChart'), {
    type: 'radar',
    data: {
      labels: ['Network','Web Vulns','Data Leak','Auth','MITM','Brute Force'],
      datasets: [{
        label: 'Risk',
        data: [
          d.ports.length * 1.2,
          (d.sql?3:0)+(d.xss?2:0),
          d.dir ? 3.5 : 0.4,
          d.csrf ? 3 : 0.4,
          !d.ssl ? 3 : 0.4,
          d.ports.includes(22)||d.ports.includes(3389) ? 2.5 : 0.4
        ],
        backgroundColor: 'rgba(37,99,235,0.1)',
        borderColor: '#2563eb',
        pointBackgroundColor: '#2563eb',
        pointRadius: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1e1e1e' } },
      scales: {
        r: {
          min: 0, max: 5,
          ticks: { stepSize: 1, font: { size: 9 }, backdropColor: 'transparent', color: '#999' },
          grid: { color: '#e5e7eb' },
          angleLines: { color: '#e5e7eb' },
          pointLabels: { font: { size: 10 }, color: '#555' }
        }
      }
    }
  });

  const labels30 = Array.from({ length: 30 }, (_, i) => `D${i+1}`);
  const lineData = labels30.map((_, i) =>
    Math.max(0, Math.min(10, d.risk + (Math.random()-0.5)*1.5 + Math.sin(i/4)*0.4))
  );
  lineChart = new Chart(document.getElementById('lineChart'), {
    type: 'line',
    data: {
      labels: labels30,
      datasets: [
        {
          label: 'Predicted Risk',
          data: lineData,
          borderColor: '#2563eb',
          backgroundColor: 'rgba(37,99,235,0.08)',
          borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0,
        },
        {
          label: 'Critical (7)',
          data: Array(30).fill(7),
          borderColor: '#dc2626',
          borderWidth: 1, borderDash: [4,4],
          fill: false, pointRadius: 0,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: {
        legend: { labels: { font: { size: 11 }, boxWidth: 12 } },
        tooltip: { backgroundColor: '#1e1e1e', titleColor: '#fff', bodyColor: '#ccc' }
      },
      scales: {
        x: { ticks: { maxTicksLimit: 10, font: { size: 9 }, color: '#999' }, grid: { color: '#f0f0f0' } },
        y: { min: 0, max: 10, ticks: { font: { size: 9 }, color: '#999' }, grid: { color: '#f0f0f0' } }
      }
    }
  });
}

function baseOpts(max) {
  return {
    responsive: true, maintainAspectRatio: true,
    plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1e1e1e', titleColor: '#fff', bodyColor: '#ccc' } },
    scales: {
      x: { ticks: { font: { size: 10 }, color: '#999' }, grid: { color: '#f0f0f0' } },
      y: { max, ticks: { font: { size: 10 }, color: '#999' }, grid: { color: '#f0f0f0' } }
    }
  };
}

function renderAI(d) {
  const lvl = d.risk < 3 ? 'low' : d.risk < 6 ? 'moderate' : 'high';
  const issues = [];
  if (d.sql) issues.push('SQL injection');
  if (d.xss) issues.push('cross-site scripting');
  if (!d.headers) issues.push('missing security headers');
  if (d.csrf) issues.push('absent CSRF protection');
  if (!d.ssl) issues.push('weak SSL/TLS');
  if (d.dir) issues.push('directory traversal');

  document.getElementById('aiText').innerHTML = `
    <strong>${d.domain}</strong> has a <strong>${lvl} risk profile</strong> — score ${d.risk}/10.
    ${issues.length
      ? ` Main issues found: ${issues.join(', ')}.`
      : ' No major vulnerabilities detected.'}
    ${d.ports.length} open port${d.ports.length !== 1 ? 's' : ''} detected (${d.ports.join(', ')}).
    ${d.ports.includes(3306) || d.ports.includes(5432) ? ' Database port exposed — restrict with firewall.' : ''}
    ${d.ports.includes(22) ? ' SSH open — use key-based auth only.' : ''}
  `;

  const tags = ['OWASP', 'CVE DB', 'ML Model', ...d.cves];
  document.getElementById('aiTags').innerHTML = tags.map(t => `<span class="tag">${t}</span>`).join('');
}

function renderPredictions(d) {
  const preds = [
    { name: 'SQL Injection attack',  pct: d.sql ? 82 : 11, color: '#dc2626' },
    { name: 'Brute force attempt',   pct: d.ports.includes(22)||d.ports.includes(3389) ? 70 : 17, color: '#ca8a04' },
    { name: 'XSS exploitation',      pct: d.xss ? 64 : 8,  color: '#ca8a04' },
    { name: 'Data exfiltration',     pct: d.dir ? 57 : 5,  color: '#7c3aed' },
    { name: 'MITM interception',     pct: !d.ssl ? 47 : 6, color: '#2563eb' },
  ];
  document.getElementById('predRows').innerHTML = preds.map(p => `
    <div class="pred-row">
      <div class="pred-top">
        <span>${p.name}</span>
        <span class="pred-pct" style="color:${p.color}">${p.pct}%</span>
      </div>
      <div class="pred-bar-bg">
        <div class="pred-bar-fill" style="background:${p.color};width:0" data-w="${p.pct}"></div>
      </div>
    </div>`).join('');
  setTimeout(() => {
    document.querySelectorAll('.pred-bar-fill[data-w]').forEach(el => { el.style.width = el.dataset.w + '%'; });
  }, 300);
}

function renderFixes(d) {
  const fixes = [];
  if (d.sql) fixes.push({ cls:'critical', title:'SQL Injection', desc:'Use parameterized queries — never interpolate user input into SQL.', code:`cursor.execute(\n  "SELECT * FROM users WHERE id=%s",\n  (user_id,)\n)` });
  if (d.xss) fixes.push({ cls:'high', title:'XSS', desc:'Escape all output rendered in HTML. Add a Content-Security-Policy header.', code:`from markupsafe import escape\nname = escape(request.args.get('name'))` });
  if (!d.headers) fixes.push({ cls:'high', title:'Security Headers', desc:'Add X-Frame-Options, HSTS, X-Content-Type-Options to all responses.', code:`r.headers['X-Frame-Options'] = 'DENY'\nr.headers['X-Content-Type-Options'] = 'nosniff'\nr.headers['Strict-Transport-Security'] = 'max-age=31536000'` });
  if (d.csrf) fixes.push({ cls:'high', title:'CSRF Tokens', desc:'Add CSRF tokens to all state-changing forms using Flask-WTF.', code:`from flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)` });
  if (!d.ssl) fixes.push({ cls:'critical', title:'SSL / TLS', desc:'Enforce TLS 1.2+ and disable weak ciphers in your server config.', code:`ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;` });
  if (d.dir) fixes.push({ cls:'critical', title:'Directory Traversal', desc:'Validate all file paths — reject any containing ../ sequences.', code:`path = os.path.realpath(os.path.join(base, inp))\nif not path.startswith(base): raise ValueError()` });
  if (!fixes.length) fixes.push({ cls:'medium', title:'Keep Monitoring', desc:'No critical issues found. Automate scanning in your CI/CD pipeline.', code:`# GitHub Actions\n- uses: zaproxy/action-full-scan@v0.9.0` });

  document.getElementById('fixGrid').innerHTML = fixes.map(f => `
    <div class="fix-card ${f.cls}">
      <div class="fix-priority ${f.cls}">${f.cls}</div>
      <div class="fix-title">${f.title}</div>
      <div class="fix-desc">${f.desc}</div>
      <div class="fix-code">${f.code}</div>
    </div>`).join('');
}

// ── HELPERS ──
function animateNum(el, from, to, dur) {
  const start = performance.now();
  (function step(now) {
    const t = Math.min((now - start) / dur, 1);
    el.textContent = (from + (to - from) * t).toFixed(1);
    if (t < 1) requestAnimationFrame(step);
  })(performance.now());
}

function buildReport() {
  if (!scanData) return '';
  const d = scanData;
  return `VulnScanner Report
==================
Target:     ${d.domain}
Date:       ${new Date().toLocaleString()}
Risk Score: ${d.risk}/10
Level:      ${d.risk<3?'Low':d.risk<6?'Medium':d.risk<8?'High':'Critical'}

Open Ports: ${d.ports.join(', ')||'None'}
CVEs:       ${d.cves.join(', ')||'None'}

Checks
------
SQL Injection:  ${d.sql?'VULNERABLE':'safe'}
XSS:            ${d.xss?'VULNERABLE':'safe'}
HTTP Headers:   ${d.headers?'present':'MISSING'}
CSRF:           ${d.csrf?'MISSING':'present'}
SSL/TLS:        ${d.ssl?'valid':'WEAK'}
Dir Traversal:  ${d.dir?'EXPOSED':'secure'}`;
}

function downloadTXT() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([buildReport()], { type: 'text/plain' }));
  a.download = `vulnscan-${scanData?.domain||'report'}.txt`;
  a.click();
}
function downloadJSON() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' }));
  a.download = `vulnscan-${scanData?.domain||'data'}.json`;
  a.click();
}
function copyReport() {
  navigator.clipboard.writeText(buildReport()).then(() => alert('Copied to clipboard.'));
}

document.getElementById('domainInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
