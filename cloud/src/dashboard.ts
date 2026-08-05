export const dashboardHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>ControlForge SOC</title>
  <style nonce="__CSP_NONCE__">
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background:#071018; color:#e8f1f5; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:radial-gradient(circle at 80% -10%,#123e45 0,transparent 38%),#071018; }
    header,main { width:min(1180px,calc(100% - 32px)); margin:auto; }
    header { display:flex; align-items:center; justify-content:space-between; padding:28px 0 18px; }
    h1 { margin:0; font-size:1.35rem; letter-spacing:.02em; } .mark { color:#52e1bd; }
    .status { color:#98aab4; font-size:.86rem; }
    .controls { display:flex; gap:12px; align-items:end; margin:24px 0; flex-wrap:wrap; }
    label { display:grid; gap:6px; color:#9fb2bd; font-size:.8rem; }
    input,button { border:1px solid #28414d; border-radius:9px; background:#0d1b24; color:#e8f1f5; padding:10px 12px; min-height:42px; }
    input { min-width:280px; } button { cursor:pointer; background:#123b3b; border-color:#28645b; font-weight:700; }
    button:hover { background:#18504c; }
    .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
    .card { padding:18px; border:1px solid #183440; border-radius:12px; background:rgba(11,25,34,.88); box-shadow:0 18px 60px rgba(0,0,0,.18); }
    .metric { font-size:2rem; font-weight:750; margin-top:8px; } .label { color:#8fa4af; font-size:.82rem; }
    section { margin:22px 0; } h2 { font-size:1rem; margin:0 0 12px; }
    table { width:100%; border-collapse:collapse; font-size:.88rem; }
    th,td { text-align:left; padding:11px 9px; border-bottom:1px solid #18323e; vertical-align:top; }
    th { color:#8fa4af; font-weight:600; } .critical { color:#ff7b82; } .high { color:#ffb36a; } .medium { color:#f5d56b; }
    .empty,.error { color:#91a5af; padding:18px 0; } .error { color:#ff969b; }
    @media(max-width:760px){ .grid{grid-template-columns:repeat(2,1fr)} input{min-width:0;width:100%} .controls{display:grid} }
  </style>
</head>
<body>
  <header><h1><span class="mark">ControlForge</span> Autonomous SOC</h1><div class="status" id="status">Not connected</div></header>
  <main>
    <div class="controls">
      <label>Tenant ID<input id="tenant" autocomplete="off" placeholder="tenant UUID"></label>
      <button id="load">Load secure dashboard</button>
    </div>
    <div class="grid" id="metrics"></div>
    <section class="card"><h2>Open cases</h2><div id="cases" class="empty">Choose a tenant to load cases.</div></section>
    <section class="card"><h2>Recent alerts</h2><div id="alerts" class="empty">Choose a tenant to load alerts.</div></section>
  </main>
  <script type="module" nonce="__CSP_NONCE__">
    const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
    const request = async (path, tenant) => {
      const response = await fetch(path, {headers:{'x-controlforge-tenant-id':tenant}});
      if (!response.ok) throw new Error('Request failed with HTTP ' + response.status);
      return response.json();
    };
    document.querySelector('#load').addEventListener('click', async () => {
      const tenant = document.querySelector('#tenant').value.trim();
      if (!tenant) return;
      localStorage.setItem('controlforgeTenant', tenant);
      document.querySelector('#status').textContent = 'Loading';
      try {
        const [summary, cases, alerts] = await Promise.all([
          request('/v1/dashboard/summary',tenant), request('/v1/cases?limit=20',tenant), request('/v1/alerts?limit=30',tenant)
        ]);
        document.querySelector('#metrics').innerHTML = [
          ['Events (24h)',summary.events_24h],['Alerts (24h)',summary.alerts_24h],['Critical open',summary.critical_open],['Open cases',summary.open_cases]
        ].map(([label,value]) => '<div class="card"><div class="label">'+escapeHtml(label)+'</div><div class="metric">'+escapeHtml(value)+'</div></div>').join('');
        document.querySelector('#cases').innerHTML = cases.length ? '<table><thead><tr><th>Priority</th><th>Case</th><th>Status</th><th>Updated</th></tr></thead><tbody>'+cases.map(item => '<tr><td class="'+escapeHtml(item.priority)+'">'+escapeHtml(item.priority)+'</td><td>'+escapeHtml(item.title)+'<br><span class="label">'+escapeHtml(item.case_id)+'</span></td><td>'+escapeHtml(item.status)+'</td><td>'+escapeHtml(item.updated_at)+'</td></tr>').join('')+'</tbody></table>' : '<div class="empty">No cases.</div>';
        document.querySelector('#alerts').innerHTML = alerts.length ? '<table><thead><tr><th>Severity</th><th>Detection</th><th>Actor</th><th>Time</th></tr></thead><tbody>'+alerts.map(item => '<tr><td class="'+escapeHtml(item.severity)+'">'+escapeHtml(item.severity)+'</td><td>'+escapeHtml(item.title)+'<br><span class="label">'+escapeHtml(item.rule_id)+'</span></td><td>'+escapeHtml(item.actor)+'</td><td>'+escapeHtml(item.created_at)+'</td></tr>').join('')+'</tbody></table>' : '<div class="empty">No alerts.</div>';
        document.querySelector('#status').textContent = 'Connected';
      } catch (error) {
        document.querySelector('#status').textContent = 'Access denied or unavailable';
        document.querySelector('#metrics').innerHTML = '<div class="error">'+escapeHtml(error.message)+'</div>';
      }
    });
    const saved = localStorage.getItem('controlforgeTenant'); if(saved) document.querySelector('#tenant').value=saved;
  </script>
</body>
</html>`;
