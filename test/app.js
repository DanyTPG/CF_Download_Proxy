document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('urlInput');
  const checkBtn = document.getElementById('checkBtn');
  const status = document.getElementById('status');
  const results = document.getElementById('results');

  function formatBytes(bytes) {
    if (!bytes || isNaN(bytes)) return null;
    const b = parseInt(bytes, 10);
    if (b === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return `${(b / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`;
  }

  function startCheck(rawUrl) {
    rawUrl = rawUrl.trim();
    if (!rawUrl) return;

    urlInput.value = rawUrl;

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `https://${rawUrl}`);
    } catch {
      status.textContent = 'Invalid URL';
      return;
    }

    const host = parsedUrl.hostname;
    const match = host.match(/^[^.]+\.(.+)$/);
    if (!match) {
      status.textContent = 'Could not parse domain from URL';
      return;
    }
    const baseDomain = match[1];

    checkBtn.disabled = true;
    status.innerHTML = '<span class="spinner"></span>Checking edge endpoints...';
    results.innerHTML = '';

    const edges = Array.from({ length: 99 }, (_, i) => i + 1);
    const CONCURRENCY = 15;
    let idx = 0;

    async function probe(i) {
      const name = `edge${String(i).padStart(2, '0')}`;
      const edgeHost = `${name}.${baseDomain}`;
      const edgeUrl = new URL(parsedUrl.toString());
      edgeUrl.hostname = edgeHost;
      const targetUrl = edgeUrl.toString();

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      try {
        const res = await fetch(targetUrl, { method: 'HEAD', signal: controller.signal });
        clearTimeout(timer);
        const size = formatBytes(res.headers.get('content-length'));
        renderEdge({ i, name, host: edgeHost, url: targetUrl, status: res.status, size, error: null });
      } catch (err) {
        clearTimeout(timer);
        renderEdge({ i, name, host: edgeHost, url: targetUrl, status: null, size: null, error: err.name === 'AbortError' ? 'Timeout' : 'Network/CORS error' });
      }
    }

    const pool = Array.from({ length: CONCURRENCY }, async () => {
      while (idx < edges.length) {
        const current = edges[idx++];
        await probe(current);
      }
    });

    Promise.all(pool).then(() => {
      status.textContent = `Done checking edges for ${baseDomain}`;
      checkBtn.disabled = false;
    });
  }

  checkBtn.addEventListener('click', () => {
    startCheck(urlInput.value);
  });

  function renderEdge(event) {
    if (document.getElementById(`edge-${event.name}`)) return;
    const isUp = event.error === null && event.status !== null;
    const card = document.createElement('div');
    card.id = `edge-${event.name}`;
    card.className = `edge-card ${isUp ? 'border-up' : 'border-down'}`;
    card.style.order = isUp ? event.i : 1000 + event.i;

    const statusText = isUp
      ? `${event.status} OK${event.size ? ` • ${event.size}` : ''}`
      : (event.error || 'Failed');

    card.innerHTML = `
      <div>
        <div class="edge-name">${event.name}</div>
        <div class="edge-host">${event.host}</div>
      </div>
      <div class="edge-actions">
        <div class="${isUp ? 'edge-status-up' : 'edge-status-down'}">${statusText}</div>
        <button class="copy-btn" data-url="${event.url}">Copy URL</button>
      </div>`;

    card.querySelector('.copy-btn').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      await navigator.clipboard.writeText(btn.dataset.url);
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy URL'; }, 1500);
    });

    results.appendChild(card);
  }

  // Auto-start from query param (?url=...) or path suffix (/test/<url>)
  const searchParams = new URLSearchParams(window.location.search);
  const queryUrl = searchParams.get('url');

  const rawPath = window.location.pathname.replace(/^\/test\/?/, '');
  if (rawPath && !rawPath.endsWith('.html') && !rawPath.endsWith('.js') && !rawPath.endsWith('.css')) {
    const fullPathUrl = rawPath + window.location.search + window.location.hash;
    startCheck(fullPathUrl);
  } else if (queryUrl) {
    startCheck(queryUrl);
  }
});
