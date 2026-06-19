const crypto = require('crypto');
const https = require('https');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
const GITHUB_REPO    = process.env.GITHUB_REPO   || 'obdcgit/ong';
const GITHUB_BRANCH  = process.env.GITHUB_BRANCH || 'main';

// ── Token helpers ──────────────────────────────────────────────
function makeToken() {
  const ts  = Date.now().toString();
  const sig = crypto.createHmac('sha256', ADMIN_PASSWORD).update(ts).digest('hex');
  return Buffer.from(ts + ':' + sig).toString('base64url');
}

function validateToken(token) {
  if (!token) return false;
  try {
    const raw = Buffer.from(token, 'base64url').toString();
    const sep = raw.indexOf(':');
    const ts  = raw.slice(0, sep);
    const sig = raw.slice(sep + 1);
    if (Date.now() - parseInt(ts, 10) > 86_400_000) return false; // 24 h
    const expected = crypto.createHmac('sha256', ADMIN_PASSWORD).update(ts).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// ── GitHub API helper ──────────────────────────────────────────
function ghRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        Authorization:  'token ' + GITHUB_TOKEN,
        'User-Agent':   'OBDC-CMS/1.0',
        Accept:         'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end',  () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function ghGetFile(filePath) {
  const r = await ghRequest('GET', `/repos/${GITHUB_REPO}/contents/${filePath}?ref=${GITHUB_BRANCH}`);
  if (r.status !== 200) return null;
  const content = Buffer.from(r.body.content.replace(/\n/g, ''), 'base64').toString('utf8');
  return { json: JSON.parse(content), sha: r.body.sha };
}

async function ghSaveFile(filePath, content, sha, msg) {
  return ghRequest('PUT', `/repos/${GITHUB_REPO}/contents/${filePath}`, {
    message: msg || 'CMS: update ' + filePath,
    content: Buffer.from(JSON.stringify(content, null, 2)).toString('base64'),
    branch:  GITHUB_BRANCH,
    ...(sha ? { sha } : {})
  });
}

async function ghUploadBinary(filePath, base64Content, sha, msg) {
  return ghRequest('PUT', `/repos/${GITHUB_REPO}/contents/${filePath}`, {
    message: msg || 'CMS: upload ' + filePath,
    content: base64Content,
    branch:  GITHUB_BRANCH,
    ...(sha ? { sha } : {})
  });
}

// ── CORS headers ───────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// ── Vercel handler ─────────────────────────────────────────────
module.exports = async (req, res) => {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = req.body || {};
  const qs   = req.query || {};
  const action = body.action || qs.action;

  const send = (code, obj) => res.status(code).json(obj);

  // ── LOGIN ──
  if (action === 'login') {
    if (!ADMIN_PASSWORD) return send(500, { error: 'ADMIN_PASSWORD não configurado' });
    if (body.password !== ADMIN_PASSWORD) return send(401, { error: 'Senha incorreta' });
    return send(200, { token: makeToken() });
  }

  // ── AUTH CHECK ──
  const token = body.token || qs.token;
  if (!validateToken(token)) return send(401, { error: 'Sessão expirada. Faça login novamente.' });

  if (!GITHUB_TOKEN) return send(500, { error: 'GITHUB_TOKEN não configurado' });

  // ── GET CONTENT ──
  if (action === 'getContent') {
    const file = body.file || qs.file;
    if (!['videos','radio','jornal','settings','gallery'].includes(file)) return send(400, { error: 'Arquivo inválido' });
    const result = await ghGetFile(`data/${file}.json`);
    if (!result) return send(404, { error: 'Arquivo não encontrado' });
    return send(200, result);
  }

  // ── SAVE CONTENT ──
  if (action === 'saveContent') {
    const { file, content, sha } = body;
    if (!['videos','radio','jornal','settings','gallery'].includes(file)) return send(400, { error: 'Arquivo inválido' });
    const r = await ghSaveFile(`data/${file}.json`, content, sha);
    if (r.status !== 200 && r.status !== 201) return send(500, { error: 'Erro ao salvar', detail: r.body?.message });
    return send(200, { success: true, sha: r.body.content?.sha });
  }

  // ── UPLOAD FILE (MP3 / imagem) ──
  if (action === 'uploadFile') {
    const { filePath, content: b64, sha } = body;
    if (!filePath || !b64) return send(400, { error: 'Dados inválidos' });
    const allowed = ['audio/', 'images/jornal/', 'images/galeria/', 'images/sobre/'];
    if (!allowed.some(p => filePath.startsWith(p))) return send(403, { error: 'Caminho não permitido' });
    const r = await ghUploadBinary(filePath, b64, sha);
    if (r.status !== 200 && r.status !== 201) return send(500, { error: 'Erro ao fazer upload', detail: r.body?.message });
    return send(200, { success: true, url: '/' + filePath, sha: r.body.content?.sha });
  }

  return send(400, { error: 'Ação desconhecida: ' + action });
};
