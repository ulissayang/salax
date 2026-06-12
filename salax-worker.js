// SaLax R2 Worker — signing dari SiPegawai (terbukti bekerja)
const MAX_BUCKET_BYTES = 9 * 1024 * 1024 * 1024;

export default {
  async fetch(req, env) {
    const origin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Bucket-Id,X-R2-Limit',
      'Access-Control-Max-Age': '86400',
    };
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    const path = url.pathname;

    if (path === '/version') return jres({ version: 'v11-storage-accurate', signing: 'signS3-path-style' }, 200, cors);

    // GET /storage?bucketId=xxx — usage akurat dari Supabase (service key, semua user)
    if (req.method === 'GET' && path === '/storage') {
      const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!token) return jres({ error: 'Unauthorized' }, 401, cors);
      const uRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${token}` } });
      if (!uRes.ok) return jres({ error: 'Unauthorized' }, 401, cors);
      const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
      // Ambil semua dokumen (paginasi) — service key bypass RLS
      const usageMap = {};
      let from = 0;
      while (true) {
        const r = await fetch(`${env.SUPABASE_URL}/rest/v1/dokumen?select=storage_bucket_id,ukuran_file`,
          { headers: { apikey: k, Authorization: `Bearer ${k}`, Range: `${from}-${from+999}`, 'Range-Unit': 'items' } });
        if (!r.ok) break;
        const rows = await r.json();
        if (!Array.isArray(rows) || !rows.length) break;
        rows.forEach(d => { const b = d.storage_bucket_id; if (b) usageMap[b] = (usageMap[b]||0) + (d.ukuran_file||0); });
        if (rows.length < 1000) break;
        from += 1000;
      }
      return jres({ usage: usageMap }, 200, cors);
    }

    // SELF-TEST tanpa login
    if (path === '/selftest') {
      const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
      const br = await fetch(`${env.SUPABASE_URL}/rest/v1/r2_buckets?select=*&limit=1`, { headers: { apikey: k, Authorization: `Bearer ${k}` } });
      const buckets = await br.json();
      if (!buckets.length) return jres({ error: 'tidak ada bucket' }, 404, cors);
      const b = buckets[0];
      const cfg = { accountId: b.account_id.trim(), accessKey: b.access_key.trim(), secretKey: b.secret_key.trim(), bucket: b.bucket.trim() };
      const testKey = '_selftest_' + Date.now() + '.txt';
      try {
        const s3url = r2url(cfg, testKey);
        const body = new TextEncoder().encode('hello').buffer;
        const hdrs = await signS3('PUT', s3url, body, 'text/plain', cfg);
        const r = await fetch(s3url, { method: 'PUT', headers: hdrs, body });
        if (r.ok) {
          // hapus file test
          const dh = await signS3('DELETE', s3url, null, '', cfg);
          await fetch(s3url, { method: 'DELETE', headers: dh }).catch(()=>{});
          return jres({ result: '✓ BERHASIL', message: 'Kredensial R2 VALID!' }, 200, cors);
        }
        return jres({ result: '✗ GAGAL', status: r.status, error: (await r.text()).slice(0,300) }, 200, cors);
      } catch (e) {
        return jres({ result: '✗ ERROR', error: e.message.slice(0,300) }, 200, cors);
      }
    }

    try {
      const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
      if (!token) return jres({ error: 'Unauthorized: token tidak ada' }, 401, cors);

      const uRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
        headers: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${token}` },
      });
      if (!uRes.ok) return jres({ error: 'Unauthorized: token tidak valid' }, 401, cors);
      const user = await uRes.json();
      const uid = user?.id;
      if (!uid) return jres({ error: 'Unauthorized' }, 401, cors);

      // Cek admin
      const pRes = await fetch(`${env.SUPABASE_URL}/rest/v1/profiles?id=eq.${uid}&select=role`,
        { headers: { apikey: env.SUPABASE_KEY, Authorization: `Bearer ${token}` } });
      const pData = pRes.ok ? await pRes.json() : [];
      const admin = pData?.[0]?.role === 'admin';

      // PUT /upload/:key
      if (req.method === 'PUT' && path.startsWith('/upload/')) {
        const key = decodeURIComponent(path.slice(8));
        if (!admin && !key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const limitBytes = parseInt(req.headers.get('X-R2-Limit') || '0');
        const bucket = await getBucket(env, bucketId);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        const cfg = bucketCfg(bucket);
        let body;
        try { body = await req.arrayBuffer(); } catch (e) { return jres({ error: 'Gagal baca body' }, 400, cors); }
        if (!body || body.byteLength === 0) return jres({ error: 'File kosong' }, 400, cors);
        // Cek kuota (total semua user)
        const cap = await checkCap(env, bucket.id, body.byteLength, Math.min(limitBytes || MAX_BUCKET_BYTES, MAX_BUCKET_BYTES));
        if (!cap.ok) return jres({ error: cap.msg }, 413, cors);
        const ct = req.headers.get('Content-Type') || 'application/octet-stream';
        const s3url = r2url(cfg, key);
        const hdrs = await signS3('PUT', s3url, body, ct, cfg);
        const r2Res = await fetch(s3url, { method: 'PUT', headers: hdrs, body });
        if (!r2Res.ok) {
          const t = await r2Res.text().catch(() => '');
          return jres({ error: `R2 upload gagal (${r2Res.status}): ${t.slice(0, 300)}` }, 502, cors);
        }
        return jres({ ok: true, key }, 200, cors);
      }

      // GET /file/:key
      if (req.method === 'GET' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!admin && !key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucket(env, bucketId) : await findBucket(env, key);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        const cfg = bucketCfg(bucket);
        const s3url = r2url(cfg, key);
        const hdrs = await signS3('GET', s3url, null, '', cfg);
        const r2Res = await fetch(s3url, { method: 'GET', headers: hdrs });
        if (!r2Res.ok) return jres({ error: 'File tidak ditemukan' }, 404, cors);
        const rh = new Headers(cors);
        rh.set('Content-Type', r2Res.headers.get('Content-Type') || 'application/octet-stream');
        const cl = r2Res.headers.get('Content-Length');
        if (cl) rh.set('Content-Length', cl);
        const rawName = key.split('/').pop() || 'file';
        const namePart = rawName.replace(/^\d+_/, '');
        rh.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(namePart)}`);
        return new Response(r2Res.body, { status: 200, headers: rh });
      }

      // DELETE /file/:key
      if (req.method === 'DELETE' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!admin && !key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucket(env, bucketId) : await findBucket(env, key);
        if (bucket) {
          const cfg = bucketCfg(bucket);
          const s3url = r2url(cfg, key);
          const hdrs = await signS3('DELETE', s3url, null, '', cfg);
          await fetch(s3url, { method: 'DELETE', headers: hdrs }).catch(() => {});
        }
        return jres({ ok: true }, 200, cors);
      }

      return jres({ error: 'Not found' }, 404, cors);
    } catch (e) {
      return jres({ error: e.message }, 500, cors);
    }
  }
};

function jres(data, status, cors) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...cors } });
}

function bucketCfg(b) {
  return { accountId: b.account_id.trim(), accessKey: b.access_key.trim(), secretKey: b.secret_key.trim(), bucket: b.bucket.trim() };
}
function r2url(cfg, key) {
  return `https://${cfg.accountId}.r2.cloudflarestorage.com/${cfg.bucket}/${key}`;
}

async function getBucket(env, id) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/r2_buckets?id=eq.${id}&select=*`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } });
  const d = await res.json();
  return Array.isArray(d) && d.length ? d[0] : null;
}
async function findBucket(env, r2Key) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/dokumen?r2_key=eq.${encodeURIComponent(r2Key)}&select=storage_bucket_id`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } });
  const d = await res.json();
  if (!Array.isArray(d) || !d[0]?.storage_bucket_id) return null;
  return getBucket(env, d[0].storage_bucket_id);
}
async function checkCap(env, bucketId, incoming, limit) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  // Paginasi penuh untuk akurasi (banyak dokumen)
  let used = 0, from = 0;
  while (true) {
    const res = await fetch(`${env.SUPABASE_URL}/rest/v1/dokumen?storage_bucket_id=eq.${bucketId}&select=ukuran_file`,
      { headers: { apikey: k, Authorization: `Bearer ${k}`, Range: `${from}-${from+999}`, 'Range-Unit': 'items' } });
    if (!res.ok) break;
    const d = await res.json();
    if (!Array.isArray(d) || !d.length) break;
    used += d.reduce((a, x) => a + (x.ukuran_file || 0), 0);
    if (d.length < 1000) break;
    from += 1000;
  }
  const eff = Math.min(limit, MAX_BUCKET_BYTES);
  if (used + incoming > eff) return { ok: false, msg: `Penyimpanan penuh (${fmt(used)} / ${fmt(eff)} terpakai)` };
  return { ok: true };
}

// ── AWS4 Signature (PERSIS dari SiPegawai yang BEKERJA) ──────────────
async function signS3(method, urlStr, body, contentType, cfg) {
  const u = new URL(urlStr);
  const now = new Date();
  const ds = now.toISOString().slice(0,10).replace(/-/g,'');
  const dts = now.toISOString().replace(/[-:]/g,'').slice(0,15) + 'Z';
  const EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  let bodyHash;
  if (!body || body.byteLength === 0 || body === '') bodyHash = EMPTY_HASH;
  else bodyHash = await sha256hex(body instanceof ArrayBuffer ? body : new TextEncoder().encode(body));
  const hmap = { 'host': u.host, 'x-amz-content-sha256': bodyHash, 'x-amz-date': dts };
  if (contentType && method === 'PUT') hmap['content-type'] = contentType;
  const sortedKeys = Object.keys(hmap).sort();
  const canonHeaders = sortedKeys.map(k => `${k}:${hmap[k]}`).join('\n') + '\n';
  const signedHeaders = sortedKeys.join(';');
  const canonReq = [method, u.pathname, '', canonHeaders, signedHeaders, bodyHash].join('\n');
  const scope = `${ds}/auto/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', dts, scope, await sha256hex(canonReq)].join('\n');
  let sk = await hmacB(`AWS4${cfg.secretKey}`, ds);
  sk = await hmacB(sk, 'auto');
  sk = await hmacB(sk, 's3');
  sk = await hmacB(sk, 'aws4_request');
  const sig = hex(await hmacB(sk, sts));
  return { ...hmap, Authorization: `AWS4-HMAC-SHA256 Credential=${cfg.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}` };
}
async function sha256hex(data) {
  const b = data instanceof ArrayBuffer ? data : typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', b)));
}
async function hmacB(key, data) {
  const kb = key instanceof Uint8Array ? key : new TextEncoder().encode(key);
  const ck = await crypto.subtle.importKey('raw', kb, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const db = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.sign('HMAC', ck, db));
}
function hex(arr) { return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join(''); }
function fmt(b) {
  const u = ['B','KB','MB','GB']; let i = 0;
  while (b >= 1024 && i < 3) { b /= 1024; i++; }
  return b.toFixed(i ? 1 : 0) + ' ' + u[i];
}
