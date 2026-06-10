// SaLax R2 Worker v4 — Fixed SignatureDoesNotMatch
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

    try {
      const token = (req.headers.get('Authorization') || '').replace('Bearer ', '').trim();
      if (!token) return jres({ error: 'Unauthorized' }, 401, cors);
      const { user, error: authErr } = await verifyToken(env, token);
      if (authErr || !user) return jres({ error: 'Unauthorized' }, 401, cors);
      const uid = user.id;

      // PUT /upload/:key
      if (req.method === 'PUT' && path.startsWith('/upload/')) {
        const key = decodeURIComponent(path.slice(8));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const limitBytes = parseInt(req.headers.get('X-R2-Limit') || '0');
        if (limitBytes <= 0) return jres({ error: 'X-R2-Limit required' }, 400, cors);
        const bucket = await getBucket(env, bucketId, uid);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        if (!bucket.secret_key) return jres({ error: 'Secret key kosong' }, 500, cors);
        // Trim whitespace/newline dari secret key
        bucket.secret_key = bucket.secret_key.trim();
        bucket.access_key = bucket.access_key.trim();
        const body = await req.arrayBuffer();
        const cap = await checkCap(env, uid, bucket.id, body.byteLength, Math.min(limitBytes, MAX_BUCKET_BYTES));
        if (!cap.ok) return jres({ error: cap.msg }, 413, cors);
        // Gunakan content-type yang diterima dari request
        const ct = req.headers.get('Content-Type') || 'application/octet-stream';
        await r2Put(bucket, key, body, ct);
        return jres({ ok: true, key }, 200, cors);
      }

      // GET /file/:key
      if (req.method === 'GET' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucket(env, bucketId, uid) : await findBucket(env, uid, key);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        const res = await r2Get(bucket, key);
        if (!res.ok) return jres({ error: 'File tidak ditemukan' }, 404, cors);
        const h = new Headers(cors);
        h.set('Content-Type', res.headers.get('Content-Type') || 'application/octet-stream');
        h.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(key.split('/').pop())}`);
        return new Response(res.body, { status: 200, headers: h });
      }

      // DELETE /file/:key
      if (req.method === 'DELETE' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucket(env, bucketId, uid) : await findBucket(env, uid, key);
        if (bucket) await r2Del(bucket, key).catch(() => {});
        return jres({ ok: true }, 200, cors);
      }

      return jres({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error(e.message);
      return jres({ error: e.message }, 500, cors);
    }
  }
};

function jres(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}

async function verifyToken(env, token) {
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: { Authorization: `Bearer ${token}`, apikey: env.SUPABASE_KEY }
  });
  if (!res.ok) return { error: 'invalid token' };
  return { user: await res.json() };
}

async function getBucket(env, id, uid) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/r2_buckets?id=eq.${id}&user_id=eq.${uid}&select=*`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } }
  );
  const d = await res.json();
  return Array.isArray(d) && d.length ? d[0] : null;
}

async function findBucket(env, uid, r2Key) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&r2_key=eq.${encodeURIComponent(r2Key)}&select=storage_bucket_id`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } }
  );
  const d = await res.json();
  if (!Array.isArray(d) || !d[0]?.storage_bucket_id) return null;
  return getBucket(env, d[0].storage_bucket_id, uid);
}

async function checkCap(env, uid, bucketId, incoming, limit) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&storage_bucket_id=eq.${bucketId}&select=ukuran_file`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } }
  );
  const d = await res.json();
  const used = Array.isArray(d) ? d.reduce((a, x) => a + (x.ukuran_file || 0), 0) : 0;
  const eff = Math.min(limit, MAX_BUCKET_BYTES);
  if (used + incoming > eff) return { ok: false, msg: `Storage penuh (${fmt(used)} / ${fmt(eff)})` };
  return { ok: true };
}

// ── R2 operations ──────────────────────────────────────────────────

// AWS S3 strict URI encode - encode semua kecuali unreserved chars
// encodeURIComponent tidak encode: ! ' ( ) * ~ tapi AWS mengharuskan encode
function awsEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!'()*~]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function r2Url(b, key) {
  const encodedKey = key.split('/').map(s => awsEncode(s)).join('/');
  return `https://${b.account_id}.r2.cloudflarestorage.com/${b.bucket}/${encodedKey}`;
}

async function r2Put(b, key, body, ct) {
  const url = r2Url(b, key);
  const h = await signV4('PUT', url, b.access_key, b.secret_key, body, ct);
  const res = await fetch(url, { method: 'PUT', headers: h, body });
  if (!res.ok) throw new Error(`R2 PUT ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

async function r2Get(b, key) {
  const url = r2Url(b, key);
  const h = await signV4('GET', url, b.access_key, b.secret_key, null, null);
  return fetch(url, { method: 'GET', headers: h });
}

async function r2Del(b, key) {
  const url = r2Url(b, key);
  const h = await signV4('DELETE', url, b.access_key, b.secret_key, null, null);
  return fetch(url, { method: 'DELETE', headers: h });
}

// ── AWS Signature V4 ──────────────────────────────────────────────

async function signV4(method, urlStr, accessKey, secretKey, body, contentType) {
  const u = new URL(urlStr);
  const now = new Date();

  // Format tanggal dengan benar
  const pad = n => String(n).padStart(2, '0');
  const ymd = `${now.getUTCFullYear()}${pad(now.getUTCMonth()+1)}${pad(now.getUTCDate())}`;
  const amzDate = `${ymd}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;

  // Hash body
  const bodyBuf = (body instanceof ArrayBuffer && body.byteLength > 0) ? body : null;
  const bodyHash = bodyBuf
    ? hex(await sha256(bodyBuf))
    : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  // Bangun headers yang akan di-sign
  // PENTING: hanya sign host, x-amz-content-sha256, x-amz-date
  // content-type TIDAK di-sign untuk menghindari mismatch
  const signHdrs = {
    'host': u.host,
    'x-amz-content-sha256': bodyHash,
    'x-amz-date': amzDate,
  };

  const sortedKeys = Object.keys(signHdrs).sort();
  const canonHdrs = sortedKeys.map(k => `${k}:${signHdrs[k]}\n`).join('');
  const signedHdrsStr = sortedKeys.join(';');

  // Canonical URI - re-encode pakai AWS strict encoding
  // Decode dulu (URL constructor mungkin encode berbeda) lalu encode ulang dengan AWS rules
  const canonUri = u.pathname.split('/').map(seg => {
    const decoded = decodeURIComponent(seg);
    return encodeURIComponent(decoded)
      .replace(/[!'()*~]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  }).join('/');

  // Canonical request
  const canonReq = [method, canonUri, '', canonHdrs, signedHdrsStr, bodyHash].join('\n');

  // Credential scope
  const region = 'auto';
  const service = 's3';
  const scope = `${ymd}/${region}/${service}/aws4_request`;

  // String to sign
  const strToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    hex(await sha256(str2buf(canonReq)))
  ].join('\n');

  // Derive signing key
  const kDate    = await hmacBuf(str2buf('AWS4' + secretKey.trim()), ymd);
  const kRegion  = await hmacBuf(kDate, region);
  const kService = await hmacBuf(kRegion, service);
  const kSign    = await hmacBuf(kService, 'aws4_request');
  const sig      = hex(await hmacBuf(kSign, strToSign));

  // Return headers untuk fetch
  const result = {
    ...signHdrs,
    'authorization': `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope},SignedHeaders=${signedHdrsStr},Signature=${sig}`,
  };

  // Tambah content-type ke request tapi TIDAK di-sign
  if (contentType) result['content-type'] = contentType;

  return result;
}

// Crypto helpers
function str2buf(s) { return new TextEncoder().encode(s); }
async function sha256(data) {
  return crypto.subtle.digest('SHA-256', data instanceof ArrayBuffer ? data : str2buf(data));
}
async function hmacBuf(keyBuf, msg) {
  // Pastikan keyBuf selalu ArrayBuffer murni
  let rawKey;
  if (keyBuf instanceof ArrayBuffer) {
    rawKey = keyBuf;
  } else if (ArrayBuffer.isView(keyBuf)) {
    // Uint8Array atau TypedArray lain - ambil buffer dengan offset yang benar
    rawKey = keyBuf.buffer.slice(keyBuf.byteOffset, keyBuf.byteOffset + keyBuf.byteLength);
  } else {
    rawKey = keyBuf;
  }
  const k = await crypto.subtle.importKey(
    'raw', rawKey,
    { name: 'HMAC', hash: { name: 'SHA-256' } },
    false, ['sign']
  );
  const msgBuf = typeof msg === 'string' ? str2buf(msg) : msg;
  return crypto.subtle.sign('HMAC', k, msgBuf);
}
function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function fmt(bytes) {
  const u = ['B','KB','MB','GB']; let i = 0;
  while (bytes >= 1024 && i < 3) { bytes /= 1024; i++; }
  return bytes.toFixed(i ? 1 : 0) + ' ' + u[i];
}
