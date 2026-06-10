// SaLax R2 Worker — pakai fetch dengan presigned URL dari AWS SDK approach
// Tapi karena Worker tidak bisa import npm, kita pakai fetch langsung ke R2
// dengan token yang di-generate via Supabase Edge Function
// 
// SOLUSI: Gunakan R2 Public URL atau pakai Cloudflare R2 Binding
// Tapi karena kita multi-bucket dari Supabase, pakai S3 API dengan signing yang benar

const MAX_BUCKET_BYTES = 9 * 1024 * 1024 * 1024;

export default {
  async fetch(req, env) {
    const origin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Bucket-Id,X-R2-Limit',
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

      if (req.method === 'PUT' && path.startsWith('/upload/')) {
        const key = decodeURIComponent(path.slice(8));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const limitBytes = parseInt(req.headers.get('X-R2-Limit') || '0');
        if (limitBytes <= 0) return jres({ error: 'X-R2-Limit required' }, 400, cors);
        const bucket = await getBucket(env, bucketId, uid);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        if (!bucket.secret_key) return jres({ error: 'Secret key kosong' }, 500, cors);
        const body = await req.arrayBuffer();
        const cap = await checkCap(env, uid, bucket.id, body.byteLength, Math.min(limitBytes, MAX_BUCKET_BYTES));
        if (!cap.ok) return jres({ error: cap.msg }, 413, cors);
        const ct = req.headers.get('Content-Type') || 'application/octet-stream';
        await r2Put(bucket, key, body, ct);
        return jres({ ok: true, key }, 200, cors);
      }

      if (req.method === 'GET' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        // Admin boleh akses file user lain; user biasa hanya filenya sendiri
        if (!key.startsWith(uid + '/')) {
          const admin = await isUserAdmin(env, uid);
          if (!admin) return jres({ error: 'Forbidden' }, 403, cors);
        }
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

      if (req.method === 'DELETE' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!key.startsWith(uid + '/')) {
          const admin = await isUserAdmin(env, uid);
          if (!admin) return jres({ error: 'Forbidden' }, 403, cors);
        }
        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucket(env, bucketId, uid) : await findBucket(env, uid, key);
        if (bucket) await r2Del(bucket, key).catch(() => {});
        return jres({ ok: true }, 200, cors);
      }

      return jres({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error(e.message, e.stack);
      return jres({ error: e.message }, 500, cors);
    }
  }
};

function jres(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...cors }
  });
}

async function verifyToken(env, token) {
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: { Authorization: `Bearer ${token}`, apikey: env.SUPABASE_KEY }
  });
  if (!res.ok) return { error: 'invalid token' };
  return { user: await res.json() };
}

async function isUserAdmin(env, uid) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/profiles?id=eq.${uid}&select=role`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } }
  );
  const d = await res.json();
  return Array.isArray(d) && d[0]?.role === 'admin';
}

async function getBucket(env, id, uid) {
  // Bucket = resource bersama (dibuat admin, dipakai semua user)
  // TIDAK filter user_id — cukup ambil bucket by id.
  // Isolasi file per-user dijaga lewat prefix key (uid/...) di route handler.
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/r2_buckets?id=eq.${id}&select=*`,
    { headers: { apikey: k, Authorization: `Bearer ${k}` } }
  );
  const d = await res.json();
  return Array.isArray(d) && d.length ? d[0] : null;
}

async function findBucket(env, uid, r2Key) {
  const k = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  // Cari dokumen by r2_key saja (service key bypass RLS)
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?r2_key=eq.${encodeURIComponent(r2Key)}&select=storage_bucket_id`,
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
  if (used + incoming > eff) return { ok: false, msg: `Storage penuh (${fmt(used)}/${fmt(eff)})` };
  return { ok: true };
}

// ── R2 S3 operations ─────────────────────────────────────────────

// Virtual-hosted endpoint (yang AWS SDK pakai)
const makeUrl = (b, key) =>
  `https://${b.bucket}.${b.account_id}.r2.cloudflarestorage.com/${key.split('/').map(s => encodeURIComponent(s)).join('/')}`;

async function r2Put(b, key, body, ct) {
  const url = makeUrl(b, key);
  const h = await sign('PUT', url, b.access_key.trim(), b.secret_key.trim(), body, ct);
  const res = await fetch(url, { method: 'PUT', headers: h, body });
  if (!res.ok) throw new Error(`R2 PUT ${res.status}: ${(await res.text()).slice(0,300)}`);
}

async function r2Get(b, key) {
  const url = makeUrl(b, key);
  const h = await sign('GET', url, b.access_key.trim(), b.secret_key.trim(), null, null);
  return fetch(url, { method: 'GET', headers: h });
}

async function r2Del(b, key) {
  const url = makeUrl(b, key);
  const h = await sign('DELETE', url, b.access_key.trim(), b.secret_key.trim(), null, null);
  return fetch(url, { method: 'DELETE', headers: h });
}

// ── AWS Signature V4 ──────────────────────────────────────────────
// Referensi: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

async function sign(method, urlStr, accessKey, secretKey, body, contentType) {
  const u = new URL(urlStr);

  // Timestamp
  const now = new Date();
  const pad2 = n => n.toString().padStart(2, '0');
  const YYYYMMDD = `${now.getUTCFullYear()}${pad2(now.getUTCMonth()+1)}${pad2(now.getUTCDate())}`;
  const HHMMSS   = `${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}`;
  const datetime = `${YYYYMMDD}T${HHMMSS}Z`;

  // Payload hash
  const payloadHash = body && body.byteLength > 0
    ? toHex(await digest(body))
    : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  // Headers to include in signature (sorted)
  const signHeaders = {
    'host': u.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': datetime,
  };

  const sortedNames = Object.keys(signHeaders).sort();
  const canonicalHeaders = sortedNames.map(n => `${n}:${signHeaders[n]}\n`).join('');
  const signedHeaderNames = sortedNames.join(';');

  // Canonical URI: setiap path segment di-encode kecuali /
  const canonicalUri = u.pathname === '/' ? '/' :
    '/' + u.pathname.split('/').filter(Boolean).map(seg => rfcEncode(seg)).join('/');

  // Canonical request
  const canonReq = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaderNames}\n${payloadHash}`;

  // Credential scope
  const scope = `${YYYYMMDD}/auto/s3/aws4_request`;

  // String to sign
  const strToSign = `AWS4-HMAC-SHA256\n${datetime}\n${scope}\n${toHex(await digest(strToBytes(canonReq)))}`;

  // Signing key
  const kDate    = await hmac(strToBytes(`AWS4${secretKey}`), YYYYMMDD);
  const kRegion  = await hmac(kDate, 'auto');
  const kService = await hmac(kRegion, 's3');
  const kSigning = await hmac(kService, 'aws4_request');
  const signature = toHex(await hmac(kSigning, strToSign));

  // Build final headers
  const headers = {
    ...signHeaders,
    'authorization': `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope},SignedHeaders=${signedHeaderNames},Signature=${signature}`,
  };
  if (contentType) headers['content-type'] = contentType;
  return headers;
}

// RFC 3986 unreserved chars: A-Z a-z 0-9 - _ . ~
// Everything else must be percent-encoded
function rfcEncode(str) {
  return Array.from(new TextEncoder().encode(str))
    .map(byte => {
      const ch = String.fromCharCode(byte);
      if (/[A-Za-z0-9\-_.~]/.test(ch)) return ch;
      return '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }).join('');
}

function strToBytes(s) { return new TextEncoder().encode(s); }
async function digest(data) {
  const buf = data instanceof ArrayBuffer ? data : (ArrayBuffer.isView(data) ? data.buffer : strToBytes(data));
  return crypto.subtle.digest('SHA-256', buf);
}
async function hmac(key, data) {
  const keyBuf = key instanceof ArrayBuffer ? key : (ArrayBuffer.isView(key) ? key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) : key);
  const k = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const msgBuf = typeof data === 'string' ? strToBytes(data) : (data instanceof ArrayBuffer ? data : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  return crypto.subtle.sign('HMAC', k, msgBuf);
}
function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function fmt(b) {
  const u = ['B','KB','MB','GB']; let i = 0;
  while (b >= 1024 && i < 3) { b /= 1024; i++; }
  return b.toFixed(i ? 1 : 0) + ' ' + u[i];
}
