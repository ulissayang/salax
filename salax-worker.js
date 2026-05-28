// ═══════════════════════════════════════════════════════════════
//  SaLax R2 Worker — Multi-Bucket Handler
//  Deploy: wrangler deploy
//  Env vars: SUPABASE_URL, SUPABASE_KEY, SUPABASE_SERVICE_KEY, ALLOWED_ORIGIN
// ═══════════════════════════════════════════════════════════════

const MAX_BUCKET_BYTES = 9 * 1024 * 1024 * 1024; // 9 GB hard cap

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Bucket-Id,X-R2-Limit',
    };

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    const path = url.pathname;

    try {
      // ── Auth ──────────────────────────────────────────────────
      const auth = req.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '').trim();
      if (!token) return jres({ error: 'Unauthorized' }, 401, cors);

      const { user, error: authErr } = await verifyToken(env, token);
      if (authErr || !user) return jres({ error: 'Unauthorized' }, 401, cors);
      const uid = user.id;

      // ── Route: PUT /upload/:key ────────────────────────────────
      if (req.method === 'PUT' && path.startsWith('/upload/')) {
        const key = decodeURIComponent(path.replace('/upload/', ''));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const limitOverride = parseInt(req.headers.get('X-R2-Limit') || '0');
        if (limitOverride <= 0) return jres({ error: 'X-R2-Limit wajib dikirim' }, 400, cors);

        // Get bucket config from Supabase
        const bucket = await getBucketConfig(env, bucketId, uid);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan atau tidak memiliki akses' }, 404, cors);

        const body = await req.arrayBuffer();
        const incoming = body.byteLength;

        // Check storage capacity
        const cap = await checkCapacity(env, uid, bucket.id, incoming, Math.min(limitOverride, MAX_BUCKET_BYTES));
        if (!cap.ok) return jres({ error: cap.msg }, 413, cors);

        // Upload to R2
        await putR2(bucket, key, body, req.headers.get('Content-Type') || 'application/octet-stream');
        return jres({ ok: true, key }, 200, cors);
      }

      // ── Route: GET /file/:key ──────────────────────────────────
      if (req.method === 'GET' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.replace('/file/', ''));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        let bucket;
        if (bucketId) {
          bucket = await getBucketConfig(env, bucketId, uid);
        } else {
          // Try to find bucket from dokumen table
          bucket = await findBucketByKey(env, uid, key);
        }
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);

        const obj = await getR2(bucket, key);
        if (!obj) return jres({ error: 'File tidak ditemukan' }, 404, cors);

        const headers = new Headers(cors);
        headers.set('Content-Type', obj.httpMetadata?.contentType || 'application/octet-stream');
        headers.set('Content-Disposition', `attachment; filename="${key.split('/').pop()}"`);
        if (obj.size) headers.set('Content-Length', String(obj.size));
        return new Response(obj.body, { status: 200, headers });
      }

      // ── Route: DELETE /file/:key ───────────────────────────────
      if (req.method === 'DELETE' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.replace('/file/', ''));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId ? await getBucketConfig(env, bucketId, uid) : await findBucketByKey(env, uid, key);
        if (bucket) {
          await deleteR2(bucket, key).catch(() => {});
        }
        return jres({ ok: true }, 200, cors);
      }

      return jres({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error('Worker error:', e);
      return jres({ error: e.message || 'Internal server error' }, 500, cors);
    }
  }
};

// ── Helpers ─────────────────────────────────────────────────────

function jres(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}

async function verifyToken(env, token) {
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': env.SUPABASE_KEY }
  });
  if (!res.ok) return { error: 'Invalid token' };
  const user = await res.json();
  return { user };
}

async function getBucketConfig(env, bucketId, uid) {
  const svcKey = (env.SUPABASE_SERVICE_KEY || '').trim() || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/r2_buckets?id=eq.${bucketId}&user_id=eq.${uid}&select=*`,
    { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}` } }
  );
  const data = await res.json();
  return data?.[0] || null;
}

async function findBucketByKey(env, uid, r2Key) {
  const svcKey = (env.SUPABASE_SERVICE_KEY || '').trim() || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&r2_key=eq.${encodeURIComponent(r2Key)}&select=storage_bucket_id`,
    { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}` } }
  );
  const data = await res.json();
  if (!data?.[0]?.storage_bucket_id) return null;
  return getBucketConfig(env, data[0].storage_bucket_id, uid);
}

async function checkCapacity(env, uid, bucketId, incoming, limit) {
  const svcKey = (env.SUPABASE_SERVICE_KEY || '').trim() || env.SUPABASE_KEY;
  // Query total size in this bucket
  let from = 0, total = 0;
  while (true) {
    const res = await fetch(
      `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&storage_bucket_id=eq.${bucketId}&select=ukuran_file&limit=1000&offset=${from}`,
      { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}`, 'Prefer': 'count=exact' } }
    );
    const data = await res.json();
    if (!data || !data.length) break;
    total += data.reduce((a, d) => a + (d.ukuran_file || 0), 0);
    if (data.length < 1000) break;
    from += 1000;
  }
  const effective = Math.min(limit, MAX_BUCKET_BYTES);
  if (total + incoming > effective) {
    return { ok: false, msg: `Storage penuh. Terpakai: ${fmtSz(total)}, Limit: ${fmtSz(effective)}, File: ${fmtSz(incoming)}` };
  }
  return { ok: true, used: total, limit: effective };
}

// ── R2 Operations using S3 API ───────────────────────────────────

function getS3Creds(bucket) {
  return {
    endpoint: `https://${bucket.account_id}.r2.cloudflarestorage.com`,
    accessKeyId: bucket.access_key,
    secretAccessKey: bucket.secret_key,
    bucketName: bucket.bucket,
  };
}

async function putR2(bkt, key, body, contentType) {
  const { endpoint, accessKeyId, secretAccessKey, bucketName } = getS3Creds(bkt);
  const url = `${endpoint}/${bucketName}/${key}`;
  const signedReq = await signS3Request('PUT', url, accessKeyId, secretAccessKey, bucketName, key, body, contentType);
  const res = await fetch(signedReq.url, { method: 'PUT', headers: signedReq.headers, body });
  if (!res.ok) throw new Error(`R2 PUT failed: ${res.status}`);
}

async function getR2(bkt, key) {
  const { endpoint, accessKeyId, secretAccessKey, bucketName } = getS3Creds(bkt);
  const url = `${endpoint}/${bucketName}/${key}`;
  const signedReq = await signS3Request('GET', url, accessKeyId, secretAccessKey, bucketName, key, null, '');
  return fetch(signedReq.url, { method: 'GET', headers: signedReq.headers });
}

async function deleteR2(bkt, key) {
  const { endpoint, accessKeyId, secretAccessKey, bucketName } = getS3Creds(bkt);
  const url = `${endpoint}/${bucketName}/${key}`;
  const signedReq = await signS3Request('DELETE', url, accessKeyId, secretAccessKey, bucketName, key, null, '');
  return fetch(signedReq.url, { method: 'DELETE', headers: signedReq.headers });
}

// AWS Signature V4
async function signS3Request(method, url, accessKeyId, secretKey, bucket, key, body, contentType) {
  const urlObj = new URL(url);
  const now = new Date();
  const date = now.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const dateShort = date.slice(0, 8);
  const region = 'auto';
  const service = 's3';

  const bodyHash = body
    ? await sha256Hex(body instanceof ArrayBuffer ? body : new TextEncoder().encode(body))
    : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const headers = {
    'host': urlObj.host,
    'x-amz-date': date,
    'x-amz-content-sha256': bodyHash,
  };
  if (contentType) headers['content-type'] = contentType;

  const sortedHeaders = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaders.map(k => `${k}:${headers[k]}`).join('\n') + '\n';
  const signedHeaders = sortedHeaders.join(';');
  const canonicalRequest = [method, urlObj.pathname, urlObj.search.replace('?',''), canonicalHeaders, signedHeaders, bodyHash].join('\n');

  const credScope = `${dateShort}/${region}/${service}/aws4_request`;
  const strToSign = `AWS4-HMAC-SHA256\n${date}\n${credScope}\n${await sha256Hex(new TextEncoder().encode(canonicalRequest))}`;

  const sigKey = await deriveSigningKey(secretKey, dateShort, region, service);
  const sig = await hmacHex(sigKey, strToSign);

  headers['authorization'] = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credScope},SignedHeaders=${signedHeaders},Signature=${sig}`;
  return { url, headers };
}

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest('SHA-256', data instanceof ArrayBuffer ? data : new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(key, msg) {
  const cryptoKey = typeof key === 'string'
    ? await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    : key;
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacRaw(key, msg) {
  const cryptoKey = typeof key === 'string'
    ? await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    : (key instanceof ArrayBuffer
      ? await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      : key);
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(msg));
}

async function deriveSigningKey(secret, date, region, service) {
  const k1 = await hmacRaw('AWS4' + secret, date);
  const k2 = await hmacRaw(k1, region);
  const k3 = await hmacRaw(k2, service);
  return hmacRaw(k3, 'aws4_request');
}

function fmtSz(bytes) {
  if (!bytes) return '0 B';
  const u = ['B','KB','MB','GB']; let i = 0;
  while (bytes >= 1024 && i < 3) { bytes /= 1024; i++; }
  return bytes.toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
}
