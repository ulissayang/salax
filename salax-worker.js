// SaLax R2 Worker — Fixed AWS Signature V4
const MAX_BUCKET_BYTES = 9 * 1024 * 1024 * 1024;

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
      const auth = req.headers.get('Authorization') || '';
      const token = auth.replace('Bearer ', '').trim();
      if (!token) return jres({ error: 'Unauthorized' }, 401, cors);

      const { user, error: authErr } = await verifyToken(env, token);
      if (authErr || !user) return jres({ error: 'Unauthorized' }, 401, cors);
      const uid = user.id;

      // PUT /upload/:key
      if (req.method === 'PUT' && path.startsWith('/upload/')) {
        const key = decodeURIComponent(path.slice('/upload/'.length));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const limitOverride = parseInt(req.headers.get('X-R2-Limit') || '0');
        if (limitOverride <= 0) return jres({ error: 'X-R2-Limit wajib dikirim' }, 400, cors);

        const bucket = await getBucketConfig(env, bucketId, uid);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);
        if (!bucket.secret_key) return jres({ error: 'Secret key R2 kosong — edit bucket di Storage' }, 500, cors);

        const body = await req.arrayBuffer();
        const cap = await checkCapacity(env, uid, bucket.id, body.byteLength, Math.min(limitOverride, MAX_BUCKET_BYTES));
        if (!cap.ok) return jres({ error: cap.msg }, 413, cors);

        await putR2(bucket, key, body, req.headers.get('Content-Type') || 'application/octet-stream');
        return jres({ ok: true, key }, 200, cors);
      }

      // GET /file/:key
      if (req.method === 'GET' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice('/file/'.length));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId
          ? await getBucketConfig(env, bucketId, uid)
          : await findBucketByKey(env, uid, key);
        if (!bucket) return jres({ error: 'Bucket tidak ditemukan' }, 404, cors);

        const obj = await getR2(bucket, key);
        if (!obj || !obj.ok) return jres({ error: 'File tidak ditemukan' }, 404, cors);

        const headers = new Headers(cors);
        headers.set('Content-Type', obj.headers.get('Content-Type') || 'application/octet-stream');
        headers.set('Content-Disposition', `attachment; filename="${encodeURIComponent(key.split('/').pop())}"`);
        return new Response(obj.body, { status: 200, headers });
      }

      // DELETE /file/:key
      if (req.method === 'DELETE' && path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice('/file/'.length));
        if (!key.startsWith(uid + '/')) return jres({ error: 'Forbidden' }, 403, cors);

        const bucketId = req.headers.get('X-Bucket-Id') || '';
        const bucket = bucketId
          ? await getBucketConfig(env, bucketId, uid)
          : await findBucketByKey(env, uid, key);
        if (bucket) await deleteR2(bucket, key).catch(() => {});
        return jres({ ok: true }, 200, cors);
      }

      return jres({ error: 'Not found' }, 404, cors);

    } catch (e) {
      console.error('Worker error:', e.message);
      return jres({ error: e.message }, 500, cors);
    }
  }
};

// ── Helpers ──────────────────────────────────────────────────────

function jres(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors }
  });
}

async function verifyToken(env, token) {
  try {
    const res = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: { 'Authorization': `Bearer ${token}`, 'apikey': env.SUPABASE_KEY }
    });
    if (!res.ok) return { error: 'Token invalid' };
    const user = await res.json();
    return { user };
  } catch(e) {
    return { error: e.message };
  }
}

async function getBucketConfig(env, bucketId, uid) {
  const svcKey = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/r2_buckets?id=eq.${bucketId}&user_id=eq.${uid}&select=*`,
    { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}` } }
  );
  const data = await res.json();
  return Array.isArray(data) ? data[0] || null : null;
}

async function findBucketByKey(env, uid, r2Key) {
  const svcKey = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&r2_key=eq.${encodeURIComponent(r2Key)}&select=storage_bucket_id`,
    { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}` } }
  );
  const data = await res.json();
  if (!Array.isArray(data) || !data[0]?.storage_bucket_id) return null;
  return getBucketConfig(env, data[0].storage_bucket_id, uid);
}

async function checkCapacity(env, uid, bucketId, incoming, limit) {
  const svcKey = env.SUPABASE_SERVICE_KEY || env.SUPABASE_KEY;
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/dokumen?user_id=eq.${uid}&storage_bucket_id=eq.${bucketId}&select=ukuran_file`,
    { headers: { 'apikey': svcKey, 'Authorization': `Bearer ${svcKey}` } }
  );
  const data = await res.json();
  const total = Array.isArray(data) ? data.reduce((a, d) => a + (d.ukuran_file || 0), 0) : 0;
  const effective = Math.min(limit, MAX_BUCKET_BYTES);
  if (total + incoming > effective) {
    return { ok: false, msg: `Storage penuh. Terpakai: ${fmtSz(total)}, Limit: ${fmtSz(effective)}` };
  }
  return { ok: true };
}

// ── R2 S3 Operations ─────────────────────────────────────────────

async function putR2(bkt, key, body, contentType) {
  const url = `https://${bkt.account_id}.r2.cloudflarestorage.com/${bkt.bucket}/${key}`;
  const headers = await signRequest('PUT', url, bkt.access_key, bkt.secret_key, body, contentType);
  const res = await fetch(url, { method: 'PUT', headers, body });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`R2 PUT ${res.status}: ${txt.slice(0, 200)}`);
  }
}

async function getR2(bkt, key) {
  const url = `https://${bkt.account_id}.r2.cloudflarestorage.com/${bkt.bucket}/${key}`;
  const headers = await signRequest('GET', url, bkt.access_key, bkt.secret_key, null, '');
  return fetch(url, { method: 'GET', headers });
}

async function deleteR2(bkt, key) {
  const url = `https://${bkt.account_id}.r2.cloudflarestorage.com/${bkt.bucket}/${key}`;
  const headers = await signRequest('DELETE', url, bkt.access_key, bkt.secret_key, null, '');
  return fetch(url, { method: 'DELETE', headers });
}

// ── AWS Signature V4 — simplified & fixed ────────────────────────

async function signRequest(method, urlStr, accessKey, secretKey, body, contentType) {
  const u = new URL(urlStr);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);

  // Body hash
  let bodyHash;
  if (body && body.byteLength > 0) {
    const hashBuf = await crypto.subtle.digest('SHA-256', body);
    bodyHash = bufToHex(hashBuf);
  } else {
    bodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  }

  // Headers to sign
  const signedHeadersMap = {
    'host': u.host,
    'x-amz-content-sha256': bodyHash,
    'x-amz-date': amzDate,
  };
  if (contentType) signedHeadersMap['content-type'] = contentType;

  const sortedKeys = Object.keys(signedHeadersMap).sort();
  const canonicalHeaders = sortedKeys.map(k => `${k}:${signedHeadersMap[k]}`).join('\n') + '\n';
  const signedHeadersStr = sortedKeys.join(';');

  // Canonical request
  // S3 butuh URI-encode path (tapi tidak encode slash pemisah bucket/key)
  // pathname sudah ter-encode dari URL constructor, tapi perlu encode ulang karakter khusus
  const encodedPath = u.pathname.split('/').map(seg => 
    encodeURIComponent(decodeURIComponent(seg))
  ).join('/');
  
  const canonicalRequest = [
    method,
    encodedPath,
    '',  // query string
    canonicalHeaders,
    signedHeadersStr,
    bodyHash,
  ].join('\n');

  // String to sign
  const credScope = `${dateStamp}/auto/s3/aws4_request`;
  const canonicalHash = bufToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalRequest)));
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credScope}\n${canonicalHash}`;

  // Derive signing key — all steps using raw bytes
  const kDate    = await hmac(new TextEncoder().encode('AWS4' + secretKey), dateStamp);
  const kRegion  = await hmac(kDate, 'auto');
  const kService = await hmac(kRegion, 's3');
  const kSigning = await hmac(kService, 'aws4_request');
  const sigBuf   = await hmac(kSigning, stringToSign);
  const signature = bufToHex(sigBuf);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credScope},SignedHeaders=${signedHeadersStr},Signature=${signature}`;

  const result = { ...signedHeadersMap, 'authorization': authHeader };
  return result;
}

// hmac: key=ArrayBuffer|Uint8Array, msg=string → ArrayBuffer
async function hmac(key, msg) {
  const keyData = key instanceof ArrayBuffer ? key : key.buffer || key;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const msgBuf = typeof msg === 'string' ? new TextEncoder().encode(msg) : msg;
  return crypto.subtle.sign('HMAC', cryptoKey, msgBuf);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fmtSz(bytes) {
  if (!bytes) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < 3) { bytes /= 1024; i++; }
  return bytes.toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
}
