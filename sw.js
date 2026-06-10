// SaLax Service Worker
const CACHE = 'salax-v1';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(clients.claim());
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  // Jangan cache request ke Supabase/Worker API
  const url = e.request.url;
  if (url.includes('supabase.co') || url.includes('workers.dev') || url.includes('googleapis.com') || url.includes('deepseek.com')) {
    return; // biarkan network handle
  }
  e.respondWith(
    fetch(e.request).then(res => {
      const clone = res.clone();
      caches.open(CACHE).then(c => c.put(e.request, clone)).catch(() => {});
      return res;
    }).catch(() => caches.match(e.request))
  );
});
