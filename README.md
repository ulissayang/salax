# SaLax — Supabase Keep-Alive

GitHub Action ini menjaga project Supabase free tier Anda tetap aktif dengan mengirim
ping otomatis setiap 3 hari sekali. Supabase free tier akan di-pause jika tidak ada
aktivitas selama 7 hari, jadi ping tiap 3 hari memastikan project Anda tidak pernah pause.

## Cara Setup

1. **Buat repository GitHub baru** (boleh private), misal `salax-keepalive`

2. **Upload folder ini** ke repository — pastikan struktur folder:
   ```
   .github/workflows/supabase-keepalive.yml
   README.md
   ```

3. **Tambahkan Secrets** di repository:
   - Buka repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**
   - Tambah 2 secret:

   | Nama Secret | Nilai |
   |---|---|
   | `SUPABASE_URL` | `https://oxttycjpgjylkjwhocuv.supabase.co` |
   | `SUPABASE_ANON_KEY` | anon key Anda (eyJ...) |

4. **Aktifkan Actions**:
   - Buka tab **Actions** di repo → klik **"I understand my workflows, enable them"**

5. **Test manual** (opsional):
   - Tab Actions → pilih "Supabase Keep-Alive" → **Run workflow**

## Verifikasi

Setelah berjalan, Anda bisa lihat log di tab **Actions**. Status hijau ✓ berarti
ping berhasil dan Supabase Anda aman dari pause.

## Catatan

- Cron `0 0 */3 * *` = setiap 3 hari pada jam 00:00 UTC (07:00 WIB / 08:00 WITA)
- GitHub Actions gratis untuk repo publik & private (2000 menit/bulan free tier)
- Ping ini sangat ringan (hanya 1 request), tidak akan menghabiskan kuota
