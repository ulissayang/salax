-- ═══════════════════════════════════════════════════════════════
-- SaLax Multi-User Setup — jalankan di Supabase SQL Editor
-- ═══════════════════════════════════════════════════════════════

-- 1. Tambah kolom role & username ke profiles (jika belum ada)
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES auth.users(id);
-- Simpan password plaintext agar admin bisa lihat (sesuai permintaan; hanya untuk sistem internal)
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS pwd_plain TEXT;

-- 2. Set user pertama (Anda) sebagai admin
-- GANTI dengan email Anda:
UPDATE profiles SET role='admin' 
WHERE id=(SELECT id FROM auth.users WHERE email='ulissayang10@gmail.com' LIMIT 1);

-- 3. RLS untuk profiles — admin lihat semua, user lihat diri sendiri
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select" ON profiles;
CREATE POLICY "profiles_select" ON profiles FOR SELECT TO authenticated
USING (
  id = auth.uid()
  OR EXISTS (SELECT 1 FROM profiles p WHERE p.id=auth.uid() AND p.role='admin')
);

DROP POLICY IF EXISTS "profiles_update" ON profiles;
CREATE POLICY "profiles_update" ON profiles FOR UPDATE TO authenticated
USING (
  id = auth.uid()
  OR EXISTS (SELECT 1 FROM profiles p WHERE p.id=auth.uid() AND p.role='admin')
);

DROP POLICY IF EXISTS "profiles_insert" ON profiles;
CREATE POLICY "profiles_insert" ON profiles FOR INSERT TO authenticated
WITH CHECK (true);

-- 4. RLS untuk dokumen — admin lihat semua, user lihat miliknya saja
ALTER TABLE dokumen ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "dokumen_all" ON dokumen;
DROP POLICY IF EXISTS "dokumen_select" ON dokumen;
CREATE POLICY "dokumen_select" ON dokumen FOR SELECT TO authenticated
USING (
  user_id = auth.uid()
  OR EXISTS (SELECT 1 FROM profiles p WHERE p.id=auth.uid() AND p.role='admin')
);

DROP POLICY IF EXISTS "dokumen_insert" ON dokumen;
CREATE POLICY "dokumen_insert" ON dokumen FOR INSERT TO authenticated
WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "dokumen_update" ON dokumen;
CREATE POLICY "dokumen_update" ON dokumen FOR UPDATE TO authenticated
USING (
  user_id = auth.uid()
  OR EXISTS (SELECT 1 FROM profiles p WHERE p.id=auth.uid() AND p.role='admin')
);

DROP POLICY IF EXISTS "dokumen_delete" ON dokumen;
CREATE POLICY "dokumen_delete" ON dokumen FOR DELETE TO authenticated
USING (
  user_id = auth.uid()
  OR EXISTS (SELECT 1 FROM profiles p WHERE p.id=auth.uid() AND p.role='admin')
);

-- 5. Kategori & buckets tetap shared (semua user pakai bucket admin)
-- app_config tetap bisa diakses semua authenticated
ALTER TABLE app_config ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "authenticated_all" ON app_config;
CREATE POLICY "authenticated_all" ON app_config FOR ALL TO authenticated
USING (true) WITH CHECK (true);

-- 6. RPC untuk admin membuat user baru (pakai service role via Edge Function lebih aman,
--    tapi untuk simple kita pakai signup biasa dari frontend)

-- Selesai! Setelah ini, login sebagai admin untuk mengakses fitur multi-user.
