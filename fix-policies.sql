-- =============================================
-- CYBEROPS — FIX SQL v2 (Resilient Trigger)
-- Run this in Supabase SQL Editor
-- This fixes: "Failed to fetch" on signu
-- =============================================

-- Step 1: Drop old policies safely
DROP POLICY IF EXISTS "profiles_select"      ON public.profiles;
DROP POLICY IF EXISTS "profiles_insert"      ON public.profiles;
DROP POLICY IF EXISTS "profiles_update"      ON public.profiles;
DROP POLICY IF EXISTS "challenges_select"    ON public.ctf_challenges;
DROP POLICY IF EXISTS "submissions_select"   ON public.ctf_submissions;
DROP POLICY IF EXISTS "submissions_insert"   ON public.ctf_submissions;
DROP POLICY IF EXISTS "lab_all"              ON public.lab_entries;
DROP POLICY IF EXISTS "threats_all"          ON public.threat_logs;
DROP POLICY IF EXISTS "training_all"         ON public.training_progress;

-- Step 2: Recreate policies
CREATE POLICY "profiles_select"    ON public.profiles         FOR SELECT USING (true);
CREATE POLICY "profiles_insert"    ON public.profiles         FOR INSERT WITH CHECK (auth.uid() = id);
CREATE POLICY "profiles_update"    ON public.profiles         FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "challenges_select"  ON public.ctf_challenges   FOR SELECT USING (true);
CREATE POLICY "submissions_select" ON public.ctf_submissions  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "submissions_insert" ON public.ctf_submissions  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "lab_all"            ON public.lab_entries      FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "threats_all"        ON public.threat_logs      FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "training_all"       ON public.training_progress FOR ALL USING (auth.uid() = user_id);

-- Step 3: RESILIENT trigger — errors won't block signup anymore
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  BEGIN
    INSERT INTO public.profiles (id, username, email)
    VALUES (
      NEW.id,
      COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
      NEW.email
    )
    ON CONFLICT (id) DO NOTHING;
  EXCEPTION WHEN OTHERS THEN
    -- Log but don't block auth if profile insert fails
    RAISE WARNING 'Profile creation skipped: %', SQLERRM;
  END;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Step 4: Insert CTF challenges
INSERT INTO public.ctf_challenges (title, category, description, hint, points, flag, difficulty) VALUES
('SQL Injection 101',   'WEB',      'Vulnerable login form — bypass auth to find the flag.',              'Try: username = admin'' OR ''1''=''1'' --',             100, 'CYBEROPS{sql_1nj3ct10n_m4st3r}', 'EASY'),
('ROT13 Secrets',       'CRYPTO',   'Decode: PLOREBC{ebg13_vf_rnfl}',                                    'ROT13 shifts each letter by 13 positions',              100, 'CYBEROPS{rot13_is_easy}',        'EASY'),
('Hidden in the Image', 'FORENSICS','A secret is embedded in the pixel data. Extract it.',               'Try steghide or run "strings" on the file',             200, 'CYBEROPS{st3g4n0_f0und_1t}',     'MEDIUM'),
('XSS Reflected',       'WEB',      'Search box reflects unsanitized input. Steal the admin cookie.',    '<script>document.write(document.cookie)</script>',      250, 'CYBEROPS{xss_c00k13_st0l3n}',   'MEDIUM'),
('RSA Baby Steps',      'CRYPTO',   'n=3233, e=17, c=2790. Small primes used — decrypt it.',            'p=61, q=53. Compute phi(n) then d.',                    300, 'CYBEROPS{rsa_f4ct0r3d_3z}',     'HARD'),
('Buffer Overflow',     'PWN',      '64-byte buffer, no canaries. Overflow to get the flag.',            'Find EIP offset with cyclic pattern, then payload',     400, 'CYBEROPS{pwn3d_th3_st4ck}',     'HARD'),
('OSINT: Find Them',    'OSINT',    'Handle "n0t_a_h4ck3r_42" left traces. Find their real name.',      'Check GitHub, Twitter/X, HackTheBox',                   150, 'CYBEROPS{0s1nt_tr4c3d}',         'EASY'),
('JWT Token Forgery',   'WEB',      'HS256 JWT, secret="password123". Forge admin token.',               'Decode at jwt.io, change role to admin, re-sign',       350, 'CYBEROPS{jwt_f0rg3d_adm1n}',    'HARD')
ON CONFLICT DO NOTHING;

SELECT 'SUCCESS: Policies fixed, resilient trigger installed, challenges loaded' AS status;
