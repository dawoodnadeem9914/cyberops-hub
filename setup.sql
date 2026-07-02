-- =============================================
-- CYBEROPS PLATFORM — DATABASE SETUP
-- Run this entire script in Supabase SQL Editor
-- Dashboard > SQL Editor > New Query > Paste > Run
-- =============================================

-- Profiles (auto-created on signup)
CREATE TABLE IF NOT EXISTS public.profiles (
                                               id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
    username TEXT,
    email TEXT,
    xp INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
    );

-- CTF Challenges
CREATE TABLE IF NOT EXISTS public.ctf_challenges (
                                                     id SERIAL PRIMARY KEY,
                                                     title TEXT NOT NULL,
                                                     category TEXT NOT NULL,
                                                     description TEXT,
                                                     hint TEXT,
                                                     points INTEGER DEFAULT 100,
                                                     flag TEXT NOT NULL,
                                                     difficulty TEXT DEFAULT 'EASY',
                                                     created_at TIMESTAMPTZ DEFAULT NOW()
    );

-- CTF Submissions (which user solved which challenge)
CREATE TABLE IF NOT EXISTS public.ctf_submissions (
                                                      id SERIAL PRIMARY KEY,
                                                      user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    challenge_id INTEGER REFERENCES public.ctf_challenges(id),
    solved_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, challenge_id)
    );

-- Pentest Lab Entries
CREATE TABLE IF NOT EXISTS public.lab_entries (
                                                  id SERIAL PRIMARY KEY,
                                                  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    vm_name TEXT NOT NULL,
    os_type TEXT DEFAULT 'Linux',
    status TEXT DEFAULT 'RUNNING',
    ip_address TEXT,
    notes TEXT,
    findings TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
    );

-- Threat Logs
CREATE TABLE IF NOT EXISTS public.threat_logs (
                                                  id SERIAL PRIMARY KEY,
                                                  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    severity TEXT DEFAULT 'LOW',
    source TEXT DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ DEFAULT NOW()
    );

-- Security Training Progress
CREATE TABLE IF NOT EXISTS public.training_progress (
                                                        id SERIAL PRIMARY KEY,
                                                        user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    module_name TEXT NOT NULL,
    completed BOOLEAN DEFAULT FALSE,
    score INTEGER DEFAULT 0,
    completed_at TIMESTAMPTZ,
    UNIQUE(user_id, module_name)
    );

-- =============================================
-- ROW LEVEL SECURITY
-- =============================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ctf_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ctf_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lab_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.training_progress ENABLE ROW LEVEL SECURITY;

-- Profiles: everyone can read, users manage own
CREATE POLICY "profiles_select" ON public.profiles FOR SELECT USING (true);
CREATE POLICY "profiles_insert" ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);
CREATE POLICY "profiles_update" ON public.profiles FOR UPDATE USING (auth.uid() = id);

-- CTF challenges: everyone can read
CREATE POLICY "challenges_select" ON public.ctf_challenges FOR SELECT USING (true);

-- CTF submissions: users manage own
CREATE POLICY "submissions_select" ON public.ctf_submissions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "submissions_insert" ON public.ctf_submissions FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Lab entries: users manage own
CREATE POLICY "lab_all" ON public.lab_entries FOR ALL USING (auth.uid() = user_id);

-- Threat logs: users manage own
CREATE POLICY "threats_all" ON public.threat_logs FOR ALL USING (auth.uid() = user_id);

-- Training: users manage own
CREATE POLICY "training_all" ON public.training_progress FOR ALL USING (auth.uid() = user_id);

-- =============================================
-- AUTO-CREATE PROFILE ON SIGNUP
-- =============================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
INSERT INTO public.profiles (id, username, email)
VALUES (
           NEW.id,
           COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
           NEW.email
       );
RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- =============================================
-- SAMPLE CTF CHALLENGES
-- =============================================
INSERT INTO public.ctf_challenges (title, category, description, hint, points, flag, difficulty) VALUES
                                                                                                     ('SQL Injection 101', 'WEB', 'A vulnerable login form is running at the target. The admin never sanitized the inputs. Can you bypass authentication and find the hidden flag?', 'Try entering: admin'' OR ''1''=''1'' -- in the username field', 100, 'CYBEROPS{sql_1nj3ct10n_m4st3r}', 'EASY'),
                                                                                                     ('ROT13 Secrets', 'CRYPTO', 'We intercepted this encoded message: PLOREBC{ebg13_vf_rnfl}. Decode it to find the flag. Classic cipher, classic mistake.', 'ROT13 shifts each letter by 13 positions in the alphabet', 100, 'CYBEROPS{rot13_is_easy}', 'EASY'),
                                                                                                     ('Hidden in the Image', 'FORENSICS', 'This image contains a hidden message. Steganography was used to embed a secret inside the pixels. Extract it to find the flag.', 'Try using steghide or running "strings" on the image file', 200, 'CYBEROPS{st3g4n0_f0und_1t}', 'MEDIUM'),
                                                                                                     ('XSS Reflected Attack', 'WEB', 'The search box on this site reflects user input directly into the page without sanitization. Inject a script to steal the admin cookie containing the flag.', 'Try: <script>document.write(document.cookie)</script>', 250, 'CYBEROPS{xss_c00k13_st0l3n}', 'MEDIUM'),
                                                                                                     ('RSA Baby Steps', 'CRYPTO', 'Given: n=3233, e=17, ciphertext=2790. Decrypt the RSA message. Small primes were used — a critical mistake by the target.', 'Factor n to get p=61 and q=53. Then compute phi(n) and d.', 300, 'CYBEROPS{rsa_f4ct0r3d_3z}', 'HARD'),
                                                                                                     ('Buffer Overflow', 'PWN', 'A legacy binary is running without stack canaries or ASLR. The buffer is 64 bytes. Overflow it to redirect execution and capture the flag from the shell.', 'Find the EIP offset with a cyclic pattern, then craft your payload', 400, 'CYBEROPS{pwn3d_th3_st4ck}', 'HARD'),
                                                                                                     ('OSINT: Find the Hacker', 'OSINT', 'A threat actor left traces online. Their handle is "n0t_a_h4ck3r_42". Search public sources to find their real name hidden in their bio.', 'Check GitHub, Twitter/X, and HackTheBox profiles with that handle', 150, 'CYBEROPS{0s1nt_tr4c3d}', 'EASY'),
                                                                                                     ('JWT Token Forgery', 'WEB', 'The API uses JWTs signed with HS256. We found the secret key is "password123". Forge an admin token and call /api/admin/flag.', 'Decode the token at jwt.io, change role to "admin", re-sign with the weak key', 350, 'CYBEROPS{jwt_f0rg3d_adm1n}', 'HARD')
    ON CONFLICT DO NOTHING;

-- Done! Your database is ready.
SELECT 'CYBEROPS DATABASE SETUP COMPLETE' as status;

-- =============================================
-- v2.0 MIGRATIONS — run these in Supabase SQL Editor
-- =============================================

-- Add profile fields (bio, social links)
ALTER TABLE public.profiles
    ADD COLUMN IF NOT EXISTS bio TEXT,
    ADD COLUMN IF NOT EXISTS github TEXT,
    ADD COLUMN IF NOT EXISTS htb TEXT,
    ADD COLUMN IF NOT EXISTS tryhackme TEXT;

-- Unique username (optional — only run if no duplicate usernames exist)
-- First clean up duplicates, then add constraint:
-- DELETE FROM profiles WHERE id NOT IN (SELECT MIN(id) FROM profiles GROUP BY username);
-- ALTER TABLE public.profiles ADD CONSTRAINT profiles_username_unique UNIQUE (username);

-- Index for faster leaderboard queries
CREATE INDEX IF NOT EXISTS profiles_xp_idx ON public.profiles(xp DESC);
CREATE INDEX IF NOT EXISTS submissions_user_idx ON public.ctf_submissions(user_id);
CREATE INDEX IF NOT EXISTS submissions_solved_at_idx ON public.ctf_submissions(solved_at);