// Use Netlify as proxy — bypasses network blocks on supabase.co
const SUPABASE_URL = window.location.origin + '/sb';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFndm5ibnl0eWZsbGxlamNxcHRvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIxODQ2NDYsImV4cCI6MjA5Nzc2MDY0Nn0.XqTYUQ-uuUQC3RG36roobpGFEoeY-E-_RDj05oOB7io';

// Use 'let' so if CDN fails, sb stays null instead of crashing everything
let sb = null;
try {
  if (window.supabase && window.supabase.createClient) {
    sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  } else {
    console.error('Supabase CDN not loaded yet');
  }
} catch(e) {
  console.error('Supabase init error:', e.message);
}

function sbCheck() {
  if (!sb) throw new Error('Supabase not loaded — refresh the page or check your connection');
}

// ---- AUTH ----
async function getUser() {
  if (!sb) return null;
  try { const { data: { user } } = await sb.auth.getUser(); return user; } catch(e) { return null; }
}
async function requireAuth() {
  const user = await getUser();
  if (!user) { window.location.href = 'index.html'; return null; }
  return user;
}
async function signOut() {
  if (sb) await sb.auth.signOut();
  window.location.href = 'index.html';
}

// ---- PROFILE ----
async function getProfile(userId) {
  sbCheck();
  const { data, error } = await sb.from('profiles').select('*').eq('id', userId).single();
  return { data, error };
}
async function updateProfile(userId, updates) {
  sbCheck();
  const { data, error } = await sb.from('profiles').update({ ...updates, updated_at: new Date().toISOString() }).eq('id', userId).select();
  return { data, error };
}
async function getLeaderboard() {
  sbCheck();
  const { data, error } = await sb.from('profiles').select('username, email, xp').order('xp', { ascending: false }).limit(10);
  return { data, error };
}

// ---- CTF ----
async function getChallenges() {
  sbCheck();
  const { data, error } = await sb.from('ctf_challenges').select('*').order('points', { ascending: true });
  return { data, error };
}
async function getUserSolvedIds(userId) {
  if (!sb) return [];
  const { data, error } = await sb.from('ctf_submissions').select('challenge_id').eq('user_id', userId);
  if (error || !data) return [];
  return data.map(r => r.challenge_id);
}
async function submitFlag(userId, challengeId, submittedFlag, correctFlag, points) {
  sbCheck();
  if (submittedFlag.trim() !== correctFlag.trim()) return { success: false, msg: 'INCORRECT FLAG — TRY AGAIN' };
  const { error } = await sb.from('ctf_submissions').insert({ user_id: userId, challenge_id: challengeId });
  if (error) {
    if (error.code === '23505') return { success: false, msg: 'CHALLENGE ALREADY SOLVED' };
    return { success: false, msg: 'ERROR: ' + error.message };
  }
  const { data: profile } = await getProfile(userId);
  if (profile) await updateProfile(userId, { xp: (profile.xp || 0) + points });
  return { success: true, msg: `FLAG ACCEPTED! +${points} XP AWARDED` };
}

// ---- LAB ----
async function getLabEntries(userId) {
  sbCheck();
  const { data, error } = await sb.from('lab_entries').select('*').eq('user_id', userId).order('created_at', { ascending: false });
  return { data: data || [], error };
}
async function addLabEntry(userId, entry) {
  sbCheck();
  return await sb.from('lab_entries').insert({ user_id: userId, ...entry });
}
async function deleteLabEntry(id) {
  sbCheck();
  const { error } = await sb.from('lab_entries').delete().eq('id', id);
  return { error };
}

// ---- THREATS ----
async function getThreatLogs(userId) {
  sbCheck();
  const { data, error } = await sb.from('threat_logs').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(8);
  return { data: data || [], error };
}
async function addThreatLog(userId, message, severity = 'LOW') {
  sbCheck();
  return await sb.from('threat_logs').insert({ user_id: userId, message, severity });
}

// ---- TRAINING ----
async function getTrainingProgress(userId) {
  sbCheck();
  const { data, error } = await sb.from('training_progress').select('*').eq('user_id', userId);
  return { data: data || [], error };
}
async function completeModule(userId, moduleName, score) {
  sbCheck();
  return await sb.from('training_progress').upsert({
    user_id: userId, module_name: moduleName,
    completed: true, score, completed_at: new Date().toISOString()
  }, { onConflict: 'user_id,module_name' });
}

// ---- MATRIX RAIN ----
function initMatrixRain(canvasId, opacity = 0.13) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  function resize() {
    canvas.width = window.innerWidth || document.documentElement.clientWidth || 400;
    canvas.height = window.innerHeight || document.documentElement.clientHeight || 800;
  }
  resize();
  window.addEventListener('resize', resize);
  const chars = 'アイウエオカキABCDEF0123456789!@#$%HIJKLMN01'.split('');
  let drops = [];
  function initDrops() {
    const cols = Math.floor(canvas.width / 14);
    drops = Array.from({ length: cols }, () => Math.random() * -40 | 0);
  }
  initDrops();
  window.addEventListener('resize', initDrops);
  canvas.style.opacity = opacity;
  return setInterval(() => {
    ctx.fillStyle = 'rgba(1,6,1,0.18)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = '13px monospace';
    drops.forEach((y, i) => {
      ctx.fillStyle = Math.random() > 0.9 ? '#afffaf' : '#22c522';
      ctx.fillText(chars[Math.random() * chars.length | 0], i * 14, y * 16);
      if (y * 16 > canvas.height && Math.random() > 0.96) drops[i] = 0;
      drops[i]++;
    });
  }, 50);
}

// ---- UTILITIES ----
function startUptime(elId) {
  let s = 0;
  setInterval(() => {
    s++;
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = [Math.floor(s/3600), Math.floor((s%3600)/60), s%60].map(n => String(n).padStart(2,'0')).join(':');
  }, 1000);
}
function startVitals() {
  const vals = { cpu: 42, ram: 64, net: 30, dsk: 71 };
  setInterval(() => {
    ['cpu','ram','net','dsk'].forEach(k => {
      vals[k] = Math.min(98, Math.max(5, vals[k] + ((Math.random()*14-7)|0)));
      const b = document.getElementById('bar-'+k), p = document.getElementById('pct-'+k);
      if (b) { b.style.width=vals[k]+'%'; b.style.background=vals[k]>85?'#c52222':vals[k]>65?'#c5a522':'#22c522'; }
      if (p) p.textContent = vals[k]+'%';
    });
  }, 2000);
}
function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff/60000);
  if (m < 1) return 'NOW';
  if (m < 60) return m+'m';
  const h = Math.floor(m/60);
  if (h < 24) return h+'h';
  return Math.floor(h/24)+'d';
}
function showAlert(id, msg, type = 'error') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = `alert alert-${type} show`;
  if (type === 'success') setTimeout(() => el.classList.remove('show'), 5000);
}
function sevColor(sev) { return { LOW:'#22c522', MED:'#c5a522', HIGH:'#c52222', CRIT:'#ff4444' }[sev]||'#22c522'; }
function sevClass(sev) { return { LOW:'sev-low', MED:'sev-med', HIGH:'sev-high', CRIT:'sev-crit' }[sev]||'sev-low'; }

// =============================================
// CYBEROPS — config.js ADDITIONS
// Paste this at the BOTTOM of your js/config.js
// =============================================

// ---- ACHIEVEMENTS ----
async function checkAndUnlockAchievements(userId) {
  // Tables not yet set up — guard silently
  if (!sb) return { unlocked: [] };
  try {
    const _test = await sb.from('user_achievements').select('achievement_key').limit(0);
    if (_test.error) return { unlocked: [] };
  } catch(e) { return { unlocked: [] }; }
  return { unlocked: [] };
}


async function getUserAchievements(userId) {
  if (!sb) return [];
  const { data } = await sb.from('user_achievements')
    .select('*, achievements(*)')
    .eq('user_id', userId)
    .order('unlocked_at', { ascending: false });
  return data || [];
}

// Show a toast popup when a new achievement is unlocked
function showAchievementToast(achievement) {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:9999;
    background:#0a1a0a; border:1px solid var(--green);
    border-radius:8px; padding:14px 18px;
    font-family:var(--font-mono); color:var(--green);
    box-shadow:0 0 20px rgba(34,197,34,0.3);
    animation:slideIn 0.3s ease; max-width:300px;
  `;
  toast.innerHTML = `
    <div style="font-size:9px;letter-spacing:2px;color:var(--green-dim);margin-bottom:4px">🏅 ACHIEVEMENT UNLOCKED</div>
    <div style="font-size:14px;font-family:var(--font-display);letter-spacing:1px;margin-bottom:2px">${achievement.icon || '🏅'} ${achievement.title}</div>
    <div style="font-size:11px;color:var(--green-dim)">${achievement.description}</div>
    ${achievement.xp_reward > 0 ? `<div style="font-size:10px;color:#c5a522;margin-top:4px">+${achievement.xp_reward} XP</div>` : ''}
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}

// Call this after any significant action (CTF solve, writeup publish, etc.)
async function triggerAchievementCheck(userId) {
  const newOnes = await checkAndUnlockAchievements(userId);
  newOnes.forEach(a => showAchievementToast(a));
  return newOnes;
}


// ---- DAILY CHALLENGES ----
async function getTodaysChallenge() {
  if (!sb) return null;
  const today = new Date().toISOString().slice(0, 10);
  const { data } = await sb.from('daily_challenges')
    .select('*, ctf_challenges(*)')
    .eq('challenge_date', today)
    .single();
  return data;
}

async function hasUserSolvedToday(userId) {
  if (!sb) return false;
  const today = new Date().toISOString().slice(0, 10);
  const { data } = await sb.from('daily_submissions')
    .select('id').eq('user_id', userId).eq('challenge_date', today).single();
  return !!data;
}

async function submitDailyChallenge(){ return {}; } async function _submitDaily_disabled(userId, submittedFlag, correctFlag) {
  if (!sb) return { success: false, msg: 'NOT CONNECTED' };
  if (submittedFlag.trim() !== correctFlag.trim()) return { success: false, msg: 'INCORRECT FLAG' };

  const today = new Date().toISOString().slice(0, 10);
  const { error } = await sb.from('daily_submissions').insert({ user_id: userId, challenge_date: today });
  if (error) {
    if (error.code === '23505') return { success: false, msg: 'ALREADY SOLVED TODAY' };
    return { success: false, msg: error.message };
  }

  // Update streak
  const { data: profile } = await sb.from('profiles').select('streak, longest_streak, last_daily_date').eq('id', userId).single();
  const lastDate = profile?.last_daily_date;
  const yesterday = new Date(); yesterday.setDate(yesterday.getDate() - 1);
  const wasYesterday = lastDate === yesterday.toISOString().slice(0, 10);
  const newStreak = wasYesterday ? (profile.streak || 0) + 1 : 1;
  const newLongest = Math.max(newStreak, profile?.longest_streak || 0);

  await sb.from('profiles').update({
    streak: newStreak,
    longest_streak: newLongest,
    last_daily_date: today,
    xp: (profile?.xp || 0) + 50  // daily bonus XP
  }).eq('id', userId);

  return { success: true, msg: `DAILY SOLVED! STREAK: ${newStreak} 🔥 +50 XP`, streak: newStreak };
}