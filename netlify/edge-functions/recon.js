// Netlify Edge Function — /api/recon
// GHOST SCANNER — All Recon Modules
// Modules: dns, geo, headers, whois, subdomains, reverse, abuse,
//          ssl, email, breach, asn, archive, cve, tech, exposure

export default async (request, context) => {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'POST, OPTIONS', 'access-control-allow-headers': '*' } });
  }
  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  });
  try {
    const { type, target } = await request.json();
    if (!target && type !== 'exposure') return json({ error: 'No target provided' }, 400);
    switch (type) {
      case 'dns':        return json(await dnsLookup(target));
      case 'geo':        return json(await geoLookup(target));
      case 'headers':    return json(await headersLookup(target));
      case 'whois':      return json(await rdapLookup(target));
      case 'subdomains': return json(await subdomainEnum(target));
      case 'reverse':    return json(await reverseIP(target));
      case 'abuse':      return json(await abuseCheck(target));
      case 'ssl':        return json(await sslCheck(target));
      case 'email':      return json(await emailSecurity(target));
      case 'breach':     return json(await breachCheck(target));
      case 'asn':        return json(await asnLookup(target));
      case 'archive':    return json(await webArchive(target));
      case 'cve':        return json(await cveSearch(target));
      case 'tech':       return json(await techFingerprint(target));
      case 'exposure': {
      const realIP = request.headers.get('x-forwarded-for')?.split(',')[0].trim()
                  || request.headers.get('x-real-ip')
                  || context.ip;
      return json(await myExposure(realIP));
    }
      default:           return json({ error: 'Unknown module: ' + type }, 400);
    }
  } catch (err) {
    return json({ error: err.message }, 500);
  }
};

// ── HELPER ──
const doH = async (name, type) => {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { Accept: 'application/dns-json' } });
    const d = await r.json();
    return d.Answer || [];
  } catch (_) { return []; }
};
const clean = t => t.replace(/^https?:\/\//, '').split('/')[0].split('?')[0];

// ── 1. DNS RECON ──
async function dnsLookup(target) {
  const dom = clean(target);
  const types = ['A','AAAA','MX','NS','TXT','CNAME','SOA'];
  const records = {};
  await Promise.all(types.map(async t => {
    const ans = await doH(dom, t);
    if (ans.length) records[t] = ans.map(a => ({ data: a.data, ttl: a.TTL }));
  }));
  return { module: 'dns', target: dom, records, total: Object.keys(records).length };
}

// ── 2. GEO TRACE ──
async function geoLookup(target) {
  const t = clean(target);
  const r = await fetch(`https://ipwho.is/${encodeURIComponent(t)}`);
  const d = await r.json();
  return { module: 'geo', target: t, ip: d.ip, type: d.type, country: d.country, country_code: d.country_code, region: d.region, city: d.city, lat: d.latitude, lng: d.longitude, org: d.connection?.org, isp: d.connection?.isp, asn: d.connection?.asn, timezone: d.timezone?.id, flag: d.flag?.emoji, success: d.success };
}

// ── 3. HTTP HEADERS PROBE ──
async function headersLookup(target) {
  let url = target.startsWith('http') ? target : 'https://' + target;
  const r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(8000) });
  const hdrs = {};
  r.headers.forEach((v, k) => hdrs[k] = v);
  const SEC = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','x-xss-protection','cross-origin-opener-policy'];
  const present = SEC.filter(h => hdrs[h]);
  const missing = SEC.filter(h => !hdrs[h]);
  const score = Math.round(present.length / SEC.length * 100);
  const grade = score>=90?'A+':score>=70?'B':score>=50?'C':score>=30?'D':'F';
  const tech = [hdrs['server'],hdrs['x-powered-by'],hdrs['x-generator']].filter(Boolean);
  return { module: 'headers', target: url, status: r.status, headers: hdrs, tech, security: { grade, score, present, missing }, redirected: r.redirected };
}

// ── 4. WHOIS / RDAP ──
async function rdapLookup(target) {
  const dom = clean(target);
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(dom)}`, { signal: AbortSignal.timeout(8000) });
    const d = await r.json();
    const reg = d.entities?.find(e => e.roles?.includes('registrar'));
    const created = d.events?.find(e => e.eventAction==='registration')?.eventDate;
    const updated = d.events?.find(e => e.eventAction==='last changed')?.eventDate;
    const expires = d.events?.find(e => e.eventAction==='expiration')?.eventDate;
    return { module: 'whois', target: dom, domain: d.ldhName, status: d.status||[], registrar: reg?.vcardArray?.[1]?.find(v=>v[0]==='fn')?.[3]||'Unknown', created, updated, expires, nameservers: d.nameservers?.map(n=>n.ldhName)||[] };
  } catch(e) { return { module: 'whois', target: dom, error: 'RDAP failed: ' + e.message }; }
}

// ── 5. SUBDOMAIN ENUM ──
async function subdomainEnum(target) {
  const dom = clean(target);
  const r = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(dom)}`, { signal: AbortSignal.timeout(15000) });
  const text = await r.text();
  if (text.includes('API count exceeded')) return { module: 'subdomains', target: dom, error: 'Daily limit reached (100/day)', results: [] };
  const results = text.trim().split('\n').map(l => { const [h,i]=l.split(','); return {host:h?.trim(),ip:i?.trim()}; }).filter(r=>r.host);
  return { module: 'subdomains', target: dom, results, count: results.length };
}

// ── 6. REVERSE IP ──
async function reverseIP(target) {
  const t = clean(target);
  const r = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(t)}`, { signal: AbortSignal.timeout(10000) });
  const text = await r.text();
  if (text.includes('API count exceeded')) return { module: 'reverse', target: t, error: 'Daily limit reached', results: [] };
  const results = text.trim().split('\n').map(l=>l.trim()).filter(l=>l&&!l.includes('error'));
  return { module: 'reverse', target: t, results, count: results.length };
}

// ── 7. ABUSEIPDB THREAT CHECK ──
async function abuseCheck(target) {
  const KEY = Deno.env.get('ABUSEIPDB_API_KEY');
  if (!KEY) return { module: 'abuse', error: 'ABUSEIPDB_API_KEY not set in Netlify env vars' };
  const t = clean(target);
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(t)}&maxAgeInDays=90&verbose=true`, { headers: { 'Key': KEY, 'Accept': 'application/json' }, signal: AbortSignal.timeout(8000) });
    if (r.status===429) return { module:'abuse', error:'Rate limit (1000/day)' };
    if (r.status===401) return { module:'abuse', error:'Invalid AbuseIPDB API key' };
    const d = (await r.json()).data;
    const score = d.abuseConfidenceScore;
    const risk = score>=80?'CRITICAL':score>=50?'HIGH':score>=20?'MEDIUM':score>0?'LOW':'CLEAN';
    return { module:'abuse', target:t, ip:d.ipAddress, risk, score, is_whitelisted:d.isWhitelisted, is_tor:d.isTor, country:d.countryCode, isp:d.isp, domain:d.domain, usage_type:d.usageType, total_reports:d.totalReports, distinct_users:d.numDistinctUsers, last_reported:d.lastReportedAt, recent_reports:(d.reports||[]).slice(0,5).map(r=>({reported_at:r.reportedAt,categories:r.categories,comment:r.comment?.slice(0,100)||null,reporter_country:r.reporterCountryCode})) };
  } catch(e) { return { module:'abuse', error:'AbuseIPDB: '+e.message }; }
}

// ── 8. SSL / TLS CERTIFICATE ──
async function sslCheck(target) {
  const dom = clean(target);
  // crt.sh only works for domains, not raw IP addresses
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(dom);
  if (isIP) return { module: 'ssl', target: dom, total_certs: 0, status: 'N/A', latest: null, subdomains_discovered: [], cert_history: [], note: 'SSL certificates are issued to domain names, not IP addresses. Enter a hostname to check SSL.' };
  try {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(dom)}&output=json&limit=50`, { signal: AbortSignal.timeout(12000) });
    const text = await r.text();
    // crt.sh returns HTML error pages when no results — detect and handle
    if (!text.trim().startsWith('[') && !text.trim().startsWith('{')) {
      return { module: 'ssl', target: dom, total_certs: 0, status: 'UNKNOWN', latest: null, subdomains_discovered: [], cert_history: [], note: 'No SSL certificate records found for this domain.' };
    }
    const certs = JSON.parse(text);
    const unique = [];
    const seen = new Set();
    for (const c of certs) {
      const key = c.serial_number;
      if (!seen.has(key)) { seen.add(key); unique.push(c); }
    }
    const sorted = unique.sort((a,b) => new Date(b.not_after) - new Date(a.not_after));
    const latest = sorted[0];
    const now = new Date();
    const expiry = latest ? new Date(latest.not_after) : null;
    const daysLeft = expiry ? Math.floor((expiry - now) / 86400000) : null;
    // Extract unique subdomains from SANs
    const subdomains = [...new Set(sorted.flatMap(c => c.name_value.split('\n').map(n=>n.trim())).filter(n=>n&&n!==dom))];
    return {
      module: 'ssl', target: dom,
      total_certs: unique.length,
      latest: latest ? { issuer: latest.issuer_name, common_name: latest.common_name, not_before: latest.not_before, not_after: latest.not_after, days_left: daysLeft, expired: daysLeft < 0 } : null,
      status: daysLeft === null ? 'UNKNOWN' : daysLeft < 0 ? 'EXPIRED' : daysLeft < 30 ? 'EXPIRING SOON' : 'VALID',
      subdomains_discovered: subdomains.slice(0, 30),
      cert_history: sorted.slice(0, 10).map(c => ({ issuer: c.issuer_name?.match(/O=([^,]+)/)?.[1] || c.issuer_name, not_after: c.not_after, common_name: c.common_name })),
    };
  } catch(e) { return { module: 'ssl', target: dom, error: 'SSL check failed: ' + e.message }; }
}

// ── 9. EMAIL SECURITY (SPF / DMARC / DKIM) ──
async function emailSecurity(target) {
  const dom = clean(target);
  const [txtRecs, dmarcRecs, mxRecs] = await Promise.all([
    doH(dom, 'TXT'),
    doH(`_dmarc.${dom}`, 'TXT'),
    doH(dom, 'MX'),
  ]);
  const spfRecord = txtRecs.find(r => r.data?.includes('v=spf1'));
  const dmarcRecord = dmarcRecs.find(r => r.data?.includes('v=DMARC1'));

  // Parse SPF
  let spfAnalysis = null;
  if (spfRecord) {
    const val = spfRecord.data;
    spfAnalysis = {
      record: val,
      all_policy: val.includes('-all') ? 'FAIL (strict)' : val.includes('~all') ? 'SOFTFAIL' : val.includes('+all') ? 'PASS ALL (DANGEROUS)' : val.includes('?all') ? 'NEUTRAL' : 'UNKNOWN',
      includes: (val.match(/include:([^\s]+)/g)||[]).map(i=>i.replace('include:','')),
      ip4: (val.match(/ip4:([^\s]+)/g)||[]).map(i=>i.replace('ip4:','')),
    };
  }

  // Parse DMARC
  let dmarcAnalysis = null;
  if (dmarcRecord) {
    const val = dmarcRecord.data;
    const policy = val.match(/p=([^;]+)/)?.[1] || 'none';
    const pct = val.match(/pct=(\d+)/)?.[1] || '100';
    dmarcAnalysis = { record: val, policy: policy.toUpperCase(), percentage: pct+'%', rua: val.match(/rua=([^;]+)/)?.[1] || null };
  }

  // Spoofing risk
  const noSpf = !spfRecord;
  const weakSpf = spfRecord && spfRecord.data?.includes('+all');
  const noDmarc = !dmarcRecord;
  const weakDmarc = dmarcRecord && (dmarcRecord.data?.includes('p=none'));
  let risk = 'LOW';
  if (noSpf && noDmarc) risk = 'CRITICAL';
  else if (noSpf || noDmarc) risk = 'HIGH';
  else if (weakSpf || weakDmarc) risk = 'MEDIUM';

  return {
    module: 'email', target: dom,
    spoofing_risk: risk,
    spf: spfRecord ? spfAnalysis : null,
    dmarc: dmarcRecord ? dmarcAnalysis : null,
    dkim: 'DKIM requires selector discovery — check your email provider',
    mx_servers: mxRecs.map(r => r.data),
    summary: {
      has_spf: !!spfRecord,
      has_dmarc: !!dmarcRecord,
      has_mx: mxRecs.length > 0,
      can_be_spoofed: noSpf || noDmarc || weakSpf || weakDmarc,
    }
  };
}

// ── 10. BREACH CHECK (HIBP - free breach list) ──
async function breachCheck(target) {
  const dom = clean(target);
  try {
    // Get all breaches (free, no key) and filter by domain
    const r = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
      headers: { 'User-Agent': 'CyberOps-Ghost-Scanner' },
      signal: AbortSignal.timeout(15000)
    });
    const all = await r.json();
    const matches = all.filter(b => b.Domain && (b.Domain.toLowerCase() === dom.toLowerCase() || b.Domain.toLowerCase().endsWith('.' + dom.toLowerCase())));
    const totalAccounts = matches.reduce((s, b) => s + (b.PwnCount || 0), 0);
    return {
      module: 'breach', target: dom,
      total_breaches: matches.length,
      total_accounts: totalAccounts,
      breaches: matches.map(b => ({
        name: b.Name, title: b.Title, domain: b.Domain,
        breach_date: b.BreachDate, added_date: b.AddedDate,
        pwn_count: b.PwnCount, description: b.Description?.replace(/<[^>]*>/g,'').slice(0,200),
        data_classes: b.DataClasses, is_verified: b.IsVerified, is_sensitive: b.IsSensitive,
      })),
      note: 'Data from HaveIBeenPwned breach database',
    };
  } catch(e) { return { module: 'breach', target: dom, error: 'Breach check failed: ' + e.message }; }
}

// ── 11. ASN INTELLIGENCE (BGPView) ──
async function asnLookup(target) {
  const t = clean(target);
  try {
    const isASN = /^(AS)?\d+$/i.test(t);
    const isIP  = /^\d{1,3}(\.\d{1,3}){3}$/.test(t);

    let asn, asnName, country, description, prefixes = [];

    if (isASN) {
      // Direct ASN lookup via RIPE STAT (no blocked domains)
      const asnNum = t.replace(/^AS/i, '');
      const [whoisR, prefixR] = await Promise.all([
        fetch(`https://stat.ripe.net/data/whois/data.json?resource=AS${asnNum}`, { signal: AbortSignal.timeout(10000) }).then(r=>r.json()),
        fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asnNum}`, { signal: AbortSignal.timeout(10000) }).then(r=>r.json()),
      ]);
      const records = whoisR?.data?.records?.[0] || [];
      asn = asnNum;
      asnName = records.find(r=>r.key==='as-name')?.value || records.find(r=>r.key==='aut-num')?.value || 'Unknown';
      description = records.find(r=>r.key==='descr')?.value;
      country = records.find(r=>r.key==='country')?.value;
      prefixes = (prefixR?.data?.prefixes || []).slice(0,15).map(p => ({ prefix: p.prefix }));
    } else {
      // IP lookup — use ipwho.is (already working for geo), it includes ASN data
      const geo = await fetch(`https://ipwho.is/${encodeURIComponent(t)}`, { signal: AbortSignal.timeout(10000) }).then(r=>r.json());
      asn = geo?.connection?.asn || null;
      asnName = geo?.connection?.org || geo?.connection?.isp || 'Unknown';
      country = geo?.country_code || geo?.country || null;
      description = geo?.connection?.isp || null;
      if (asn) {
        // Get prefix list from RIPE STAT using the resolved ASN
        try {
          const prefixR = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, { signal: AbortSignal.timeout(5000) }).then(r=>r.json()).catch(()=>({data:{prefixes:[]}}));
          prefixes = (prefixR?.data?.prefixes || []).slice(0,15).map(p => ({ prefix: p.prefix }));
        } catch(_) {}
      }
    }

    return {
      module: 'asn', target: t,
      asn, name: asnName, description, country,
      owned_prefixes: prefixes,
      prefix_count: prefixes.length,
      rir: null,
    };
  } catch(e) { return { module: 'asn', target: t, error: 'ASN lookup failed: ' + e.message }; }
}

// ── 12. WEB ARCHIVE (Wayback Machine) ──
async function webArchive(target) {
  const dom = clean(target);
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(dom);
  try {
    // IPs are rarely archived — skip slow CDX query for them
    const [avail, cdxText] = await Promise.all([
      fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(dom)}`, { signal: AbortSignal.timeout(6000) }).then(r=>r.json()),
      isIP ? Promise.resolve('[]') :
        fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(dom)}/*&output=json&limit=20&fl=timestamp,original,statuscode,mimetype&collapse=digest`, { signal: AbortSignal.timeout(10000) }).then(r=>r.text()).catch(()=>'[]'),
    ]);
    const cdx = (typeof cdxText === 'string' && cdxText.trim().startsWith('[')) ? JSON.parse(cdxText) : [];

    const latest = avail?.archived_snapshots?.closest;
    const rows = Array.isArray(cdx) ? cdx.slice(1) : [];
    const first = rows[rows.length-1];
    const snapshots = rows.slice(0,15).map(r => ({ timestamp: r[0], url: r[1], status: r[2], type: r[3] }));
    const totalSnaps = rows.length;

    return {
      module: 'archive', target: dom,
      has_archive: !!latest,
      latest_snapshot: latest ? { url: latest.url, timestamp: latest.timestamp, status: latest.status } : null,
      first_seen: first ? first[0] : null,
      total_snapshots: totalSnaps,
      snapshots,
      wayback_url: `https://web.archive.org/web/*/${dom}`,
    };
  } catch(e) { return { module: 'archive', target: dom, error: 'Wayback failed: ' + e.message }; }
}

// ── 13. CVE SEARCH (NVD NIST - free) ──
async function cveSearch(target) {
  try {
    const isCVE = /^CVE-\d{4}-\d+$/i.test(target.trim());
    let url;
    if (isCVE) {
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(target.trim().toUpperCase())}`;
    } else {
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(target)}&resultsPerPage=10`;
    }
    const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    const vulns = (d.vulnerabilities||[]).map(v => {
      const cve = v.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const score = metrics?.cvssData?.baseScore;
      const severity = metrics?.cvssData?.baseSeverity || (score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':'LOW');
      return {
        id: cve.id,
        description: cve.descriptions?.find(d=>d.lang==='en')?.value?.slice(0,300) || 'No description',
        score, severity,
        published: cve.published,
        modified: cve.lastModified,
        references: cve.references?.slice(0,3).map(r=>r.url).filter(u=>u && u.startsWith('http')) || [],
        cwe: cve.weaknesses?.[0]?.description?.[0]?.value || null,
      };
    });
    return { module: 'cve', target, total: d.totalResults||vulns.length, results: vulns };
  } catch(e) { return { module: 'cve', target, error: 'CVE search failed: ' + e.message }; }
}

// ── 14. TECHNOLOGY FINGERPRINT ──
async function techFingerprint(target) {
  const dom = clean(target);
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(dom);
  let url = target.startsWith('http') ? target : 'https://' + dom;
  let r;
  try {
    r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(8000) });
  } catch(e) {
    // HTTPS failed — try HTTP fallback
    try {
      url = url.replace('https://', 'http://');
      r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(6000) });
    } catch(e2) {
      const msg = isIP
        ? 'No web server found on this IP address. Tech scan requires a domain or IP serving HTTP/HTTPS.'
        : 'Tech fingerprint failed: ' + e2.message;
      return { module: 'tech', target: url, technologies: [], categories: [], count: 0, error: msg };
    }
  }
  try {
    const html = await r.text();
    const hdrs = {};
    r.headers.forEach((v,k) => hdrs[k]=v);
    const techs = [];
    const add = (name, cat, ver=null) => { if (!techs.find(t=>t.name===name)) techs.push({name,cat,ver}); };

    // Server / hosting
    if (hdrs['server']) {
      const s = hdrs['server'];
      if (s.match(/apache/i)) add('Apache', 'Server', s.match(/Apache\/([\d.]+)/i)?.[1]);
      if (s.match(/nginx/i)) add('Nginx', 'Server', s.match(/nginx\/([\d.]+)/i)?.[1]);
      if (s.match(/iis/i)) add('IIS', 'Server', s.match(/IIS\/([\d.]+)/i)?.[1]);
      if (s.match(/cloudflare/i)) add('Cloudflare', 'CDN');
      if (s.match(/openresty/i)) add('OpenResty', 'Server');
      if (s.match(/litespeed/i)) add('LiteSpeed', 'Server');
    }
    if (hdrs['cf-ray']) add('Cloudflare', 'CDN');
    if (hdrs['x-powered-by']) {
      const p = hdrs['x-powered-by'];
      if (p.match(/php/i)) add('PHP', 'Language', p.match(/PHP\/([\d.]+)/i)?.[1]);
      if (p.match(/asp\.net/i)) add('ASP.NET', 'Framework', p.match(/ASP\.NET ([\d.]+)/i)?.[1]);
      if (p.match(/express/i)) add('Express.js', 'Framework');
      if (p.match(/next\.js/i)) add('Next.js', 'Framework');
    }

    // CMS detection from HTML
    if (html.includes('/wp-content/') || html.includes('/wp-includes/')) add('WordPress', 'CMS');
    if (html.match(/content="WordPress ([\d.]+)/i)) add('WordPress', 'CMS', html.match(/content="WordPress ([\d.]+)/i)?.[1]);
    if (html.includes('Joomla!') || html.includes('/components/com_')) add('Joomla', 'CMS');
    if (html.includes('data-drupal') || html.includes('drupal.js')) add('Drupal', 'CMS');
    if (html.includes('content="Wix.com"')) add('Wix', 'CMS');
    if (html.includes('squarespace') || html.includes('Squarespace')) add('Squarespace', 'CMS');
    if (html.includes('shopify') || html.includes('Shopify.theme')) add('Shopify', 'E-Commerce');
    if (html.includes('woocommerce')) add('WooCommerce', 'E-Commerce');
    if (html.includes('Magento') || html.includes('mage/')) add('Magento', 'E-Commerce');

    // JS Frameworks
    if (html.match(/react(-dom)?\.min\.js|react\.(development|production)/i) || html.includes('__reactFiber') || html.includes('_reactRoot')) add('React', 'JS Framework');
    if (html.match(/angular(\.min)?\.js/i) || html.includes('ng-version') || html.includes('ng-app')) add('Angular', 'JS Framework');
    if (html.match(/vue(\.min)?\.js/i) || html.includes('__vue_app__') || html.includes('data-v-')) add('Vue.js', 'JS Framework');
    if (html.includes('__next') || html.includes('_next/static')) add('Next.js', 'JS Framework');
    if (html.includes('__nuxt') || html.includes('_nuxt/')) add('Nuxt.js', 'JS Framework');
    if (html.match(/jquery[.-]([\d.]+)(\.min)?\.js/i)) add('jQuery', 'JS Library', html.match(/jquery[.-]([\d.]+)/i)?.[1]);
    if (html.match(/bootstrap(\.min)?\.css/i) || html.match(/bootstrap(\.bundle)?(\.min)?\.js/i)) add('Bootstrap', 'CSS Framework');
    if (html.includes('tailwindcss') || html.includes('tailwind.')) add('Tailwind CSS', 'CSS Framework');

    // Analytics & tracking
    if (html.includes('google-analytics.com') || html.includes('gtag(') || html.includes('ga.js')) add('Google Analytics', 'Analytics');
    if (html.includes('googletagmanager.com')) add('Google Tag Manager', 'Analytics');
    if (html.includes('hotjar.com')) add('Hotjar', 'Analytics');
    if (html.includes('facebook.net/en_US/fbevents')) add('Facebook Pixel', 'Analytics');
    if (html.includes('clarity.ms')) add('Microsoft Clarity', 'Analytics');

    // CDN
    if (html.includes('cdnjs.cloudflare.com')) add('Cloudflare CDN', 'CDN');
    if (html.includes('cdn.jsdelivr.net')) add('jsDelivr', 'CDN');
    if (html.includes('unpkg.com')) add('unpkg', 'CDN');
    if (hdrs['x-amz-cf-id'] || hdrs['x-amz-cf-pop']) add('AWS CloudFront', 'CDN');
    if (hdrs['x-served-by']?.includes('cache')) add('Fastly', 'CDN');

    // Security
    if (hdrs['x-sucuri-id'] || hdrs['x-sucuri-cache']) add('Sucuri WAF', 'Security');
    if (hdrs['x-fw-type'] || hdrs['x-waf-event-info']) add('Web Application Firewall', 'Security');

    const categories = [...new Set(techs.map(t=>t.cat))];
    return { module: 'tech', target: url, technologies: techs, categories, count: techs.length, status: r.status };
  } catch(e) { return { module: 'tech', target: url, technologies: [], categories: [], count: 0, error: 'Tech fingerprint failed: ' + e.message }; }
}

// ── 15. MY EXPOSURE (auto-detect user's public IP) ──
async function myExposure(clientIP) {
  if (!clientIP) return { module: 'exposure', error: 'Could not detect client IP' };
  const [geo, abuse, asn] = await Promise.all([
    geoLookup(clientIP),
    abuseCheck(clientIP),
    asnLookup(clientIP),
  ]);
  // Check if IP is VPN/proxy/hosting
  const usageType = abuse?.usage_type || '';
  const isVPN = /vpn|proxy|hosting|data.center/i.test(usageType);
  return {
    module: 'exposure', your_ip: clientIP,
    geo, abuse, asn,
    is_vpn_proxy: isVPN,
    usage_type: usageType,
    summary: {
      ip: clientIP, country: geo?.country, isp: geo?.isp,
      abuse_score: abuse?.score ?? null,
      risk: abuse?.risk ?? 'UNKNOWN',
      is_tor: abuse?.is_tor ?? false,
      is_vpn_proxy: isVPN,
    }
  };
}

export const config = { path: '/api/recon' };