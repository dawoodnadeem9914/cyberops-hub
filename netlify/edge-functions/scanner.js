// Netlify Edge Function — /scanner
// GET requests (browser) → redirect to scanner.html
// POST requests (JS fetch) → Shodan intelligence lookup

export default async (request, context) => {
  // Redirect browser GET requests to the actual page
  if (request.method === 'GET') {
    return Response.redirect(new URL('/scanner.html', request.url), 302);
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'POST, GET, OPTIONS',
        'access-control-allow-headers': '*',
      },
    });
  }

  const SHODAN_KEY = Deno.env.get('SHODAN_API_KEY');

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  });

  if (!SHODAN_KEY) {
    return json({ error: 'SHODAN_API_KEY not set — add it in Netlify → Project configuration → Environment variables' }, 500);
  }

  try {
    const body = await request.json();
    const target = (body.target || '').trim();
    if (!target) return json({ error: 'No target provided' }, 400);

    let ip = target;

    // Resolve domain to IP if needed
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
    if (!isIP) {
      const dnsResp = await fetch(
        `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(target)}&key=${SHODAN_KEY}`
      );
      const dnsData = await dnsResp.json();
      if (dnsData.error) throw new Error('DNS: ' + dnsData.error);
      ip = dnsData[target];
      if (!ip) throw new Error('Could not resolve: ' + target);
    }

    const hostResp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}`);
    const d = await hostResp.json();
    if (d.error) throw new Error(d.error);

    return json({
      ip: d.ip_str,
      hostname: !isIP ? target : (d.hostnames?.[0] || null),
      hostnames: d.hostnames || [],
      org: d.org || 'Unknown',
      isp: d.isp || 'Unknown',
      os: d.os || null,
      country: d.country_name || 'Unknown',
      city: d.city || 'Unknown',
      last_update: d.last_update || null,
      ports: d.ports || [],
      vulns: d.vulns ? Object.keys(d.vulns) : [],
      vuln_details: d.vulns || {},
      services: (d.data || []).map(s => ({
        port: s.port,
        transport: s.transport || 'tcp',
        product: s.product || null,
        version: s.version || null,
        banner: s.data ? s.data.slice(0, 300) : null,
        cpe: s.cpe || [],
        tags: s.tags || [],
      })),
    });
  } catch (err) {
    return json({ error: err.message }, 400);
  }
};

export const config = { path: '/scanner' };