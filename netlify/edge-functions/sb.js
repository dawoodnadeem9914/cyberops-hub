// Netlify Edge Function — proxies all /sb/* requests to Supabase
// Edge nodes have different IPs than Netlify's proxy, bypassing the block

export default async (request, context) => {
  const SUPABASE_URL = 'https://qgvnbnytyflllejcqpto.supabase.co';
  const url = new URL(request.url);

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'access-control-allow-headers': '*',
        'access-control-max-age': '86400',
      },
    });
  }

  // Strip /sb prefix to get the real Supabase path
  const supaPath = url.pathname.replace('/sb', '') || '/';
  const targetUrl = SUPABASE_URL + supaPath + url.search;

  // Forward headers (drop hop-by-hop headers)
  const skipHeaders = ['host', 'accept-encoding', 'x-forwarded-for', 'x-forwarded-proto'];
  const fwdHeaders = {};
  for (const [k, v] of request.headers.entries()) {
    if (!skipHeaders.includes(k.toLowerCase())) fwdHeaders[k] = v;
  }
  fwdHeaders['host'] = new URL(SUPABASE_URL).host;

  // Read body for non-GET requests
  let body = undefined;
  if (!['GET', 'HEAD'].includes(request.method)) {
    body = await request.text();
  }

  try {
    const resp = await fetch(targetUrl, {
      method: request.method,
      headers: fwdHeaders,
      body,
    });

    const respText = await resp.text();

    // Build response headers
    const outHeaders = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*' };
    for (const [k, v] of resp.headers.entries()) {
      if (!['transfer-encoding', 'content-encoding', 'connection'].includes(k.toLowerCase())) {
        outHeaders[k] = v;
      }
    }

    return new Response(respText, { status: resp.status, headers: outHeaders });

  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'Edge proxy error: ' + err.message }),
      { status: 502, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' } }
    );
  }
};

export const config = { path: "/sb/*" };