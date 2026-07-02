// CyberOps — OpenAI GPT-4o-mini Proxy with Streaming Support
export default async (request, context) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const OPENAI_API_KEY = Deno.env.get('OPENAI_API_KEY');
  if (!OPENAI_API_KEY) {
    return new Response(JSON.stringify({
      content: [{ type: 'text', text: 'ERROR: OPENAI_API_KEY not set in Netlify environment variables.' }]
    }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }

  try {
    const body = await request.json();
    const shouldStream = body.stream === true;

    // Convert Anthropic format → OpenAI messages format
    const messages = [];
    if (body.system) messages.push({ role: 'system', content: body.system });
    if (body.messages) messages.push(...body.messages);

    if (shouldStream) {
      // ── STREAMING MODE — tokens arrive one by one ──
      const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages,
          stream: true
        })
      });

      // Pass OpenAI's SSE stream straight through to browser
      return new Response(openaiRes.body, {
        headers: {
          ...corsHeaders,
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'X-Accel-Buffering': 'no'
        }
      });

    } else {
      // ── NON-STREAMING MODE — used by Code Auditor, Bug Bounty etc ──
      const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          max_tokens: body.max_tokens || 1000,
          messages,
          temperature: 0.7
        })
      });

      const data = await openaiRes.json();
      if (data.error) {
        return new Response(JSON.stringify({
          content: [{ type: 'text', text: `OpenAI Error: ${data.error.message}` }]
        }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }

      // Return in Anthropic format so existing code works unchanged
      const text = data.choices?.[0]?.message?.content || '';
      return new Response(JSON.stringify({
        content: [{ type: 'text', text }]
      }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

  } catch (e) {
    return new Response(JSON.stringify({
      content: [{ type: 'text', text: `Proxy error: ${e.message}` }]
    }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
};
