function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    const bin = Array.from(bytes, b => String.fromCharCode(b)).join('');
    return btoa(bin);
}

function fromBase64(b64) {
    try {
        const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
        return new TextDecoder().decode(bytes);
    } catch {
        throw new Error('Invalid Base64 string');
    }
}

async function timingSafeEqualStr(a, b) {
    const enc = new TextEncoder();
    const bufA = enc.encode(a);
    const bufB = enc.encode(b);
    if (bufA.byteLength !== bufB.byteLength) return false;
    return crypto.subtle.timingSafeEqual(bufA, bufB);
}

async function checkAuth(request, env) {
    if (env.AUTH_ENABLED === "false" || !env.AUTH_ENABLED) return true;

    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) return false;

    try {
        const encoded = authHeader.slice(6);
        const decoded = atob(encoded);
        const separatorIdx = decoded.indexOf(':');
        if (separatorIdx === -1) return false;

        const username = decoded.slice(0, separatorIdx);
        const password = decoded.slice(separatorIdx + 1);

        const validUser = await timingSafeEqualStr(username, env.USERNAME || '');
        const validPass = await timingSafeEqualStr(password, env.PASSWORD || '');
        return validUser && validPass;
    } catch {
        return false;
    }
}

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': '*',
};

export default {
    async fetch(request, env, ctx) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);
        const { pathname } = url;

        // Static asset bypass for CSS/JS
        const isStaticAsset = pathname.endsWith('.css') || pathname.endsWith('.js') || pathname.endsWith('.ico') || pathname.endsWith('.svg');
        if (!isStaticAsset && !(await checkAuth(request, env))) {
            return new Response('Unauthorized', {
                status: 401,
                headers: {
                    ...corsHeaders,
                    'WWW-Authenticate': 'Basic realm="Multi-URL Proxy", charset="UTF-8"'
                }
            });
        }

        // Backward compatibility for /proxy endpoint (encoded client-side in updated UI)
        if (pathname === '/proxy') {
            const originalUrl = url.searchParams.get('url');
            if (!originalUrl) {
                return new Response('URL parameter is missing', { status: 400, headers: corsHeaders });
            }

            try {
                const parsed = new URL(originalUrl);
                if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                    return new Response('Invalid URL protocol', { status: 400, headers: corsHeaders });
                }
                const filename = parsed.pathname.split('/').filter(Boolean).pop() || 'download';
                const encodedData = toBase64(JSON.stringify({ url: originalUrl, filename }));
                const domain = env.DOMAIN || url.origin;
                const proxiedUrl = `${domain}/dl/${encodedData}`;

                return new Response(JSON.stringify({ proxiedUrl, filename }), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            } catch {
                return new Response('Invalid URL format', { status: 400, headers: corsHeaders });
            }
        }

        if (pathname.startsWith('/dl/')) {
            const base64Data = pathname.slice(4);
            if (!base64Data) {
                return new Response('Data parameter is missing', { status: 400, headers: corsHeaders });
            }

            try {
                const decodedData = fromBase64(base64Data);
                const { url: targetUrl, filename } = JSON.parse(decodedData);

                const parsedTarget = new URL(targetUrl);
                if (parsedTarget.protocol !== 'http:' && parsedTarget.protocol !== 'https:') {
                    return new Response('Unsupported protocol', { status: 400, headers: corsHeaders });
                }

                // Forward only safe request headers to upstream
                const forwardHeaders = new Headers();
                for (const header of ['range', 'if-range', 'if-match', 'if-none-match', 'user-agent']) {
                    const value = request.headers.get(header);
                    if (value) forwardHeaders.set(header, value);
                }

                const upstreamResponse = await fetch(parsedTarget.toString(), {
                    method: 'GET',
                    headers: forwardHeaders,
                    redirect: 'follow'
                });

                const responseHeaders = new Headers();
                const safeFilename = (filename || parsedTarget.pathname.split('/').filter(Boolean).pop() || 'download')
                    .replace(/["\r\n\\]/g, '_');

                responseHeaders.set('Content-Disposition', `attachment; filename="${safeFilename}"`);
                responseHeaders.set('Accept-Ranges', 'bytes');

                for (const h of ['content-type', 'content-length', 'content-range', 'etag', 'last-modified']) {
                    const val = upstreamResponse.headers.get(h);
                    if (val) responseHeaders.set(h, val);
                }

                for (const [key, value] of Object.entries(corsHeaders)) {
                    responseHeaders.set(key, value);
                }

                return new Response(upstreamResponse.body, {
                    status: upstreamResponse.status,
                    headers: responseHeaders
                });

            } catch (error) {
                return new Response(`Error: ${error.message}`, {
                    status: 400,
                    headers: corsHeaders
                });
            }
        }

        // Fallback for static assets
        const assetResponse = await env.ASSETS.fetch(request);
        const modifiedHeaders = new Headers(assetResponse.headers);
        for (const [key, value] of Object.entries(corsHeaders)) {
            modifiedHeaders.set(key, value);
        }

        return new Response(assetResponse.body, {
            status: assetResponse.status,
            headers: modifiedHeaders,
        });
    }
};
