// کش برای ذخیره نتایج درخواست‌های تکراری
const cache = new Map();

function toBase64(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

function fromBase64(b64) {
    try {
        return decodeURIComponent(escape(atob(b64)));
    } catch (error) {
        throw new Error('Invalid Base64 string');
    }
}

function checkAuth(request, env) {
    if (env.AUTH_ENABLED === "false") return true;
    
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) return false;

    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = atob(encodedCredentials);
    const [username, password] = decodedCredentials.split(':');
    
    return username === env.USERNAME && password === env.PASSWORD;
}

export default {
    async fetch(request, env, ctx) {
        const Domain = env.DOMAIN;
        const AUTH_ENABLED = env.AUTH_ENABLED;
        const USERNAME = env.USERNAME;
        const PASSWORD = env.PASSWORD;

        const url = new URL(request.url);
        const { pathname } = url;

        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        if (!pathname.endsWith('.css') && !pathname.endsWith('.js')) {
            if (!checkAuth(request, env)) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: {
                        ...corsHeaders,
                        'WWW-Authenticate': 'Basic realm="Multi-URL Proxy", charset="UTF-8"'
                    }
                });
            }
        }

        if (pathname === '/proxy') {
            const originalUrl = url.searchParams.get('url');
            if (!originalUrl) {
                return new Response('URL parameter is missing', { status: 400, headers: corsHeaders });
            }

            const cacheKey = originalUrl;
            if (cache.has(cacheKey)) {
                return new Response(JSON.stringify(cache.get(cacheKey)), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }

            const urlWithoutParams = originalUrl.split('?')[0];
            const filename = urlWithoutParams.split('/').pop();
            const encodedData = toBase64(JSON.stringify({ url: originalUrl, filename }));
            const proxiedUrl = `${Domain}/dl/${encodedData}`;

            const responseData = { proxiedUrl, filename };
            cache.set(cacheKey, responseData);

            return new Response(JSON.stringify(responseData), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        else if (pathname.startsWith('/dl/')) {
            const base64Data = pathname.replace('/dl/', '');
            if (!base64Data) {
                return new Response('Data parameter is missing', { status: 400, headers: corsHeaders });
            }

            try {
                const decodedData = fromBase64(base64Data);
                const { url: decodedUrl, filename } = JSON.parse(decodedData);

                const range = request.headers.get('Range');
                const fetchHeaders = new Headers(request.headers);

                const upstreamResponse = await fetch(decodedUrl, {
                    method: 'GET',
                    headers: range ? fetchHeaders : {},
                    redirect: 'follow'
                });

                if (!upstreamResponse.ok && (!range || upstreamResponse.status !== 206)) {
                    throw new Error(`Failed to fetch file: ${upstreamResponse.status}`);
                }

                const responseHeaders = new Headers();
                responseHeaders.set('Content-Disposition', `attachment; filename="${filename}"`);
                responseHeaders.set('Accept-Ranges', 'bytes');

                const contentLength = upstreamResponse.headers.get('Content-Length');
                if (contentLength) {
                    responseHeaders.set('Content-Length', contentLength);
                }

                const contentRange = upstreamResponse.headers.get('Content-Range');
                if (contentRange) {
                    responseHeaders.set('Content-Range', contentRange);
                }

                Object.keys(corsHeaders).forEach(key => {
                    responseHeaders.set(key, corsHeaders[key]);
                });

                const status = range && contentRange ? 206 : 200;

                return new Response(upstreamResponse.body, {
                    status,
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
        Object.keys(corsHeaders).forEach(key => {
            modifiedHeaders.set(key, corsHeaders[key]);
        });

        return new Response(assetResponse.body, {
            status: assetResponse.status,
            headers: modifiedHeaders,
        });
    }
};
