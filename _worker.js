function bytesToBase64Url(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function stringToBase64Url(str) {
    const bytes = new TextEncoder().encode(str);
    return bytesToBase64Url(bytes);
}

function base64UrlToBytes(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
        base64 += '=';
    }
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
}

function base64UrlToString(base64url) {
    const bytes = base64UrlToBytes(base64url);
    return new TextDecoder().decode(bytes);
}

async function signHmacSha256(dataStr, secretKey) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signatureBuffer = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(dataStr)
    );
    return bytesToBase64Url(new Uint8Array(signatureBuffer));
}

async function verifyHmacSha256(dataStr, base64UrlSig, secretKey) {
    try {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secretKey),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );
        const sigBytes = base64UrlToBytes(base64UrlSig);
        return await crypto.subtle.verify(
            'HMAC',
            key,
            sigBytes,
            encoder.encode(dataStr)
        );
    } catch {
        return false;
    }
}

function getFormattedDomain(domain, fallbackOrigin) {
    if (!domain) return fallbackOrigin;
    domain = domain.trim();
    if (!domain) return fallbackOrigin;
    if (!domain.startsWith('http://') && !domain.startsWith('https://')) {
        domain = `https://${domain}`;
    }
    return domain.replace(/\/+$/, '');
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
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
    'Access-Control-Allow-Headers': '*',
};

export default {
    async fetch(request, env, ctx) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);
        const { pathname } = url;

        // Static asset bypass for CSS/JS/fonts/icons
        const isStaticAsset = pathname.endsWith('.css') ||
                              pathname.endsWith('.js') ||
                              pathname.endsWith('.ico') ||
                              pathname.endsWith('.svg') ||
                              pathname.endsWith('.png') ||
                              pathname.endsWith('.jpg');

        // Public routes exempt from Basic Auth:
        // - Static assets (CSS, JS, fonts, images)
        // - /dl/ routes (authenticated by HMAC-SHA256 signatures)
        // - /test/ edge checker suite
        const isPublicRoute = isStaticAsset ||
                              pathname.startsWith('/dl/') ||
                              pathname === '/test' ||
                              pathname.startsWith('/test/');

        if (!isPublicRoute && !(await checkAuth(request, env))) {
            return new Response('Unauthorized', {
                status: 401,
                headers: {
                    ...corsHeaders,
                    'WWW-Authenticate': 'Basic realm="Multi-URL Proxy", charset="UTF-8"'
                }
            });
        }

        const configuredDomain = getFormattedDomain(env.DOMAIN, url.origin);
        const secretKey = env.DOWNLOAD_PROXY_SECRET || env.SIGNING_SECRET || env.HMAC_SECRET || env.SECRET_KEY || 'cf-download-proxy-secret-key';

        // /proxy endpoint for generating HMAC-SHA256 signed URLs
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
                const filename = url.searchParams.get('filename') || parsed.pathname.split('/').filter(Boolean).pop() || 'download';
                const payload = { url: originalUrl, filename };
                const expParam = url.searchParams.get('exp');
                if (expParam) {
                    const expNum = Number(expParam);
                    if (!isNaN(expNum)) payload.exp = expNum;
                }

                const jsonPayload = JSON.stringify(payload);
                const encodedData = stringToBase64Url(jsonPayload);
                const signature = await signHmacSha256(jsonPayload, secretKey);
                const proxiedUrl = `${configuredDomain}/dl/${encodedData}.${signature}`;

                return new Response(JSON.stringify({ proxiedUrl, filename }), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            } catch {
                return new Response('Invalid URL format', { status: 400, headers: corsHeaders });
            }
        }

        if (pathname.startsWith('/dl/')) {
            const token = pathname.replace(/^\/dl\/?/, '');
            if (!token) {
                return new Response('Data parameter is missing', { status: 400, headers: corsHeaders });
            }

            const dotIndex = token.indexOf('.');
            if (dotIndex === -1) {
                return new Response('Invalid token format: missing signature', { status: 403, headers: corsHeaders });
            }

            const b64UrlPayload = token.slice(0, dotIndex);
            const b64UrlSignature = token.slice(dotIndex + 1);

            if (!b64UrlPayload || !b64UrlSignature) {
                return new Response('Invalid token format', { status: 403, headers: corsHeaders });
            }

            let jsonPayload;
            try {
                jsonPayload = base64UrlToString(b64UrlPayload);
            } catch {
                return new Response('Invalid Base64 payload', { status: 400, headers: corsHeaders });
            }

            if (!secretKey) {
                return new Response('Server configuration error: signing secret is not configured', { status: 500, headers: corsHeaders });
            }

            // Verify HMAC-SHA256 signature calculated from the exact JSON payload
            const isValid = await verifyHmacSha256(jsonPayload, b64UrlSignature, secretKey);
            if (!isValid) {
                return new Response('Invalid signature', { status: 403, headers: corsHeaders });
            }

            try {
                const payload = JSON.parse(jsonPayload);
                const { url: targetUrl, filename, exp } = payload;

                if (!targetUrl || typeof targetUrl !== 'string') {
                    return new Response('Invalid payload: missing target URL', { status: 400, headers: corsHeaders });
                }

                // Check link expiration if present
                if (exp !== undefined && exp !== null) {
                    const expNum = Number(exp);
                    if (isNaN(expNum)) {
                        return new Response('Invalid expiration timestamp', { status: 400, headers: corsHeaders });
                    }
                    const now = Math.floor(Date.now() / 1000);
                    if (now > expNum) {
                        return new Response('Link expired', { status: 403, headers: corsHeaders });
                    }
                }

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

                const method = request.method === 'HEAD' ? 'HEAD' : 'GET';
                const upstreamResponse = await fetch(parsedTarget.toString(), {
                    method,
                    headers: forwardHeaders,
                    redirect: 'follow'
                });

                const responseHeaders = new Headers();
                const safeFilename = (filename || parsedTarget.pathname.split('/').filter(Boolean).pop() || 'download')
                    .replace(/["\r\n\\]/g, '_');

                const asciiFilename = safeFilename.replace(/[^\x20-\x7E]/g, '_');
                const encodedFilename = encodeURIComponent(safeFilename);
                responseHeaders.set('Content-Disposition', `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
                responseHeaders.set('Accept-Ranges', 'bytes');

                for (const h of ['content-type', 'content-length', 'content-range', 'etag', 'last-modified']) {
                    const val = upstreamResponse.headers.get(h);
                    if (val) responseHeaders.set(h, val);
                }

                for (const [key, value] of Object.entries(corsHeaders)) {
                    responseHeaders.set(key, value);
                }

                return new Response(request.method === 'HEAD' ? null : upstreamResponse.body, {
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
        const contentType = assetResponse.headers.get('content-type') || '';

        // Inject configured domain into root HTML
        if (contentType.includes('text/html') && (pathname === '/' || pathname === '/index.html')) {
            const html = await assetResponse.text();
            const injectedHtml = html.replace(
                '</head>',
                `<meta name="proxy-domain" content="${configuredDomain}">\n</head>`
            );
            const modifiedHeaders = new Headers(assetResponse.headers);
            for (const [key, value] of Object.entries(corsHeaders)) {
                modifiedHeaders.set(key, value);
            }
            modifiedHeaders.delete('content-length');

            return new Response(injectedHtml, {
                status: assetResponse.status,
                headers: modifiedHeaders,
            });
        }

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
