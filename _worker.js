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

// تابع بررسی احراز هویت HTTP Basic
function checkAuth(request, env) {
    // اگر احراز هویت غیرفعال است، همیشه اجازه دسترسی بدهید
    if (env.AUTH_ENABLED === "false") return true;
    
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return false;
    }
    
    // دریافت کردن اطلاعات احراز هویت از هدر
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = atob(encodedCredentials);
    const [username, password] = decodedCredentials.split(':');
    
    // بررسی نام کاربری و رمز عبور
    return username === env.USERNAME && password === env.PASSWORD;
}

export default {
    async fetch(request, env, ctx) {

        // دامنه ورکرتون یا نیم بهارو اینجا بزارید 
        const Domain = env.DOMAIN; 

        // تنظیمات احراز هویت HTTP
        const AUTH_ENABLED = env.AUTH_ENABLED; // تغییر به true یا false برای فعال/غیرفعال کردن احراز هویت
        const USERNAME = env.USERNAME;  // نام کاربری را اینجا تغییر دهید
        const PASSWORD = env.PASSWORD; // رمز عبور را اینجا تغییر دهید

        const url = new URL(request.url);
        const { pathname } = url;

        // تنظیم CORS برای پذیرش همه درخواست‌ها
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
        };

        // پاسخ به درخواست‌های OPTIONS
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // بررسی احراز هویت برای همه درخواست‌ها به جز فایل‌های استاتیک
        if (!pathname.endsWith('.css') && !pathname.endsWith('.js')) {
            // بررسی احراز هویت
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
            const originalUrl = new URL(request.url).searchParams.get('url');
            if (!originalUrl) {
                return new Response('URL parameter is missing', { status: 400, headers: corsHeaders });
            }

            // استفاده از کش برای درخواست‌های تکراری
            const cacheKey = originalUrl;
            if (cache.has(cacheKey)) {
                return new Response(JSON.stringify(cache.get(cacheKey)), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }

            const urlWithoutParams = originalUrl.split('?')[0];
            const filename = urlWithoutParams.split('/').pop();

            // فقط از Base64 استفاده می‌کنیم بدون XOR
            const encodedData = toBase64(JSON.stringify({ url: originalUrl, filename }));
            const proxiedUrl = `${Domain}/dl/${encodedData}`;

            const responseData = {
                proxiedUrl,
                filename
            };
            
            // ذخیره نتیجه در کش
            cache.set(cacheKey, responseData);

            return new Response(JSON.stringify(responseData), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } else if (pathname.startsWith('/dl/')) {
            // گرفتن دیتای Base64 از URL
            const base64Data = pathname.replace('/dl/', '');
            
            if (!base64Data) {
                return new Response('Data parameter is missing', { status: 400, headers: corsHeaders });
            }

            try {
                // دیکد کردن دیتا (فقط با Base64)
                const decodedData = fromBase64(base64Data);
                const { url: decodedUrl, filename } = JSON.parse(decodedData);
                
                // بررسی هدر Range
                const range = request.headers.get('Range');
                let fetchHeaders = new Headers(request.headers);
                
                // درخواست HEAD برای گرفتن اطلاعات فایل بدون دانلود محتوا
                const headResponse = await fetch(decodedUrl, {
                    method: 'HEAD',
                });
                
                if (!headResponse.ok) {
                    throw new Error(`Failed to get file information: ${headResponse.status}`);
                }
                
                // دریافت حجم فایل از هدر Content-Length
                const contentLength = headResponse.headers.get('Content-Length');
                if (!contentLength) {
                    throw new Error('Could not determine file size');
                }
                
                // تنظیم هدرهای پاسخ
                const responseHeaders = new Headers();
                responseHeaders.set('Content-Disposition', `attachment; filename="${filename}"`);
                responseHeaders.set('Accept-Ranges', 'bytes');
                responseHeaders.set('Content-Length', contentLength);
                
                // اضافه کردن هدرهای CORS
                Object.keys(corsHeaders).forEach(key => {
                    responseHeaders.set(key, corsHeaders[key]);
                });
                
                // پردازش Range Requests
                if (range) {
                    const parts = range.replace(/bytes=/, "").split("-");
                    const start = parseInt(parts[0], 10);
                    const end = parts[1] ? parseInt(parts[1], 10) : parseInt(contentLength) - 1;
                    
                    // بررسی معتبر بودن محدوده
                    if (isNaN(start) || isNaN(end) || start < 0 || end >= parseInt(contentLength) || start > end) {
                        responseHeaders.set('Content-Range', `bytes */${contentLength}`);
                        return new Response('Invalid range', { 
                            status: 416, 
                            headers: responseHeaders 
                        });
                    }
                    
                    const chunkSize = (end - start) + 1;
                    
                    // تنظیم هدرهای Range
                    fetchHeaders.set('Range', `bytes=${start}-${end}`);
                    responseHeaders.set('Content-Range', `bytes ${start}-${end}/${contentLength}`);
                    responseHeaders.set('Content-Length', chunkSize.toString());
                    
                    // ارسال درخواست با Range مشخص شده
                    const rangeResponse = await fetch(decodedUrl, {
                        headers: fetchHeaders
                    });
                    
                    if (!rangeResponse.ok && rangeResponse.status !== 206) {
                        throw new Error(`Failed to fetch range: ${rangeResponse.status}`);
                    }
                    
                    // استفاده از TransformStream برای بهبود انتقال داده
                    const { readable, writable } = new TransformStream();
                    rangeResponse.body.pipeTo(writable).catch(err => console.error('Stream error:', err));
                    
                    return new Response(readable, {
                        status: 206,
                        headers: responseHeaders
                    });
                } else {
                    // دانلود کامل فایل
                    const response = await fetch(decodedUrl, {
                        headers: fetchHeaders
                    });
                    
                    if (!response.ok) {
                        throw new Error(`Failed to fetch file: ${response.status}`);
                    }
                    
                    // استفاده از TransformStream برای بهبود انتقال داده
                    const { readable, writable } = new TransformStream();
                    response.body.pipeTo(writable).catch(err => console.error('Stream error:', err));
                    
                    return new Response(readable, {
                        status: 200,
                        headers: responseHeaders
                    });
                }
            } catch (error) {
                return new Response(`Error: ${error.message}`, { 
                    status: 400, 
                    headers: corsHeaders 
                });
            }
        } else {
            // برای سایر مسیرها، هدرهای CORS را اضافه کنید
            const response = await env.ASSETS.fetch(request);
            const newHeaders = new Headers(response.headers);
            Object.keys(corsHeaders).forEach(key => {
                newHeaders.set(key, corsHeaders[key]);
            });
            return new Response(response.body, {
                status: response.status,
                headers: newHeaders,
            });
        }
    }
};
