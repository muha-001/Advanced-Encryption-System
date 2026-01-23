// ============================================
// Service Worker لنظام التشفير المتقدم
// ============================================

const CACHE_NAME = 'encryption-system-v4.1';
const CACHE_VERSION = '4.1.0';
const APP_NAME = 'نظام التشفير المتقدم';

// الملفات التي سيتم تخزينها مؤقتاً
const CORE_FILES = [
    './',
    './index.html',
    './style.css',
    './app.js',
    './crypto-engine.js',
    './manifest.json'
];

// الملفات الخارجية
const EXTERNAL_FILES = [
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/hash-wasm@4'
];

// ============================================
// التثبيت
// ============================================

self.addEventListener('install', (event) => {
    console.log(`🚀 ${APP_NAME} - تثبيت Service Worker`);

    event.waitUntil(
        (async () => {
            try {
                // فتح التخزين المؤقت
                const cache = await caches.open(CACHE_NAME);
                console.log('📦 فتح التخزين المؤقت:', CACHE_NAME);

                // تخزين الملفات الأساسية
                await cache.addAll(CORE_FILES);
                console.log('✅ تم تخزين الملفات الأساسية');

                // تخزين الملفات الخارجية
                for (const url of EXTERNAL_FILES) {
                    try {
                        await cache.add(url);
                        console.log(`✅ تم تخزين: ${url}`);
                    } catch (error) {
                        console.warn(`⚠️ فشل تخزين ${url}:`, error);
                    }
                }

                // تفعيل Service Worker فوراً
                await self.skipWaiting();
                console.log('⚡ Service Worker مفعل وجاهز للعمل');

            } catch (error) {
                console.error('❌ فشل التثبيت:', error);
                throw error;
            }
        })()
    );
});

// ============================================
// التفعيل
// ============================================

self.addEventListener('activate', (event) => {
    console.log(`⚡ ${APP_NAME} - تفعيل Service Worker`);

    event.waitUntil(
        (async () => {
            try {
                // حذف التخزين المؤقت القديم
                const cacheNames = await caches.keys();
                await Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== CACHE_NAME) {
                            console.log(`🗑️ حذف التخزين المؤقت القديم: ${cacheName}`);
                            return caches.delete(cacheName);
                        }
                    })
                );

                // المطالبة بالتحكم في العملاء
                await self.clients.claim();
                console.log('✅ Service Worker مسيطر على جميع الصفحات');

                // إرسال رسالة إلى الصفحات
                const clients = await self.clients.matchAll();
                clients.forEach((client) => {
                    client.postMessage({
                        type: 'SW_ACTIVATED',
                        version: CACHE_VERSION,
                        cacheName: CACHE_NAME
                    });
                });

            } catch (error) {
                console.error('❌ فشل التفعيل:', error);
            }
        })()
    );
});

// ============================================
// معالجة الطلبات
// ============================================

self.addEventListener('fetch', (event) => {
    // تجاهل الطلبات غير GET
    if (event.request.method !== 'GET') return;

    const url = new URL(event.request.url);

    // تجاهل الطلبات غير HTTP/HTTPS
    if (!url.protocol.startsWith('http')) return;

    // تجاهل الطلبات لموارد محددة
    if (url.pathname.includes('browser-sync') ||
        url.pathname.includes('socket.io') ||
        url.pathname.includes('__webpack')) {
        return;
    }

    event.respondWith(
        (async () => {
            try {
                // محاولة جلب من التخزين المؤقت أولاً
                const cachedResponse = await caches.match(event.request);

                if (cachedResponse) {
                    console.log(`🔍 وجد في التخزين المؤقت: ${url.pathname}`);

                    // تحديث التخزين المؤقت في الخلفية
                    this.updateCacheInBackground(event.request);

                    return cachedResponse;
                }

                // إذا لم يوجد في التخزين المؤقت، جلب من الشبكة
                console.log(`🌐 جلب من الشبكة: ${url.pathname}`);
                const networkResponse = await fetch(event.request);

                // التحقق من صحة الاستجابة
                if (networkResponse && networkResponse.status === 200) {
                    // تخزين في التخزين المؤقت
                    const cache = await caches.open(CACHE_NAME);
                    await cache.put(event.request, networkResponse.clone());
                    console.log(`💾 تم تخزين: ${url.pathname}`);
                }

                return networkResponse;

            } catch (error) {
                console.error(`❌ فشل جلب ${url.pathname}:`, error);

                // إذا كان طلباً لصفحة HTML، إرجاع الصفحة الرئيسية
                if (event.request.mode === 'navigate') {
                    const fallbackResponse = await caches.match('./index.html');
                    if (fallbackResponse) {
                        return fallbackResponse;
                    }
                }

                // صفحة عدم الاتصال
                return new Response(
                    `
                    <!DOCTYPE html>
                    <html lang="ar" dir="rtl">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>وضع عدم الاتصال - نظام التشفير</title>
                        <style>
                            body {
                                font-family: system-ui, -apple-system, sans-serif;
                                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                                color: #f8fafc;
                                min-height: 100vh;
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                padding: 20px;
                                text-align: center;
                            }
                            .container {
                                max-width: 500px;
                                background: rgba(30, 41, 59, 0.9);
                                border-radius: 20px;
                                padding: 40px;
                                border: 1px solid rgba(255, 255, 255, 0.1);
                                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                            }
                            h1 {
                                font-size: 2.5rem;
                                margin-bottom: 20px;
                                color: #60a5fa;
                            }
                            p {
                                font-size: 1.125rem;
                                line-height: 1.6;
                                margin-bottom: 30px;
                                color: #cbd5e1;
                            }
                            .features {
                                text-align: right;
                                margin: 30px 0;
                            }
                            .feature {
                                display: flex;
                                align-items: center;
                                gap: 10px;
                                margin-bottom: 15px;
                                padding: 10px;
                                background: rgba(255, 255, 255, 0.05);
                                border-radius: 10px;
                            }
                            .feature i {
                                color: #10b981;
                                font-size: 1.25rem;
                            }
                            button {
                                background: linear-gradient(135deg, #2563eb, #1d4ed8);
                                color: white;
                                border: none;
                                padding: 15px 30px;
                                border-radius: 10px;
                                font-size: 1.125rem;
                                font-weight: 600;
                                cursor: pointer;
                                transition: transform 0.3s;
                            }
                            button:hover {
                                transform: translateY(-2px);
                            }
                        </style>
                        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
                    </head>
                    <body>
                        <div class="container">
                            <h1><i class="fas fa-wifi-slash"></i> وضع عدم الاتصال</h1>
                            <p>أنت غير متصل بالإنترنت. نظام التشفير يعمل محلياً على جهازك.</p>
                            
                            <div class="features">
                                <div class="feature">
                                    <i class="fas fa-check-circle"></i>
                                    <span>يمكنك تشفير وفك تشفير النصوص</span>
                                </div>
                                <div class="feature">
                                    <i class="fas fa-check-circle"></i>
                                    <span>جميع عمليات التشفير تتم محلياً</span>
                                </div>
                                <div class="feature">
                                    <i class="fas fa-check-circle"></i>
                                    <span>لا حاجة لاتصال بالإنترنت</span>
                                </div>
                            </div>
                            
                            <p>عند استعادة الاتصال، سيتم تحديث النظام تلقائياً.</p>
                            <button onclick="location.reload()">
                                <i class="fas fa-sync-alt"></i>
                                إعادة المحاولة
                            </button>
                        </div>
                    </body>
                    </html>
                    `,
                    {
                        headers: {
                            'Content-Type': 'text/html; charset=utf-8'
                        }
                    }
                );
            }
        })()
    );
});

// ============================================
// تحديث التخزين المؤقت في الخلفية
// ============================================

async function updateCacheInBackground(request) {
    try {
        const response = await fetch(request);
        if (response && response.status === 200) {
            const cache = await caches.open(CACHE_NAME);
            await cache.put(request, response);
            console.log(`🔄 تم تحديث التخزين المؤقت: ${request.url}`);

            // إعلام الصفحة بالتحديث
            const clients = await self.clients.matchAll();
            clients.forEach((client) => {
                client.postMessage({
                    type: 'CACHE_UPDATED',
                    url: request.url,
                    timestamp: new Date().toISOString()
                });
            });
        }
    } catch (error) {
        // تجاهل الأخطاء في التحديث الخلفي
        console.debug(`⚠️ فشل تحديث التخزين المؤقت: ${request.url}`);
    }
}

// ============================================
// استقبال الرسائل
// ============================================

self.addEventListener('message', (event) => {
    console.log('📨 استقبال رسالة:', event.data);

    if (!event.data || !event.data.type) return;

    switch (event.data.type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;

        case 'CLEAR_CACHE':
            caches.delete(CACHE_NAME)
                .then(() => {
                    console.log('🧹 تم مسح التخزين المؤقت');
                    if (event.ports && event.ports[0]) {
                        event.ports[0].postMessage({ success: true });
                    }
                });
            break;

        case 'GET_CACHE_INFO':
            caches.open(CACHE_NAME)
                .then((cache) => cache.keys())
                .then((requests) => {
                    if (event.ports && event.ports[0]) {
                        event.ports[0].postMessage({
                            cacheName: CACHE_NAME,
                            version: CACHE_VERSION,
                            cachedItems: requests.length,
                            totalSize: 'يتم الحساب...'
                        });
                    }
                });
            break;

        case 'UPDATE_CACHE':
            this.updateCache();
            break;
    }
});

// ============================================
// تحديث التخزين المؤقت
// ============================================

async function updateCache() {
    console.log('🔄 بدء تحديث التخزين المؤقت');

    try {
        const cache = await caches.open(CACHE_NAME);

        for (const url of [...CORE_FILES, ...EXTERNAL_FILES]) {
            try {
                const response = await fetch(url, { cache: 'no-store' });
                if (response.ok) {
                    await cache.put(url, response);
                    console.log(`✅ تم تحديث: ${url}`);
                }
            } catch (error) {
                console.warn(`⚠️ فشل تحديث ${url}:`, error);
            }
        }

        console.log('✅ اكتمل تحديث التخزين المؤقت');

        // إعلام الصفحة
        const clients = await self.clients.matchAll();
        clients.forEach((client) => {
            client.postMessage({
                type: 'CACHE_UPDATE_COMPLETE',
                timestamp: new Date().toISOString()
            });
        });

    } catch (error) {
        console.error('❌ فشل تحديث التخزين المؤقت:', error);
    }
}

// ============================================
// دورة حياة التخزين المؤقت
// ============================================

self.addEventListener('activate', (event) => {
    // تنظيف التخزين المؤقت القديم
    event.waitUntil(
        (async () => {
            // حذف التخزين المؤقت الأقدم من أسبوع
            const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);

            const cache = await caches.open(CACHE_NAME);
            const requests = await cache.keys();

            await Promise.all(
                requests.map(async (request) => {
                    const response = await cache.match(request);
                    if (response) {
                        const date = response.headers.get('date');
                        if (date && new Date(date).getTime() < oneWeekAgo) {
                            await cache.delete(request);
                            console.log(`🗑️ حذف الملف القديم: ${request.url}`);
                        }
                    }
                })
            );
        })()
    );
});

// ============================================
// تسجيل الأخطاء
// ============================================

self.addEventListener('error', (event) => {
    console.error('Service Worker Error:', event.error);
});

self.addEventListener('unhandledrejection', (event) => {
    console.error('Service Worker Unhandled Rejection:', event.reason);
});

// ============================================
// التنبيهات (إذا تم تفعيلها)
// ============================================

self.addEventListener('push', (event) => {
    if (!event.data) return;

    const data = event.data.json();

    const options = {
        body: data.body || 'تحديث جديد متاح',
        icon: 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22 fill=%22%232563eb%22>🔐</text></svg>',
        badge: 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22 fill=%22%232563eb%22>🔐</text></svg>',
        tag: 'encryption-update',
        renotify: true,
        actions: [
            {
                action: 'open',
                title: 'فتح'
            },
            {
                action: 'dismiss',
                title: 'تجاهل'
            }
        ]
    };

    event.waitUntil(
        self.registration.showNotification(data.title || 'نظام التشفير', options)
    );
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    if (event.action === 'open') {
        event.waitUntil(
            clients.openWindow('./')
        );
    }
});

// ============================================
// تسجيل الخدمة
// ============================================

console.log(`✅ ${APP_NAME} Service Worker v${CACHE_VERSION} - جاهز للعمل`);
