// ============================================
// Service Worker لـ GitHub Pages
// ============================================

const CACHE_NAME = 'github-pages-encryption-system-v3';
const CACHE_VERSION = '3.0.0';
const GITHUB_PAGES = true;

// الملفات التي سيتم تخزينها مؤقتاً
const urlsToCache = [
  './',
  './index.html',
  './style.css',
  './script.js',
  './manifest.json',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
];

// ============================================
// التثبيت
// ============================================

self.addEventListener('install', event => {
  console.log('🚀 Installing Service Worker for GitHub Pages');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('📦 Opening cache:', CACHE_NAME);
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('✅ All resources cached');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('❌ Cache installation failed:', error);
      })
  );
});

// ============================================
// التفعيل
// ============================================

self.addEventListener('activate', event => {
  console.log('⚡ Activating Service Worker');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            // حذف التخزين المؤقت القديم
            if (cacheName !== CACHE_NAME) {
              console.log(`🗑️ Deleting old cache: ${cacheName}`);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('✅ Service Worker activated for GitHub Pages');
        return self.clients.claim();
      })
  );
});

// ============================================
// اعتراض الطلبات
// ============================================

self.addEventListener('fetch', event => {
  // تجاهل الطلبات غير GET
  if (event.request.method !== 'GET') return;

  // فقط الطلبات من نفس المصدر لـ GitHub Pages
  const isSameOrigin = event.request.url.startsWith(self.location.origin);
  const isFontAwesome = event.request.url.includes('cdnjs.cloudflare.com');
  
  if (!isSameOrigin && !isFontAwesome) {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // إذا وجد في التخزين المؤقت
        if (response) {
          console.log(`🔍 Cache hit: ${event.request.url}`);
          return response;
        }

        // إذا لم يوجد، جلب من الشبكة
        console.log(`🌐 Fetching from network: ${event.request.url}`);
        
        return fetch(event.request)
          .then(response => {
            // التحقق من صحة الاستجابة
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }

            // استنساخ الاستجابة للتخزين
            const responseToCache = response.clone();

            // تخزين في الكاش
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
                console.log(`💾 Cached: ${event.request.url}`);
              });

            return response;
          })
          .catch(error => {
            console.error('❌ Fetch failed:', error);
            
            // في حالة الفشل، إرجاع الصفحة الرئيسية للطلبات التصفحية
            if (event.request.headers.get('accept').includes('text/html')) {
              return caches.match('./index.html');
            }
            
            return new Response(
              JSON.stringify({
                error: 'Network error',
                message: 'GitHub Pages - فشل الاتصال بالشبكة',
                offline: true
              }),
              {
                status: 503,
                headers: { 'Content-Type': 'application/json' }
              }
            );
          });
      })
  );
});

// ============================================
// استقبال الرسائل
// ============================================

self.addEventListener('message', event => {
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data.type === 'CLEAR_CACHE') {
    caches.delete(CACHE_NAME)
      .then(success => {
        console.log('🧹 Cache cleared for GitHub Pages');
        event.ports[0].postMessage({ success: success });
      });
  }
  
  if (event.data.type === 'GET_CACHE_INFO') {
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.keys();
      })
      .then(requests => {
        event.ports[0].postMessage({
          cacheName: CACHE_NAME,
          version: CACHE_VERSION,
          isGitHubPages: GITHUB_PAGES,
          cachedItems: requests.length
        });
      });
  }
});

// ============================================
// تحديث الخلفية
// ============================================

async function updateCache() {
  try {
    const cache = await caches.open(CACHE_NAME);
    
    for (const url of urlsToCache) {
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (response.ok) {
          await cache.put(url, response);
          console.log(`🔄 Updated cache for: ${url}`);
        }
      } catch (error) {
        console.error(`Failed to update ${url}:`, error);
      }
    }
    
    console.log('✅ GitHub Pages cache update completed');
  } catch (error) {
    console.error('GitHub Pages cache update failed:', error);
  }
}

// ============================================
// إدارة الذاكرة
// ============================================

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          return caches.open(cacheName)
            .then(cache => {
              return cache.keys()
                .then(requests => {
                  const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000);
                  
                  return Promise.all(
                    requests.map(request => {
                      return cache.match(request)
                        .then(response => {
                          if (response) {
                            const date = new Date(response.headers.get('date'));
                            if (date && date.getTime() < cutoff) {
                              return cache.delete(request);
                            }
                          }
                        });
                    })
                  );
                });
            });
        })
      );
    })
  );
});

// ============================================
// الوضع دون اتصال لـ GitHub Pages
// ============================================

self.addEventListener('fetch', event => {
  // إذا كان الطلب لصفحة HTML وحدث خطأ، عرض صفحة عدم الاتصال
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          return caches.match('./index.html')
            .then(response => {
              if (response) {
                return response;
              }
              // صفحة عدم الاتصال مخصصة
              return new Response(
                `
                <!DOCTYPE html>
                <html lang="ar" dir="rtl">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>نظام التشفير - وضع عدم الاتصال</title>
                    <style>
                        body { font-family: Arial; text-align: center; padding: 50px; }
                        h1 { color: #666; }
                    </style>
                </head>
                <body>
                    <h1>🔌 وضع عدم الاتصال</h1>
                    <p>أنت غير متصل بالإنترنت. نظام التشفير يعمل محلياً.</p>
                    <p>يمكنك استخدام الميزات الأساسية.</p>
                </body>
                </html>
                `,
                {
                  headers: { 'Content-Type': 'text/html' }
                }
              );
            });
        })
    );
  }
});

// ============================================
// تسجيل الأخطاء
// ============================================

self.addEventListener('error', event => {
  console.error('Service Worker Error:', event.error);
});

self.addEventListener('unhandledrejection', event => {
  console.error('Service Worker Unhandled Rejection:', event.reason);
});
