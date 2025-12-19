// اسم التخزين المؤقت
const CACHE_NAME = 'advanced-encryption-system-v3';
const CACHE_VERSION = '3.0.0';

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
// تثبيت Service Worker
// ============================================

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log(`📦 Installing Cache: ${CACHE_NAME} v${CACHE_VERSION}`);
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('✅ Cache installed successfully');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('❌ Cache installation failed:', error);
      })
  );
});

// ============================================
// تفعيل Service Worker
// ============================================

self.addEventListener('activate', event => {
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
        console.log('✅ Service Worker activated');
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

  // تجاهل الطلبات من مصادر مختلفة (Cross-Origin)
  if (!event.request.url.startsWith(self.location.origin)) {
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
            
            // في حالة الفشل، إرجاع صفحة بديلة
            if (event.request.headers.get('accept').includes('text/html')) {
              return caches.match('./index.html');
            }
            
            // للطلبات الأخرى، إرجاع رسالة خطأ
            return new Response(
              JSON.stringify({
                error: 'Network error',
                message: 'فشل الاتصال بالشبكة'
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
        console.log('🧹 Cache cleared');
        event.ports[0].postMessage({ success: success });
      });
  }
});

// ============================================
// تحديث الخلفية
// ============================================

self.addEventListener('periodicsync', event => {
  if (event.tag === 'update-cache') {
    event.waitUntil(updateCache());
  }
});

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
    
    console.log('✅ Cache update completed');
  } catch (error) {
    console.error('Cache update failed:', error);
  }
}

// ============================================
// إدارة الذاكرة
// ============================================

self.addEventListener('activate', event => {
  // تنظيف التخزين المؤقت الزائد
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          return caches.open(cacheName)
            .then(cache => {
              return cache.keys()
                .then(requests => {
                  // حذف الملفات القديمة
                  const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 أيام
                  
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
// إعدادات الخصوصية
// ============================================

// لا نتعقب المستخدمين
self.addEventListener('fetch', event => {
  // منع تتبع التحليلات إذا لم يوافق المستخدم
  if (event.request.url.includes('analytics') || 
      event.request.url.includes('tracking') ||
      event.request.url.includes('google-analytics')) {
    event.respondWith(new Response(null, { status: 204 }));
    return;
  }
});

// ============================================
// وضع عدم الاتصال
// ============================================

// دعم وضع عدم الاتصال الكامل
self.addEventListener('fetch', event => {
  // إذا كان الطلب لصفحة HTML وحدث خطأ، عرض صفحة عدم الاتصال
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          return caches.match('./index.html');
        })
    );
  }
});

// ============================================
// الأمان
// ============================================

// منع هجمات XSS
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // إضافة رؤوس الأمان
        const secureResponse = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: new Headers(response.headers)
        });
        
        Object.entries(securityHeaders).forEach(([header, value]) => {
          secureResponse.headers.set(header, value);
        });
        
        return secureResponse;
      })
      .catch(error => {
        console.error('Security headers error:', error);
        return response;
      })
  );
});
