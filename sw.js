// اسم التخزين المؤقت
const CACHE_NAME = 'encryption-system-v1';

// الملفات التي سيتم تخزينها مؤقتًا
const urlsToCache = [
  './',
  './index.html',
  './style.css',
  './script.js',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  './manifest.json'
];

// تثبيت Service Worker وتخزين الملفات المؤقتة
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('تم فتح التخزين المؤقت');
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting())
  );
});

// تفعيل Service Worker وحذف التخزين المؤقت القديم
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
    .then(() => self.clients.claim())
  );
});

// اعتراض الطلبات وتقديمها من التخزين المؤقت
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // إذا وجدت الملف في التخزين المؤقت، قم بإرجاعه
        if (response) {
          return response;
        }

        // إذا لم يكن موجودًا، قم بتنزيله من الشبكة
        return fetch(event.request)
          .then(response => {
            // تحقق مما إذا كانت الاستجابة صالحة
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }

            // استنساخ الاستجابة
            const responseToCache = response.clone();

            // فتح التخزين المؤقت وحفظ الاستجابة
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });

            return response;
          })
          .catch(() => {
            // في حالة الفشل، يمكن إرجاع صفحة بديلة
            if (event.request.headers.get('accept').includes('text/html')) {
              return caches.match('./index.html');
            }
          });
      })
  );
});
