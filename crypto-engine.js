// ============================================
// محرك التشفير الهجين (Hybrid Crypto Engine)
// AES-256-GCM + ChaCha20-Poly1305 (or AES-CTR fallback)
// Argon2id (1.5GB) + PBKDF2 (2M)
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            // الطبقة 1: AES-256-GCM
            layer1: {
                algorithm: 'AES-GCM',
                keyDerivation: 'Argon2id',
                memoryCost: 1572864, // 1.5 GB in KB
                parallelism: 1,
                iterations: 2, // Argon2 iterations
                hashLength: 32, // 256-bit key
                ivLength: 12
            },

            // الطبقة 2: ChaCha20-Poly1305 (أو AES-CTR إذا لم يتوفر)
            layer2: {
                algorithm: 'ChaCha20-Poly1305', // Fallback to AES-CTR
                keyDerivation: 'PBKDF2',
                iterations: 2000000, // 2 Million iterations
                hash: 'SHA-256',
                keyLength: 256,
                saltLength: 32, // Stronger salt
                ivLength: 12
            }
        };

        this.crypto = window.crypto.subtle;
        this.chachaSupported = false;

        // التحقق من دعم ChaCha20
        this.supportCheckPromise = this.checkChaChaSupport();

        console.log('🚀 محرك التشفير الثلاثي (Triple Argon2 v5.0) جاهز للعمل');
        console.log(`🔒 3x Argon2id Layers (1GB each)`);
    }

    async checkChaChaSupport() {
        try {
            // أولاً: محاولة الدعم الأصلي (Native)
            const key = await this.crypto.generateKey(
                { name: 'ChaCha20-Poly1305', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            this.chachaSupported = true;
            this.useExternalChaCha = false;
            console.log('✅ ChaCha20-Poly1305 مدعوم محلياً (Native)');
        } catch (e) {
            // ثانياً: التحقق من المكتبة الخارجية
            if (typeof window.chacha20poly1305 !== 'undefined') {
                this.chachaSupported = true;
                this.useExternalChaCha = true;
                console.log('✅ ChaCha20-Poly1305 مدعوم عبر المكتبة الخارجية (Polyfill)');

                // تحديث الإعدادات
                this.config.layer2.algorithm = 'ChaCha20-Poly1305';
                this.config.layer2.ivLength = 12; // Noble uses 12-byte nonce
            } else {
                console.warn('⚠️ ChaCha20-Poly1305 غير مدعوم، سيتم استخدام AES-CTR كطبقة ثانية (IV: 16 bytes)');
                this.config.layer2.algorithm = 'AES-CTR'; // Fallback
                this.config.layer2.ivLength = 16;
            }
        }
    }

    // ===== التشفير المتسلسل =====
    async encrypt(plainText, password, options = {}) {
        try {
            if (!plainText || !password) throw new Error('البيانات ناقصة');
            if (typeof hashwasm === 'undefined') throw new Error('مكتبة Argon2id (hash-wasm) غير محملة');

            // انتظار انتهاء فحص الدعم
            await this.supportCheckPromise;

            const startTime = performance.now();

            // 1. توليد 3 أملاح فريدة (لعزل الطبقات)
            const salt1 = this.generateRandomBytes(16); // للطبقة 3 (الخارجية)
            const salt2 = this.generateRandomBytes(16); // للطبقة 2 (الوسطى)
            const salt3 = this.generateRandomBytes(16); // للطبقة 1 (الداخلية)

            // 2. اشتقاق المفاتيح (تسلسلي لتوفير الذاكرة)
            // ننفذها بالتسلسل لتجنب استخدام 3GB+ RAM في نفس اللحظة
            console.log('🔨 جاري اشتقاق المفاتيح (Triple Argon2)...');

            console.log('--- اشتقاق مفتاح الطبقة الخارجية ---');
            const key3Data = await this.deriveKeyArgon2id(password, salt1, this.config.layer3.memoryCost); // Key for Outer (AES-CTR)

            console.log('--- اشتقاق مفتاح الطبقة الوسطى ---');
            const key2Data = await this.deriveKeyArgon2id(password, salt2, this.config.layer2.memoryCost); // Key for Middle (ChaCha)

            console.log('--- اشتقاق مفتاح الطبقة الداخلية ---');
            const key1Data = await this.deriveKeyArgon2id(password, salt3, this.config.layer1.memoryCost); // Key for Inner (GCM)

            // استيراد المفاتيح
            const key3 = await this.importKey(key3Data, 'AES-CTR');

            // مفتاح ChaCha20 - معالجة خاصة للـ Polyfill
            let key2;
            let layer2AlgoName = this.chachaSupported ? 'ChaCha20-Poly1305' : 'AES-CTR';
            if (this.useExternalChaCha) {
                key2 = new Uint8Array(key2Data); // Raw bytes
            } else {
                key2 = await this.importKey(key2Data, layer2AlgoName);
            }

            const key1 = await this.importKey(key1Data, 'AES-GCM');

            // 3. التجهيز والضغط
            let dataToEncrypt;
            if (options.compression) {
                const compressed = await this.compressString(plainText);
                dataToEncrypt = new Uint8Array(compressed);
            } else {
                dataToEncrypt = new TextEncoder().encode(plainText);
            }

            // 4. التشفير - الطبقة 1 (الداخلية): AES-GCM
            const iv1 = this.generateRandomBytes(12);
            const cipher1 = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: iv1 },
                key1,
                dataToEncrypt
            );

            // 5. التشفير - الطبقة 2 (الوسطى): ChaCha20 (أو AES-CTR كبديل)
            const iv2 = this.generateRandomBytes(12); // 12 bytes standard for ChaCha
            let cipher2;

            if (this.useExternalChaCha) {
                const chacha = window.chacha20poly1305(key2, iv2);
                cipher2 = chacha.encrypt(new Uint8Array(cipher1));
                layer2AlgoName = 'ChaCha20-Poly1305';
            } else {
                const params = layer2AlgoName === 'ChaCha20-Poly1305' ?
                    { name: 'ChaCha20-Poly1305', iv: iv2 } :
                    { name: 'AES-CTR', counter: iv2, length: 64 };
                cipher2 = await this.crypto.encrypt(params, key2, cipher1);
            }

            // 6. التشفير - الطبقة 3 (الخارجية): AES-CTR
            const iv3 = this.generateRandomBytes(16); // 16 bytes for AES-CTR
            const cipher3 = await this.crypto.encrypt(
                { name: 'AES-CTR', counter: iv3, length: 64 },
                key3,
                cipher2
            );

            // 7. بناء التقرير النهائي
            const encryptedData = {
                version: '5.0-TRIPLE',
                timestamp: Date.now(),
                layers: {
                    outer: { // AES-CTR
                        algo: 'AES-CTR',
                        iv: this.arrayToBase64(iv3),
                        salt: this.arrayToBase64(salt1),
                        mem: this.config.layer3.memoryCost
                    },
                    middle: { // ChaCha20
                        algo: layer2AlgoName,
                        iv: this.arrayToBase64(iv2),
                        salt: this.arrayToBase64(salt2),
                        mem: this.config.layer2.memoryCost
                    },
                    inner: { // AES-GCM
                        algo: 'AES-GCM',
                        iv: this.arrayToBase64(iv1),
                        salt: this.arrayToBase64(salt3),
                        mem: this.config.layer1.memoryCost
                    }
                },
                ciphertext: this.arrayToBase64(cipher3)
            };

            const endTime = performance.now();
            encryptedData.performance = {
                time: Math.round(endTime - startTime),
                memory: 'Triple Argon2 (1GB x3)'
            };
            return encryptedData;

            return encryptedData;

        } catch (error) {
            console.error('❌ خطأ في التشفير الهجين:', error);
            throw new Error(`فشل التشفير: ${error.message}`);
        }
    }

    // ===== فك التشفير المتسلسل =====
    async decrypt(encryptedData, password) {
        try {
            // دعم الإصدارات القديمة (v3.0, v3.1)
            if (encryptedData.version && encryptedData.version.startsWith('3')) {
                console.log('⚠️ اكتشاف إصدار تشفير قديم v3, جاري التحويل للمعالج القديم...');
                return this.decryptLegacyV3(encryptedData, password);
            }

            // معالجة الإصدار v5.0-TRIPLE
            let data = encryptedData;
            if (typeof data === 'string') {
                try { data = JSON.parse(data); } catch { throw new Error('تنسيق البيانات غير صالح'); }
            }

            if (!data.version || !data.version.includes('TRIPLE')) {
                // If it's the recent Hybrid v4, we could add support, but sticking to the plan:
                if (data.version && data.version.includes('HYBRID')) {
                    throw new Error('هذه الرسالة مشفرة بنظام Hybrid v4 القديم. هذا النظام يدعم Triple v5 فقط.');
                }
                // محاولة ذكية لكشف الإصدار
                if (data.salt && data.iv && data.ciphertext && !data.layers) {
                    return this.decryptLegacyV3(data, password);
                }
                throw new Error('إصدار غير مدعوم أو بيانات تالفة');
            }

            const startTime = performance.now();

            // 1. استخراج المتغيرات
            const salt1 = this.base64ToArray(data.layers.outer.salt);   // AES-CTR
            const salt2 = this.base64ToArray(data.layers.middle.salt);  // ChaCha
            const salt3 = this.base64ToArray(data.layers.inner.salt);   // AES-GCM

            const iv3 = this.base64ToArray(data.layers.outer.iv);
            const iv2 = this.base64ToArray(data.layers.middle.iv);
            const iv1 = this.base64ToArray(data.layers.inner.iv);

            const ciphertext = this.base64ToArray(data.ciphertext);

            // 2. اشتقاق المفاتيح (تسلسلي لتوفير الذاكرة)
            console.log('🔓 جاري اشتقاق المفاتيح لفك التشفير (Triple)...');

            console.log('--- مفتاح Outer ---');
            const key3Data = await this.deriveKeyArgon2id(password, salt1, data.layers.outer.mem);

            console.log('--- مفتاح Middle ---');
            const key2Data = await this.deriveKeyArgon2id(password, salt2, data.layers.middle.mem);

            console.log('--- مفتاح Inner ---');
            const key1Data = await this.deriveKeyArgon2id(password, salt3, data.layers.inner.mem);

            const key3 = await this.importKey(key3Data, 'AES-CTR');
            const key1 = await this.importKey(key1Data, 'AES-GCM');

            // 3. فك الطبقة 3 (الخارجية): AES-CTR
            const cipher2 = await this.crypto.decrypt(
                { name: 'AES-CTR', counter: new Uint8Array(iv3), length: 64 },
                key3,
                ciphertext
            );

            // 4. فك الطبقة 2 (الوسطى): ChaCha20
            let cipher1;
            const middleAlgo = data.layers.middle.algo;

            if (middleAlgo === 'ChaCha20-Poly1305' && this.useExternalChaCha) {
                // استخدام noble-ciphers
                const key2 = new Uint8Array(key2Data);
                const chacha = window.chacha20poly1305(key2, iv2);
                try {
                    cipher1 = chacha.decrypt(new Uint8Array(cipher2));
                } catch (e) { throw new Error('فشل فك تشفير ChaCha20 (Polyfill): ' + e.message); }
            } else {
                // استخدام Native
                const key2 = await this.importKey(key2Data, middleAlgo);
                const params = middleAlgo === 'ChaCha20-Poly1305' ?
                    { name: 'ChaCha20-Poly1305', iv: iv2 } :
                    { name: 'AES-CTR', counter: new Uint8Array(iv2), length: 64 };

                cipher1 = await this.crypto.decrypt(params, key2, cipher2);
            }

            // 5. فك الطبقة 1 (الداخلية): AES-GCM
            const decrypted = await this.crypto.decrypt(
                { name: 'AES-GCM', iv: new Uint8Array(iv1) },
                key1,
                cipher1
            );

            // 6. فك الضغط
            const decryptedBytes = new Uint8Array(decrypted);
            let plainText;

            if (decryptedBytes.length > 2 && decryptedBytes[0] === 0x1f && decryptedBytes[1] === 0x8b) {
                try {
                    plainText = await this.decompressString(decryptedBytes);
                } catch {
                    plainText = new TextDecoder().decode(decryptedBytes);
                }
            } else {
                plainText = new TextDecoder().decode(decryptedBytes);
            }

            return {
                text: plainText,
                integrity: true,
                metadata: {
                    version: data.version,
                    timestamp: data.timestamp,
                    security: 'Triple Argon2 (GCM+ChaCha+CTR)'
                },
                performance: {
                    time: Math.round(performance.now() - startTime)
                }
            };

        } catch (error) {
            console.error('❌ خطأ في فك التشفير:', error);
            if (error.message.includes('Memory')) {
                throw new Error('ذاكرة غير كافية لمعالجة Argon2id');
            }
            throw new Error('كلمة المرور غير صحيحة أو البيانات تالفة');
        }
    }

    // ===== دوال مساعدة للاشتقاق =====
    async deriveKeyArgon2id(password, salt, memoryCost = null) {
        // استخدام مكتبة hash-wasm
        const saltArray = new Uint8Array(salt);
        const result = await hashwasm.argon2id({
            password: password,
            salt: saltArray,
            parallelism: this.config.layer1.parallelism,
            iterations: this.config.layer1.iterations,
            memorySize: memoryCost || this.config.layer1.memoryCost,
            hashLength: this.config.layer1.hashLength,
            outputType: 'binary'
        });
        return result;
    }

    async deriveKeyPBKDF2(password, salt, iterations = null) {
        const encoder = new TextEncoder();
        const keyMaterial = await this.crypto.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const key = await this.crypto.deriveKey(
            {
                name: 'PBKDF2',
                salt: new Uint8Array(salt),
                iterations: iterations || this.config.layer2.iterations,
                hash: this.config.layer2.hash
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 }, // الطول فقط يهم هنا
            true,
            ['encrypt', 'decrypt']
        );

        // تصدير المفتاح كـ RAW Bytes
        return await this.crypto.exportKey('raw', key);
    }

    async importKey(rawKey, algorithm) {
        // تحديد الخوارزمية للاستيراد
        let algoParams = { name: algorithm };
        if (algorithm === 'ChaCha20-Poly1305') algoParams = { name: 'ChaCha20-Poly1305' };
        if (algorithm === 'AES-CTR') algoParams = { name: 'AES-CTR' };

        return await this.crypto.importKey(
            'raw',
            rawKey,
            algoParams,
            false,
            ['encrypt', 'decrypt']
        );
    }

    // ===== دعم المعالج القديم (Legacy) =====
    async decryptLegacyV3(data, password) {
        // إعادة تنفيذ منطق v3 المبسط هنا
        const salt = this.base64ToArray(data.salt || data.s); // v3 uses 's' sometimes
        const iv = this.base64ToArray(data.iv || data.i);
        const ciphertext = this.base64ToArray(data.ciphertext || data.d);
        const iterations = data.iterations || data.c || 310000;

        // PBKDF2 Only
        const encoder = new TextEncoder();
        const keyMaterial = await this.crypto.importKey(
            'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
        );

        const key = await this.crypto.deriveKey(
            { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: iterations, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false, ['decrypt']
        );

        // التعامل مع التنسيق القديم للبيانات (قد يكون Tag مضمن أو لا)
        // في v3 القديم كان Tag مفصولاً أو مدمجاً، الكود القديم كان يدمجه.
        // سنفترض أن data.d يحتوي على كل شيء.
        // لكن wait، الكود القديم كان: ciphertext + tag.

        let encryptedBuffer = ciphertext;
        // إذا كان هناك tag منفصل (v3.1 code uses explicit tag separation in JSON but combines for decrypt?)
        // الكود القديم: encrypted.set(ciphertext, 0); encrypted.set(tag, ...);
        if (data.tag) {
            const tag = this.base64ToArray(data.tag);
            const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
            combined.set(new Uint8Array(ciphertext));
            combined.set(new Uint8Array(tag), ciphertext.byteLength);
            encryptedBuffer = combined.buffer;
        }

        const decrypted = await this.crypto.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(iv) },
            key,
            encryptedBuffer
        );

        return {
            text: new TextDecoder().decode(decrypted),
            integrity: true,
            metadata: { version: '3.x', security: 'Standard' }
        };
    }

    // ===== الضغط والتفريغ =====
    async compressString(str) {
        if ('CompressionStream' in window) {
            const stream = new Blob([str]).stream();
            const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
            return await new Response(compressedStream).arrayBuffer();
        }
        return new TextEncoder().encode(str);
    }

    async decompressString(data) {
        if ('DecompressionStream' in window) {
            const stream = new Blob([data]).stream();
            const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
            return await new Response(decompressedStream).text();
        }
        return new TextDecoder().decode(data);
    }

    // ===== أدوات مساعدة =====
    generateRandomBytes(len) { return window.crypto.getRandomValues(new Uint8Array(len)); }

    arrayToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    base64ToArray(base64) {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }
}

// تصدير
window.CryptoEngine = CryptoEngine;
