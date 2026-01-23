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
        this.checkChaChaSupport();

        console.log('🚀 محرك التشفير الهجين (Paranoid Mode) جاهز للعمل');
        console.log(`🔒 Argon2id Memory: ${this.config.layer1.memoryCost / 1024} MB`);
        console.log(`🔒 PBKDF2 Iterations: ${this.config.layer2.iterations}`);
    }

    async checkChaChaSupport() {
        try {
            const key = await this.crypto.generateKey(
                { name: 'ChaCha20-Poly1305', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            this.chachaSupported = true;
            console.log('✅ ChaCha20-Poly1305 مدعوم محلياً');
        } catch (e) {
            console.warn('⚠️ ChaCha20-Poly1305 غير مدعوم، سيتم استخدام AES-CTR كطبقة ثانية (IV: 16 bytes)');
            this.config.layer2.algorithm = 'AES-CTR'; // Fallback
            this.config.layer2.ivLength = 16;
        }
    }

    // ===== التشفير المتسلسل =====
    async encrypt(plainText, password, options = {}) {
        try {
            if (!plainText || !password) throw new Error('البيانات ناقصة');
            if (typeof hashwasm === 'undefined') throw new Error('مكتبة Argon2id (hash-wasm) غير محملة');

            const startTime = performance.now();

            // 1. توليد الأملاح
            const salt1 = this.generateRandomBytes(16);
            const salt2 = this.generateRandomBytes(32);

            // 2. اشتقاق المفاتيح (توازي)
            console.log('🔨 جاري اشتقاق المفاتيح الهجينة...');
            const [key1Data, key2Data] = await Promise.all([
                this.deriveKeyArgon2id(password, salt1),
                this.deriveKeyPBKDF2(password, salt2)
            ]);

            // استيراد المفاتيح لـ Web Crypto
            const key1 = await this.importKey(key1Data, this.config.layer1.algorithm);
            const key2 = await this.importKey(key2Data, this.config.layer2.algorithm);

            // 3. التشفير الطبقة 1 (الداخلي): AES-256-GCM
            const iv1 = this.generateRandomBytes(12);
            // ضغط وتشفير (الطبقة 1 - AES-GCM)
            let dataToEncrypt;
            if (options.compression) {
                const compressed = await this.compressString(plainText);
                dataToEncrypt = new Uint8Array(compressed);
            } else {
                dataToEncrypt = new TextEncoder().encode(plainText);
            }

            const layer1Cipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: iv1 },
                key1,
                dataToEncrypt
            );

            // 4. التشفير الطبقة 2 (الخارجي): ChaCha20 أو AES-CTR
            const layer2Algorithm = this.chachaSupported ? 'ChaCha20-Poly1305' : 'AES-CTR';

            // تحديد طول IV بناءً على الخوارزمية
            // ChaCha20: 12 bytes
            // AES-CTR: 16 bytes
            const ivLength = this.chachaSupported ? 12 : 16;
            const iv2 = this.generateRandomBytes(ivLength);

            const layer2Params = this.chachaSupported ?
                { name: 'ChaCha20-Poly1305', iv: iv2 } :
                { name: 'AES-CTR', counter: iv2, length: 64 };

            const finalCipher = await this.crypto.encrypt(
                layer2Params,
                key2,
                layer1Cipher // تشفير الناتج السابق
            );

            // 5. بناء التقرير النهائي
            const encryptedData = {
                version: '4.0-HYBRID',
                timestamp: Date.now(),
                layers: {
                    outer: {
                        algo: layer2Algorithm,
                        iv: this.arrayToBase64(iv2),
                        salt: this.arrayToBase64(salt2), // Salt for PBKDF2
                        iter: this.config.layer2.iterations
                    },
                    inner: {
                        algo: 'AES-GCM',
                        iv: this.arrayToBase64(iv1),
                        salt: this.arrayToBase64(salt1), // Salt for Argon2id
                        mem: this.config.layer1.memoryCost
                    }
                },
                ciphertext: this.arrayToBase64(finalCipher)
            };

            const endTime = performance.now();

            // إضافة معلومات الأداء
            encryptedData.performance = {
                time: Math.round(endTime - startTime),
                argon2Memory: this.config.layer1.memoryCost
            };

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

            // معالجة الإصدار v4.0-HYBRID
            let data = encryptedData;
            if (typeof data === 'string') {
                try { data = JSON.parse(data); } catch { throw new Error('تنسيق البيانات غير صالح'); }
            }

            if (!data.version || !data.version.includes('HYBRID')) {
                // محاولة ذكية لكشف الإصدار
                if (data.salt && data.iv && data.ciphertext && !data.layers) {
                    return this.decryptLegacyV3(data, password);
                }
                throw new Error('إصدار غير مدعوم أو بيانات تالفة');
            }

            const startTime = performance.now();

            // 1. استخراج المتغيرات
            const salt1 = this.base64ToArray(data.layers.inner.salt);
            const salt2 = this.base64ToArray(data.layers.outer.salt);
            const iv1 = this.base64ToArray(data.layers.inner.iv);
            const iv2 = this.base64ToArray(data.layers.outer.iv);
            const ciphertext = this.base64ToArray(data.ciphertext);

            // 2. اشتقاق المفاتيح
            console.log('🔓 جاري اشتقاق المفاتيح لفك التشفير...');
            const [key1Data, key2Data] = await Promise.all([
                this.deriveKeyArgon2id(password, salt1, data.layers.inner.mem),
                this.deriveKeyPBKDF2(password, salt2, data.layers.outer.iter)
            ]);

            const key1 = await this.importKey(key1Data, 'AES-GCM');
            const key2 = await this.importKey(key2Data, data.layers.outer.algo);

            // 3. فك الطبقة الخارجية (ChaCha/AES-CTR)
            const layer2Params = data.layers.outer.algo === 'ChaCha20-Poly1305' ?
                { name: 'ChaCha20-Poly1305', iv: iv2 } :
                { name: 'AES-CTR', counter: iv2, length: 64 };

            const innerCipher = await this.crypto.decrypt(
                layer2Params,
                key2,
                ciphertext
            );

            // 4. فك الطبقة الداخلية (AES-GCM)
            const decrypted = await this.crypto.decrypt(
                { name: 'AES-GCM', iv: iv1 },
                key1,
                innerCipher
            );

            // فك التشفير والضغط
            const decryptedBytes = new Uint8Array(decrypted);
            let plainText;

            // محاولة فك الضغط (GZIP magic bytes: 0x1f 0x8b)
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
                    security: 'Paranoid (Hybrid)'
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
