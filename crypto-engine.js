// ============================================
// محرك التشفير السيادي (Sovereign Grade Crypto Engine)
// v6.0: AES-GCM + ChaCha20-Poly1305
// HKDF Key Separation + AAD Binding + Header HMAC Signature
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            // المعلمات الرئيسية
            master: {
                algorithm: 'Argon2id',
                memoryCost: 1572864, // 1.5 GB
                parallelism: 1,
                iterations: 2,
                hashLength: 32, // 256-bit Master Secret
                saltLength: 32
            },

            // الطبقة الداخلية
            inner: {
                algorithm: 'AES-GCM',
                ivLength: 12,
                keyLength: 256
            },

            // الطبقة الخارجية
            outer: {
                algorithm: 'ChaCha20-Poly1305',
                ivLength: 12,
                keyLength: 256
            },

            // نزاهة الهيكل
            integrity: {
                algorithm: 'HMAC',
                hash: 'SHA-256'
            }
        };

        this.crypto = window.crypto.subtle;
        this.chachaSupported = false;
        this.supportCheckPromise = this.checkChaChaSupport();

        console.log('🚀 محرك التشفير السيادي (Sovereign v6.0) جاهز للعمل');
        console.log('🔒 HKDF Key Separation | AAD Binding | Structure Hardening');
    }

    async checkChaChaSupport() {
        try {
            const key = await this.crypto.generateKey(
                { name: 'ChaCha20-Poly1305', length: 256 },
                true, ['encrypt', 'decrypt']
            );
            this.chachaSupported = true;
            this.useExternalChaCha = false;
            console.log('✅ ChaCha20-Poly1305 مدعوم محلياً (Native)');
        } catch (e) {
            if (typeof window.chacha20poly1305 !== 'undefined') {
                this.chachaSupported = true;
                this.useExternalChaCha = true;
                console.log('✅ ChaCha20-Poly1305 مدعوم عبر المكتبة الخارجية (Polyfill)');
            } else {
                console.error('❌ ChaCha20 غير مدعوم نهائياً! النظام لا يمكنه العمل.');
                this.chachaSupported = false;
            }
        }
    }

    // ===== التشفير السيادي =====
    async encrypt(plainText, password, options = {}) {
        try {
            if (!plainText || !password) throw new Error('البيانات ناقصة');
            if (typeof hashwasm === 'undefined') throw new Error('مكتبة Argon2id غير محملة');
            await this.supportCheckPromise; // منع تعارض السباق

            const startTime = performance.now();

            // 1. توليد الملح الرئيسي (Master Salt)
            const masterSalt = this.generateRandomBytes(this.config.master.saltLength);

            // 2. اشتقاق السر الرئيسي (Master Secret) - الكلفة العالية هنا
            console.log('🔨 جاري اشتقاق السر الرئيسي (Argon2id 1.5GB)...');
            const masterSecret = await this.deriveMasterSecret(password, masterSalt);

            // 3. اشتقاق المفاتيح الفرعية (HKDF Separation)
            console.log('🔑 جاري فصل المفاتيح (HKDF-SHA256)...');
            const keys = await this.deriveSubKeys(masterSecret);

            // تنظيف السر الرئيسي من الذاكرة (محاولة)
            masterSecret.fill(0);

            // 4. تجهيز البيانات والضغط
            let dataPayload;
            if (options.compression) {
                dataPayload = new Uint8Array(await this.compressString(plainText));
            } else {
                dataPayload = new TextEncoder().encode(plainText);
            }

            // 5. الطبقة الداخلية (AES-GCM) مع AAD
            const innerIV = this.generateRandomBytes(this.config.inner.ivLength);
            // Binding Context: v6.0 | Inner
            const innerAAD = new TextEncoder().encode('v6.0|AES-GCM|Inner');

            const innerCipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                keys.innerKey,
                dataPayload
            );

            // 6. الطبقة الخارجية (ChaCha20-Poly1305) مع AAD
            const outerIV = this.generateRandomBytes(this.config.outer.ivLength);
            // Binding Context: v6.0 | Outer | Timestamp
            const timestamp = Date.now();
            const outerAAD = new TextEncoder().encode(`v6.0|ChaCha20|Outer|${timestamp}`);

            let finalCipher;
            if (this.useExternalChaCha) {
                // Polyfill handling
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                finalCipher = chacha.encrypt(new Uint8Array(innerCipher));
            } else {
                finalCipher = await this.crypto.encrypt(
                    { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                    keys.outerKey,
                    innerCipher
                );
            }

            // 7. بناء الهيكل (Structure)
            const header = {
                v: '6.0',
                ts: timestamp,
                ms: this.arrayToBase64(masterSalt), // Master Salt
                iiv: this.arrayToBase64(innerIV),   // Inner IV
                oiv: this.arrayToBase64(outerIV),   // Outer IV
                algo: 'Argon2id+HKDF|AES-GCM|ChaCha20'
            };

            // 8. توقيع الهيكل (HMAC Integrity)
            const headerString = JSON.stringify(header);
            const headerBytes = new TextEncoder().encode(headerString);
            const signature = await this.crypto.sign(
                'HMAC',
                keys.integrityKey,
                headerBytes
            );

            // 9. الخرج النهائي
            const result = {
                header: header,
                sig: this.arrayToBase64(signature),
                data: this.arrayToBase64(finalCipher),
                performance: {
                    time: Math.round(performance.now() - startTime),
                    memory: '1.5GB (Argon2id)'
                }
            };

            return result;

        } catch (error) {
            console.error('❌ خطأ في التشفير السيادي:', error);
            throw error;
        }
    }

    // ===== فك التشفير السيادي =====
    async decrypt(encryptedData, password) {
        try {
            // معالجة البيانات
            let data = encryptedData;
            if (typeof data === 'string') {
                try { data = JSON.parse(data); } catch { throw new Error('تنسيق البيانات تالف'); }
            }

            // التحقق من الإصدار
            if (!data.header || data.header.v !== '6.0') {
                // دعم v5.0 القديم إذا لزم الأمر، لكننا الآن "Sovereign Only"
                throw new Error('إصدار غير مدعوم. هذا النظام يقبل فقط ملفات Sovereign v6.0');
            }

            const startTime = performance.now();

            // 1. استخراج المتغيرات الأساسية
            const masterSalt = this.base64ToArray(data.header.ms);
            const signature = this.base64ToArray(data.sig);
            const ciphertext = this.base64ToArray(data.data);

            // 2. اشتقاق المفاتيح مجدداً
            console.log('🔓 جاري اشتقاق المفاتيح (Argon2id + HKDF)...');
            const masterSecret = await this.deriveMasterSecret(password, masterSalt);
            const keys = await this.deriveSubKeys(masterSecret);
            masterSecret.fill(0); // Wipe

            // 3. التحقق من سلامة الهيكل (Signature Verification)
            const headerString = JSON.stringify(data.header);
            const headerBytes = new TextEncoder().encode(headerString);

            const isValid = await this.crypto.verify(
                'HMAC',
                keys.integrityKey,
                signature,
                headerBytes
            );

            if (!isValid) {
                throw new Error('⛔ كشف محاولة تلاعب! توقيع الملف (HMAC) غير صحيح. قد يكون الملف معدلاً.');
            }
            console.log('✅ توقيع الهيكل سليم.');

            // 4. فك الطبقة الخارجية (ChaCha20) مع التحقق من AAD
            const outerIV = this.base64ToArray(data.header.oiv);
            const timestamp = data.header.ts;
            const outerAAD = new TextEncoder().encode(`v6.0|ChaCha20|Outer|${timestamp}`);

            let innerCipher;
            if (this.useExternalChaCha) {
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                try {
                    innerCipher = chacha.decrypt(new Uint8Array(ciphertext));
                } catch (e) { throw new Error('فشل فك الطبقة الخارجية (ChaCha20): ' + e.message); }
            } else {
                try {
                    innerCipher = await this.crypto.decrypt(
                        { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                        keys.outerKey,
                        ciphertext
                    );
                } catch (e) { throw new Error('فشل فك الطبقة الخارجية (Auth Tag Mismatch - AAD Error).'); }
            }

            // 5. فك الطبقة الداخلية (AES-GCM) مع التحقق من AAD
            const innerIV = this.base64ToArray(data.header.iiv);
            const innerAAD = new TextEncoder().encode('v6.0|AES-GCM|Inner');

            let plainBuffer;
            try {
                plainBuffer = await this.crypto.decrypt(
                    { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                    keys.innerKey,
                    innerCipher
                );
            } catch (e) { throw new Error('فشل فك الطبقة الداخلية (AES-GCM Integrity Fail - AAD Error).'); }

            // 6. فك الضغط
            let plainText;
            const plainBytes = new Uint8Array(plainBuffer);
            if (plainBytes.length > 2 && plainBytes[0] === 0x1f && plainBytes[1] === 0x8b) {
                try { plainText = await this.decompressString(plainBytes); }
                catch { plainText = new TextDecoder().decode(plainBytes); }
            } else {
                plainText = new TextDecoder().decode(plainBytes);
            }

            return {
                text: plainText,
                integrity: true,
                metadata: {
                    version: '6.0 (Sovereign)',
                    timestamp: timestamp,
                    security: 'Argon2id + HKDF + AAD'
                },
                performance: { time: Math.round(performance.now() - startTime) }
            };

        } catch (error) {
            console.error('❌ خطأ في فك التشفير:', error);
            throw error;
        }
    }

    // ===== عمليات الاشتقاق (Key Derivation Functions) =====

    // 1. Argon2id: Password + Salt -> Master Secret
    async deriveMasterSecret(password, salt) {
        const result = await hashwasm.argon2id({
            password: password,
            salt: new Uint8Array(salt),
            parallelism: this.config.master.parallelism,
            iterations: this.config.master.iterations,
            memorySize: this.config.master.memoryCost,
            hashLength: this.config.master.hashLength,
            outputType: 'binary'
        });
        return result; // Uint8Array
    }

    // 2. HKDF: Master Secret -> Sub-Keys
    async deriveSubKeys(masterSecret) {
        // استيراد السر الرئيسي كمفتاح أولي (IKM)
        const masterKey = await this.crypto.importKey(
            'raw', masterSecret, 'HKDF', false, ['deriveKey', 'deriveBits']
        );

        // -- المفتاح الداخلي (Inner - AES-GCM) --
        const innerKey = await this.crypto.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(0),
                info: new TextEncoder().encode('v6-inner-aes-gcm') // Context Binding
            },
            masterKey,
            { name: 'AES-GCM', length: 256 },
            false, ['encrypt', 'decrypt']
        );

        // -- المفتاح الخارجي (Outer - ChaCha20) --
        let outerKey;
        if (this.useExternalChaCha) {
            // اشتقاق كـ Raw Bits للـ Polyfill
            const bits = await this.crypto.deriveBits(
                {
                    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
                    info: new TextEncoder().encode('v6-outer-chacha20')
                },
                masterKey,
                256
            );
            outerKey = await this.crypto.importKey('raw', bits, 'ChaCha20-Poly1305', true, ['encrypt', 'decrypt']);
        } else {
            outerKey = await this.crypto.deriveKey(
                {
                    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
                    info: new TextEncoder().encode('v6-outer-chacha20')
                },
                masterKey,
                { name: 'ChaCha20-Poly1305' },
                false, ['encrypt', 'decrypt']
            );
        }

        // -- مفتاح النزاهة (Integrity - HMAC) --
        const integrityKey = await this.crypto.deriveKey(
            {
                name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
                info: new TextEncoder().encode('v6-header-integrity')
            },
            masterKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false, ['sign', 'verify']
        );

        return { innerKey, outerKey, integrityKey };
    }

    // ===== أدوات مساعدة =====
    generateRandomBytes(len) { return window.crypto.getRandomValues(new Uint8Array(len)); }
    async exportRawKey(key) { return await this.crypto.exportKey('raw', key); }

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
}

// تصدير
window.CryptoEngine = CryptoEngine;
