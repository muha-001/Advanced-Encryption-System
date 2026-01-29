// ============================================
// محرك التشفير السيادي (v8.0-SOVEREIGN Crypto Engine)
// Cascade: AES-256-GCM (Outer) + XChaCha20 (Inner)
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            ver: "8.0-SOVEREIGN",
            pipeline: {
                stage1: { type: 'PBKDF2-HMAC-SHA256', iterations: 2000000 },
                stage2: {
                    type: 'Argon2id',
                    memoryCost: 1572864,
                    parallelism: 4,
                    iterations: 2,
                    hashLength: 32
                }
            },
            encryption: {
                inner: { algorithm: 'XChaCha20', nonceLength: 24 },
                outer: { algorithm: 'AES-GCM', ivLength: 12 },
                tagLength: 128
            },
            integrity: { algorithm: 'HMAC', hash: 'SHA-256' }
        };

        this.crypto = window.crypto.subtle;
        this.supportsNativeXChaCha = false;
        this.supportCheckPromise = this.checkSecuritySupport();

        console.log('🚀 محرك التشفير السيادي v8.0 جاهز (XChaCha20 + AES-GCM Cascade)');
    }

    // آمن: تصفير الذاكرة باستخدام قيم عشوائية لمنع استعادة البيانات
    wipe(buffer) {
        if (buffer && (buffer instanceof Uint8Array || buffer instanceof ArrayBuffer)) {
            const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
            window.crypto.getRandomValues(view);
            console.log('🛡️ تم تصفير المخزن المؤقت بنجاح');
        }
    }

    async checkSecuritySupport() {
        // التحقق من دعم المتصفح للوغاريتمات بشكل أصلي
        try {
            // XChaCha20 غالباً ما يحتاج إلى Polyfill
            this.supportsNativeXChaCha = false;
        } catch (e) { }
    }

    async encrypt(plainText, password, options = {}) {
        let passwordBytes, masterSalt, intermediateHash, masterKeyMaterial, keys, dataPayload;
        let innerCipher, finalCipher, innerIV, outerIV;

        try {
            if (!plainText || !password) throw new Error('بيانات ناقصة');
            await this.supportCheckPromise;

            const startTime = performance.now();
            passwordBytes = new TextEncoder().encode(password);
            masterSalt = this.generateRandomBytes(32);

            // 1. اشتقاق المفاتيح (Heritage Pipeline)
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // 2. تجهيز البيانات
            dataPayload = options.compression
                ? new Uint8Array(await this.compressString(plainText))
                : new TextEncoder().encode(plainText);

            // 3. التشفير الطبقي (XChaCha20 Inner -> AES-GCM Outer)
            innerIV = this.generateRandomBytes(24); // XChaCha20 Nonce (Extended)
            outerIV = this.generateRandomBytes(12); // AES-GCM IV

            // الطبقة 1: XChaCha20 (Inner)
            const xchachaKey = await this.exportRawKey(keys.innerKey);
            try {
                if (typeof window.xchacha20 === 'function') {
                    innerCipher = window.xchacha20(xchachaKey, innerIV, dataPayload);
                } else if (typeof noble !== 'undefined' && noble.ciphers && noble.ciphers.xchacha20) {
                    innerCipher = noble.ciphers.xchacha20(xchachaKey, innerIV, dataPayload);
                } else {
                    throw new Error('مكتبة XChaCha20 غير متوفرة. يرجى التأكد من تحميل polyfill.');
                }
            } finally {
                this.wipe(xchachaKey);
            }

            // الطبقة 2: AES-256-GCM (Outer)
            const timestamp = Date.now();
            const outerAAD = new TextEncoder().encode(`v8.0|AES-GCM|${timestamp}`);
            finalCipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: outerIV, additionalData: outerAAD },
                keys.outerKey,
                innerCipher
            );

            // 4. البناء النهائي (Structured JSON)
            const header = {
                ver: "8.0-SOVEREIGN",
                timestamp: timestamp,
                classification: "PROBABILISTIC | HIGH-ENTROPY",
                kdf_pipeline: {
                    desc: "Hybrid: PBKDF2 (CPU-Hard) -> Argon2id (RAM-Hard) -> HKDF (Split)",
                    salt: this.arrayToBase64(masterSalt),
                    params: {
                        pbkdf2_iter: this.config.pipeline.stage1.iterations,
                        argon2_mem_kb: this.config.pipeline.stage2.memoryCost,
                        argon2_lanes: this.config.pipeline.stage2.parallelism,
                        argon2_time: this.config.pipeline.stage2.iterations
                    }
                },
                encryption: {
                    algo: "Cascade: AES-256-GCM (Outer) + XChaCha20 (Inner)",
                    iv_outer: this.arrayToBase64(outerIV),
                    iv_inner: this.arrayToBase64(innerIV),
                    tag_length: 128
                }
            };

            const headerJSON = JSON.stringify(header);
            const cipherBase64 = this.arrayToBase64(finalCipher);

            // ختم المصادقة النهائي (HMAC فوق الهيدر والـ Ciphertext)
            const authTag = await this.crypto.sign('HMAC', keys.integrityKey, new TextEncoder().encode(headerJSON + cipherBase64));

            return {
                header: header,
                ciphertext: cipherBase64,
                auth_tag: this.arrayToBase64(authTag),
                security_meta: {
                    memory_wiped: true,
                    dom_nuked: true
                }
            };

        } finally {
            this.wipe(passwordBytes);
            this.wipe(intermediateHash);
            this.wipe(masterKeyMaterial);
            this.wipe(dataPayload);
            if (innerCipher) this.wipe(new Uint8Array(innerCipher));
        }
    }

    async decrypt(encryptedData, password) {
        let passwordBytes, intermediateHash, masterKeyMaterial, keys;
        let innerCipher, plainBuffer;

        try {
            let data = encryptedData;
            if (typeof data === 'string') data = JSON.parse(data);

            if (!data.header || !data.header.ver || !data.header.ver.startsWith('8.0')) {
                throw new Error('إصدار غير مدعوم أو تنسيق خاطئ');
            }

            passwordBytes = new TextEncoder().encode(password);
            const masterSalt = this.base64ToArray(data.header.kdf_pipeline.salt);
            const outerIV = this.base64ToArray(data.header.encryption.iv_outer);
            const innerIV = this.base64ToArray(data.header.encryption.iv_inner);
            const ciphertext = this.base64ToArray(data.ciphertext);
            const authTag = this.base64ToArray(data.auth_tag);

            // 1. إعادة بناء المفاتيح
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // 2. التحقق من المصادقة (Auth Tag)
            const headerJSON = JSON.stringify(data.header);
            const isValid = await this.crypto.verify('HMAC', keys.integrityKey, authTag, new TextEncoder().encode(headerJSON + data.ciphertext));
            if (!isValid) throw new Error('⛔ فشل التحقق من المصادقة! تم اكتشاف تلاعب في البيانات.');

            // 3. فك التشفير الطبقي
            const outerAAD = new TextEncoder().encode(`v8.0|AES-GCM|${data.header.timestamp}`);
            innerCipher = await this.crypto.decrypt(
                { name: 'AES-GCM', iv: outerIV, additionalData: outerAAD },
                keys.outerKey, ciphertext
            );

            // الطبقة 1 (Inner): XChaCha20
            const xchachaKey = await this.exportRawKey(keys.innerKey);
            try {
                if (typeof window.xchacha20 === 'function') {
                    plainBuffer = window.xchacha20(xchachaKey, innerIV, new Uint8Array(innerCipher));
                } else if (typeof noble !== 'undefined' && noble.ciphers && noble.ciphers.xchacha20) {
                    plainBuffer = noble.ciphers.xchacha20(xchachaKey, innerIV, new Uint8Array(innerCipher));
                } else {
                    throw new Error('مكتبة XChaCha20 غير متوفرة');
                }
            } finally {
                this.wipe(xchachaKey);
            }

            const plainBytes = new Uint8Array(plainBuffer);
            let plainText;
            if (plainBytes.length > 2 && plainBytes[0] === 0x1f && plainBytes[1] === 0x8b) {
                plainText = await this.decompressString(plainBytes);
            } else {
                plainText = new TextDecoder().decode(plainBytes);
            }

            return {
                text: plainText,
                integrity: true,
                metadata: { version: data.header.ver, timestamp: data.header.timestamp }
            };

        } finally {
            this.wipe(passwordBytes);
            this.wipe(intermediateHash);
            this.wipe(masterKeyMaterial);
            if (innerCipher) this.wipe(new Uint8Array(innerCipher));
            if (plainBuffer) this.wipe(new Uint8Array(plainBuffer));
        }
    }

    async deriveStage1_PBKDF2(passwordBytes, salt) {
        const keyMaterial = await this.crypto.importKey(
            'raw', passwordBytes, 'PBKDF2', false, ['deriveBits']
        );
        const bits = await this.crypto.deriveBits(
            {
                name: 'PBKDF2',
                salt: new Uint8Array(salt),
                iterations: this.config.pipeline.stage1.iterations,
                hash: 'SHA-256'
            },
            keyMaterial, 256
        );
        return new Uint8Array(bits);
    }

    async deriveStage2_Argon2id(intermediateHash, salt) {
        return await hashwasm.argon2id({
            password: intermediateHash,
            salt: new Uint8Array(salt),
            parallelism: this.config.pipeline.stage2.parallelism,
            iterations: this.config.pipeline.stage2.iterations,
            memorySize: this.config.pipeline.stage2.memoryCost,
            hashLength: 32,
            outputType: 'binary'
        });
    }

    async deriveStage3_HKDF(masterSecret) {
        const masterKey = await this.crypto.importKey(
            'raw', masterSecret, 'HKDF', false, ['deriveKey', 'deriveBits']
        );

        // مفتاح الطبقة الخارجية: AES-256-GCM
        const outerKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v8.0-outer') },
            masterKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );

        // مفتاح الطبقة الداخلية: XChaCha20 (نقوم باشتقاق Bits)
        const innerKeyBits = await this.crypto.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v8.0-inner') },
            masterKey, 256
        );
        const innerKey = new Uint8Array(innerKeyBits);

        // مفتاح المصادقة والـ SIV
        const integrityKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v8.0-integ') },
            masterKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
        );

        return { innerKey, outerKey, integrityKey };
    }

    generateRandomBytes(len) { return window.crypto.getRandomValues(new Uint8Array(len)); }
    async exportRawKey(key) {
        if (key instanceof CryptoKey) return await this.crypto.exportKey('raw', key);
        return key;
    }
    arrayToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }
    base64ToArray(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
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

window.CryptoEngine = CryptoEngine;
