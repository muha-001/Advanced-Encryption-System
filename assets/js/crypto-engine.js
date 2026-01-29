// ============================================
// محرك التشفير النووي (Nuclear Pipeline Crypto Engine)
// v7.0: SIV Deterministic + Hardened Memory Wiping
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
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
            inner: { algorithm: 'AES-GCM', ivLength: 12 },
            outer: { algorithm: 'ChaCha20-Poly1305', ivLength: 12 },
            integrity: { algorithm: 'HMAC', hash: 'SHA-256' }
        };

        this.deterministicSalt = new TextEncoder().encode('SIV-DETERMINISTIC-SALT-V1');
        this.crypto = window.crypto.subtle;
        this.chachaSupported = false;
        this.supportCheckPromise = this.checkChaChaSupport();

        console.log('🚀 محرك التشفير النووي v7.0 جاهز (SIV + RAM Hardening)');
    }

    // آمن: تصفير الذاكرة باستخدام قيم عشوائية لمنع استعادة البيانات
    wipe(buffer) {
        if (buffer && (buffer instanceof Uint8Array || buffer instanceof ArrayBuffer)) {
            const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
            window.crypto.getRandomValues(view);
            console.log('🛡️ تم تصفير المخزن المؤقت بنجاح');
        }
    }

    async checkChaChaSupport() {
        try {
            await this.crypto.generateKey(
                { name: 'ChaCha20-Poly1305', length: 256 },
                true, ['encrypt', 'decrypt']
            );
            this.chachaSupported = true;
            this.useExternalChaCha = false;
        } catch (e) {
            if (typeof window.chacha20poly1305 !== 'undefined') {
                this.chachaSupported = true;
                this.useExternalChaCha = true;
                console.log('✅ استخدام Polyfill لـ ChaCha20');
            }
        }
    }

    // اشتقاق IV حتمي وآمن (SIV) بناءً على النص والمفتاح
    async deriveSIV(dataBytes, sivKey) {
        const signature = await this.crypto.sign('HMAC', sivKey, dataBytes);
        const sigBytes = new Uint8Array(signature);
        // نأخذ أول 12 بايت لكل طبقة (أو نشتق أكثر إذا لزم الأمر)
        return {
            innerIV: sigBytes.slice(0, 12),
            outerIV: sigBytes.slice(12, 24)
        };
    }

    async encrypt(plainText, password, options = {}) {
        let passwordBytes, masterSalt, intermediateHash, masterKeyMaterial, keys, dataPayload, innerIV, outerIV;

        try {
            if (!plainText || !password) throw new Error('بيانات ناقصة');
            await this.supportCheckPromise;

            const startTime = performance.now();
            passwordBytes = new TextEncoder().encode(password);

            // 1. اشتقاق الملح (Salt)
            masterSalt = options.deterministic
                ? new Uint8Array(this.deterministicSalt)
                : this.generateRandomBytes(32);

            // 2. خط أنابيب المفاتيح (Key Pipeline)
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // 3. تجهيز البيانات
            dataPayload = options.compression
                ? new Uint8Array(await this.compressString(plainText))
                : new TextEncoder().encode(plainText);

            // 4. اشتقاق IV (عشوائي أو SIV)
            if (options.deterministic) {
                const sivs = await this.deriveSIV(dataPayload, keys.sivKey);
                innerIV = sivs.innerIV;
                outerIV = sivs.outerIV;
            } else {
                innerIV = this.generateRandomBytes(12);
                outerIV = this.generateRandomBytes(12);
            }

            // 5. التشفير (طبقتان)
            const timestamp = Date.now();
            const innerAAD = new TextEncoder().encode('v7.0|AES-GCM');
            const innerCipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                keys.innerKey,
                dataPayload
            );

            const outerAAD = new TextEncoder().encode(`v7.0|ChaCha20|${timestamp}`);
            let finalCipher;
            if (this.useExternalChaCha) {
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                try {
                    const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                    finalCipher = chacha.encrypt(new Uint8Array(innerCipher));
                } finally { this.wipe(keyBytes); }
            } else {
                finalCipher = await this.crypto.encrypt(
                    { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                    keys.outerKey,
                    innerCipher
                );
            }

            // 6. البناء النهائي
            const header = {
                v: "7.0",
                mode: options.deterministic ? "NUCLEAR_SIV" : "RANDOM_IV",
                ts: timestamp,
                det: !!options.deterministic,
                ms: this.arrayToBase64(masterSalt),
                iiv: this.arrayToBase64(innerIV),
                oiv: this.arrayToBase64(outerIV)
            };

            const headerBytes = new TextEncoder().encode(JSON.stringify(header));
            const signature = await this.crypto.sign('HMAC', keys.integrityKey, headerBytes);

            return {
                header: header,
                sig: this.arrayToBase64(signature),
                data: this.arrayToBase64(finalCipher),
                performance: { time: Math.round(performance.now() - startTime) }
            };

        } finally {
            // تصفير الذاكرة العشوائية فوراً
            this.wipe(passwordBytes);
            this.wipe(intermediateHash);
            this.wipe(masterKeyMaterial);
            this.wipe(dataPayload);
            if (innerIV && options.deterministic) this.wipe(innerIV);
            if (outerIV && options.deterministic) this.wipe(outerIV);
        }
    }

    async decrypt(encryptedData, password) {
        let passwordBytes, intermediateHash, masterKeyMaterial, keys, innerCipher, plainBuffer;
        try {
            let data = encryptedData;
            if (typeof data === 'string') data = JSON.parse(data);
            if (!data.header || (data.header.v !== '6.5' && data.header.v !== '7.0')) {
                throw new Error('إصدار غير مدعوم');
            }

            const startTime = performance.now();
            passwordBytes = new TextEncoder().encode(password);
            const masterSalt = this.base64ToArray(data.header.ms);
            const innerIV = this.base64ToArray(data.header.iiv);
            const outerIV = this.base64ToArray(data.header.oiv);
            const ciphertext = this.base64ToArray(data.data);
            const signature = this.base64ToArray(data.sig);

            // إعادة بناء المفاتيح
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // التحقق من السلامة
            const headerBytes = new TextEncoder().encode(JSON.stringify(data.header));
            const isValid = await this.crypto.verify('HMAC', keys.integrityKey, signature, headerBytes);
            if (!isValid) throw new Error('⛔ تم اكتشاف تلاعب في البيانات!');

            // فك التشفير
            const outerAAD = new TextEncoder().encode(`v${data.header.v}|ChaCha20|${data.header.ts}`);
            if (this.useExternalChaCha) {
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                try {
                    const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                    innerCipher = chacha.decrypt(new Uint8Array(ciphertext));
                } finally { this.wipe(keyBytes); }
            } else {
                innerCipher = await this.crypto.decrypt(
                    { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                    keys.outerKey, ciphertext
                );
            }

            const innerAAD = new TextEncoder().encode(`v${data.header.v}|AES-GCM`);
            plainBuffer = await this.crypto.decrypt(
                { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                keys.innerKey, innerCipher
            );

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
                metadata: { version: data.header.v, timestamp: data.header.ts },
                performance: { time: Math.round(performance.now() - startTime) }
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
            'raw', masterSecret, 'HKDF', false, ['deriveKey', 'deriveBits', 'deriveKey']
        );

        const innerKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v7.0-inner') },
            masterKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );

        const integrityKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v7.0-integ') },
            masterKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
        );

        const sivKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v7.0-siv') },
            masterKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );

        let outerKey;
        if (this.useExternalChaCha) {
            outerKey = await this.crypto.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v7.0-outer') },
                masterKey, 256
            );
        } else {
            outerKey = await this.crypto.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v7.0-outer') },
                masterKey, { name: 'ChaCha20-Poly1305' }, false, ['encrypt', 'decrypt']
            );
        }

        return { innerKey, outerKey, integrityKey, sivKey };
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
