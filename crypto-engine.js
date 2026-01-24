// ============================================
// محرك التشفير النووي (Nuclear Pipeline Crypto Engine)
// v6.5: PBKDF2 (CPU) -> Argon2id (RAM) -> HKDF
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            // المعلمات الرئيسية (The Pipeline Config)
            pipeline: {
                stage1: {
                    type: 'PBKDF2-HMAC-SHA256',
                    iterations: 2000000,
                    desc: 'CPU-Hard (Pre-Computation)'
                },
                stage2: {
                    type: 'Argon2id',
                    memoryCost: 1572864, // 1.5 GB
                    parallelism: 4,      // p=4
                    iterations: 2,       // ops=2
                    hashLength: 32,
                    desc: 'Memory-Hard (Main Key Gen)'
                }
            },

            // الطبقة الداخلية
            inner: {
                algorithm: 'AES-GCM',
                ivLength: 12
            },

            // الطبقة الخارجية
            outer: {
                algorithm: 'ChaCha20-Poly1305',
                ivLength: 12
            },

            integrity: {
                algorithm: 'HMAC',
                hash: 'SHA-256'
            }
        };

        this.crypto = window.crypto.subtle;
        this.chachaSupported = false;
        this.supportCheckPromise = this.checkChaChaSupport();

        console.log('🚀 محرك التشفير النووي (Pipeline v6.5) جاهز للعمل');
        console.log('🔥 2M PBKDF2 + 1.5GB Argon2id -> HKDF');
    }

    async checkChaChaSupport() {
        try {
            const key = await this.crypto.generateKey(
                { name: 'ChaCha20-Poly1305', length: 256 },
                true, ['encrypt', 'decrypt']
            );
            this.chachaSupported = true;
            this.useExternalChaCha = false;
        } catch (e) {
            if (typeof window.chacha20poly1305 !== 'undefined') {
                this.chachaSupported = true;
                this.useExternalChaCha = true;
                console.log('✅ استخدام Polyfill لطبقة ChaCha20');
            } else {
                this.chachaSupported = false;
            }
        }
    }

    // ===== التشفير النووي =====
    async encrypt(plainText, password, options = {}) {
        try {
            /* 
               Step 1: Check Pre-requisites 
            */
            if (!plainText || !password) throw new Error('البيانات ناقصة');
            if (typeof hashwasm === 'undefined') throw new Error('Argon2id lib missing');
            await this.supportCheckPromise;

            const startTime = performance.now();
            let timer_pbkdf2 = 0;
            let timer_argon2 = 0;

            /* 
               Step 2: The Pipeline (Key Derivation) 
            */
            const masterSalt = this.generateRandomBytes(32); // 32 bytes salt

            // --- Stage 1: CPU Burn (PBKDF2) ---
            console.log('🔥 المرحلة 1: حرق المعالج (PBKDF2 2M)...');
            const t1 = performance.now();
            const intermediateHash = await this.deriveStage1_PBKDF2(password, masterSalt);
            timer_pbkdf2 = performance.now() - t1;

            // --- Stage 2: RAM Burn (Argon2id) ---
            console.log('🧠 المرحلة 2: حرق الذاكرة (Argon2id 1.5GB)...');
            const t2 = performance.now();
            const masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            timer_argon2 = performance.now() - t2;

            // --- Stage 3: Distribution (HKDF) ---
            console.log('🔑 المرحلة 3: توزيع المفاتيح (HKDF)...');
            const keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // Clean up secrets
            intermediateHash.fill(0);
            masterKeyMaterial.fill(0);

            /* 
               Step 3: Encryption Context 
            */
            // Prepare Payload
            let dataPayload;
            if (options.compression) {
                dataPayload = new Uint8Array(await this.compressString(plainText));
            } else {
                dataPayload = new TextEncoder().encode(plainText);
            }

            // --- Layer 1: Inner (AES-GCM) ---
            const innerIV = this.generateRandomBytes(12);
            const innerAAD = new TextEncoder().encode('v6.5|AES-GCM');

            const innerCipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                keys.innerKey,
                dataPayload
            );

            // --- Layer 2: Outer (ChaCha20-Poly1305) ---
            const outerIV = this.generateRandomBytes(12);
            // Timestamp included in header
            const timestamp = Date.now();
            const outerAAD = new TextEncoder().encode(`v6.5|ChaCha20|${timestamp}`);

            let finalCipher;
            if (this.useExternalChaCha) {
                // Polyfill
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                finalCipher = chacha.encrypt(new Uint8Array(innerCipher));
            } else {
                // Native
                finalCipher = await this.crypto.encrypt(
                    { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                    keys.outerKey,
                    innerCipher
                );
            }

            /* 
               Step 4: Construct Header & Output 
            */
            const encTotalTime = Math.round(performance.now() - startTime);

            const header = {
                v: "6.5",
                ts: timestamp,
                algo: "PBKDF2->Argon2id->HKDF | AES-GCM+ChaCha20",

                kdf_pipeline: [
                    {
                        step: 1,
                        type: this.config.pipeline.stage1.type,
                        iter: this.config.pipeline.stage1.iterations,
                        desc: this.config.pipeline.stage1.desc
                    },
                    {
                        step: 2,
                        type: this.config.pipeline.stage2.type,
                        mem: this.config.pipeline.stage2.memoryCost,
                        ops: this.config.pipeline.stage2.iterations,
                        p: this.config.pipeline.stage2.parallelism,
                        desc: this.config.pipeline.stage2.desc
                    }
                ],

                ms: this.arrayToBase64(masterSalt),
                iiv: this.arrayToBase64(innerIV),
                oiv: this.arrayToBase64(outerIV)
            };

            // Sign the header
            const headerBytes = new TextEncoder().encode(JSON.stringify(header));
            const signature = await this.crypto.sign('HMAC', keys.integrityKey, headerBytes);

            return {
                header: header,
                sig: this.arrayToBase64(signature),
                data: this.arrayToBase64(finalCipher),
                performance: {
                    time: encTotalTime,
                    note: `Latency: ~${(timer_pbkdf2 / 1000).toFixed(1)}s (PBKDF2) + ~${(timer_argon2 / 1000).toFixed(1)}s (Argon2) = ~${(encTotalTime / 1000).toFixed(1)}s Total`
                }
            };

        } catch (error) {
            console.error('Encryption Failed:', error);
            throw error;
        }
    }

    // ===== فك التشفير النووي =====
    async decrypt(encryptedData, password) {
        try {
            let data = encryptedData;
            if (typeof data === 'string') {
                try { data = JSON.parse(data); } catch { throw new Error('Invalid JSON'); }
            }

            if (!data.header || data.header.v !== '6.5') {
                throw new Error('Unsupported Version. This engine requires v6.5 Nuclear Pipeline.');
            }

            const startTime = performance.now();

            // 1. Extract Metadata
            const masterSalt = this.base64ToArray(data.header.ms);
            const innerIV = this.base64ToArray(data.header.iiv);
            const outerIV = this.base64ToArray(data.header.oiv);
            const ciphertext = this.base64ToArray(data.data);
            const signature = this.base64ToArray(data.sig);

            // 2. Re-run Pipeline (Derive Keys)
            console.log('♻️ Re-running Key Pipeline...');

            // Stage 1: PBKDF2
            const intermediateHash = await this.deriveStage1_PBKDF2(password, masterSalt);

            // Stage 2: Argon2id
            // Use params from header to ensure compatibility even if config changes slightly
            const memCost = data.header.kdf_pipeline[1].mem || 1572864;
            const ops = data.header.kdf_pipeline[1].ops || 2;
            const p = data.header.kdf_pipeline[1].p || 4;

            const masterKeyMaterial = await this.deriveStage2_Argon2id(
                intermediateHash, masterSalt, memCost, ops, p
            );

            // Stage 3: HKDF
            const keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // Wipe secrets
            intermediateHash.fill(0);
            masterKeyMaterial.fill(0);

            // 3. Verify Signature (Integrity)
            const headerBytes = new TextEncoder().encode(JSON.stringify(data.header));
            const isValid = await this.crypto.verify('HMAC', keys.integrityKey, signature, headerBytes);

            if (!isValid) throw new Error('⛔ TAMPERING DETECTED! Header signature mismatch.');
            console.log('✅ Integrity Check Passed.');

            // 4. Decrypt Outer (ChaCha20)
            const outerAAD = new TextEncoder().encode(`v6.5|ChaCha20|${data.header.ts}`);
            let innerCipher;

            if (this.useExternalChaCha) {
                const keyBytes = new Uint8Array(await this.exportRawKey(keys.outerKey));
                const chacha = window.chacha20poly1305(keyBytes, new Uint8Array(outerIV), outerAAD);
                try {
                    innerCipher = chacha.decrypt(new Uint8Array(ciphertext));
                } catch (e) { throw new Error('Decryption Failed (Outer Layer).'); }
            } else {
                try {
                    innerCipher = await this.crypto.decrypt(
                        { name: 'ChaCha20-Poly1305', iv: outerIV, additionalData: outerAAD },
                        keys.outerKey,
                        ciphertext
                    );
                } catch (e) { throw new Error('Decryption Failed (Outer Layer).'); }
            }

            // 5. Decrypt Inner (AES-GCM)
            const innerAAD = new TextEncoder().encode('v6.5|AES-GCM');
            let plainBuffer;
            try {
                plainBuffer = await this.crypto.decrypt(
                    { name: 'AES-GCM', iv: innerIV, additionalData: innerAAD },
                    keys.innerKey,
                    innerCipher
                );
            } catch (e) { throw new Error('Decryption Failed (Inner Layer).'); }

            // 6. Decompress
            const plainBytes = new Uint8Array(plainBuffer);
            let plainText;
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
                    version: '6.5 (Nuclear Pipeline)',
                    timestamp: data.header.ts,
                    security: 'PBKDF2->Argon2->HKDF'
                },
                performance: { time: Math.round(performance.now() - startTime) }
            };

        } catch (error) {
            console.error('Decryption error:', error);
            throw error;
        }
    }

    // ===== PIPELINE FUNCTIONS =====

    // Stage 1: CPU-Hard (PBKDF2) -> Returns Uint8Array (Intermediate Data)
    async deriveStage1_PBKDF2(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await this.crypto.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
        );

        const bits = await this.crypto.deriveBits(
            {
                name: 'PBKDF2',
                salt: new Uint8Array(salt),
                iterations: this.config.pipeline.stage1.iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            256 // 32 bytes output
        );
        return new Uint8Array(bits);
    }

    // Stage 2: Memory-Hard (Argon2id) -> Returns Uint8Array (Master Secret)
    // Takes Intermediate Hash (bytes) as password input
    async deriveStage2_Argon2id(intermediateHash, salt, mem, ops, p) {
        // Warning: hash-wasm may expect Uint8Array for password
        const result = await hashwasm.argon2id({
            password: intermediateHash,
            salt: new Uint8Array(salt),
            parallelism: p || this.config.pipeline.stage2.parallelism,
            iterations: ops || this.config.pipeline.stage2.iterations,
            memorySize: mem || this.config.pipeline.stage2.memoryCost,
            hashLength: 32,
            outputType: 'binary'
        });
        return result;
    }

    // Stage 3: Distribution (HKDF) -> Returns Key Objects
    async deriveStage3_HKDF(masterSecret) {
        const masterKey = await this.crypto.importKey(
            'raw', masterSecret, 'HKDF', false, ['deriveKey', 'deriveBits']
        );

        const innerKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v6.5-inner') },
            masterKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );

        const integrityKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v6.5-integ') },
            masterKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
        );

        let outerKey;
        if (this.useExternalChaCha) {
            const bits = await this.crypto.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v6.5-outer') },
                masterKey, 256
            );
            outerKey = bits;
        } else {
            outerKey = await this.crypto.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('v6.5-outer') },
                masterKey, { name: 'ChaCha20-Poly1305' }, false, ['encrypt', 'decrypt']
            );
        }

        return { innerKey, outerKey, integrityKey };
    }

    // ===== Helpers =====
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

window.CryptoEngine = CryptoEngine;
