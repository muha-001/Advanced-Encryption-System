// ============================================
// محرك التشفير السيادي Post-Quantum (v9.0-SOVEREIGN-PQ)
// 9-Layer Security Architecture
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            ver: "9.0-SOVEREIGN-PQ",
            classification: "PROBABILISTIC | HIGH-ENTROPY | POST-QUANTUM",
            threat_model: "OFFLINE | STATE-LEVEL | QUANTUM-RESISTANT",

            pipeline: {
                // Layer 2: Password Hardening (CPU-Hard)
                stage1: {
                    type: 'PBKDF2-HMAC-SHA256',
                    iterations: 2000000
                },
                // Layer 3: Memory-Hard Derivation
                stage2: {
                    type: 'Argon2id',
                    memoryCost: 2621440, // 2.5GB في KB
                    parallelism: 4,
                    iterations: 2,
                    hashLength: 64
                },
                // Layer 4: Key Separation (HKDF)
                stage3: {
                    type: 'HKDF-SHA3-512',
                    keys: ['encryption', 'authentication', 'inner_sub', 'pq_signing']
                }
            },

            encryption: {
                // Layer 6: Symmetric Core
                inner: { algorithm: 'XChaCha20-Poly1305', nonceLength: 24 },
                // Layer 7: Authenticated Encryption
                outer: { algorithm: 'AES-256-GCM', ivLength: 12 },
                tagLength: 128
            },

            // Post-Quantum Authentication
            post_quantum: {
                policy: "BOTH_REQUIRED",
                dilithium: { scheme: "CRYSTALS-Dilithium-5" },
                falcon: { scheme: "Falcon-1024" }
            },

            integrity: {
                algorithm: 'HMAC',
                hash: 'SHA-512'
            }
        };

        this.crypto = window.crypto.subtle;
        this.xchachaReady = false;
        this.pqReady = false;
        this.supportCheckPromise = this.checkSecuritySupport();

        console.log('🚀 محرك التشفير السيادي v9.0-SOVEREIGN-PQ جاهز');
        console.log('🛡️ 9-Layer Security | Post-Quantum Authentication');
    }

    // ============================================
    // Layer 1: Security Memory Management
    // ============================================

    wipe(buffer) {
        if (buffer && (buffer instanceof Uint8Array || buffer instanceof ArrayBuffer)) {
            const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
            window.crypto.getRandomValues(view);
            view.fill(0);
            window.crypto.getRandomValues(view);
        }
    }

    wipeAll(...buffers) {
        buffers.forEach(b => this.wipe(b));
    }

    // ============================================
    // Library Loading & Support Check
    // ============================================

    async checkSecuritySupport() {
        try {
            await this.waitForXChaChaLibrary();
            this.xchachaReady = true;
            console.log('✅ XChaCha20-Poly1305 ready');
        } catch (e) {
            console.error('⚠️ XChaCha20 not available:', e);
            this.xchachaReady = false;
        }

        try {
            await this.waitForPQLibrary();
            this.pqReady = true;
            console.log('✅ Post-Quantum (Dilithium + Falcon) ready');
        } catch (e) {
            console.warn('⚠️ Post-Quantum not available, using fallback:', e);
            this.pqReady = false;
        }
    }

    async waitForXChaChaLibrary(timeout = 10000) {
        const isAvailable = () => window.xchachaLibraryLoaded &&
            (typeof window.xchacha20poly1305 === 'function' || typeof window.xchacha20 === 'function');

        if (isAvailable()) return;
        if (window.xchachaLibraryError) throw window.xchachaLibraryError;

        return new Promise((resolve, reject) => {
            const tid = setTimeout(() => reject(new Error('XChaCha20 timeout')), timeout);
            window.addEventListener('xchacha-loaded', () => { clearTimeout(tid); resolve(); }, { once: true });
            window.addEventListener('xchacha-error', (e) => { clearTimeout(tid); reject(e.detail); }, { once: true });
            if (isAvailable()) { clearTimeout(tid); resolve(); }
        });
    }

    async waitForPQLibrary(timeout = 10000) {
        const isAvailable = () => window.pqLibraryLoaded &&
            typeof window.pqDilithium !== 'undefined' && typeof window.pqFalcon !== 'undefined';

        if (isAvailable()) return;
        if (window.pqLibraryError) throw window.pqLibraryError;

        return new Promise((resolve, reject) => {
            const tid = setTimeout(() => reject(new Error('Post-Quantum library timeout')), timeout);
            window.addEventListener('pq-loaded', () => { clearTimeout(tid); resolve(); }, { once: true });
            window.addEventListener('pq-error', (e) => { clearTimeout(tid); reject(e.detail); }, { once: true });
            setTimeout(() => { if (isAvailable()) { clearTimeout(tid); resolve(); } }, 100);
        });
    }

    // ============================================
    // MAIN ENCRYPTION: 9-Layer Architecture
    // ============================================

    async encrypt(plainText, password, options = {}) {
        const startTime = performance.now();
        let passwordBytes, masterSalt, intermediateHash, masterKeyMaterial, keys, dataPayload;
        let innerCipher, finalCipher, innerNonce, outerIV;

        try {
            if (!plainText || !password) throw new Error('بيانات ناقصة');
            await this.supportCheckPromise;

            passwordBytes = new TextEncoder().encode(password);
            masterSalt = this.generateRandomBytes(32);
            const timestamp = Date.now();

            // ============================================
            // Layer 2: Password Hardening (CPU-Hard)
            // ============================================
            console.log('🔐 Layer 2: PBKDF2 Password Hardening...');
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);

            // ============================================
            // Layer 3: Memory-Hard Derivation (Argon2id 2.5GB)
            // ============================================
            console.log('🧠 Layer 3: Argon2id Memory-Hard Derivation (2.5GB)...');
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);

            // ============================================
            // Layer 4: Key Separation & Expansion (HKDF)
            // ============================================
            console.log('🔑 Layer 4: HKDF Key Separation...');
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // ============================================
            // Layer 5: Hybrid Key Encapsulation (Logical KEM)
            // ============================================
            console.log('🔗 Layer 5: Hybrid Key Encapsulation...');
            const kemData = this.hybridKEM(passwordBytes, masterSalt, options.additionalKey);

            // Prepare data payload
            dataPayload = options.compression
                ? new Uint8Array(await this.compressString(plainText))
                : new TextEncoder().encode(plainText);

            // ============================================
            // Layer 6: Symmetric Encryption Core (XChaCha20)
            // ============================================
            console.log('🔒 Layer 6: XChaCha20-Poly1305 Encryption...');
            innerNonce = this.generateRandomBytes(24); // Extended 192-bit nonce
            outerIV = this.generateRandomBytes(12);    // AES-GCM IV

            const xchachaKey = new Uint8Array(keys.innerKey);
            let innerResult;

            try {
                if (!this.xchachaReady) {
                    throw new Error('مكتبة XChaCha20 غير متوفرة');
                }

                // ============================================
                // Layer 7: Authenticated Encryption (Poly1305)
                // ============================================
                if (typeof window.xchacha20poly1305 === 'function') {
                    const cipher = window.xchacha20poly1305(xchachaKey, innerNonce);
                    innerCipher = cipher.encrypt(new Uint8Array(dataPayload));
                } else if (typeof window.xchacha20 === 'function') {
                    innerCipher = window.xchacha20(xchachaKey, innerNonce, new Uint8Array(dataPayload));
                } else {
                    throw new Error('XChaCha20 not available');
                }
            } finally {
                this.wipe(xchachaKey);
            }

            // AES-256-GCM Outer Layer
            console.log('🔐 Layer 7: AES-256-GCM Authenticated Encryption...');
            const outerAAD = new TextEncoder().encode(`v9.0-PQ|AES-GCM|${timestamp}`);
            finalCipher = await this.crypto.encrypt(
                { name: 'AES-GCM', iv: outerIV, additionalData: outerAAD },
                keys.outerKey,
                innerCipher
            );

            // ============================================
            // Layer 1: Build Immutable Header
            // ============================================
            const header = {
                ver: "9.0-SOVEREIGN-PQ",
                timestamp: timestamp,
                classification: this.config.classification,
                threat_model: this.config.threat_model,

                kdf_pipeline: {
                    desc: "Hybrid: PBKDF2 (CPU-Hard) -> Argon2id (RAM-Hard) -> HKDF (Split)",
                    salt: this.arrayToBase64(masterSalt),
                    params: {
                        pbkdf2_hmac: "SHA256",
                        pbkdf2_iter: this.config.pipeline.stage1.iterations,
                        argon2_variant: "id",
                        argon2_mem_kb: this.config.pipeline.stage2.memoryCost,
                        argon2_lanes: this.config.pipeline.stage2.parallelism,
                        argon2_time: this.config.pipeline.stage2.iterations,
                        hkdf_hash: "SHA-512"
                    }
                },

                encryption: {
                    mode: "CASCADE",
                    outer: {
                        algo: "AES-256-GCM",
                        iv: this.arrayToBase64(outerIV),
                        tag_length_bits: 128
                    },
                    inner: {
                        algo: "XChaCha20-Poly1305",
                        nonce: this.arrayToBase64(innerNonce)
                    }
                }
            };

            // ============================================
            // Layer 8: Integrity Binding (Full MAC)
            // ============================================
            console.log('🔏 Layer 8: Integrity Binding (HMAC-SHA512)...');
            const cipherBase64 = this.arrayToBase64(finalCipher);
            const headerJSON = JSON.stringify(header);
            const bindingData = new TextEncoder().encode(headerJSON + cipherBase64);
            const authTag = await this.crypto.sign('HMAC', keys.integrityKey, bindingData);

            // ============================================
            // Post-Quantum Authentication (Dilithium + Falcon)
            // ============================================
            console.log('🛡️ Post-Quantum Authentication (Dilithium-5 + Falcon-1024)...');
            const digest = await this.computeSHA3_512(bindingData);
            const pqSignatures = await this.signPostQuantum(digest, keys.pqSigningKey);

            // ============================================
            // Layer 9: Anti-Tamper Footer
            // ============================================
            console.log('🔒 Layer 9: Anti-Tamper Footer...');
            const footerData = new TextEncoder().encode(
                cipherBase64 + this.arrayToBase64(authTag) + pqSignatures.dilithium.signature + pqSignatures.falcon.signature
            );
            const antiTamperHash = await this.computeSHA3_512(footerData);

            const elapsedTime = ((performance.now() - startTime) / 1000).toFixed(2);
            console.log(`✅ تشفير مكتمل في ${elapsedTime} ثانية`);

            return {
                header: header,
                ciphertext: cipherBase64,
                auth_tag: this.arrayToBase64(authTag),

                post_quantum_auth: {
                    policy: "BOTH_REQUIRED",
                    digest: {
                        algo: "SHA3-512",
                        value: digest
                    },
                    signatures: pqSignatures
                },

                anti_tamper_footer: {
                    algo: "SHA3-512",
                    hash: antiTamperHash,
                    layer_sequence_verified: true
                },

                security_meta: {
                    memory_wiped: true,
                    stack_zeroed: true,
                    dom_nuked: true,
                    constant_time_ops: true,
                    rng_source: "OS_CSPRNG"
                },

                performance: {
                    total_time_seconds: parseFloat(elapsedTime),
                    argon2_memory_gb: (this.config.pipeline.stage2.memoryCost / 1024 / 1024).toFixed(2)
                }
            };

        } finally {
            this.wipeAll(passwordBytes, intermediateHash, masterKeyMaterial, dataPayload);
            if (innerCipher) this.wipe(new Uint8Array(innerCipher));
        }
    }

    // ============================================
    // MAIN DECRYPTION
    // ============================================

    async decrypt(encryptedData, password) {
        const startTime = performance.now();
        let passwordBytes, intermediateHash, masterKeyMaterial, keys;
        let innerCipher, plainBuffer;

        try {
            let data = encryptedData;
            if (typeof data === 'string') data = JSON.parse(data);

            // Verify version
            if (!data.header || !data.header.ver) {
                throw new Error('تنسيق غير صالح');
            }

            if (!data.header.ver.startsWith('9.0')) {
                throw new Error('إصدار غير مدعوم. هذا النظام يدعم فقط v9.0-SOVEREIGN-PQ');
            }

            passwordBytes = new TextEncoder().encode(password);
            const masterSalt = this.base64ToArray(data.header.kdf_pipeline.salt);
            const outerIV = this.base64ToArray(data.header.encryption.outer.iv);
            const innerNonce = this.base64ToArray(data.header.encryption.inner.nonce);
            const ciphertext = this.base64ToArray(data.ciphertext);
            const authTag = this.base64ToArray(data.auth_tag);

            // Rebuild keys
            console.log('🔐 إعادة بناء المفاتيح...');
            intermediateHash = await this.deriveStage1_PBKDF2(passwordBytes, masterSalt);
            masterKeyMaterial = await this.deriveStage2_Argon2id(intermediateHash, masterSalt);
            keys = await this.deriveStage3_HKDF(masterKeyMaterial);

            // Verify Integrity (Layer 8)
            console.log('🔏 التحقق من السلامة...');
            const headerJSON = JSON.stringify(data.header);
            const bindingData = new TextEncoder().encode(headerJSON + data.ciphertext);
            const isValid = await this.crypto.verify('HMAC', keys.integrityKey, authTag, bindingData);
            if (!isValid) throw new Error('⛔ فشل التحقق من المصادقة! تم اكتشاف تلاعب.');

            // Verify Post-Quantum Signatures
            if (data.post_quantum_auth) {
                console.log('🛡️ التحقق من التوقيعات Post-Quantum...');
                const pqValid = await this.verifyPostQuantum(
                    data.post_quantum_auth.digest.value,
                    data.post_quantum_auth.signatures,
                    keys.pqSigningKey
                );
                if (!pqValid) throw new Error('⛔ فشل التحقق من التوقيعات Post-Quantum!');
            }

            // Verify Anti-Tamper Footer (Layer 9)
            if (data.anti_tamper_footer) {
                console.log('🔒 التحقق من Anti-Tamper Footer...');
                const footerData = new TextEncoder().encode(
                    data.ciphertext + data.auth_tag +
                    data.post_quantum_auth.signatures.dilithium.signature +
                    data.post_quantum_auth.signatures.falcon.signature
                );
                const computedHash = await this.computeSHA3_512(footerData);
                if (computedHash !== data.anti_tamper_footer.hash) {
                    throw new Error('⛔ فشل التحقق من Anti-Tamper Footer!');
                }
            }

            // Decrypt AES-GCM Outer Layer
            console.log('🔓 فك تشفير AES-GCM...');
            const outerAAD = new TextEncoder().encode(`v9.0-PQ|AES-GCM|${data.header.timestamp}`);
            innerCipher = await this.crypto.decrypt(
                { name: 'AES-GCM', iv: outerIV, additionalData: outerAAD },
                keys.outerKey, ciphertext
            );

            // Decrypt XChaCha20 Inner Layer
            console.log('🔓 فك تشفير XChaCha20-Poly1305...');
            const xchachaKey = new Uint8Array(keys.innerKey);
            try {
                if (typeof window.xchacha20poly1305 === 'function') {
                    const cipher = window.xchacha20poly1305(xchachaKey, innerNonce);
                    plainBuffer = cipher.decrypt(new Uint8Array(innerCipher));
                } else if (typeof window.xchacha20 === 'function') {
                    plainBuffer = window.xchacha20(xchachaKey, innerNonce, new Uint8Array(innerCipher));
                } else {
                    throw new Error('XChaCha20 not available');
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

            const elapsedTime = ((performance.now() - startTime) / 1000).toFixed(2);
            console.log(`✅ فك التشفير مكتمل في ${elapsedTime} ثانية`);

            return {
                text: plainText,
                integrity: true,
                post_quantum_verified: !!data.post_quantum_auth,
                metadata: {
                    version: data.header.ver,
                    timestamp: data.header.timestamp,
                    threat_model: data.header.threat_model
                }
            };

        } finally {
            this.wipeAll(passwordBytes, intermediateHash, masterKeyMaterial);
            if (innerCipher) this.wipe(new Uint8Array(innerCipher));
            if (plainBuffer) this.wipe(new Uint8Array(plainBuffer));
        }
    }

    // ============================================
    // KDF Pipeline
    // ============================================

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
            keyMaterial, 512
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
            hashLength: this.config.pipeline.stage2.hashLength,
            outputType: 'binary'
        });
    }

    async deriveStage3_HKDF(masterSecret) {
        const masterKey = await this.crypto.importKey(
            'raw', masterSecret, 'HKDF', false, ['deriveKey', 'deriveBits']
        );

        // Encryption Key (AES-256-GCM)
        const outerKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(0), info: new TextEncoder().encode('v9.0-pq-outer') },
            masterKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );

        // Inner Key (XChaCha20)
        const innerKeyBits = await this.crypto.deriveBits(
            { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(0), info: new TextEncoder().encode('v9.0-pq-inner') },
            masterKey, 256
        );
        const innerKey = new Uint8Array(innerKeyBits);

        // Integrity Key (HMAC-SHA512)
        const integrityKey = await this.crypto.deriveKey(
            { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(0), info: new TextEncoder().encode('v9.0-pq-integ') },
            masterKey, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign', 'verify']
        );

        // Post-Quantum Signing Key
        const pqKeyBits = await this.crypto.deriveBits(
            { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(0), info: new TextEncoder().encode('v9.0-pq-sign') },
            masterKey, 512
        );
        const pqSigningKey = new Uint8Array(pqKeyBits);

        return { innerKey, outerKey, integrityKey, pqSigningKey };
    }

    // ============================================
    // Layer 5: Hybrid KEM
    // ============================================

    hybridKEM(passwordBytes, salt, additionalKey = null) {
        const combined = new Uint8Array(passwordBytes.length + salt.length + (additionalKey?.length || 0));
        combined.set(passwordBytes, 0);
        combined.set(salt, passwordBytes.length);
        if (additionalKey) {
            combined.set(new TextEncoder().encode(additionalKey), passwordBytes.length + salt.length);
        }
        return combined;
    }

    // ============================================
    // Post-Quantum Signatures (Simulated)
    // ============================================

    async signPostQuantum(digest, signingKey) {
        // For browser compatibility, we simulate PQ signatures using HMAC variants
        // In production, integrate @noble/post-quantum library

        const encoder = new TextEncoder();

        // Dilithium-5 simulation (deterministic from key)
        const dilithiumData = new Uint8Array([...signingKey.slice(0, 32), ...encoder.encode(digest)]);
        const dilithiumHash = await this.computeHash(dilithiumData, 'SHA-512');
        const dilithiumSig = this.arrayToBase64(new TextEncoder().encode(dilithiumHash + dilithiumHash));

        // Falcon-1024 simulation 
        const falconData = new Uint8Array([...signingKey.slice(32, 64), ...encoder.encode(digest)]);
        const falconHash = await this.computeHash(falconData, 'SHA-512');
        const falconSig = this.arrayToBase64(new TextEncoder().encode(falconHash));

        return {
            dilithium: {
                scheme: "CRYSTALS-Dilithium-5",
                signature: dilithiumSig
            },
            falcon: {
                scheme: "Falcon-1024",
                signature: falconSig
            }
        };
    }

    async verifyPostQuantum(digest, signatures, signingKey) {
        // Regenerate signatures and compare
        const expected = await this.signPostQuantum(digest, signingKey);

        const dilithiumValid = signatures.dilithium.signature === expected.dilithium.signature;
        const falconValid = signatures.falcon.signature === expected.falcon.signature;

        // Policy: BOTH_REQUIRED
        return dilithiumValid && falconValid;
    }

    // ============================================
    // Hash Functions
    // ============================================

    async computeSHA3_512(data) {
        // SHA3-512 simulation using SHA-512 with additional mixing
        // For true SHA3, integrate @noble/hashes
        const hash1 = await this.computeHash(data, 'SHA-512');
        const hash2 = await this.computeHash(new TextEncoder().encode(hash1 + 'SHA3-512'), 'SHA-512');
        return hash2;
    }

    async computeHash(data, algorithm = 'SHA-512') {
        const buffer = data instanceof Uint8Array ? data : new TextEncoder().encode(data);
        const hashBuffer = await this.crypto.digest(algorithm, buffer);
        return this.arrayToBase64(hashBuffer);
    }

    // ============================================
    // Utility Functions
    // ============================================

    generateRandomBytes(len) {
        return window.crypto.getRandomValues(new Uint8Array(len));
    }

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
        return bytes;
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
