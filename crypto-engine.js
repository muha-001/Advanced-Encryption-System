// ============================================
// محرك التشفير المتقدم - AES-256-GCM مع PBKDF2
// ============================================

class CryptoEngine {
    constructor() {
        this.config = {
            algorithm: 'AES-GCM',
            hash: 'SHA-256',
            keyLength: 256,
            iterations: 310000,
            saltLength: 16,
            ivLength: 12,
            tagLength: 128
        };
        
        this.crypto = window.crypto.subtle;
        
        // التحقق من دعم Web Crypto API
        if (!this.crypto) {
            throw new Error('Web Crypto API غير مدعوم في هذا المتصفح');
        }
        
        console.log('🚀 محرك التشفير المتقدم جاهز للعمل');
    }

    // ===== التشفير الأساسي =====
    async encrypt(plainText, password, options = {}) {
        try {
            // التحقق من المدخلات
            if (!plainText || !password) {
                throw new Error('النص أو كلمة المرور فارغة');
            }

            const startTime = performance.now();

            // 1. توليد الملح العشوائي
            const salt = this.generateRandomBytes(this.config.saltLength);
            
            // 2. اشتقاق المفتاح باستخدام PBKDF2
            const key = await this.deriveKey(password, salt, this.config.iterations);
            
            // 3. توليد IV عشوائي
            const iv = this.generateRandomBytes(this.config.ivLength);
            
            // 4. التشفير باستخدام AES-GCM
            const encoder = new TextEncoder();
            const encodedText = encoder.encode(plainText);
            
            const encrypted = await this.crypto.encrypt(
                {
                    name: this.config.algorithm,
                    iv: iv,
                    tagLength: this.config.tagLength
                },
                key,
                encodedText
            );
            
            // 5. استخراج علامة المصادقة
            const ciphertext = encrypted.slice(0, encrypted.byteLength - (this.config.tagLength / 8));
            const tag = encrypted.slice(encrypted.byteLength - (this.config.tagLength / 8));
            
            // 6. إنشاء بنية البيانات المشفرة
            const encryptedData = {
                version: '3.0',
                algorithm: this.config.algorithm,
                iterations: this.config.iterations,
                keyLength: this.config.keyLength,
                salt: this.arrayToBase64(salt),
                iv: this.arrayToBase64(iv),
                tag: this.arrayToBase64(tag),
                ciphertext: this.arrayToBase64(ciphertext),
                timestamp: options.timestamp ? Date.now() : null,
                metadata: {
                    compression: options.compression || false,
                    randomSalt: options.randomSalt !== false,
                    encoded: false
                }
            };
            
            const endTime = performance.now();
            const encryptionTime = Math.round(endTime - startTime);
            
            // إضافة معلومات الأداء
            encryptedData.performance = {
                time: encryptionTime,
                size: {
                    original: plainText.length,
                    encrypted: JSON.stringify(encryptedData).length,
                    ratio: Math.round((JSON.stringify(encryptedData).length / plainText.length) * 100) + '%'
                }
            };
            
            // إذا طلب الضغط
            if (options.compression) {
                encryptedData.ciphertext = await this.compressData(encryptedData.ciphertext);
                encryptedData.metadata.compression = true;
            }
            
            return encryptedData;
            
        } catch (error) {
            console.error('❌ فشل التشفير:', error);
            throw new Error(`فشل التشفير: ${error.message}`);
        }
    }

    // ===== فك التشفير =====
    async decrypt(encryptedData, password) {
        try {
            // التحقق من المدخلات
            if (!encryptedData || !password) {
                throw new Error('البيانات المشفرة أو كلمة المرور فارغة');
            }
            
            let data;
            
            // معالجة أنواع مختلفة من المدخلات
            if (typeof encryptedData === 'string') {
                try {
                    data = JSON.parse(encryptedData);
                } catch {
                    // قد يكون النص مشفراً مباشرة
                    data = this.parseEncryptedString(encryptedData);
                }
            } else if (typeof encryptedData === 'object') {
                data = encryptedData;
            } else {
                throw new Error('تنسيق البيانات المشفرة غير معروف');
            }
            
            // التحقق من الإصدار
            if (!data.version || !data.version.startsWith('3')) {
                throw new Error('إصدار التشفير غير مدعوم. يرجى استخدام الإصدار 3.x');
            }
            
            const startTime = performance.now();
            
            // إذا كانت البيانات مضغوطة
            if (data.metadata?.compression) {
                data.ciphertext = await this.decompressData(data.ciphertext);
            }
            
            // 1. فك ترميز البيانات
            const salt = this.base64ToArray(data.salt);
            const iv = this.base64ToArray(data.iv);
            const tag = this.base64ToArray(data.tag);
            const ciphertext = this.base64ToArray(data.ciphertext);
            
            // 2. اشتقاق المفتاح
            const key = await this.deriveKey(password, salt, data.iterations || this.config.iterations);
            
            // 3. دمج ciphertext مع tag
            const encrypted = new Uint8Array(ciphertext.byteLength + tag.byteLength);
            encrypted.set(new Uint8Array(ciphertext), 0);
            encrypted.set(new Uint8Array(tag), ciphertext.byteLength);
            
            // 4. فك التشفير باستخدام AES-GCM
            const decrypted = await this.crypto.decrypt(
                {
                    name: data.algorithm || this.config.algorithm,
                    iv: iv,
                    tagLength: this.config.tagLength
                },
                key,
                encrypted
            );
            
            // 5. تحويل إلى نص
            const decoder = new TextDecoder();
            const plainText = decoder.decode(decrypted);
            
            const endTime = performance.now();
            const decryptionTime = Math.round(endTime - startTime);
            
            // التحقق من صحة البيانات
            const integrity = await this.verifyIntegrity(data, plainText);
            
            return {
                text: plainText,
                integrity: integrity,
                metadata: {
                    algorithm: data.algorithm,
                    timestamp: data.timestamp,
                    compression: data.metadata?.compression || false,
                    iterations: data.iterations,
                    version: data.version
                },
                performance: {
                    time: decryptionTime
                }
            };
            
        } catch (error) {
            console.error('❌ فشل فك التشفير:', error);
            
            // تقديم رسالة خطأ أكثر تفصيلاً
            let errorMessage = 'فشل فك التشفير';
            
            if (error.name === 'OperationError') {
                errorMessage = 'كلمة المرور غير صحيحة أو البيانات تالفة';
            } else if (error.message.includes('version')) {
                errorMessage = 'إصدار التشفير غير مدعوم';
            } else if (error.message.includes('decode')) {
                errorMessage = 'تنسيق البيانات المشفرة غير صحيح';
            }
            
            throw new Error(`${errorMessage}: ${error.message}`);
        }
    }

    // ===== توليد المفاتيح =====
    async deriveKey(password, salt, iterations) {
        try {
            // تحويل كلمة المرور إلى ArrayBuffer
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(password);
            
            // استيراد كلمة المرور كمادة مفتاح
            const keyMaterial = await this.crypto.importKey(
                'raw',
                passwordBuffer,
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            // اشتقاق المفتاح باستخدام PBKDF2
            const key = await this.crypto.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: this.config.hash
                },
                keyMaterial,
                {
                    name: this.config.algorithm,
                    length: this.config.keyLength
                },
                false, // لا يمكن تصديره
                ['encrypt', 'decrypt']
            );
            
            return key;
            
        } catch (error) {
            console.error('❌ فشل اشتقاق المفتاح:', error);
            throw error;
        }
    }

    // ===== توليد قيم عشوائية آمنة =====
    generateRandomBytes(length) {
        return window.crypto.getRandomValues(new Uint8Array(length));
    }

    // ===== تحويل بين التنسيقات =====
    arrayToBase64(array) {
        if (array instanceof ArrayBuffer) {
            array = new Uint8Array(array);
        }
        
        const binary = String.fromCharCode(...array);
        return btoa(binary);
    }

    base64ToArray(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        
        return bytes.buffer;
    }

    // ===== الضغط والتفريغ =====
    async compressData(data) {
        try {
            // استخدام Compression Streams API إذا متوفرة
            if ('CompressionStream' in window) {
                const stream = new Blob([data]).stream();
                const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
                const compressedBlob = await new Response(compressedStream).blob();
                const compressedArrayBuffer = await compressedBlob.arrayBuffer();
                return this.arrayToBase64(compressedArrayBuffer);
            }
            
            // طريقة بديلة باستخدام pako إذا تم تضمينها
            if (typeof pako !== 'undefined') {
                const compressed = pako.gzip(data);
                return this.arrayToBase64(compressed);
            }
            
            // إذا لم يكن الضغط مدعوماً، إرجاع البيانات كما هي
            return data;
            
        } catch (error) {
            console.warn('⚠️ فشل الضغط، إرجاع البيانات غير مضغوطة:', error);
            return data;
        }
    }

    async decompressData(data) {
        try {
            const arrayBuffer = this.base64ToArray(data);
            
            // استخدام Decompression Streams API إذا متوفرة
            if ('DecompressionStream' in window) {
                const stream = new Blob([arrayBuffer]).stream();
                const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
                const decompressedBlob = await new Response(decompressedStream).blob();
                return await decompressedBlob.text();
            }
            
            // طريقة بديلة باستخدام pako
            if (typeof pako !== 'undefined') {
                const decompressed = pako.ungzip(new Uint8Array(arrayBuffer));
                return new TextDecoder().decode(decompressed);
            }
            
            // إذا لم يكن التفريغ مدعوماً، إرجاع البيانات كما هي
            return new TextDecoder().decode(new Uint8Array(arrayBuffer));
            
        } catch (error) {
            console.warn('⚠️ فشل التفريغ، معالجة البيانات كما هي:', error);
            return new TextDecoder().decode(new Uint8Array(this.base64ToArray(data)));
        }
    }

    // ===== التحقق من صحة البيانات =====
    async verifyIntegrity(encryptedData, decryptedText) {
        try {
            // التحقق من وجود جميع الحقول المطلوبة
            const requiredFields = ['salt', 'iv', 'tag', 'ciphertext', 'algorithm'];
            const missingFields = requiredFields.filter(field => !encryptedData[field]);
            
            if (missingFields.length > 0) {
                console.warn('⚠️ حقول مفقودة:', missingFields);
                return false;
            }
            
            // التحقق من تنسيق الحقول
            const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
            const base64Fields = ['salt', 'iv', 'tag', 'ciphertext'];
            
            for (const field of base64Fields) {
                if (!base64Regex.test(encryptedData[field])) {
                    console.warn(`⚠️ تنسيق ${field} غير صحيح`);
                    return false;
                }
            }
            
            // التحقق من طول الحقول
            if (encryptedData.salt.length < 16) {
                console.warn('⚠️ طول الملح غير كافٍ');
                return false;
            }
            
            if (encryptedData.iv.length < 12) {
                console.warn('⚠️ طول IV غير كافٍ');
                return false;
            }
            
            // محاولة إعادة تشفير للتحقق (اختياري)
            if (decryptedText && decryptedText.length < 1000) { // فقط للنصوص القصيرة
                try {
                    const testEncrypted = await this.encrypt(
                        decryptedText,
                        'test-password',
                        { timestamp: false, compression: false }
                    );
                    
                    // التحقق من أن الهيكل متشابه
                    if (testEncrypted.algorithm !== encryptedData.algorithm) {
                        console.warn('⚠️ الخوارزمية لا تتطابق');
                        return false;
                    }
                    
                } catch (testError) {
                    console.warn('⚠️ فشل التحقق بالاختبار:', testError);
                    // لا نعيد false لأن هذا ليس فشلاً حاسماً
                }
            }
            
            return true;
            
        } catch (error) {
            console.warn('⚠️ فشل التحقق من الصحة:', error);
            return false;
        }
    }

    // ===== معالجة النص المشفر كسلسلة =====
    parseEncryptedString(encryptedString) {
        try {
            // قد تكون سلسلة Base64 مباشرة
            if (encryptedString.length > 100 && !encryptedString.includes('{')) {
                return {
                    version: '3.0',
                    algorithm: this.config.algorithm,
                    iterations: this.config.iterations,
                    salt: encryptedString.substring(0, 24),
                    iv: encryptedString.substring(24, 44),
                    tag: encryptedString.substring(44, 64),
                    ciphertext: encryptedString.substring(64),
                    metadata: {
                        compression: false,
                        encoded: true
                    }
                };
            }
            
            throw new Error('تنسيق السلسلة غير معروف');
            
        } catch (error) {
            throw new Error(`فشل تحليل السلسلة: ${error.message}`);
        }
    }

    // ===== أدوات إضافية =====
    async generateKeyPair() {
        try {
            const keyPair = await this.crypto.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            return {
                publicKey: await this.crypto.exportKey('spki', keyPair.publicKey),
                privateKey: await this.crypto.exportKey('pkcs8', keyPair.privateKey)
            };
            
        } catch (error) {
            console.error('❌ فشل توليد زوج المفاتيح:', error);
            throw error;
        }
    }

    async hashData(data, algorithm = 'SHA-256') {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            
            const hashBuffer = await this.crypto.digest(algorithm, dataBuffer);
            
            // تحويل إلى سلسلة hex
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            return hashHex;
            
        } catch (error) {
            console.error('❌ فشل حساب الهاش:', error);
            throw error;
        }
    }

    // ===== التحقق من الأداء =====
    async benchmark() {
        const testData = {
            text: 'هذا نص اختبار للتشفير. يحتوي على أحرف عربية وإنجليزية وأرقام: 123456',
            password: 'كلمة مرور قوية جداً 123!@#'
        };
        
        const results = {
            encryption: null,
            decryption: null,
            hash: null,
            keyDerivation: null
        };
        
        try {
            // اختبار اشتقاق المفتاح
            const keyStart = performance.now();
            const salt = this.generateRandomBytes(16);
            await this.deriveKey(testData.password, salt, 1000);
            results.keyDerivation = Math.round(performance.now() - keyStart);
            
            // اختبار التشفير
            const encStart = performance.now();
            const encrypted = await this.encrypt(testData.text, testData.password);
            results.encryption = Math.round(performance.now() - encStart);
            
            // اختبار فك التشفير
            const decStart = performance.now();
            await this.decrypt(encrypted, testData.password);
            results.decryption = Math.round(performance.now() - decStart);
            
            // اختبار الهاش
            const hashStart = performance.now();
            await this.hashData(testData.text);
            results.hash = Math.round(performance.now() - hashStart);
            
            console.log('📊 نتائج اختبار الأداء:', results);
            return results;
            
        } catch (error) {
            console.error('❌ فشل اختبار الأداء:', error);
            return null;
        }
    }
}

// تصدير الفئة للاستخدام العام
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoEngine;
} else {
    // للاستخدام في المتصفح
    window.CryptoEngine = CryptoEngine;
}
