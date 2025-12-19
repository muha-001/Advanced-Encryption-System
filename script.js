// ============================================
// نظام التشفير المتقدم - GitHub Pages Edition
// ============================================

// تعريف الثوابت الأمنية
const SECURITY_CONFIG = {
    PBKDF2_ITERATIONS: 310000, // معيار OWASP 2023
    SALT_LENGTH: 16, // 128-bit salt
    IV_LENGTH: 12, // 96-bit IV for AES-GCM
    KEY_LENGTH: 256, // AES-256
    ALGORITHM: 'AES-GCM',
    HASH: 'SHA-256',
    IS_GITHUB_PAGES: window.location.hostname.includes('github.io')
};

// إدارة حالة التطبيق
const AppState = {
    language: 'ar',
    totalEncryptions: 0,
    failedAttempts: 0,
    decryptAttempts: 0,
    sessionStart: null,
    securityChecks: {
        https: false,
        crypto: false,
        storage: false,
        browser: false,
        githubPages: false
    },
    passwordAttempts: new Map(),
    maxAttempts: 10,
    lockoutTime: 15 * 60 * 1000 // 15 دقيقة
};

// ترجمة النصوص
const translations = {
    ar: {
        title: "نظام التشفير المتقدم",
        subtitle: "نظام تشفير من المستوى العسكري على GitHub Pages. يستخدم Web Crypto API مع AES-256-GCM وPBKDF2 مع 310,000 تكرار. تشفير محلي 100% - لا توجد بيانات ترسل إلى أي خادم.",
        encryptTitle: "تشفير النص الآمن",
        plainTextLabel: "النص المراد تشفيره:",
        passwordLabel: "كلمة المرور للتشفير:",
        strengthLabel: "قوة كلمة المرور:",
        encryptBtnText: "تشفير النص",
        clearEncryptBtnText: "مسح الحقول",
        decryptTitle: "فك تشفير النص",
        encryptedTextLabel: "النص المشفر:",
        decryptPasswordLabel: "كلمة المرور لفك التشفير:",
        decryptBtnText: "فك تشفير النص",
        clearDecryptBtnText: "مسح الحقول",
        decryptedTextLabel: "النص بعد فك التشفير:",
        weakPassword: "ضعيفة",
        mediumPassword: "متوسطة",
        strongPassword: "قوية",
        veryStrongPassword: "قوية جداً",
        encryptSuccess: "✅ تم تشفير النص بنجاح!",
        encryptError: "❌ يرجى إدخال نص وكلمة مرور للتشفير",
        decryptSuccess: "✅ تم فك تشفير النص بنجاح!",
        decryptError: "❌ فشل فك التشفير. تأكد من صحة النص المشفر وكلمة المرور.",
        copySuccess: "✅ تم نسخ النص إلى الحافظة!",
        clearConfirm: "هل تريد مسح جميع الحقول؟",
        sessionExpired: "⏳ انتهت الجلسة الأمنية. يرجى إعادة التحميل.",
        maxAttemptsExceeded: "🚫 تجاوزت الحد الأقصى للمحاولات. تم تأمين النظام.",
        securityCheckFailed: "⚠️ فشل التحقق من البيئة الآمنة. لا يمكن استخدام النظام.",
        generatingPassword: "🔄 جاري توليد كلمة مرور آمنة...",
        passwordGenerated: "✅ تم توليد كلمة مرور آمنة",
        secureWipeComplete: "🧹 تم المسح الآمن للبيانات الحساسة",
        dataIntegrityValid: "✅ صحة البيانات: سليمة",
        dataIntegrityInvalid: "❌ صحة البيانات: تالفة",
        githubPagesActive: "🚀 يعمل على GitHub Pages - تشفير محلي 100%"
    },
    en: {
        title: "Advanced Encryption System",
        subtitle: "Military-grade encryption system on GitHub Pages. Uses Web Crypto API with AES-256-GCM and PBKDF2 with 310,000 iterations. 100% local encryption - no data sent to any server.",
        encryptTitle: "Secure Text Encryption",
        plainTextLabel: "Text to encrypt:",
        passwordLabel: "Encryption password:",
        strengthLabel: "Password strength:",
        encryptBtnText: "Encrypt Text",
        clearEncryptBtnText: "Clear Fields",
        decryptTitle: "Decrypt Text",
        encryptedTextLabel: "Encrypted text:",
        decryptPasswordLabel: "Password for decryption:",
        decryptBtnText: "Decrypt Text",
        clearDecryptBtnText: "Clear Fields",
        decryptedTextLabel: "Decrypted text:",
        weakPassword: "Weak",
        mediumPassword: "Medium",
        strongPassword: "Strong",
        veryStrongPassword: "Very Strong",
        encryptSuccess: "✅ Text encrypted successfully!",
        encryptError: "❌ Please enter text and password for encryption",
        decryptSuccess: "✅ Text decrypted successfully!",
        decryptError: "❌ Decryption failed. Make sure the encrypted text and password are correct.",
        copySuccess: "✅ Text copied to clipboard!",
        clearConfirm: "Do you want to clear all fields?",
        sessionExpired: "⏳ Security session expired. Please reload.",
        maxAttemptsExceeded: "🚫 Maximum attempts exceeded. System locked.",
        securityCheckFailed: "⚠️ Security environment check failed. Cannot use the system.",
        generatingPassword: "🔄 Generating secure password...",
        passwordGenerated: "✅ Secure password generated",
        secureWipeComplete: "🧹 Secure wipe completed",
        dataIntegrityValid: "✅ Data integrity: Valid",
        dataIntegrityInvalid: "❌ Data integrity: Invalid",
        githubPagesActive: "🚀 Running on GitHub Pages - 100% local encryption"
    }
};

// ============================================
// فئة النظام الأمني الرئيسية لـ GitHub Pages
// ============================================

class GitHubPagesEncryptionSystem {
    constructor() {
        this.crypto = window.crypto.subtle;
        this.state = AppState;
        this.sessionTimer = null;
        this.isGitHubPages = SECURITY_CONFIG.IS_GITHUB_PAGES;
        this.initialize();
    }

    async initialize() {
        try {
            // التحقق من أننا على GitHub Pages
            if (this.isGitHubPages) {
                console.log('🚀 GitHub Pages Encryption System Initialized');
                this.updateSecurityStatus('githubPages', 'نشط ✓');
                this.state.securityChecks.githubPages = true;
            }
            
            // بدء التحقق من الأمان
            await this.performSecurityChecks();
            
            // تهيئة واجهة المستخدم
            this.initUI();
            
            // بدء جلسة آمنة
            this.startSecureSession();
            
            // تسجيل الأحداث
            this.setupEventListeners();
            
        } catch (error) {
            console.error('System initialization failed:', error);
            this.showNotification(this.t('securityCheckFailed'), 'error');
        }
    }

    async performSecurityChecks() {
        return new Promise(async (resolve, reject) => {
            try {
                // 1. التحقق من HTTPS (GitHub Pages دائماً HTTPS)
                this.updateSecurityStatus('https', 'جارٍ التحقق...');
                const isHTTPS = window.location.protocol === 'https:' || this.isGitHubPages;
                await this.delay(500);
                this.updateSecurityStatus('https', isHTTPS ? 'آمن ✓' : 'غير آمن ✗');
                this.state.securityChecks.https = isHTTPS;

                // 2. التحقق من Web Crypto API
                this.updateSecurityStatus('crypto', 'جارٍ التحقق...');
                const hasCrypto = !!window.crypto && !!window.crypto.subtle;
                await this.delay(500);
                this.updateSecurityStatus('crypto', hasCrypto ? 'متاح ✓' : 'غير متاح ✗');
                this.state.securityChecks.crypto = hasCrypto;

                // 3. التحقق من التخزين الآمن
                this.updateSecurityStatus('storage', 'جارٍ التحقق...');
                const hasStorage = typeof localStorage !== 'undefined';
                await this.delay(500);
                this.updateSecurityStatus('storage', hasStorage ? 'متاح ✓' : 'غير متاح ✗');
                this.state.securityChecks.storage = hasStorage;

                // 4. التحقق من المتصفح الآمن
                this.updateSecurityStatus('browser', 'جارٍ التحقق...');
                const isModernBrowser = this.checkModernBrowser();
                await this.delay(500);
                this.updateSecurityStatus('browser', isModernBrowser ? 'حديث ✓' : 'قديم ✗');
                this.state.securityChecks.browser = isModernBrowser;

                // التحقق النهائي
                await this.delay(1000);
                
                const allChecksPassed = Object.values(this.state.securityChecks).every(check => check);
                
                if (allChecksPassed) {
                    document.getElementById('continueBtn').disabled = false;
                    this.showNotification(this.t('githubPagesActive'), 'success');
                    resolve();
                } else {
                    reject(new Error('Security checks failed'));
                }

            } catch (error) {
                reject(error);
            }
        });
    }

    // ============================================
    // التشفير الأساسي (نفس النظام السابق)
    // ============================================

    async encryptText(text, password, options = {}) {
        try {
            // التحقق من المدخلات
            if (!text || !password) {
                throw new Error('Missing text or password');
            }

            // التحقق من تجاوز الحد الأقصى للمحاولات
            if (this.isRateLimited(password)) {
                throw new Error('Rate limited');
            }

            const startTime = performance.now();

            // 1. توليد الملح (Salt) عشوائي
            const salt = window.crypto.getRandomValues(new Uint8Array(SECURITY_CONFIG.SALT_LENGTH));

            // 2. اشتقاق المفتاح باستخدام PBKDF2
            const keyMaterial = await this.crypto.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await this.crypto.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: SECURITY_CONFIG.PBKDF2_ITERATIONS,
                    hash: SECURITY_CONFIG.HASH
                },
                keyMaterial,
                {
                    name: SECURITY_CONFIG.ALGORITHM,
                    length: SECURITY_CONFIG.KEY_LENGTH
                },
                false,
                ['encrypt', 'decrypt']
            );

            // 3. توليد IV عشوائي
            const iv = window.crypto.getRandomValues(new Uint8Array(SECURITY_CONFIG.IV_LENGTH));

            // 4. التشفير باستخدام AES-GCM
            const encrypted = await this.crypto.encrypt(
                {
                    name: SECURITY_CONFIG.ALGORITHM,
                    iv: iv
                },
                key,
                new TextEncoder().encode(text)
            );

            // 5. إنشاء بنية البيانات المشفرة
            const encryptedData = {
                v: '3.0', // الإصدار 3.0 لـ GitHub Pages
                a: SECURITY_CONFIG.ALGORITHM,
                i: Array.from(iv),
                s: Array.from(salt),
                d: Array.from(new Uint8Array(encrypted)),
                t: options.timestamp ? Date.now() : null,
                h: options.compression ? 'gzip' : null,
                c: SECURITY_CONFIG.PBKDF2_ITERATIONS,
                p: this.isGitHubPages ? 'gh-pages' : 'standard'
            };

            // 6. تحويل إلى Base64 (آمن لـ GitHub Pages)
            const jsonString = JSON.stringify(encryptedData);
            const base64String = btoa(unescape(encodeURIComponent(jsonString)));

            const endTime = performance.now();
            const encryptionTime = Math.round(endTime - startTime);

            // تحديث الإحصائيات
            this.state.totalEncryptions++;
            this.updateStatistics();

            return {
                encrypted: base64String,
                time: encryptionTime,
                algorithm: SECURITY_CONFIG.ALGORITHM,
                keyLength: SECURITY_CONFIG.KEY_LENGTH,
                iterations: SECURITY_CONFIG.PBKDF2_ITERATIONS,
                environment: this.isGitHubPages ? 'GitHub Pages' : 'Local'
            };

        } catch (error) {
            console.error('Encryption error:', error);
            this.state.failedAttempts++;
            throw error;
        }
    }

    async decryptText(encryptedData, password) {
        try {
            // التحقق من المدخلات
            if (!encryptedData || !password) {
                throw new Error('Missing encrypted data or password');
            }

            // التحقق من تجاوز الحد الأقصى للمحاولات
            if (this.isRateLimited(password)) {
                throw new Error('Rate limited');
            }

            const startTime = performance.now();

            // 1. فك Base64 وتحليل JSON
            const jsonString = decodeURIComponent(escape(atob(encryptedData)));
            const data = JSON.parse(jsonString);

            // التحقق من الإصدار
            if (data.v !== '3.0') {
                throw new Error('Unsupported version. Please re-encrypt with the latest version.');
            }

            // 2. تحويل البيانات إلى Uint8Array
            const salt = new Uint8Array(data.s);
            const iv = new Uint8Array(data.i);
            const encrypted = new Uint8Array(data.d);

            // 3. اشتقاق المفتاح باستخدام PBKDF2
            const keyMaterial = await this.crypto.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await this.crypto.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: data.c || SECURITY_CONFIG.PBKDF2_ITERATIONS,
                    hash: SECURITY_CONFIG.HASH
                },
                keyMaterial,
                {
                    name: data.a,
                    length: SECURITY_CONFIG.KEY_LENGTH
                },
                false,
                ['decrypt']
            );

            // 4. فك التشفير باستخدام AES-GCM
            const decrypted = await this.crypto.decrypt(
                {
                    name: data.a,
                    iv: iv
                },
                key,
                encrypted
            );

            // 5. تحويل إلى نص
            const text = new TextDecoder().decode(decrypted);

            const endTime = performance.now();
            const decryptionTime = Math.round(endTime - startTime);

            // تحديث محاولات فك التشفير الناجحة
            this.state.decryptAttempts++;
            this.updateStatistics();

            return {
                text: text,
                time: decryptionTime,
                metadata: {
                    algorithm: data.a,
                    timestamp: data.t,
                    compression: data.h,
                    iterations: data.c,
                    environment: data.p || 'standard'
                },
                integrity: true
            };

        } catch (error) {
            console.error('Decryption error:', error);
            this.state.decryptAttempts++;
            this.state.failedAttempts++;
            
            // تسجيل محاولة فاشلة
            this.recordFailedAttempt(password);
            
            throw error;
        }
    }

    // ============================================
    // وظائف المساعدة (نفس النظام السابق)
    // ============================================

    updateSecurityStatus(type, status) {
        const element = document.getElementById(`${type}Status`);
        if (element) {
            element.textContent = status;
            element.className = status.includes('✓') ? 'status-good' : 'status-bad';
        }
    }

    checkModernBrowser() {
        try {
            const features = [
                'Promise',
                'fetch',
                'crypto',
                'crypto.subtle',
                'TextEncoder',
                'TextDecoder',
                'Uint8Array'
            ];
            return features.every(feature => feature in window);
        } catch {
            return false;
        }
    }

    startSecureSession() {
        this.state.sessionStart = Date.now();
        this.updateSessionTimer();
        
        this.sessionTimer = setInterval(() => {
            this.updateSessionTimer();
        }, 1000);
    }

    updateSessionTimer() {
        const elapsed = Date.now() - this.state.sessionStart;
        const remaining = Math.max(0, 15 * 60 * 1000 - elapsed);
        
        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        
        const timerElement = document.getElementById('sessionTimer');
        if (timerElement) {
            timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            if (remaining < 60000) {
                timerElement.style.color = 'var(--danger)';
                timerElement.style.animation = 'pulse 1s infinite';
            }
        }
        
        if (remaining === 0) {
            this.endSession();
        }
    }

    endSession() {
        clearInterval(this.sessionTimer);
        this.showNotification(this.t('sessionExpired'), 'warning');
        this.clearAllSensitiveData();
        
        setTimeout(() => {
            window.location.reload();
        }, 5000);
    }

    showMainApp() {
        document.getElementById('loadingScreen').style.display = 'none';
        document.getElementById('securityCheck').style.display = 'none';
        document.getElementById('mainApp').classList.remove('hidden');
        this.startSecureSession();
    }

    // بقية الدوال (نفس النظام السابق)...
    // [جميع الدوال الأخرى تبقى كما هي]
}

// ============================================
// تهيئة النظام
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // التحقق من دعم Web Crypto API
    if (!window.crypto || !window.crypto.subtle) {
        alert('⚠️ هذا المتصفح لا يدعم Web Crypto API. يرجى استخدام متصفح حديث.');
        return;
    }
    
    // بدء النظام
    window.encryptionSystem = new GitHubPagesEncryptionSystem();
    
    // إضافة حدث للمتابعة
    document.getElementById('continueBtn').addEventListener('click', () => {
        window.encryptionSystem.showMainApp();
    });
});

// دالة تأخير
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
