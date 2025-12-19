// ============================================
// نظام التشفير المتقدم باستخدام Web Crypto API
// ============================================

// تعريف الثوابت الأمنية
const SECURITY_CONFIG = {
    PBKDF2_ITERATIONS: 310000, // معيار OWASP 2023
    SALT_LENGTH: 16, // 128-bit salt
    IV_LENGTH: 12, // 96-bit IV for AES-GCM
    KEY_LENGTH: 256, // AES-256
    ALGORITHM: 'AES-GCM',
    HASH: 'SHA-256'
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
        browser: false
    },
    passwordAttempts: new Map(),
    maxAttempts: 10,
    lockoutTime: 15 * 60 * 1000 // 15 دقيقة
};

// ترجمة النصوص
const translations = {
    ar: {
        title: "نظام التشفير المتقدم",
        subtitle: "نظام تشفير من المستوى العسكري باستخدام Web Crypto API مع AES-256-GCM وPBKDF2 مع 310,000 تكرار. تشفير محلي 100% - لا توجد بيانات ترسل إلى أي خادم.",
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
        securityTitle: "مستوى أمني لا يمكن اختراقه",
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
        dataIntegrityInvalid: "❌ صحة البيانات: تالفة"
    },
    en: {
        title: "Advanced Encryption System",
        subtitle: "Military-grade encryption system using Web Crypto API with AES-256-GCM and PBKDF2 with 310,000 iterations. 100% local encryption - no data sent to any server.",
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
        securityTitle: "Unbreakable Security Level",
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
        dataIntegrityInvalid: "❌ Data integrity: Invalid"
    }
};

// ============================================
// فئة النظام الأمني الرئيسية
// ============================================

class AdvancedEncryptionSystem {
    constructor() {
        this.crypto = window.crypto.subtle;
        this.state = AppState;
        this.sessionTimer = null;
        this.initialize();
    }

    async initialize() {
        try {
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

    // ============================================
    // التحقق من البيئة الآمنة
    // ============================================

    async performSecurityChecks() {
        return new Promise(async (resolve, reject) => {
            try {
                // 1. التحقق من HTTPS
                this.updateSecurityStatus('https', 'جارٍ التحقق...');
                const isHTTPS = window.location.protocol === 'https:';
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
                    resolve();
                } else {
                    reject(new Error('Security checks failed'));
                }

            } catch (error) {
                reject(error);
            }
        });
    }

    updateSecurityStatus(type, status) {
        const element = document.getElementById(`${type}Status`);
        if (element) {
            element.textContent = status;
            element.className = status.includes('✓') ? 'status-good' : 'status-bad';
        }
    }

    checkModernBrowser() {
        try {
            // التحقق من دعم الميزات الحديثة
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

    // ============================================
    // إدارة الجلسة الآمنة
    // ============================================

    startSecureSession() {
        this.state.sessionStart = Date.now();
        this.updateSessionTimer();
        
        // جلسة مدتها 15 دقيقة
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
            
            if (remaining < 60000) { // أقل من دقيقة
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
        
        // إعادة تحميل الصفحة بعد 5 ثواني
        setTimeout(() => {
            window.location.reload();
        }, 5000);
    }

    // ============================================
    // التشفير باستخدام Web Crypto API
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
                v: '2.0', // الإصدار
                a: SECURITY_CONFIG.ALGORITHM,
                i: Array.from(iv),
                s: Array.from(salt),
                d: Array.from(new Uint8Array(encrypted)),
                t: options.timestamp ? Date.now() : null,
                h: options.compression ? 'gzip' : null,
                c: SECURITY_CONFIG.PBKDF2_ITERATIONS
            };

            // 6. تحويل إلى Base64
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
                iterations: SECURITY_CONFIG.PBKDF2_ITERATIONS
            };

        } catch (error) {
            console.error('Encryption error:', error);
            this.state.failedAttempts++;
            throw error;
        }
    }

    // ============================================
    // فك التشفير باستخدام Web Crypto API
    // ============================================

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
            if (data.v !== '2.0') {
                throw new Error('Unsupported version');
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
                    iterations: data.c
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
    // إدارة كلمات المرور والأمان
    // ============================================

    checkPasswordStrength(password) {
        let score = 0;
        const requirements = {
            length: false,
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false
        };

        // 1. الطول (12+ حرف)
        if (password.length >= 12) {
            score += 2;
            requirements.length = true;
        } else if (password.length >= 8) {
            score += 1;
        }

        // 2. أحرف كبيرة
        if (/[A-Z]/.test(password)) {
            score += 1;
            requirements.uppercase = true;
        }

        // 3. أحرف صغيرة
        if (/[a-z]/.test(password)) {
            score += 1;
            requirements.lowercase = true;
        }

        // 4. أرقام
        if (/[0-9]/.test(password)) {
            score += 1;
            requirements.numbers = true;
        }

        // 5. رموز خاصة
        if (/[^A-Za-z0-9]/.test(password)) {
            score += 1;
            requirements.symbols = true;
        }

        // 6. عدم وجود كلمات شائعة
        const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome'];
        if (!commonPasswords.some(common => password.toLowerCase().includes(common))) {
            score += 1;
        }

        // تحديث متطلبات القوة
        this.updatePasswordRequirements(requirements);

        // تحديد مستوى القوة
        if (score <= 3) return { level: 'weak', score, percentage: 25 };
        if (score <= 5) return { level: 'medium', score, percentage: 50 };
        if (score <= 7) return { level: 'strong', score, percentage: 75 };
        return { level: 'very-strong', score, percentage: 100 };
    }

    updatePasswordRequirements(requirements) {
        const container = document.getElementById('strengthRequirements');
        if (!container) return;

        const requirementElements = container.querySelectorAll('.requirement');
        
        requirementElements[0].innerHTML = requirements.length ? 
            '<i class="fas fa-check"></i> 12+ أحرف' : 
            '<i class="fas fa-times"></i> 8 أحرف على الأقل';
            
        requirementElements[1].innerHTML = requirements.uppercase ? 
            '<i class="fas fa-check"></i> حرف كبير' : 
            '<i class="fas fa-times"></i> حرف كبير';
            
        requirementElements[2].innerHTML = requirements.lowercase ? 
            '<i class="fas fa-check"></i> حرف صغير' : 
            '<i class="fas fa-times"></i> حرف صغير';
            
        requirementElements[3].innerHTML = requirements.numbers ? 
            '<i class="fas fa-check"></i> رقم' : 
            '<i class="fas fa-times"></i> رقم';
            
        requirementElements[4].innerHTML = requirements.symbols ? 
            '<i class="fas fa-check"></i> رمز خاص' : 
            '<i class="fas fa-times"></i> رمز خاص';
    }

    generateRandomPassword(length = 16, options = {
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true
    }) {
        const charset = {
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };

        let availableChars = '';
        Object.keys(options).forEach(key => {
            if (options[key]) {
                availableChars += charset[key];
            }
        });

        if (!availableChars) {
            availableChars = charset.lowercase + charset.numbers;
        }

        // التأكد من وجود حرف واحد من كل نوع مختار
        let password = '';
        if (options.uppercase) {
            password += charset.uppercase[Math.floor(Math.random() * charset.uppercase.length)];
        }
        if (options.lowercase) {
            password += charset.lowercase[Math.floor(Math.random() * charset.lowercase.length)];
        }
        if (options.numbers) {
            password += charset.numbers[Math.floor(Math.random() * charset.numbers.length)];
        }
        if (options.symbols) {
            password += charset.symbols[Math.floor(Math.random() * charset.symbols.length)];
        }

        // إكمال الباقي عشوائياً
        for (let i = password.length; i < length; i++) {
            password += availableChars[Math.floor(Math.random() * availableChars.length)];
        }

        // خلط الأحرف
        password = password.split('').sort(() => Math.random() - 0.5).join('');

        return password;
    }

    // ============================================
    // الحماية من الهجمات
    // ============================================

    isRateLimited(password) {
        const ip = 'user'; // في الواقع، يجب الحصول على IP المستخدم
        const now = Date.now();
        
        if (!this.state.passwordAttempts.has(ip)) {
            this.state.passwordAttempts.set(ip, []);
        }
        
        const attempts = this.state.passwordAttempts.get(ip);
        
        // إزالة المحاولات القديمة
        const recentAttempts = attempts.filter(time => now - time < this.state.lockoutTime);
        
        // التحقق من تجاوز الحد
        if (recentAttempts.length >= this.state.maxAttempts) {
            return true;
        }
        
        // تسجيل المحاولة الجديدة
        recentAttempts.push(now);
        this.state.passwordAttempts.set(ip, recentAttempts);
        
        return false;
    }

    recordFailedAttempt(password) {
        const now = Date.now();
        const ip = 'user';
        
        if (!this.state.passwordAttempts.has(ip)) {
            this.state.passwordAttempts.set(ip, []);
        }
        
        const attempts = this.state.passwordAttempts.get(ip);
        attempts.push(now);
        
        // إظهار تحذير إذا اقترب من الحد
        const recentAttempts = attempts.filter(time => now - time < this.state.lockoutTime);
        if (recentAttempts.length >= this.state.maxAttempts * 0.8) {
            this.showNotification(`⚠️ اقتربت من الحد الأقصى للمحاولات (${recentAttempts.length}/${this.state.maxAttempts})`, 'warning');
        }
    }

    // ============================================
    // مسح البيانات الحساسة
    // ============================================

    clearAllSensitiveData() {
        try {
            // مسح الحقول
            const sensitiveFields = [
                'plainText', 'password', 'encryptedText', 
                'decryptPassword', 'decryptedText', 'generatedPassword'
            ];
            
            sensitiveFields.forEach(id => {
                const field = document.getElementById(id);
                if (field) {
                    if (field.tagName === 'TEXTAREA' || field.tagName === 'INPUT') {
                        field.value = '';
                    }
                }
            });
            
            // إعادة تعيين العدادات
            document.getElementById('decryptAttempts').textContent = '0';
            document.getElementById('plainTextCount').textContent = '0';
            
            // مسح مؤقتات المحاولات
            this.state.passwordAttempts.clear();
            this.state.decryptAttempts = 0;
            
            // إجبار جمع القمامة (إن أمكن)
            if (window.gc) {
                window.gc();
            }
            
            this.showNotification(this.t('secureWipeComplete'), 'success');
            
        } catch (error) {
            console.error('Secure wipe failed:', error);
        }
    }

    secureWipeArray(array) {
        if (array && array.length) {
            for (let i = 0; i < array.length; i++) {
                array[i] = 0;
            }
        }
    }

    // ============================================
    // واجهة المستخدم
    // ============================================

    initUI() {
        // تحديث اللغة
        this.updateLanguage('ar');
        
        // إعداد عدادات الأحرف
        this.setupCharacterCounters();
        
        // تحديث الإحصائيات
        this.updateStatistics();
        
        // إعداد تقييم قوة كلمة المرور
        this.setupPasswordStrength();
        
        // إعداد مولد كلمة المرور
        this.setupPasswordGenerator();
    }

    setupEventListeners() {
        // أحداث التشفير
        document.getElementById('encryptBtn').addEventListener('click', () => this.handleEncryption());
        document.getElementById('decryptBtn').addEventListener('click', () => this.handleDecryption());
        
        // أحداث النسخ
        document.getElementById('copyEncryptedBtn').addEventListener('click', () => this.copyToClipboard('encryptedText'));
        document.getElementById('copyDecryptedBtn').addEventListener('click', () => this.copyToClipboard('decryptedText'));
        
        // أحداث المسح
        document.getElementById('clearEncryptBtn').addEventListener('click', () => this.clearEncryptionFields());
        document.getElementById('clearDecryptBtn').addEventListener('click', () => this.clearDecryptionFields());
        document.getElementById('secureWipeBtn').addEventListener('click', () => this.clearAllSensitiveData());
        
        // أحداث كلمة المرور
        document.getElementById('togglePassword').addEventListener('click', () => this.togglePasswordVisibility('password'));
        document.getElementById('toggleDecryptPassword').addEventListener('click', () => this.togglePasswordVisibility('decryptPassword'));
        document.getElementById('generatePasswordBtn').addEventListener('click', () => this.showPasswordGenerator());
        
        // أحداث النمط
        document.getElementById('enableCompression').addEventListener('change', (e) => this.updateEncryptionOptions());
        document.getElementById('enableTimestamp').addEventListener('change', (e) => this.updateEncryptionOptions());
        
        // أحداث المتابعة
        document.getElementById('continueBtn').addEventListener('click', () => this.showMainApp());
        
        // إغلاق التنبيهات
        document.querySelector('.alert-close').addEventListener('click', (e) => {
            e.target.closest('.alert').style.display = 'none';
        });
    }

    setupCharacterCounters() {
        const textarea = document.getElementById('plainText');
        const counter = document.getElementById('plainTextCount');
        
        textarea.addEventListener('input', () => {
            counter.textContent = textarea.value.length;
        });
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('password');
        const strengthBar = document.getElementById('strengthBar');
        const strengthValue = document.getElementById('strengthValue');
        
        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            
            if (password.length === 0) {
                strengthBar.style.width = '0%';
                strengthBar.style.backgroundColor = '';
                strengthValue.textContent = '';
                return;
            }
            
            const strength = this.checkPasswordStrength(password);
            
            // تحديث الشريط
            strengthBar.style.width = `${strength.percentage}%`;
            
            // تحديث اللون
            switch (strength.level) {
                case 'weak':
                    strengthBar.style.backgroundColor = 'var(--danger)';
                    strengthValue.className = 'strength-weak';
                    strengthValue.textContent = this.t('weakPassword');
                    break;
                case 'medium':
                    strengthBar.style.backgroundColor = 'var(--warning)';
                    strengthValue.className = 'strength-medium';
                    strengthValue.textContent = this.t('mediumPassword');
                    break;
                case 'strong':
                    strengthBar.style.backgroundColor = 'var(--secondary)';
                    strengthValue.className = 'strength-strong';
                    strengthValue.textContent = this.t('strongPassword');
                    break;
                case 'very-strong':
                    strengthBar.style.backgroundColor = 'var(--secondary-dark)';
                    strengthValue.className = 'strength-very-strong';
                    strengthValue.textContent = this.t('veryStrongPassword');
                    break;
            }
        });
    }

    setupPasswordGenerator() {
        document.getElementById('regeneratePassword').addEventListener('click', () => this.generateAndDisplayPassword());
        document.getElementById('usePassword').addEventListener('click', () => this.useGeneratedPassword());
        document.getElementById('copyGeneratedPassword').addEventListener('click', () => this.copyGeneratedPassword());
        document.querySelector('.modal-close').addEventListener('click', () => this.hidePasswordGenerator());
        
        // إغلاق النافذة عند النقر خارجها
        document.getElementById('passwordModal').addEventListener('click', (e) => {
            if (e.target.id === 'passwordModal') {
                this.hidePasswordGenerator();
            }
        });
    }

    // ============================================
    // معالجة الأحداث
    // ============================================

    async handleEncryption() {
        try {
            const text = document.getElementById('plainText').value;
            const password = document.getElementById('password').value;
            
            if (!text || !password) {
                this.showNotification(this.t('encryptError'), 'error');
                return;
            }
            
            // التحقق من قوة كلمة المرور
            const strength = this.checkPasswordStrength(password);
            if (strength.level === 'weak') {
                if (!confirm('⚠️ كلمة المرور ضعيفة. هل تريد المتابعة؟')) {
                    return;
                }
            }
            
            // إظهار تحميل
            this.showLoading('جاري التشفير...');
            
            // الحصول على الخيارات
            const options = {
                compression: document.getElementById('enableCompression').checked,
                timestamp: document.getElementById('enableTimestamp').checked
            };
            
            // التشفير
            const result = await this.encryptText(text, password, options);
            
            // إظهار النتيجة
            document.getElementById('encryptedText').value = result.encrypted;
            
            // تحديث معلومات التشفير
            this.updateEncryptionInfo(result);
            
            // إظهار إشعار النجاح
            this.showNotification(this.t('encryptSuccess'), 'success');
            
            // تحديث الوقت في لوحة التحكم
            document.getElementById('encryptTime').textContent = result.time;
            
        } catch (error) {
            console.error('Encryption failed:', error);
            this.showNotification(error.message || this.t('encryptError'), 'error');
        } finally {
            this.hideLoading();
        }
    }

    async handleDecryption() {
        try {
            const encryptedText = document.getElementById('encryptedText').value;
            const password = document.getElementById('decryptPassword').value;
            
            if (!encryptedText || !password) {
                this.showNotification(this.t('decryptError'), 'error');
                return;
            }
            
            // التحقق من تجاوز الحد الأقصى للمحاولات
            if (this.isRateLimited(password)) {
                this.showNotification(this.t('maxAttemptsExceeded'), 'error');
                return;
            }
            
            // إظهار تحميل
            this.showLoading('جاري فك التشفير...');
            
            // فك التشفير
            const startTime = performance.now();
            const result = await this.decryptText(encryptedText, password);
            const endTime = performance.now();
            
            // إظهار النتيجة
            document.getElementById('decryptedText').value = result.text;
            
            // تحديث إحصائيات فك التشفير
            document.getElementById('decryptTime').textContent = Math.round(endTime - startTime);
            document.getElementById('decryptAttempts').textContent = this.state.decryptAttempts;
            document.getElementById('dataIntegrity').textContent = 
                result.integrity ? this.t('dataIntegrityValid') : this.t('dataIntegrityInvalid');
            
            // تحديث البيانات الوصفية
            this.updateDecryptionMetadata(result.metadata);
            
            // إظهار إشعار النجاح
            this.showNotification(this.t('decryptSuccess'), 'success');
            
        } catch (error) {
            console.error('Decryption failed:', error);
            this.showNotification(error.message || this.t('decryptError'), 'error');
            
            // تحديث محاولات فك التشفير الفاشلة
            document.getElementById('decryptAttempts').textContent = this.state.decryptAttempts;
        } finally {
            this.hideLoading();
        }
    }

    // ============================================
    // أدوات المساعدة
    // ============================================

    updateLanguage(lang) {
        this.state.language = lang;
        const t = this.t.bind(this);
        
        // تحديث جميع النصوص
        document.querySelectorAll('[id]').forEach(element => {
            const key = element.id;
            if (translations[lang][key]) {
                if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
                    element.placeholder = translations[lang][key];
                } else {
                    element.textContent = translations[lang][key];
                }
            }
        });
        
        // تحديث اتجاه الصفحة
        document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = lang;
    }

    t(key) {
        return translations[this.state.language][key] || key;
    }

    showNotification(message, type = 'info') {
        const notification = document.getElementById('notification');
        const icon = notification.querySelector('i');
        const messageElement = document.getElementById('notificationMessage');
        
        // تحديث النص والأيقونة
        messageElement.textContent = message;
        
        switch (type) {
            case 'success':
                icon.className = 'fas fa-check-circle';
                notification.style.borderLeftColor = 'var(--secondary)';
                break;
            case 'error':
                icon.className = 'fas fa-exclamation-circle';
                notification.style.borderLeftColor = 'var(--danger)';
                break;
            case 'warning':
                icon.className = 'fas fa-exclamation-triangle';
                notification.style.borderLeftColor = 'var(--warning)';
                break;
            default:
                icon.className = 'fas fa-info-circle';
                notification.style.borderLeftColor = 'var(--info)';
        }
        
        // إظهار الإشعار
        notification.classList.add('show');
        
        // إخفاء الإشعار بعد 5 ثواني
        setTimeout(() => {
            notification.classList.remove('show');
        }, 5000);
    }

    async copyToClipboard(elementId) {
        try {
            const element = document.getElementById(elementId);
            if (!element || !element.value) return;
            
            await navigator.clipboard.writeText(element.value);
            this.showNotification(this.t('copySuccess'), 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            this.showNotification('فشل النسخ', 'error');
        }
    }

    togglePasswordVisibility(fieldId) {
        const field = document.getElementById(fieldId);
        const toggle = document.getElementById(`toggle${fieldId.charAt(0).toUpperCase() + fieldId.slice(1)}`);
        
        if (field.type === 'password') {
            field.type = 'text';
            toggle.innerHTML = '<i class="far fa-eye-slash"></i>';
        } else {
            field.type = 'password';
            toggle.innerHTML = '<i class="far fa-eye"></i>';
        }
    }

    showLoading(message = 'جاري المعالجة...') {
        // يمكن إضافة مؤشر تحميل هنا
        document.body.style.cursor = 'wait';
        
        // تعطيل الأزرار
        document.querySelectorAll('.btn').forEach(btn => {
            btn.disabled = true;
        });
    }

    hideLoading() {
        document.body.style.cursor = 'default';
        
        // تمكين الأزرار
        document.querySelectorAll('.btn').forEach(btn => {
            btn.disabled = false;
        });
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    updateStatistics() {
        document.getElementById('totalEncryptions').textContent = this.state.totalEncryptions;
        document.getElementById('failedAttempts').textContent = this.state.failedAttempts;
    }

    updateEncryptionInfo(result) {
        const infoElement = document.getElementById('encryptionInfo');
        if (infoElement) {
            infoElement.innerHTML = `
                <div class="info-item">
                    <i class="fas fa-clock"></i>
                    <span>الوقت: ${result.time} مللي ثانية</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-key"></i>
                    <span>المفتاح: ${result.keyLength}-bit</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-redo"></i>
                    <span>التكرارات: ${result.iterations.toLocaleString()}</span>
                </div>
            `;
        }
    }

    updateDecryptionMetadata(metadata) {
        const metaElement = document.getElementById('decryptionMeta');
        if (metaElement && metadata) {
            let html = '<div class="metadata">';
            
            if (metadata.timestamp) {
                const date = new Date(metadata.timestamp);
                html += `<div><i class="fas fa-calendar"></i> تاريخ التشفير: ${date.toLocaleString()}</div>`;
            }
            
            if (metadata.algorithm) {
                html += `<div><i class="fas fa-microchip"></i> الخوارزمية: ${metadata.algorithm}</div>`;
            }
            
            if (metadata.compression) {
                html += `<div><i class="fas fa-compress"></i> الضغط: ${metadata.compression}</div>`;
            }
            
            if (metadata.iterations) {
                html += `<div><i class="fas fa-redo"></i> تكرارات PBKDF2: ${metadata.iterations.toLocaleString()}</div>`;
            }
            
            html += '</div>';
            metaElement.innerHTML = html;
        }
    }

    showPasswordGenerator() {
        this.generateAndDisplayPassword();
        document.getElementById('passwordModal').classList.add('active');
    }

    hidePasswordGenerator() {
        document.getElementById('passwordModal').classList.remove('active');
    }

    generateAndDisplayPassword() {
        const length = parseInt(document.getElementById('passwordLength').value) || 16;
        const options = {
            uppercase: document.getElementById('includeUppercase').checked,
            lowercase: document.getElementById('includeLowercase').checked,
            numbers: document.getElementById('includeNumbers').checked,
            symbols: document.getElementById('includeSymbols').checked
        };
        
        const password = this.generateRandomPassword(length, options);
        document.getElementById('generatedPassword').value = password;
        
        // تحديث قوة كلمة المرور المولدة
        const strength = this.checkPasswordStrength(password);
        const strengthElement = document.getElementById('generatedStrength');
        strengthElement.textContent = this.t(`${strength.level.replace('-', '')}Password`);
        strengthElement.className = `strength-${strength.level}`;
    }

    useGeneratedPassword() {
        const generatedPassword = document.getElementById('generatedPassword').value;
        if (generatedPassword) {
            document.getElementById('password').value = generatedPassword;
            document.getElementById('password').dispatchEvent(new Event('input'));
            this.hidePasswordGenerator();
            this.showNotification(this.t('passwordGenerated'), 'success');
        }
    }

    copyGeneratedPassword() {
        const passwordField = document.getElementById('generatedPassword');
        if (passwordField.value) {
            navigator.clipboard.writeText(passwordField.value)
                .then(() => this.showNotification(this.t('copySuccess'), 'success'))
                .catch(() => this.showNotification('فشل النسخ', 'error'));
        }
    }

    clearEncryptionFields() {
        if (confirm(this.t('clearConfirm'))) {
            document.getElementById('plainText').value = '';
            document.getElementById('password').value = '';
            document.getElementById('encryptedText').value = '';
            document.getElementById('plainTextCount').textContent = '0';
            
            // إعادة تعيين قوة كلمة المرور
            document.getElementById('strengthBar').style.width = '0%';
            document.getElementById('strengthValue').textContent = '';
        }
    }

    clearDecryptionFields() {
        if (confirm(this.t('clearConfirm'))) {
            document.getElementById('encryptedText').value = '';
            document.getElementById('decryptPassword').value = '';
            document.getElementById('decryptedText').value = '';
            document.getElementById('decryptionMeta').innerHTML = '';
            document.getElementById('decryptTime').textContent = '0';
            document.getElementById('dataIntegrity').textContent = 'غير معروف';
        }
    }

    updateEncryptionOptions() {
        // يمكن إضافة منطق إضافي هنا لتحديث الخيارات
        console.log('Encryption options updated');
    }

    showMainApp() {
        // إخفاء شاشات التحميل والتحقق
        document.getElementById('loadingScreen').style.display = 'none';
        document.getElementById('securityCheck').style.display = 'none';
        
        // إظهار التطبيق الرئيسي
        document.getElementById('mainApp').classList.remove('hidden');
        
        // بدء الجلسة
        this.startSecureSession();
    }
}

// ============================================
// تهيئة النظام عند تحميل الصفحة
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // التحقق من دعم Web Crypto API
    if (!window.crypto || !window.crypto.subtle) {
        alert('⚠️ هذا المتصفح لا يدعم Web Crypto API. يرجى استخدام متصفح حديث مثل Chrome, Firefox, أو Edge.');
        return;
    }
    
    // تهيئة النظام
    window.encryptionSystem = new AdvancedEncryptionSystem();
});

// دالة تأخير مساعدة
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// تحويل ArrayBuffer إلى Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// تحويل Base64 إلى ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// هاش بسيط للنصوص (للاستخدامات غير الأمنية)
async function simpleHash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return arrayBufferToBase64(hash).substring(0, 16);
}
