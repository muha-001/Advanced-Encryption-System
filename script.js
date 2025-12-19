// ============================================
// نظام التشفير - التكامل مع الواجهة الجديدة
// ============================================

class EncryptionSystem {
    constructor() {
        this.config = {
            PBKDF2_ITERATIONS: 310000,
            SALT_LENGTH: 16,
            IV_LENGTH: 12,
            KEY_LENGTH: 256,
            ALGORITHM: 'AES-GCM',
            HASH: 'SHA-256',
            IS_GITHUB_PAGES: window.location.hostname.includes('github.io')
        };
        
        this.crypto = window.crypto.subtle;
        this.state = {
            totalEncryptions: 0,
            failedAttempts: 0,
            sessionStart: null,
            passwordAttempts: new Map(),
            maxAttempts: 10
        };
        
        this.initialize();
    }

    async initialize() {
        console.log('🔧 تهيئة نظام التشفير...');
        
        // الانتظار حتى يتم تحميل DOM
        if (document.readyState === 'loading') {
            await new Promise(resolve => {
                document.addEventListener('DOMContentLoaded', resolve);
            });
        }
        
        // تهيئة واجهة المستخدم
        this.initUI();
        
        // إعداد مستمعي الأحداث
        this.setupEventListeners();
        
        console.log('✅ نظام التشفير جاهز');
    }

    initUI() {
        // تحديث النصوص المترجمة
        this.updateUITexts();
        
        // إعداد مؤشر التحميل
        this.setupLoadingAnimation();
        
        // إعداد التحقق من الأمان
        this.setupSecurityCheck();
    }

    updateUITexts() {
        // هذه النصوص موجودة في app.js، نستخدمها فقط كدعم إضافي
        const elements = {
            'title': 'نظام التشفير المتقدم',
            'subtitle': 'نظام تشفير من المستوى العسكري على GitHub Pages',
            'encryptionPassword': 'كلمة المرور للتشفير',
            'decryptionPassword': 'كلمة المرور لفك التشفير'
        };
        
        Object.entries(elements).forEach(([id, text]) => {
            const element = document.getElementById(id);
            if (element && !element.textContent) {
                element.textContent = text;
            }
        });
    }

    setupLoadingAnimation() {
        const progressBar = document.getElementById('loadingProgress');
        const statusText = document.getElementById('loadingStatus');
        
        if (!progressBar || !statusText) return;
        
        const steps = [
            'جاري تحميل الوحدات الأساسية',
            'جاري تهيئة نظام التشفير',
            'جاري التحقق من الأمان',
            'جاري التشغيل النهائي'
        ];
        
        let step = 0;
        const interval = setInterval(() => {
            if (step >= steps.length) {
                clearInterval(interval);
                progressBar.style.width = '100%';
                this.completeLoading();
                return;
            }
            
            statusText.textContent = steps[step];
            progressBar.style.width = `${((step + 1) / steps.length) * 100}%`;
            step++;
        }, 800);
    }

    setupSecurityCheck() {
        const checks = [
            { id: 'httpsStatus', check: () => this.checkHTTPS() },
            { id: 'cryptoStatus', check: () => this.checkCryptoAPI() },
            { id: 'storageStatus', check: () => this.checkStorage() },
            { id: 'githubStatus', check: () => this.checkGitHubPages() }
        ];
        
        let completed = 0;
        
        checks.forEach(({ id, check }, index) => {
            setTimeout(async () => {
                try {
                    const result = await check();
                    this.updateCheckStatus(id, result.status, result.message);
                    
                    completed++;
                    if (completed === checks.length) {
                        this.enableContinueButton();
                    }
                } catch (error) {
                    this.updateCheckStatus(id, 'error', 'فشل التحقق');
                }
            }, index * 600);
        });
    }

    async checkHTTPS() {
        await this.delay(300);
        const isSecure = window.location.protocol === 'https:' || 
                        this.config.IS_GITHUB_PAGES;
        return {
            status: isSecure ? 'success' : 'error',
            message: isSecure ? 'آمن ✓' : 'غير آمن ✗'
        };
    }

    async checkCryptoAPI() {
        await this.delay(300);
        const hasCrypto = !!window.crypto && !!window.crypto.subtle;
        return {
            status: hasCrypto ? 'success' : 'error',
            message: hasCrypto ? 'متاح ✓' : 'غير متاح ✗'
        };
    }

    async checkStorage() {
        await this.delay(300);
        const hasStorage = typeof localStorage !== 'undefined' && 
                          typeof sessionStorage !== 'undefined';
        return {
            status: hasStorage ? 'success' : 'error',
            message: hasStorage ? 'متاح ✓' : 'غير متاح ✗'
        };
    }

    async checkGitHubPages() {
        await this.delay(300);
        const isGitHubPages = this.config.IS_GITHUB_PAGES;
        return {
            status: isGitHubPages ? 'success' : 'info',
            message: isGitHubPages ? 'نشط ✓' : 'غير نشط'
        };
    }

    updateCheckStatus(elementId, status, message) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const statusText = element.querySelector('span:last-child');
        if (statusText) {
            statusText.textContent = message;
        }
        
        const dot = element.querySelector('.status-dot');
        if (dot) {
            dot.className = 'status-dot';
            dot.classList.add(status);
        }
        
        // تحديث عداد الأمان
        this.updateSecurityMeter();
    }

    updateSecurityMeter() {
        const meter = document.getElementById('securityMeter');
        if (!meter) return;
        
        const checks = [
            document.getElementById('httpsStatus'),
            document.getElementById('cryptoStatus'),
            document.getElementById('storageStatus'),
            document.getElementById('githubStatus')
        ];
        
        let passed = 0;
        checks.forEach(check => {
            if (check && check.textContent.includes('✓')) {
                passed++;
            }
        });
        
        const level = (passed / checks.length) * 100;
        meter.style.width = `${level}%`;
        
        // تحديث اللون
        if (level >= 75) {
            meter.style.background = 'linear-gradient(90deg, #10b981, #059669)';
        } else if (level >= 50) {
            meter.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
        } else {
            meter.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
        }
    }

    enableContinueButton() {
        const continueBtn = document.getElementById('continueBtn');
        if (continueBtn) {
            continueBtn.disabled = false;
            continueBtn.addEventListener('click', () => {
                this.showMainApp();
            });
        }
    }

    completeLoading() {
        setTimeout(() => {
            const loadingScreen = document.getElementById('loadingScreen');
            const securityCheck = document.getElementById('securityCheck');
            
            if (loadingScreen) {
                loadingScreen.style.opacity = '0';
                setTimeout(() => {
                    loadingScreen.style.display = 'none';
                    if (securityCheck) {
                        securityCheck.classList.remove('hidden');
                    }
                }, 500);
            }
        }, 500);
    }

    showMainApp() {
        const securityCheck = document.getElementById('securityCheck');
        const mainApp = document.getElementById('mainApp');
        
        if (securityCheck) {
            securityCheck.style.opacity = '0';
            setTimeout(() => {
                securityCheck.style.display = 'none';
                if (mainApp) {
                    mainApp.classList.remove('hidden');
                    mainApp.style.animation = 'fadeIn 0.8s ease-out';
                    this.startSecureSession();
                }
            }, 500);
        }
        
        this.showNotification('🚀 نظام التشفير جاهز للاستخدام', 'success');
    }

    startSecureSession() {
        this.state.sessionStart = Date.now();
        this.updateSessionTimer();
        
        this.sessionTimer = setInterval(() => {
            this.updateSessionTimer();
            this.checkSessionTimeout();
        }, 1000);
        
        // تحديث وقت بدء الجلسة
        const sessionStartEl = document.getElementById('sessionStart');
        if (sessionStartEl) {
            const now = new Date();
            sessionStartEl.textContent = now.toLocaleTimeString('ar-SA');
        }
    }

    updateSessionTimer() {
        const elapsed = Date.now() - this.state.sessionStart;
        const remaining = Math.max(0, 15 * 60 * 1000 - elapsed);
        
        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        
        // تحديث العداد
        const timerElement = document.getElementById('sessionTimer');
        if (timerElement) {
            timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            if (remaining < 60000) {
                timerElement.style.color = '#ef4444';
            }
        }
        
        // تحديث الوقت المتبقي
        const remainingElement = document.getElementById('sessionRemaining');
        if (remainingElement) {
            remainingElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }

    checkSessionTimeout() {
        const idleTime = Date.now() - this.state.sessionStart;
        
        if (idleTime > 15 * 60 * 1000) {
            this.endSession();
        }
    }

    endSession() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
        }
        
        this.showNotification('⏳ انتهت الجلسة الأمنية. يتم إعادة التحميل...', 'warning');
        
        setTimeout(() => {
            window.location.reload();
        }, 3000);
    }

    setupEventListeners() {
        // مستمعي الأحداث الأساسية
        this.setupPasswordStrength();
        this.setupTextCounters();
        this.setupActionButtons();
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('encryptionPassword');
        const decryptInput = document.getElementById('decryptionPassword');
        
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value);
            });
        }
        
        if (decryptInput) {
            decryptInput.addEventListener('input', (e) => {
                this.updateDecryptionStatus(e.target.value);
            });
        }
    }

    checkPasswordStrength(password) {
        if (!password) {
            this.updatePasswordStrengthUI(0, 'غير مقاسة');
            return;
        }
        
        let score = 0;
        
        // طول كلمة المرور
        if (password.length >= 16) score += 30;
        else if (password.length >= 12) score += 20;
        else if (password.length >= 8) score += 10;
        
        // أحرف كبيرة
        if (/[A-Z]/.test(password)) score += 20;
        
        // أحرف صغيرة
        if (/[a-z]/.test(password)) score += 20;
        
        // أرقام
        if (/[0-9]/.test(password)) score += 15;
        
        // رموز خاصة
        if (/[^A-Za-z0-9]/.test(password)) score += 15;
        
        // تحديث الواجهة
        const strengthBar = document.getElementById('passwordStrengthBar');
        const strengthText = document.getElementById('passwordStrengthText');
        
        if (strengthBar) {
            strengthBar.style.width = `${Math.min(score, 100)}%`;
            
            if (score >= 80) {
                strengthBar.style.background = 'linear-gradient(90deg, #10b981, #059669)';
            } else if (score >= 60) {
                strengthBar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else if (score >= 30) {
                strengthBar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else {
                strengthBar.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
            }
        }
        
        if (strengthText) {
            let level = 'ضعيفة';
            if (score >= 80) level = 'قوية جداً';
            else if (score >= 60) level = 'قوية';
            else if (score >= 30) level = 'متوسطة';
            
            strengthText.textContent = level;
        }
    }

    updatePasswordStrengthUI(score, level) {
        // تحديث الواجهة (دعم إضافي)
        console.log(`قوة كلمة المرور: ${level} (${score}%)`);
    }

    updateDecryptionStatus(password) {
        // تحديث حالة فك التشفير
        if (!password) return;
        
        const attempts = this.state.passwordAttempts.get(password) || 0;
        const failedAttemptsEl = document.getElementById('failedAttempts');
        
        if (failedAttemptsEl) {
            failedAttemptsEl.textContent = attempts;
            failedAttemptsEl.style.color = attempts >= 5 ? '#ef4444' : '#f59e0b';
        }
    }

    setupTextCounters() {
        const plainText = document.getElementById('plainText');
        if (plainText) {
            plainText.addEventListener('input', () => {
                const text = plainText.value;
                document.getElementById('charCount').textContent = `${text.length} حرف`;
                document.getElementById('lineCount').textContent = `${text.split('\n').length} سطر`;
                document.getElementById('wordCount').textContent = `${text.trim() ? text.trim().split(/\s+/).length : 0} كلمة`;
            });
        }
    }

    setupActionButtons() {
        // أزرار التشفير
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        
        if (encryptBtn) {
            encryptBtn.addEventListener('click', () => this.handleEncryption());
        }
        
        if (decryptBtn) {
            decryptBtn.addEventListener('click', () => this.handleDecryption());
        }
        
        // أزرار المساعدة
        const helpBtns = document.querySelectorAll('.btn-info');
        helpBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.showHelp();
            });
        });
    }

    async handleEncryption() {
        const plainText = document.getElementById('plainText');
        const password = document.getElementById('encryptionPassword');
        
        if (!plainText || !password || !plainText.value || !password.value) {
            this.showNotification('❌ الرجاء إدخال النص وكلمة المرور', 'error');
            return;
        }
        
        try {
            this.showNotification('🔒 جاري تشفير النص...', 'info');
            
            const result = await this.encryptText(plainText.value, password.value);
            
            // عرض النتيجة
            const encryptedText = document.getElementById('encryptedText');
            const resultContainer = document.getElementById('encryptionResult');
            
            if (encryptedText) {
                encryptedText.value = JSON.stringify(result, null, 2);
            }
            
            if (resultContainer) {
                resultContainer.classList.remove('hidden');
            }
            
            this.state.totalEncryptions++;
            this.updateStatistics();
            
            this.showNotification('✅ تم تشفير النص بنجاح', 'success');
            
        } catch (error) {
            console.error('❌ فشل التشفير:', error);
            this.state.failedAttempts++;
            this.updateStatistics();
            this.showNotification('❌ فشل التشفير: ' + error.message, 'error');
        }
    }

    async handleDecryption() {
        const encryptedInput = document.getElementById('encryptedInput');
        const password = document.getElementById('decryptionPassword');
        
        if (!encryptedInput || !password || !encryptedInput.value || !password.value) {
            this.showNotification('❌ الرجاء إدخال النص المشفر وكلمة المرور', 'error');
            return;
        }
        
        try {
            this.showNotification('🔓 جاري فك تشفير النص...', 'info');
            
            let encryptedData;
            try {
                encryptedData = JSON.parse(encryptedInput.value);
            } catch {
                encryptedData = encryptedInput.value;
            }
            
            const result = await this.decryptText(encryptedData, password.value);
            
            // عرض النتيجة
            const decryptedText = document.getElementById('decryptedText');
            const resultContainer = document.getElementById('decryptionResult');
            
            if (decryptedText) {
                decryptedText.value = result.text;
            }
            
            if (resultContainer) {
                resultContainer.classList.remove('hidden');
            }
            
            this.showNotification('✅ تم فك التشفير بنجاح', 'success');
            
        } catch (error) {
            console.error('❌ فشل فك التشفير:', error);
            this.state.failedAttempts++;
            this.updateStatistics();
            
            // تسجيل المحاولة الفاشلة
            if (password.value) {
                const attempts = this.state.passwordAttempts.get(password.value) || 0;
                this.state.passwordAttempts.set(password.value, attempts + 1);
            }
            
            this.showNotification('❌ فشل فك التشفير: تأكد من صحة البيانات', 'error');
        }
    }

    async encryptText(text, password) {
        try {
            if (!text || !password) {
                throw new Error('النص أو كلمة المرور فارغة');
            }
            
            const salt = window.crypto.getRandomValues(new Uint8Array(this.config.SALT_LENGTH));
            
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
                    iterations: this.config.PBKDF2_ITERATIONS,
                    hash: this.config.HASH
                },
                keyMaterial,
                {
                    name: this.config.ALGORITHM,
                    length: this.config.KEY_LENGTH
                },
                false,
                ['encrypt', 'decrypt']
            );
            
            const iv = window.crypto.getRandomValues(new Uint8Array(this.config.IV_LENGTH));
            
            const encrypted = await this.crypto.encrypt(
                {
                    name: this.config.ALGORITHM,
                    iv: iv
                },
                key,
                new TextEncoder().encode(text)
            );
            
            const encryptedData = {
                v: '3.0',
                a: this.config.ALGORITHM,
                i: Array.from(iv),
                s: Array.from(salt),
                d: Array.from(new Uint8Array(encrypted)),
                c: this.config.PBKDF2_ITERATIONS
            };
            
            return {
                data: encryptedData,
                base64: btoa(JSON.stringify(encryptedData))
            };
            
        } catch (error) {
            throw new Error(`فشل التشفير: ${error.message}`);
        }
    }

    async decryptText(encryptedData, password) {
        try {
            if (!encryptedData || !password) {
                throw new Error('البيانات المشفرة أو كلمة المرور فارغة');
            }
            
            let data;
            if (typeof encryptedData === 'string') {
                try {
                    data = JSON.parse(encryptedData);
                } catch {
                    data = JSON.parse(atob(encryptedData));
                }
            } else {
                data = encryptedData;
            }
            
            if (data.v !== '3.0') {
                throw new Error('إصدار التشفير غير مدعوم');
            }
            
            const salt = new Uint8Array(data.s);
            const iv = new Uint8Array(data.i);
            const encrypted = new Uint8Array(data.d);
            
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
                    iterations: data.c || this.config.PBKDF2_ITERATIONS,
                    hash: this.config.HASH
                },
                keyMaterial,
                {
                    name: data.a,
                    length: this.config.KEY_LENGTH
                },
                false,
                ['decrypt']
            );
            
            const decrypted = await this.crypto.decrypt(
                {
                    name: data.a,
                    iv: iv
                },
                key,
                encrypted
            );
            
            return {
                text: new TextDecoder().decode(decrypted),
                integrity: true
            };
            
        } catch (error) {
            throw new Error(`فشل فك التشفير: ${error.message}`);
        }
    }

    updateStatistics() {
        const totalEncryptionsEl = document.getElementById('totalEncryptions');
        const encryptionCountEl = document.getElementById('encryptionCount');
        const totalFailedAttemptsEl = document.getElementById('totalFailedAttempts');
        
        if (totalEncryptionsEl) {
            totalEncryptionsEl.textContent = this.state.totalEncryptions;
        }
        
        if (encryptionCountEl) {
            encryptionCountEl.textContent = this.state.totalEncryptions;
        }
        
        if (totalFailedAttemptsEl) {
            totalFailedAttemptsEl.textContent = this.state.failedAttempts;
        }
    }

    showNotification(message, type = 'info') {
        // دعم الإشعارات المدمجة
        if (window.app && typeof window.app.showNotification === 'function') {
            window.app.showNotification(message, type);
            return;
        }
        
        // دعم بدائي
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };
        
        console.log(`%c${type}: ${message}`, `color: ${colors[type] || '#000'}`);
        
        // عرض تنبيه بسيط
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${colors[type] || '#3b82f6'};
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            z-index: 10000;
            font-family: inherit;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: fadeIn 0.3s ease-out;
        `;
        
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    showHelp() {
        this.showNotification('💡 استخدم كلمات مرور قوية بطول 16+ حرفاً تحتوي على أحرف كبيرة وصغيرة وأرقام ورموز خاصة', 'info');
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// ============================================
// تهيئة النظام
// ============================================

// إضافة أنماط للتنبيهات
if (!document.querySelector('#notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes fadeOut {
            from { opacity: 1; transform: translateY(0); }
            to { opacity: 0; transform: translateY(-20px); }
        }
    `;
    document.head.appendChild(style);
}

// بدء النظام بعد تحميل الصفحة
document.addEventListener('DOMContentLoaded', () => {
    if (!window.crypto || !window.crypto.subtle) {
        alert('⚠️ هذا المتصفح لا يدعم Web Crypto API. يرجى استخدام متصفح حديث.');
        return;
    }
    
    // إنشاء نسخة احتياطية من النظام
    window.backupEncryptionSystem = new EncryptionSystem();
    
    console.log('🔧 نظام التشفير الاحتياطي جاهز');
});
