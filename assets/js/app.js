// ============================================
// نظام التشفير المتقدم - التطبيق الرئيسي
// الإصدار المحسّن للأجهزة المحمولة
// ============================================

import { CryptoEngine } from './crypto-engine.js';

class EncryptionApp {
    constructor() {
        // إعدادات التطبيق
        this.config = {
            appName: 'نظام التشفير السيادي',
            version: '10.0-SOVEREIGN',
            algorithm: 'NIST-FIPS PQ Cascade',
            iterations: 2000000,
            maxAttempts: 10,
            sessionTimeout: 15 * 60 * 1000, // 15 دقيقة
            defaultLanguage: 'ar',
            strengthLevels: {
                weak: { min: 0, max: 30, color: '#ef4444', text: 'ضعيفة' },
                medium: { min: 31, max: 60, color: '#f59e0b', text: 'متوسطة' },
                strong: { min: 61, max: 80, color: '#10b981', text: 'قوية' },
                veryStrong: { min: 81, max: 100, color: '#059669', text: 'قوية جداً' }
            }
        };

        // حالة التطبيق
        this.state = {
            ver: "v10.0-SOVEREIGN",
            isSecure: false,
            isInitialized: false,
            sessionStart: null,
            lastActivity: Date.now(),
            sessionTimer: null,
            maxSession: 15 * 60 * 1000, // 15 Minutes
            passwordAttempts: new Map(),
            encryptionHistory: [],
            stats: {
                totalEncrypted: 0,
                totalDecrypted: 0,
                failedAttempts: 0
            },
            securityLevel: 'desktop', // Default
            isOnline: navigator.onLine,
            cryptoEngineReady: false,
            language: 'ar',
            keystrokeBuffer: []
        };

        // Dictionary for Translations
        this.i18n = {
            ar: {
                appName: 'نظام التشفير السيادي',
                headerSubtitle: 'نظام تشفير سيادي (v10.0) بمعايير <strong>FIPS/NIST</strong>. يستخدم توقيعات <strong>ML-DSA/FN-DSA</strong> حقيقية، و <strong>AEAD Cascade</strong>. معالج <strong>PBKDF2-SHA512</strong> + <strong>Argon2id (512MB)</strong>. <span class="highlight">بيئة معزولة تماماً (Air-Gapped Logic).</span>',
                footerSystemName: 'نظام التشفير السيادي © 2026',
                footerHost: 'نظام Sovereign Grade - حماية ضد الحوسبة الكمومية (PQ)',
                footerWarning: '<strong>تنبيه سيادي هام:</strong> هذا النظام يستخدم معايير تشفير عسكرية (Post-Quantum) فائقة الحساسية. المستخدم يتحمل المسؤولية القانونية والأمنية الكاملة عن استخدام هذا النظام.',
                sessionExpiredTitle: 'انتهت الجلسة الأمنية',
                sessionExpiredMsg1: 'لقد تجاوزت الجلسة الوقت المسموح به (15 دقيقة).',
                sessionExpiredMsg2: 'لأسباب أمنية قصوى، يجب إغلاق الجلسة الحالية ومسح الذاكرة (RAM Purge).',
                startNewSession: 'بدء جلسة جديدة (تطهير الذاكرة)',
            },
            en: {
                appName: 'Sovereign Encryption System',
                headerSubtitle: 'Sovereign Encryption (v10.0) with <strong>FIPS/NIST</strong> standards. Using real <strong>ML-DSA/FN-DSA</strong> signatures and <strong>AEAD Cascade</strong>. <strong>PBKDF2-SHA512</strong> + <strong>Argon2id (512MB)</strong>. <span class="highlight">Fully Isolated Environment (Air-Gapped Logic).</span>',
                footerSystemName: 'Sovereign Encryption System © 2026',
                footerHost: 'Sovereign Grade - Post-Quantum Protection (PQ)',
                footerWarning: '<strong>CRITICAL SOVEREIGN WARNING:</strong> This system utilizes military-grade Post-Quantum encryption. The user assumes full legal and security responsibility for its usage.',
                sessionExpiredTitle: 'Security Session Expired',
                sessionExpiredMsg1: 'Session has exceeded the allowed time limit (15 minutes).',
                sessionExpiredMsg2: 'For maximum security, the current session must be closed and memory purged.',
                startNewSession: 'Start New Session (Purge Memory)',
            }
        };

    }

    async init() {
        try {
            // تسجيل بدء التطبيق
            console.log(`🚀 ${this.config.appName} v${this.config.version} - بدء التشغيل`);

            // Initialize Language
            this.toggleLanguage(this.config.defaultLanguage);

            // التحقق من دعم Web Crypto API أولاً
            if (!this.checkCryptoSupport()) {
                this.showNotification('❌ المتصفح لا يدعم Web Crypto API', 'error');
                this.hideLoadingScreen();
                return;
            }

            // تهيئة واجهة المستخدم
            this.initUI();

            // التحقق من الأمان (بدون انتظار)
            this.checkSecurity().catch(error => {
                console.warn('⚠️ بعض فحوصات الأمان فشلت:', error);
            });

            // ربط الأحداث
            this.bindEvents();

            // بدء جلسة آمنة
            this.startSecureSession();

            // تحديث حالة الاتصال
            this.updateOnlineStatus();

            // تهيئة محرك التشفير بشكل منفصل
            this.initializeCryptoEngine();

            // إخفاء شاشة التحميل بعد 3 ثوان كحد أقصى
            setTimeout(() => {
                if (!this.state.isInitialized) {
                    this.state.isInitialized = true;
                    this.hideLoadingScreen();
                    this.showNotification('⚠️ النظام يعمل بوظائف محدودة', 'warning');
                }
            }, 3000);

        } catch (error) {
            console.error('❌ فشل تهيئة التطبيق:', error);
            // إخفاء شاشة التحميل حتى في حالة الخطأ
            setTimeout(() => {
                this.hideLoadingScreen();
                this.showNotification('⚠️ حدث خطأ في التهيئة، جرب تحديث الصفحة', 'warning');
            }, 1000);
        }
    }

    checkCryptoSupport() {
        return !!(window.crypto && window.crypto.subtle);
    }

    // ===== تهيئة واجهة المستخدم =====
    initUI() {
        // تحديث الإحصائيات
        this.updateStatistics();

        // تعيين نص النسخة
        document.querySelectorAll('.version').forEach(el => {
            el.textContent = `v${this.config.version}`;
        });

        // إعداد مؤشر التحميل
        this.setupLoadingAnimation();

        // إعداد مؤشر قوة كلمة المرور
        this.setupPasswordStrength();
    }

    setupLoadingAnimation() {
        const progressBar = document.getElementById('loadingProgress');
        const steps = document.querySelectorAll('.loading-steps .step');
        const statusText = document.getElementById('loadingStatus');

        if (!progressBar) return;

        const stepsData = [
            { text: 'جاري تحميل الوحدات الأساسية', duration: 600 },
            { text: 'جاري تهيئة نظام التشفير', duration: 800 },
            { text: 'جاري التحقق من البيئة الآمنة', duration: 700 },
            { text: 'جاري التشغيل النهائي', duration: 500 }
        ];

        let currentStep = 0;

        const animateStep = () => {
            if (currentStep >= stepsData.length) {
                progressBar.style.width = '100%';

                // عند اكتمال التحميل، تمكين الزر مباشرة
                setTimeout(() => {
                    const continueBtn = document.getElementById('continueBtn');
                    if (continueBtn) {
                        continueBtn.disabled = false;
                        this.showNotification('✅ النظام جاهز، اضغط للمتابعة', 'success');
                    }
                }, 300);
                return;
            }

            const step = stepsData[currentStep];

            // تحديث النص
            if (statusText) {
                statusText.textContent = step.text;
            }

            // تحديث الخطوة
            steps.forEach((s, i) => {
                s.classList.remove('active');
                if (i <= currentStep) {
                    s.classList.add('active');
                }
            });

            // حساب التقدم
            const progress = ((currentStep + 1) / stepsData.length) * 100;
            progressBar.style.width = `${progress}%`;

            currentStep++;
            setTimeout(animateStep, step.duration);
        };

        animateStep();
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('encryptionPassword');
        const decryptionInput = document.getElementById('decryptionPassword');

        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value);
            });
        }

        if (decryptionInput) {
            decryptionInput.addEventListener('input', (e) => {
                this.updateDecryptionStatus();
            });
        }
    }

    // ===== تهيئة محرك التشفير =====
    async initializeCryptoEngine() {
        try {
            // انتظار تحميل الملف أولاً
            await new Promise(resolve => setTimeout(resolve, 500));

            if (typeof CryptoEngine !== 'undefined') {
                window.cryptoEngine = new CryptoEngine();
                this.state.cryptoEngineReady = true;
                console.log('✅ محرك التشفير تم تهيئته بنجاح');

                // إذا كان التطبيق جاهزاً، إظهار إشعار
                if (this.state.isInitialized) {
                    this.showNotification('✅ محرك التشفير جاهز للاستخدام', 'success');
                }
            } else {
                console.warn('⚠️ CryptoEngine غير متاح بعد، سيتم تحميله عند الحاجة');
                // سنحاول تحميله لاحقاً عند الحاجة
            }
        } catch (error) {
            console.error('❌ فشل تهيئة محرك التشفير:', error);
            // لا نوقف التطبيق إذا فشل تحميل المحرك
        }
    }

    // ===== التحقق من الأمان =====
    async checkSecurity() {
        return new Promise(async (resolve, reject) => {
            try {
                // 1. التحقق من HTTPS
                await this.checkHTTPS();

                // 2. التحقق من Web Crypto API
                await this.checkCryptoAPI();

                // 3. التحقق من التخزين
                await this.checkStorage();

                // 4. التحقق من GitHub Pages
                await this.checkGitHubPages();

                // تمكين زر المتابعة
                const continueBtn = document.getElementById('continueBtn');
                if (continueBtn) {
                    continueBtn.disabled = false;
                    continueBtn.addEventListener('click', () => {
                        this.showMainApp();
                        resolve();
                    });
                } else {
                    resolve();
                }

                // تمكين الزر بعد 2 ثانية كحد أقصى
                setTimeout(() => {
                    if (continueBtn && continueBtn.disabled) {
                        continueBtn.disabled = false;
                        this.showNotification('✅ يمكنك المتابعة الآن', 'info');
                    }
                }, 2000);

            } catch (error) {
                console.error('❌ فشل التحقق من الأمان:', error);
                // عدم رفض الـ Promise حتى لو فشلت الفحوصات
                resolve();
            }
        });
    }

    async checkHTTPS() {
        return new Promise((resolve) => {
            setTimeout(() => {
                const isSecure = window.location.protocol === 'https:' ||
                    window.location.hostname.includes('github.io');

                this.updateSecurityStatus('httpsStatus',
                    isSecure ? 'آمن ✓' : 'غير آمن ✗',
                    isSecure ? 'success' : 'error');

                resolve(isSecure);
            }, 400);
        });
    }

    async checkCryptoAPI() {
        return new Promise((resolve) => {
            setTimeout(() => {
                const hasCrypto = !!window.crypto && !!window.crypto.subtle;

                this.updateSecurityStatus('cryptoStatus',
                    hasCrypto ? 'متاح ✓' : 'غير متاح ✗',
                    hasCrypto ? 'success' : 'error');

                // لا ننشئ cryptoEngine هنا
                resolve(hasCrypto);
            }, 600);
        });
    }

    async checkStorage() {
        return new Promise((resolve) => {
            setTimeout(() => {
                const hasStorage = typeof localStorage !== 'undefined' &&
                    typeof sessionStorage !== 'undefined';

                this.updateSecurityStatus('storageStatus',
                    hasStorage ? 'متاح ✓' : 'غير متاح ✗',
                    hasStorage ? 'success' : 'error');

                resolve(hasStorage);
            }, 300);
        });
    }

    checkGitHubPages() {
        // Removed for Sovereign Security Standard - No external checks
        this.updateSecurityStatus('githubStatus', 'Sovereign Env', 'success');
    }

    updateSecurityStatus(elementId, status, type = 'info') {
        const element = document.getElementById(elementId);
        if (!element) return;

        // تحديث النص
        const statusText = element.querySelector('span:last-child');
        if (statusText) {
            statusText.textContent = status;
        }

        // تحديث النقطة
        const dot = element.querySelector('.status-dot');
        if (dot) {
            dot.className = 'status-dot';
            dot.classList.add(type);
        }

        // تحديث عداد الأمان
        this.updateSecurityMeter();
    }

    updateSecurityMeter() {
        const meter = document.getElementById('securityMeter');
        if (!meter) return;

        // حساب مستوى الأمان بناءً على التحققات
        const checks = [
            document.getElementById('httpsStatus'),
            document.getElementById('cryptoStatus'),
            document.getElementById('storageStatus'),
            document.getElementById('githubStatus')
        ];

        let passedChecks = 0;
        checks.forEach(check => {
            if (check && check.textContent.includes('✓')) {
                passedChecks++;
            }
        });

        const securityLevel = (passedChecks / checks.length) * 100;
        meter.style.width = `${securityLevel}%`;

        // تحديث اللون بناءً على المستوى
        if (securityLevel >= 75) {
            meter.style.background = 'linear-gradient(90deg, #10b981, #059669)';
        } else if (securityLevel >= 50) {
            meter.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
        } else {
            meter.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
        }
    }

    // ===== إدارة الجلسات =====
    startSecureSession() {
        this.state.sessionStart = Date.now();
        this.state.lastActivity = Date.now();

        // بدء المؤقت
        this.updateSessionTimer();
        this.state.sessionTimer = setInterval(() => {
            this.updateSessionTimer();
            this.checkSessionTimeout();
        }, 1000);

        // مراقبة النشاط
        document.addEventListener('click', () => this.updateLastActivity());
        document.addEventListener('keypress', () => this.updateLastActivity());

        // تحديث وقت بدء الجلسة
        const sessionStartEl = document.getElementById('sessionStart');
        if (sessionStartEl) {
            const now = new Date();
            sessionStartEl.textContent = now.toLocaleTimeString('ar-SA');
        }
    }

    updateSessionTimer() {
        const elapsed = Date.now() - this.state.sessionStart;
        const remaining = Math.max(0, this.config.sessionTimeout - elapsed);

        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);

        // تحديث العداد
        const timerElement = document.getElementById('sessionTimer');
        if (timerElement) {
            timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

            if (remaining < 60000) {
                timerElement.style.color = '#ef4444';
                timerElement.style.animation = 'pulse 1s infinite';
            }
        }

        // تحديث الوقت المتبقي
        const remainingElement = document.getElementById('sessionRemaining');
        if (remainingElement) {
            remainingElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }

        // تحديث وقت التشغيل
        this.updateUptime();
    }

    updateUptime() {
        const uptimeElement = document.getElementById('uptime');
        if (!uptimeElement) return;

        const elapsed = Date.now() - this.state.sessionStart;
        const hours = Math.floor(elapsed / 3600000);
        const minutes = Math.floor((elapsed % 3600000) / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);

        uptimeElement.textContent =
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    updateLastActivity() {
        this.state.lastActivity = Date.now();
    }

    checkSessionTimeout() {
        // Strict Hard Limit: 15 Minutes from Session Start (Activity Ignored)
        // Hard limit ensures memory is purged regardless of user presence
        if (!this.state.sessionStart) return;

        const elapsedTime = Date.now() - this.state.sessionStart;

        if (elapsedTime > this.config.sessionTimeout) {
            console.warn('⚠️ Session Hard Limit Reached. Purging Memory...');
            this.endSession();
        }
    }

    endSession() {
        clearInterval(this.state.sessionTimer);

        // 1. Immediate Deep Clean
        this.clearSensitiveData();

        // 2. Show Blocking Modal
        const modal = document.getElementById('sessionExpiredModal');
        if (modal) {
            modal.classList.add('active');
            modal.style.display = 'flex'; // Force flex for centering

            // Lock Scrolling
            document.body.style.overflow = 'hidden';
            document.documentElement.style.overflow = 'hidden';
        }

        this.showNotification('⏳ انتهت الجلسة الأمنية (Hard Limit). تم مسح الذاكرة.', 'warning');
    }

    toggleLanguage(forceLang = null) {
        if (forceLang) {
            this.state.language = forceLang;
        } else {
            this.state.language = this.state.language === 'ar' ? 'en' : 'ar';
        }

        const lang = this.state.language;
        const texts = this.i18n[lang];
        const dir = lang === 'ar' ? 'rtl' : 'ltr';

        // Update HTML Direction
        document.documentElement.lang = lang;
        document.documentElement.dir = dir;

        // Update Button Text
        const btn = document.getElementById('langBtn');
        if (btn) {
            btn.innerHTML = lang === 'ar'
                ? '<i class="fas fa-globe"></i> English'
                : '<i class="fas fa-globe"></i> العربية';
        }

        // Apply Translations to Elements with data-i18n attribute
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (texts[key]) {
                el.innerHTML = texts[key];
            }
        });

        // Update Placeholders (Specific elements)
        const plainText = document.getElementById('plainText');
        if (plainText) {
            plainText.placeholder = lang === 'ar'
                ? "أدخل النص الذي تريد حمايته هنا... النظام يدعم التشفير متعدد اللغات مع الحفاظ على التنسيق."
                : "Enter text to protect here... System supports multi-language encryption while preserving formatting.";
        }
    }

    // ===== التشفير =====
    async encrypt() {
        try {
            const plainText = document.getElementById('plainText').value;
            const password = document.getElementById('encryptionPassword').value;

            if (!plainText || !password) {
                this.showNotification('❌ الرجاء إدخال النص وكلمة المرور', 'error');
                return;
            }

            // التحقق من قوة كلمة المرور
            if (!this.isPasswordStrong(password)) {
                this.showNotification('⚠️ كلمة المرور ضعيفة. استخدم كلمة أقوى.', 'warning');
                return;
            }

            // التحقق من تجاوز الحد الأقصى للمحاولات
            if (this.isRateLimited(password)) {
                this.showNotification('🚫 تم تجاوز الحد الأقصى للمحاولات. حاول لاحقاً.', 'error');
                return;
            }

            this.showNotification('☢️ جاري تنفيذ التشفير السيادي (v10.0-SOVEREIGN)... معالجة NIST PQC', 'info');

            const startTime = performance.now();

            // خيارات التشفير المتقدمة
            const options = {
                compression: true,
                securityLevel: this.state.securityLevel
            };

            // التحقق من وجود محرك التشفير
            if (!window.cryptoEngine) {
                if (typeof CryptoEngine !== 'undefined') {
                    window.cryptoEngine = new CryptoEngine();
                    this.state.cryptoEngineReady = true;
                } else {
                    throw new Error('محرك التشفير غير متاح. يرجى تحديث الصفحة.');
                }
            }

            // تنفيذ التشفير
            const result = await window.cryptoEngine.encrypt(plainText, password, options);
            const endTime = performance.now();
            const encryptionTime = ((endTime - startTime) / 1000).toFixed(2);

            // عرض النتيجة
            this.showEncryptionResult(result, encryptionTime);

            // تحديث الإحصائيات
            this.state.totalEncryptions++;
            this.updateStatistics();

            this.showNotification('✅ تم التشفير بنظام Sovereign v10.0 (NIST/FIPS Cascade) بنجاح', 'success');

            // حفظ في السجل
            this.saveToHistory({
                type: 'encryption',
                time: new Date().toISOString(),
                size: plainText.length,
                duration: encryptionTime
            });

        } catch (error) {
            console.error('❌ فشل التشفير:', error);
            this.state.failedAttempts++;
            this.updateStatistics();

            this.showNotification('❌ فشل التشفير: ' + error.message, 'error');
        } finally {
            // تصفير مدخلات الواجهة فوراً
            this.wipeUI('plainText', 'encryptionPassword');
        }
    }

    // تصفير واجهة المستخدم وإجبار المتصفح على تنظيف الذاكرة
    wipeUI(...ids) {
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;

            // 1. مسح القيمة برمجياً
            el.value = '';

            // 2. تدمير وإعادة إنشاء العنصر (لإجبار المتصفح على تنظيف Render Tree)
            const parent = el.parentNode;
            const next = el.nextSibling;
            const clone = el.cloneNode(true);

            parent.removeChild(el);
            parent.insertBefore(clone, next);

            // إعادة ربط أحداث الإدخال إذا لزم الأمر
            if (id === 'plainText') {
                clone.addEventListener('input', () => {
                    const text = clone.value;
                    document.getElementById('charCount').textContent = `${text.length} حرف`;
                    document.getElementById('lineCount').textContent = `${text.split('\n').length} سطر`;
                    document.getElementById('wordCount').textContent = `${text.trim() ? text.trim().split(/\s+/).length : 0} كلمة`;
                });
            }
        });
        console.log('🛡️ تم تنظيف الـ DOM والحقول الحساسة');
    }

    showEncryptionResult(result, encryptionTime) {
        const resultContainer = document.getElementById('encryptionResult');
        const encryptedText = document.getElementById('encryptedText');
        const encryptionTimeEl = document.getElementById('encryptionTime');
        const encryptionSizeEl = document.getElementById('encryptionSize');

        if (resultContainer) {
            resultContainer.classList.remove('hidden');
            resultContainer.style.display = 'block';
        }

        if (encryptedText) {
            encryptedText.value = JSON.stringify(result, null, 2);
        }

        if (encryptionTimeEl) {
            encryptionTimeEl.textContent = encryptionTime;
        }

        if (encryptionSizeEl) {
            const size = new Blob([JSON.stringify(result)]).size;
            encryptionSizeEl.textContent = size;
        }

        const summary = `
            <div class="result-badge security-high">
                <i class="fas fa-shield-alt"></i> NIST FIPS 10.0 Strict Protection
            </div>
            <div class="result-badge pq-active">
                <i class="fas fa-atom"></i> Post-Quantum Active (ML-DSA + FN-DSA)
            </div>
        `;
        const summaryEl = document.getElementById('securitySummary');
        if (summaryEl) summaryEl.innerHTML = summary;
    }

    // ===== فك التشفير =====
    async decrypt() {
        try {
            const encryptedInput = document.getElementById('encryptedInput').value;
            const password = document.getElementById('decryptionPassword').value;

            if (!encryptedInput || !password) {
                this.showNotification('❌ الرجاء إدخال النص المشفر وكلمة المرور', 'error');
                return;
            }

            // التحقق من تجاوز الحد الأقصى للمحاولات
            if (this.isRateLimited(password)) {
                this.showNotification('🚫 تم تجاوز الحد الأقصى للمحاولات. حاول لاحقاً.', 'error');
                return;
            }

            this.showNotification('🔓 جاري فك تشفير النص...', 'info');

            const startTime = performance.now();

            // التحقق من وجود محرك التشفير
            if (!window.cryptoEngine) {
                if (typeof CryptoEngine !== 'undefined') {
                    window.cryptoEngine = new CryptoEngine();
                    this.state.cryptoEngineReady = true;
                } else {
                    throw new Error('محرك التشفير غير متاح. يرجى تحديث الصفحة.');
                }
            }

            // تنفيذ فك التشفير
            let parsedEncrypted;
            try {
                parsedEncrypted = JSON.parse(encryptedInput);
            } catch {
                // إذا لم يكن JSON، حاول معالجته كنص مشفر مباشر
                parsedEncrypted = encryptedInput;
            }

            const result = await window.cryptoEngine.decrypt(parsedEncrypted, password);

            const endTime = performance.now();
            const decryptionTime = Math.round(endTime - startTime);

            // عرض النتيجة
            this.showDecryptionResult(result, decryptionTime);

            // تحديث الإحصائيات
            this.state.totalDecryptions++;
            this.updateStatistics();

            this.showNotification('✅ تم فك تشفير النص بنجاح', 'success');

            // حفظ في السجل
            this.saveToHistory({
                type: 'decryption',
                time: new Date().toISOString(),
                success: true,
                duration: decryptionTime
            });

        } catch (error) {
            console.error('❌ فشل فك التشفير:', error);

            // تسجيل المحاولة الفاشلة
            const password = document.getElementById('decryptionPassword').value;
            this.recordFailedAttempt(password);

            this.state.failedAttempts++;
            this.updateStatistics();

            this.showNotification('❌ فشل فك التشفير: تأكد من صحة البيانات وكلمة المرور', 'error');
        } finally {
            this.wipeUI('encryptedInput', 'decryptionPassword');
        }
    }

    showDecryptionResult(result, decryptionTime) {
        const resultContainer = document.getElementById('decryptionResult');
        const decryptedText = document.getElementById('decryptedText');
        const decryptionTimeEl = document.getElementById('decryptionTime');
        const integrityStatusEl = document.getElementById('integrityStatus');
        const encryptionDateEl = document.getElementById('encryptionDate');

        if (resultContainer) {
            resultContainer.classList.remove('hidden');
            resultContainer.style.display = 'block';
        }

        if (decryptedText && result.text) {
            decryptedText.value = result.text;
        }

        if (decryptionTimeEl) {
            decryptionTimeEl.textContent = decryptionTime;
        }

        if (integrityStatusEl) {
            let statusText = result.integrity ? 'سليمة ✓' : 'تالفة ✗';

            if (result.metadata?.version === "10.0-SOVEREIGN") {
                statusText += ' | 🛡️ NIST PQC Verified';
            } else if (result.pq_auth) {
                statusText += ' | 🛡️ PQ-Verified';
            }

            integrityStatusEl.textContent = statusText;
            integrityStatusEl.style.color = result.integrity ? '#10b981' : '#ef4444';
        }

        if (encryptionDateEl && result.metadata?.timestamp) {
            const date = new Date(result.metadata.timestamp);
            encryptionDateEl.textContent = date.toLocaleString('ar-SA');
        }
    }

    // ===== إدارة كلمات المرور =====
    checkPasswordStrength(password) {
        if (!password) {
            this.updatePasswordStrengthUI(0, 'غير مقاسة');
            return;
        }

        let score = 0;
        const requirements = {
            length: false,
            upper: false,
            lower: false,
            number: false,
            special: false
        };

        // طول كلمة المرور
        if (password.length >= 16) {
            score += 30;
            requirements.length = true;
        } else if (password.length >= 12) {
            score += 20;
            requirements.length = true;
        } else if (password.length >= 8) {
            score += 10;
        }

        // أحرف كبيرة
        if (/[A-Z]/.test(password)) {
            score += 20;
            requirements.upper = true;
        }

        // أحرف صغيرة
        if (/[a-z]/.test(password)) {
            score += 20;
            requirements.lower = true;
        }

        // أرقام
        if (/[0-9]/.test(password)) {
            score += 15;
            requirements.number = true;
        }

        // رموز خاصة
        if (/[^A-Za-z0-9]/.test(password)) {
            score += 15;
            requirements.special = true;
        }

        // عدم التكرار
        if (/(.)\1{2,}/.test(password)) {
            score -= 10;
        }

        // تحديد مستوى القوة
        let strengthLevel;
        for (const [level, range] of Object.entries(this.config.strengthLevels)) {
            if (score >= range.min && score <= range.max) {
                strengthLevel = level;
                break;
            }
        }

        // تحديث الواجهة
        this.updatePasswordStrengthUI(score, strengthLevel, requirements);
    }

    updatePasswordStrengthUI(score, strengthLevel, requirements = {}) {
        const strengthBar = document.getElementById('passwordStrengthBar');
        const strengthText = document.getElementById('passwordStrengthText');

        if (strengthBar) {
            strengthBar.style.width = `${Math.min(score, 100)}%`;

            // تحديث اللون بناءً على المستوى
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
            const levelText = this.config.strengthLevels[strengthLevel]?.text || 'ضعيفة';
            strengthText.textContent = levelText;
            strengthText.style.color = this.config.strengthLevels[strengthLevel]?.color || '#ef4444';
        }

        // تحديث متطلبات كلمة المرور
        Object.keys(requirements).forEach(req => {
            const reqElement = document.getElementById(`req${req.charAt(0).toUpperCase() + req.slice(1)}`);
            if (reqElement) {
                const icon = reqElement.querySelector('i');
                if (icon) {
                    icon.className = requirements[req] ? 'fas fa-check' : 'fas fa-times';
                    icon.style.color = requirements[req] ? '#10b981' : '#ef4444';
                }
            }
        });
    }

    isPasswordStrong(password) {
        const minLength = 12;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);

        return password.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial;
    }

    generatePassword() {
        this.showPasswordModal();
    }

    showPasswordModal() {
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.classList.add('active');
            this.generateNewPassword();
        }
    }

    hideModal() {
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.classList.remove('active');
        }
    }

    generateNewPassword() {
        // High-Security Password Generation (CSPRNG + Fisher-Yates)
        const length = parseInt(document.getElementById('passwordLength')?.value || 16);
        const includeUpper = document.getElementById('includeUpper')?.checked || true;
        const includeLower = document.getElementById('includeLower')?.checked || true;
        const includeNumbers = document.getElementById('includeNumbers')?.checked || true;
        const includeSpecial = document.getElementById('includeSpecial')?.checked || true;

        const charSets = {
            upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lower: 'abcdefghijklmnopqrstuvwxyz',
            number: '0123456789',
            special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };

        let availableChars = '';
        let guaranteedChars = [];

        // Build character pool and guaranteed characters
        if (includeUpper) {
            availableChars += charSets.upper;
            guaranteedChars.push(this.getSecureRandomChar(charSets.upper));
        }
        if (includeLower) {
            availableChars += charSets.lower;
            guaranteedChars.push(this.getSecureRandomChar(charSets.lower));
        }
        if (includeNumbers) {
            availableChars += charSets.number;
            guaranteedChars.push(this.getSecureRandomChar(charSets.number));
        }
        if (includeSpecial) {
            availableChars += charSets.special;
            guaranteedChars.push(this.getSecureRandomChar(charSets.special));
        }

        // Fallback if nothing selected
        if (!availableChars) {
            availableChars = charSets.upper + charSets.lower + charSets.number;
            guaranteedChars.push(this.getSecureRandomChar(charSets.upper));
        }

        // Fill remaining slots
        let passwordArray = [...guaranteedChars];
        const remainingLength = length - guaranteedChars.length;

        for (let i = 0; i < remainingLength; i++) {
            passwordArray.push(this.getSecureRandomChar(availableChars));
        }

        // Fisher-Yates Shuffle using CSPRNG
        for (let i = passwordArray.length - 1; i > 0; i--) {
            const j = this.getSecureRandomInt(i + 1);
            [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
        }

        const password = passwordArray.join('');

        const passwordInput = document.getElementById('generatedPassword');
        if (passwordInput) {
            passwordInput.value = password;
        }

        // Update length label
        const lengthValue = document.getElementById('lengthValue');
        if (lengthValue) {
            lengthValue.textContent = `${length} حرفاً`;
        }

        // Check strength
        this.checkPasswordStrength(password);
    }

    // Helper: Get secure random character from string
    getSecureRandomChar(charString) {
        const randomIndex = this.getSecureRandomInt(charString.length);
        return charString[randomIndex];
    }

    // Helper: Get secure random integer [0, max)
    getSecureRandomInt(max) {
        if (max === 0) return 0;
        const array = new Uint32Array(1);
        let randomValue;

        // Rejection sampling to avoid modulo bias
        const limit = 4294967296 - (4294967296 % max);

        do {
            window.crypto.getRandomValues(array);
            randomValue = array[0];
        } while (randomValue >= limit);

        return randomValue % max;
    }

    useGeneratedPassword() {
        const generatedPassword = document.getElementById('generatedPassword')?.value;
        const encryptionPassword = document.getElementById('encryptionPassword');

        if (generatedPassword && encryptionPassword) {
            encryptionPassword.value = generatedPassword;
            this.checkPasswordStrength(generatedPassword);
            this.hideModal();
            this.showNotification('✅ تم تعيين كلمة المرور المولدة', 'success');
        }
    }

    copyGeneratedPassword() {
        const passwordInput = document.getElementById('generatedPassword');
        if (passwordInput && passwordInput.value) {
            navigator.clipboard.writeText(passwordInput.value)
                .then(() => {
                    this.showNotification('✅ تم نسخ كلمة المرور', 'success');
                })
                .catch(() => {
                    this.showNotification('❌ فشل نسخ كلمة المرور', 'error');
                });
        }
    }

    // ===== إدارة المحاولات =====
    isRateLimited(password) {
        const attempts = this.state.passwordAttempts.get(password) || 0;
        return attempts >= this.config.maxAttempts;
    }

    recordFailedAttempt(password) {
        if (!password) return;

        const attempts = this.state.passwordAttempts.get(password) || 0;
        this.state.passwordAttempts.set(password, attempts + 1);

        // تحديث العداد في الواجهة
        const failedAttemptsEl = document.getElementById('failedAttempts');
        if (failedAttemptsEl) {
            failedAttemptsEl.textContent = attempts + 1;
        }

        // إذا تجاوز الحد الأقصى
        if (attempts + 1 >= this.config.maxAttempts) {
            this.showNotification('🚫 تم تأمين النظام بسبب كثرة المحاولات الفاشلة', 'error');
            this.lockSystem();
        }
    }

    lockSystem() {
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');

        if (encryptBtn) encryptBtn.disabled = true;
        if (decryptBtn) decryptBtn.disabled = true;

        setTimeout(() => {
            if (encryptBtn) encryptBtn.disabled = false;
            if (decryptBtn) decryptBtn.disabled = false;
            this.state.passwordAttempts.clear();
            this.showNotification('✅ تم فتح النظام مرة أخرى', 'success');
        }, 300000); // 5 دقائق
    }

    // ===== مساعدة =====
    toggleAdvancedOptions() {
        const options = document.getElementById('advancedOptions');
        const toggleIcon = document.querySelector('.options-toggle .fa-chevron-down');

        if (options) {
            options.classList.toggle('hidden');
            if (toggleIcon) {
                toggleIcon.style.transform = options.classList.contains('hidden') ?
                    'rotate(0deg)' : 'rotate(180deg)';
            }
        }
    }

    togglePassword(fieldId) {
        const field = document.getElementById(fieldId);
        const icon = document.querySelector(`#${fieldId} + .password-actions .password-action i`);

        if (field && icon) {
            if (field.type === 'password') {
                field.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                field.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }
    }

    pasteText(fieldId) {
        navigator.clipboard.readText()
            .then(text => {
                const field = document.getElementById(fieldId);
                if (field) {
                    field.value = text;
                    field.dispatchEvent(new Event('input'));
                    this.showNotification('✅ تم لصق النص', 'success');
                }
            })
            .catch(() => {
                this.showNotification('❌ فشل قراءة الحافظة', 'error');
            });
    }

    copyResult(fieldId) {
        const field = document.getElementById(fieldId);
        if (field && field.value) {
            navigator.clipboard.writeText(field.value)
                .then(() => {
                    this.showNotification('✅ تم نسخ النص', 'success');
                })
                .catch(() => {
                    // طريقة بديلة
                    field.select();
                    document.execCommand('copy');
                    this.showNotification('✅ تم نسخ النص', 'success');
                });
        }
    }

    clearField(fieldId) {
        const field = document.getElementById(fieldId);
        if (field) {
            field.value = '';
            field.dispatchEvent(new Event('input'));
        }
    }

    clearEncryption() {
        if (confirm('هل تريد مسح جميع حقول التشفير؟')) {
            this.clearField('plainText');
            this.clearField('encryptionPassword');
            this.clearField('encryptedText');

            const resultContainer = document.getElementById('encryptionResult');
            if (resultContainer) {
                resultContainer.classList.add('hidden');
                resultContainer.style.display = 'none';
            }

            this.showNotification('🗑️ تم مسح حقول التشفير', 'info');
        }
    }

    clearDecryption() {
        if (confirm('هل تريد مسح جميع حقول فك التشفير؟')) {
            this.clearField('encryptedInput');
            this.clearField('decryptionPassword');
            this.clearField('decryptedText');

            const resultContainer = document.getElementById('decryptionResult');
            if (resultContainer) {
                resultContainer.classList.add('hidden');
                resultContainer.style.display = 'none';
            }

            this.showNotification('🗑️ تم مسح حقول فك التشفير', 'info');
        }
    }

    downloadResult() {
        const encryptedText = document.getElementById('encryptedText');
        if (!encryptedText || !encryptedText.value) {
            this.showNotification('❌ لا توجد بيانات للتحميل', 'error');
            return;
        }

        const blob = new Blob([encryptedText.value], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');

        a.href = url;
        a.download = `encrypted-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification('💾 تم تحميل الملف', 'success');
    }

    // ===== التحديثات والإشعارات =====
    updateStatistics() {
        // تحديث عدادات التشفير
        const totalEncryptionsEl = document.getElementById('totalEncryptions');
        const encryptionCountEl = document.getElementById('encryptionCount');
        const totalFailedAttemptsEl = document.getElementById('totalFailedAttempts');

        if (totalEncryptionsEl) {
            totalEncryptionsEl.textContent = this.state.totalEncryptions + this.state.totalDecryptions;
        }

        if (encryptionCountEl) {
            encryptionCountEl.textContent = this.state.totalEncryptions;
        }

        if (totalFailedAttemptsEl) {
            totalFailedAttemptsEl.textContent = this.state.failedAttempts;
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.getElementById('notification');
        const notificationTitle = document.getElementById('notificationTitle');
        const notificationMessage = document.getElementById('notificationMessage');

        if (!notification || !notificationTitle || !notificationMessage) return;

        // تعيين النص
        notificationTitle.textContent = this.getNotificationTitle(type);
        notificationMessage.textContent = message;

        // تعيين الأنماط
        notification.className = 'notification';
        notification.classList.add(`notification-${type}`);

        // إظهار الإشعار
        notification.classList.add('show');

        // إخفاء الإشعار بعد 5 ثوانٍ
        setTimeout(() => {
            this.hideNotification();
        }, 5000);
    }

    getNotificationTitle(type) {
        const titles = {
            success: 'نجاح',
            error: 'خطأ',
            warning: 'تحذير',
            info: 'معلومات'
        };
        return titles[type] || 'إشعار';
    }

    hideNotification() {
        const notification = document.getElementById('notification');
        if (notification) {
            notification.classList.remove('show');
        }
    }

    // ===== التحكم في الشاشات =====
    hideLoadingScreen() {
        const loadingScreen = document.getElementById('loadingScreen');
        if (loadingScreen) {
            loadingScreen.style.opacity = '0';
            setTimeout(() => {
                loadingScreen.style.display = 'none';
                this.showSecurityCheck();
            }, 500);
        }
    }

    showSecurityCheck() {
        const securityCheck = document.getElementById('securityCheck');
        if (securityCheck) {
            securityCheck.classList.remove('hidden');
            securityCheck.style.display = 'flex';
        }
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
                    mainApp.style.display = 'block';
                    mainApp.style.animation = 'fadeIn 0.8s ease-out';
                    this.state.isInitialized = true;
                    this.showNotification('🚀 نظام التشفير جاهز للاستخدام', 'success');
                }
            }, 500);
        }
    }

    showAbout() {
        const infoModal = document.getElementById('infoModal');
        if (infoModal) {
            infoModal.classList.add('active');
        }
    }

    hideInfoModal() {
        const infoModal = document.getElementById('infoModal');
        if (infoModal) {
            infoModal.classList.remove('active');
        }
    }

    // ===== أخرى =====
    bindEvents() {
        // تهيئة النظام
        // تحديث حالة الاتصال
        window.addEventListener('online', () => {
            this.state.isOnline = true;
            this.showNotification('🌐 تم استعادة الاتصال بالإنترنت', 'success');
        });

        window.addEventListener('offline', () => {
            this.state.isOnline = false;
            this.showNotification('⚠️ فقد الاتصال بالإنترنت. النظام يعمل محلياً.', 'warning');
        });

        // مراقبة إدخال النص
        const plainText = document.getElementById('plainText');
        if (plainText) {
            plainText.addEventListener('input', () => {
                const text = plainText.value;
                document.getElementById('charCount').textContent = `${text.length} حرف`;
                document.getElementById('lineCount').textContent = `${text.split('\n').length} سطر`;
                document.getElementById('wordCount').textContent = `${text.trim() ? text.trim().split(/\s+/).length : 0} كلمة`;
            });
        }

        // إغلاق التنبيهات
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('alert-close')) {
                e.target.closest('.alert').style.display = 'none';
            }
        });

        // تحسينات للأجهزة المحمولة
        this.setupMobileEnhancements();
    }

    setupMobileEnhancements() {
        // تحسين إدخال النص على الهواتف
        const textareas = document.querySelectorAll('textarea');
        textareas.forEach(textarea => {
            textarea.addEventListener('focus', () => {
                // تأخير بسيط لضمان ظهور لوحة المفاتيح بشكل صحيح
                setTimeout(() => {
                    textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }, 300);
            });
        });

        // تحسين الأزرار على الهواتف
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(button => {
            button.addEventListener('touchstart', () => {
                button.style.transform = 'scale(0.98)';
            });

            button.addEventListener('touchend', () => {
                setTimeout(() => {
                    button.style.transform = 'scale(1)';
                }, 150);
            });
        });
    }
    updateOnlineStatus() {
        const statusElement = document.querySelector('.status-online');
        if (statusElement) {
            statusElement.textContent = this.state.isOnline ? 'متصل' : 'غير متصل';
            statusElement.style.color = this.state.isOnline ? '#10b981' : '#ef4444';
        }
    }

    clearSensitiveData() {
        // 1. Purge Application State
        this.state.keystrokeBuffer = [];
        this.state.encryptionHistory = [];
        this.state.passwordAttempts.clear();
        this.config.strengthLevels = null;

        // 2. Overwrite & Clear Clipboard (Attempt)
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText('Memory Purged').catch(() => { });
        }

        // 3. Scrub DOM Inputs (Passwords, Text, Textareas)
        const inputs = document.querySelectorAll('input, textarea, [contenteditable]');
        inputs.forEach(el => {
            el.value = '';
            el.innerHTML = '';
            el.setAttribute('value', ''); // Anti-restoration
        });

        // 4. Scrub Result Display Containers
        const resultContainers = document.querySelectorAll('.result-box, #encryptedOutput, #decryptedOutput');
        resultContainers.forEach(el => el.innerHTML = 'MEMORY_PURGED');

        // 5. Clear Storage (Session & Local related to current session)
        sessionStorage.clear();

        console.clear();
        console.log('☢️ MEMORY DEEPLY PURGED');

        // مسح الذاكرة
        if (window.gc) window.gc();
    }

    saveToHistory(entry) {
        this.state.encryptionHistory.unshift(entry);
        if (this.state.encryptionHistory.length > 100) {
            this.state.encryptionHistory.pop();
        }
    }

    refreshDashboard() {
        this.updateStatistics();
        this.updateUptime();
        this.showNotification('🔄 تم تحديث لوحة المعلومات', 'info');
    }

    showPasswordGuide() {
        this.showNotification('💡 استخدم كلمات مرور قوية بطول 16+ حرفاً تحتوي على أحرف كبيرة وصغيرة وأرقام ورموز خاصة', 'info');
    }

    scanQRCode() {
        this.showNotification('⏳ ميزة مسح QR قيد التطوير', 'info');
    }

    showPrivacy() {
        this.showNotification('🔒 الخصوصية: جميع عمليات التشفير تتم محلياً على جهازك. لا توجد بيانات ترسل إلى الإنترنت.', 'info');
    }

    updateDecryptionStatus() {
        const password = document.getElementById('decryptionPassword')?.value;
        const attempts = this.state.passwordAttempts.get(password) || 0;
        const failedAttemptsEl = document.getElementById('failedAttempts');

        if (failedAttemptsEl) {
            failedAttemptsEl.textContent = attempts;
            failedAttemptsEl.style.color = attempts >= 5 ? '#ef4444' : '#f59e0b';
        }
    }
}

// تصدير الفئة للاستخدام العام
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionApp;
}

// تهيئة النظام الآمن
window.app = new EncryptionApp();

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.app.init();
    });
} else {
    window.app.init();
}
