// ============================================
// Sovereign Encryption System - Test Runner
// Automated Testing Suite for Real Post-Quantum Cryptography
// ============================================

import { CryptoEngine } from '../assets/js/crypto-engine.js';

class TestRunner {
    constructor() {
        this.engine = new CryptoEngine();
        this.results = [];
        this.logContainer = document.getElementById('test-logs');
        this.statusContainer = document.getElementById('test-status');
    }

    log(message, type = 'info') {
        const div = document.createElement('div');
        div.className = `log-entry ${type}`;
        div.innerHTML = `<span class="timestamp">[${new Date().toLocaleTimeString()}]</span> ${message}`;
        this.logContainer.appendChild(div);
        this.logContainer.scrollTop = this.logContainer.scrollHeight;
        console.log(`[${type.toUpperCase()}] ${message}`);
    }

    async runAllTests() {
        this.results = [];
        this.logContainer.innerHTML = '';
        this.updateStatus('تشغيل الاختبارات...', 'running');

        try {
            await this.setup();

            await this.runGroup('1. البيئة والتجهيز (Environment)', async () => {
                await this.testEnvironment();
            });

            await this.runGroup('2. أمان العشوائية (Security & RNG)', async () => {
                await this.testRNG();
            });

            await this.runGroup('3. وظائف ML-DSA-87 (Functional)', async () => {
                await this.testDilithiumFunctional();
            });

            await this.runGroup('4. وظائف Falcon-Binding (Functional)', async () => {
                await this.testFalconBindingAndConsistency();
            });

            await this.runGroup('5. التكامل الكامل (Integration)', async () => {
                await this.testFullEncryptionCycle();
            });

            await this.runGroup('6. الأداء (Performance)', async () => {
                await this.testPerformance();
            });

            this.updateStatus('✅ اكتملت جميع الاختبارات بنجاح', 'success');
            this.finalReport();

        } catch (e) {
            this.log(`❌ توقفت الاختبارات بسبب خطأ فادح: ${e.message}`, 'error');
            this.updateStatus('❌ فشل الاختبار', 'error');
        }
    }

    async setup() {
        this.log('جاري تهيئة محرك التشفير وتنزيل المكتبات...');
        await this.engine.checkSecuritySupport();
        if (!this.engine.pqReady) throw new Error('فشل تحميل مكتبات التشفير الكمومي الحقيقية');
        this.log('✅ المحرك جاهز والمكتبات محملة.');
    }

    async runGroup(name, fn) {
        this.log(`--- بدء مجموعة: ${name} ---`, 'header');
        const start = performance.now();
        try {
            await fn();
            this.log(`✅ انتهت المجموعة: ${name} (${(performance.now() - start).toFixed(2)}ms)`, 'success');
        } catch (e) {
            this.log(`❌ فشلت المجموعة: ${name} - ${e.message}`, 'error');
            throw e;
        }
    }

    // ============================================
    // 1. Environment Tests
    // ============================================
    async testEnvironment() {
        // Check for Web Crypto API
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API غير مدعوم!');
        }
        this.log('✅ Web Crypto API متاح.');

        // Check for Secure Context
        if (!window.isSecureContext) {
            this.log('⚠️ تحذير: الصفحة لا تعمل في سياق آمن (HTTPS/Localhost).', 'warning');
        } else {
            this.log('✅ سياق آمن (Secure Context).');
        }

        // Check Logic Libs
        if (!window.ml_dsa) throw new Error('مكتبة ML-DSA لم يتم تحميلها في window.ml_dsa');
        this.log('✅ مكتبة @noble/post-quantum/ml-dsa محملة.');
    }

    // ============================================
    // 2. Security Tests
    // ============================================
    async testRNG() {
        const buffer = new Uint8Array(32);
        window.crypto.getRandomValues(buffer);

        // Zero Check
        let allZero = true;
        for (let b of buffer) if (b !== 0) allZero = false;

        if (allZero) throw new Error('CSPRNG أنتج مصفوفة صفرية بالكامل! (خطر أمني)');
        this.log(`✅ CSPRNG يعمل (Generated 32 bytes entropy).`);
    }

    // ============================================
    // 3. functional ML-DSA
    // ============================================
    async testDilithiumFunctional() {
        const seed = new Uint8Array(32);
        window.crypto.getRandomValues(seed);

        this.log('جاري توليد مفاتيح Dilithium-5...');
        const keys = window.ml_dsa.keygen(seed);

        if (!keys.publicKey || !keys.secretKey) throw new Error('فشل توليد المفاتيح');
        this.log(`✅ تم توليد المفاتيح (PK Size: ${keys.publicKey.length} bytes).`);

        const msg = new TextEncoder().encode("Sovereign-Test-Vector-123");

        // Sign
        const startSign = performance.now();
        const sig = window.ml_dsa.sign(keys.secretKey, msg);
        const signTime = performance.now() - startSign;
        this.log(`✅ تم التوقيع (${signTime.toFixed(2)}ms). Sig Size: ${sig.length} bytes.`);

        // Verify Positive
        const isValid = window.ml_dsa.verify(keys.publicKey, msg, sig);
        if (!isValid) throw new Error('فشل التحقق من توقيع صحيح!');
        this.log('✅ التحقق الإيجابي نجح.');

        // Verify Negative (Tampered)
        sig[0] ^= 1; // Flip first bit
        const isTamperedValid = window.ml_dsa.verify(keys.publicKey, msg, sig);
        if (isTamperedValid) throw new Error('كارثة! تم قبول توقيع مزور!');
        this.log('✅ التحقق السلبي نجح (رفض التزوير).');
    }

    // ============================================
    // 4. Functional Falcon Binding
    // ============================================
    async testFalconBindingAndConsistency() {
        const seed = new Uint8Array(64);
        window.crypto.getRandomValues(seed);
        const digest = "Hash-Test-Digest-XYZ"; // Simulated hash

        // Test consistency
        this.log('اختبار الحتمية (Determinism) لـ Falcon Binding...');
        const sig1 = await this.engine.signPostQuantum(digest, seed);
        const sig2 = await this.engine.signPostQuantum(digest, seed);

        if (sig1.falcon.signature !== sig2.falcon.signature) {
            throw new Error('Falcon Binding غير حتمي! نفس المدخلات أعطت مخرجات مختلفة.');
        }
        this.log('✅ التوقيع حتمي ومستقر.');

        // Test length check
        if (sig1.falcon.length !== 1280) throw new Error(`طول التوقيع غير صحيح: ${sig1.falcon.length}`);
        this.log('✅ طول التوقيع مطابق لمعيار Falcon-1024 (1280 bytes).');
    }

    // ============================================
    // 5. Full Integration
    // ============================================
    async testFullEncryptionCycle() {
        const password = "TestPasswordStrong123!";
        const content = "سر للغاية - Top Secret Data";

        this.log('بدء دورة تشفير كاملة...');
        const encrypted = await this.engine.encrypt(content, password);
        this.log('✅ التشفير تم بنجاح.');

        // Verify Metadata
        if (encrypted.pq_auth.standard !== "FIPS-204-REAL") throw new Error('Metadata Standard Incorrect');
        this.log('✅ علامة الإصدار (FIPS-204-REAL) صحيحة.');

        this.log('بدء فك التشفير...');
        const decrypted = await this.engine.decrypt(encrypted, password);

        if (decrypted.text !== content) throw new Error('النص المفكوك غير مطابق للنص الأصلي!');
        this.log('✅ النص مطابق تماماً.');
    }

    // ============================================
    // 6. Performance
    // ============================================
    async testPerformance() {
        const iterations = 5;
        this.log(`قياس متوسط الأداء عبر ${iterations} محاولات...`);

        let totalTime = 0;
        const password = "ValidPass";
        const file = new File(["PermData"], "p.txt");

        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            await this.engine.encrypt(file, password);
            totalTime += (performance.now() - start);
        }

        const avg = totalTime / iterations;
        this.log(`📊 متوسط زمن التشفير الكامل: ${avg.toFixed(2)}ms`);

        if (performance.memory) {
            this.log(`🧠 استخدام الذاكرة (Heap): ${(performance.memory.usedJSHeapSize / 1024 / 1024).toFixed(2)} MB`);
        }
    }

    updateStatus(text, cls) {
        this.statusContainer.textContent = text;
        this.statusContainer.className = `status ${cls}`;
    }

    finalReport() {
        // Here we could export JSON results
        this.log('--- نهاية التقرير ---');
    }
}

// Initialize
window.testRunner = new TestRunner();
document.getElementById('run-btn').addEventListener('click', () => window.testRunner.runAllTests());
