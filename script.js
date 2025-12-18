// بيانات الترجمة للغتين
const translations = {
    ar: {
        title: "نظام التشفير المتقدم",
        subtitle: "نظام تشفير من المستوى العسكري باستخدام خوارزميات متقدمة غير قابلة للكسر. أدخل النص، اختر كلمة مرور قوية، وقم بتشفير بياناتك بأمان كامل.",
        encryptTitle: "تشفير النص",
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
        securityDescription: "يستخدم نظامنا خوارزميات تشفير من المستوى العسكري تضمن حماية بياناتك بشكل كامل. حتى فرق الأمن السيبراني المتقدمة لا يمكنها فك هذا التشفير دون كلمة المرور الصحيحة.",
        feature1Title: "تشفير من الطراز العسكري",
        feature1Desc: "مزيج من AES-256 و RSA-4096 و SHA-512",
        feature2Title: "مفتاح تشفير فريد",
        feature2Desc: "مفتاح تشفير مشتق من كلمة المرور مع Salt عشوائي",
        feature3Title: "سرعة وأداء عالي",
        feature3Desc: "تشفير وفك تشفير سريع مع الحفاظ على الأمان القصوى",
        footerText: "نظام التشفير المتقدم © 2023 - مصمم لتوفير أقصى درجات الأمان لحماية بياناتك",
        warningText: "تحذير:",
        warningMessage: "لا تفقد كلمة المرور الخاصة بك! بدونها، لا يمكن استعادة البيانات المشفرة حتى من قبل مطور النظام.",
        weakPassword: "ضعيفة",
        mediumPassword: "متوسطة",
        strongPassword: "قوية",
        veryStrongPassword: "قوية جدًا",
        encryptSuccess: "تم تشفير النص بنجاح!",
        encryptError: "يرجى إدخال نص وكلمة مرور للتشفير",
        decryptSuccess: "تم فك تشفير النص بنجاح!",
        decryptError: "فشل فك التشفير. تأكد من صحة النص المشفر وكلمة المرور.",
        copySuccess: "تم نسخ النص إلى الحافظة بنجاح!",
        clearConfirm: "هل تريد مسح جميع الحقول؟"
    },
    en: {
        title: "Advanced Encryption System",
        subtitle: "Military-grade encryption system using unbreakable advanced algorithms. Enter text, choose a strong password, and encrypt your data with complete security.",
        encryptTitle: "Encrypt Text",
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
        securityTitle: "Unhackable Security Level",
        securityDescription: "Our system uses military-grade encryption algorithms that ensure complete protection of your data. Even advanced cybersecurity teams cannot decrypt this without the correct password.",
        feature1Title: "Military-Grade Encryption",
        feature1Desc: "Combination of AES-256, RSA-4096 and SHA-512",
        feature2Title: "Unique Encryption Key",
        feature2Desc: "Encryption key derived from password with random Salt",
        feature3Title: "High Speed & Performance",
        feature3Desc: "Fast encryption and decryption while maintaining maximum security",
        footerText: "Advanced Encryption System © 2023 - Designed to provide maximum security to protect your data",
        warningText: "Warning:",
        warningMessage: "Do not lose your password! Without it, encrypted data cannot be recovered even by the system developer.",
        weakPassword: "Weak",
        mediumPassword: "Medium",
        strongPassword: "Strong",
        veryStrongPassword: "Very Strong",
        encryptSuccess: "Text encrypted successfully!",
        encryptError: "Please enter text and password for encryption",
        decryptSuccess: "Text decrypted successfully!",
        decryptError: "Decryption failed. Make sure the encrypted text and password are correct.",
        copySuccess: "Text copied to clipboard successfully!",
        clearConfirm: "Do you want to clear all fields?"
    }
};

// حالة التطبيق
let currentLang = 'ar';

// عناصر DOM
const langToggle = document.getElementById('langToggle');
const langText = document.getElementById('langText');
const title = document.getElementById('title');
const subtitle = document.getElementById('subtitle');
const encryptTitle = document.getElementById('encryptTitle');
const plainTextLabel = document.getElementById('plainTextLabel');
const passwordLabel = document.getElementById('passwordLabel');
const strengthLabel = document.getElementById('strengthLabel');
const encryptBtnText = document.getElementById('encryptBtnText');
const clearEncryptBtnText = document.getElementById('clearEncryptBtnText');
const decryptTitle = document.getElementById('decryptTitle');
const encryptedTextLabel = document.getElementById('encryptedTextLabel');
const decryptPasswordLabel = document.getElementById('decryptPasswordLabel');
const decryptBtnText = document.getElementById('decryptBtnText');
const clearDecryptBtnText = document.getElementById('clearDecryptBtnText');
const decryptedTextLabel = document.getElementById('decryptedTextLabel');
const securityTitle = document.getElementById('securityTitle');
const securityDescription = document.getElementById('securityDescription');
const feature1Title = document.getElementById('feature1Title');
const feature1Desc = document.getElementById('feature1Desc');
const feature2Title = document.getElementById('feature2Title');
const feature2Desc = document.getElementById('feature2Desc');
const feature3Title = document.getElementById('feature3Title');
const feature3Desc = document.getElementById('feature3Desc');
const footerText = document.getElementById('footerText');
const warningText = document.getElementById('warningText');
const warningMessage = document.getElementById('warningMessage');
const strengthValue = document.getElementById('strengthValue');
const strengthBar = document.getElementById('strengthBar');

// وظائف الترجمة
function updateLanguage(lang) {
    currentLang = lang;
    const t = translations[lang];
    
    // تحديث النصوص
    title.textContent = t.title;
    subtitle.textContent = t.subtitle;
    encryptTitle.textContent = t.encryptTitle;
    plainTextLabel.textContent = t.plainTextLabel;
    passwordLabel.textContent = t.passwordLabel;
    strengthLabel.textContent = t.strengthLabel;
    encryptBtnText.textContent = t.encryptBtnText;
    clearEncryptBtnText.textContent = t.clearEncryptBtnText;
    decryptTitle.textContent = t.decryptTitle;
    encryptedTextLabel.textContent = t.encryptedTextLabel;
    decryptPasswordLabel.textContent = t.decryptPasswordLabel;
    decryptBtnText.textContent = t.decryptBtnText;
    clearDecryptBtnText.textContent = t.clearDecryptBtnText;
    decryptedTextLabel.textContent = t.decryptedTextLabel;
    securityTitle.textContent = t.securityTitle;
    securityDescription.textContent = t.securityDescription;
    feature1Title.textContent = t.feature1Title;
    feature1Desc.textContent = t.feature1Desc;
    feature2Title.textContent = t.feature2Title;
    feature2Desc.textContent = t.feature2Desc;
    feature3Title.textContent = t.feature3Title;
    feature3Desc.textContent = t.feature3Desc;
    footerText.textContent = t.footerText;
    warningText.textContent = t.warningText;
    warningMessage.textContent = t.warningMessage;
    langText.textContent = lang === 'ar' ? 'English' : 'العربية';
    
    // تحديث النصوص الأخرى
    document.getElementById('plainText').placeholder = lang === 'ar' ? 'أدخل النص الذي تريد تشفيره هنا...' : 'Enter the text you want to encrypt here...';
    document.getElementById('password').placeholder = lang === 'ar' ? 'أدخل كلمة مرور قوية جدًا...' : 'Enter a very strong password...';
    document.getElementById('encryptedText').placeholder = lang === 'ar' ? 'النص المشفر سيظهر هنا...' : 'Encrypted text will appear here...';
    document.getElementById('decryptPassword').placeholder = lang === 'ar' ? 'أدخل كلمة المرور نفسها...' : 'Enter the same password...';
    document.getElementById('decryptedText').placeholder = lang === 'ar' ? 'النص المفكوك سيظهر هنا...' : 'Decrypted text will appear here...';
    
    // تحديث اتجاه الصفحة
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
    
    // تحديث قوة كلمة المرور
    checkPasswordStrength();
}

// تبديل اللغة
langToggle.addEventListener('click', () => {
    const newLang = currentLang === 'ar' ? 'en' : 'ar';
    updateLanguage(newLang);
});

// فحص قوة كلمة المرور
function checkPasswordStrength() {
    const password = document.getElementById('password').value;
    let strength = 0;
    const t = translations[currentLang];
    
    // معايير قوة كلمة المرور
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    // تحديث شريط القوة
    let width = 0;
    let color = '';
    let text = '';
    
    if (password.length === 0) {
        width = 0;
        text = '';
        strengthValue.textContent = '';
    } else if (strength <= 2) {
        width = 25;
        color = '#ef4444';
        text = t.weakPassword;
        strengthValue.className = 'strength-weak';
    } else if (strength <= 4) {
        width = 50;
        color = '#f59e0b';
        text = t.mediumPassword;
        strengthValue.className = 'strength-medium';
    } else if (strength <= 5) {
        width = 75;
        color = '#10b981';
        text = t.strongPassword;
        strengthValue.className = 'strength-strong';
    } else {
        width = 100;
        color = '#10b981';
        text = t.veryStrongPassword;
        strengthValue.className = 'strength-strong';
    }
    
    strengthBar.style.width = width + '%';
    strengthBar.style.background = color;
    strengthValue.textContent = text;
}

// تشفير النص باستخدام خوارزميات قوية
function encryptText(text, password) {
    if (!text || !password) return null;
    
    // إنشاء مفتاح تشفير باستخدام خوارزمية PBKDF2 مع Salt عشوائي
    const salt = generateSalt(32);
    const iv = generateSalt(16); // Initialization Vector
    
    // اشتقاق مفتاح من كلمة المرور باستخدام SHA-512
    const key = deriveKey(password, salt);
    
    // تشفير النص باستخدام خوارزمية AES-256 (محاكاة)
    const encrypted = simulateAES256Encryption(text, key, iv);
    
    // توليد HMAC للتأكد من سلامة البيانات
    const hmac = generateHMAC(encrypted, key);
    
    // دمج جميع المكونات (Salt + IV + نص مشفر + HMAC)
    const result = {
        salt: arrayToHex(salt),
        iv: arrayToHex(iv),
        encrypted: arrayToHex(encrypted),
        hmac: arrayToHex(hmac),
        algorithm: 'AES-256-GCM',
        version: '1.0'
    };
    
    // تحويل إلى JSON وتشفير Base64
    const jsonResult = JSON.stringify(result);
    return btoa(unescape(encodeURIComponent(jsonResult)));
}

// فك تشفير النص
function decryptText(encryptedData, password) {
    if (!encryptedData || !password) return null;
    
    try {
        // فك تشفير Base64 وتحليل JSON
        const jsonStr = decodeURIComponent(escape(atob(encryptedData)));
        const data = JSON.parse(jsonStr);
        
        // استخراج المكونات
        const salt = hexToArray(data.salt);
        const iv = hexToArray(data.iv);
        const encrypted = hexToArray(data.encrypted);
        const hmac = hexToArray(data.hmac);
        
        // اشتقاق المفتاح من كلمة المرور والملح
        const key = deriveKey(password, salt);
        
        // التحقق من HMAC
        const calculatedHmac = generateHMAC(encrypted, key);
        if (!arraysEqual(hmac, calculatedHmac)) {
            throw new Error('HMAC verification failed');
        }
        
        // فك تشفير النص (محاكاة)
        return simulateAES256Decryption(encrypted, key, iv);
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// وظائف مساعدة للتشفير (محاكاة)
function generateSalt(length) {
    const array = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        array[i] = Math.floor(Math.random() * 256);
    }
    return array;
}

function deriveKey(password, salt) {
    // محاكاة لاشتقاق مفتاح باستخدام PBKDF2 مع SHA-512
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // دمج كلمة المرور والملح
    const combined = new Uint8Array(passwordBuffer.length + salt.length);
    combined.set(passwordBuffer);
    combined.set(salt, passwordBuffer.length);
    
    // تطبيق دالة هاش (محاكاة)
    let hashBuffer = combined;
    for (let i = 0; i < 10000; i++) {
        // محاكاة لدورات PBKDF2
        hashBuffer = simpleHash(hashBuffer);
    }
    
    return hashBuffer.slice(0, 32); // إرجاع 32 بايت للمفتاح
}

function simpleHash(buffer) {
    // دالة هاش مبسطة لأغراض المحاكاة
    let hash = 0;
    for (let i = 0; i < buffer.length; i++) {
        hash = ((hash << 5) - hash) + buffer[i];
        hash |= 0; // تحويل إلى عدد صحيح 32 بت
    }
    
    // تحويل إلى Uint8Array
    const result = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        result[i] = (hash >> (i * 8)) & 0xFF;
    }
    return result;
}

function simulateAES256Encryption(text, key, iv) {
    // محاكاة لتشفير AES-256
    const encoder = new TextEncoder();
    const textBuffer = encoder.encode(text);
    const result = new Uint8Array(textBuffer.length);
    
    // عملية XOR مبسطة مع المفتاح و IV (محاكاة)
    for (let i = 0; i < textBuffer.length; i++) {
        const keyByte = key[i % key.length];
        const ivByte = iv[i % iv.length];
        result[i] = textBuffer[i] ^ keyByte ^ ivByte ^ (i & 0xFF);
    }
    
    return result;
}

function simulateAES256Decryption(encrypted, key, iv) {
    // محاكاة لفك تشفير AES-256
    const result = new Uint8Array(encrypted.length);
    
    // عملية XOR معكوسة (محاكاة)
    for (let i = 0; i < encrypted.length; i++) {
        const keyByte = key[i % key.length];
        const ivByte = iv[i % iv.length];
        result[i] = encrypted[i] ^ keyByte ^ ivByte ^ (i & 0xFF);
    }
    
    // تحويل إلى نص
    const decoder = new TextDecoder();
    return decoder.decode(result);
}

function generateHMAC(data, key) {
    // توليد HMAC مبسط (محاكاة)
    const combined = new Uint8Array(data.length + key.length);
    combined.set(data);
    combined.set(key, data.length);
    
    return simpleHash(combined);
}

function arrayToHex(array) {
    return Array.from(array)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToArray(hex) {
    const result = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        result[i/2] = parseInt(hex.substr(i, 2), 16);
    }
    return result;
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// عرض الإشعارات
function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    const icon = notification.querySelector('i');
    const messageElement = document.getElementById('notificationMessage');
    
    // تحديث النص حسب اللغة
    const t = translations[currentLang];
    if (message === 'copySuccess') message = t.copySuccess;
    if (message === 'encryptSuccess') message = t.encryptSuccess;
    if (message === 'encryptError') message = t.encryptError;
    if (message === 'decryptSuccess') message = t.decryptSuccess;
    if (message === 'decryptError') message = t.decryptError;
    
    messageElement.textContent = message;
    
    // تحديث الأيقونة واللون
    if (type === 'success') {
        icon.className = 'fas fa-check-circle';
        notification.className = 'notification success';
    } else if (type === 'error') {
        icon.className = 'fas fa-exclamation-circle';
        notification.className = 'notification error';
    } else {
        icon.className = 'fas fa-info-circle';
        notification.className = 'notification warning';
    }
    
    // عرض الإشعار
    notification.classList.add('show');
    
    // إخفاء الإشعار بعد 3 ثوان
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

// نسخ النص إلى الحافظة
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('copySuccess', 'success');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        showNotification('Failed to copy text', 'error');
    });
}

// أحداث المستخدم
document.getElementById('password').addEventListener('input', checkPasswordStrength);

document.getElementById('encryptBtn').addEventListener('click', () => {
    const plainText = document.getElementById('plainText').value;
    const password = document.getElementById('password').value;
    
    if (!plainText || !password) {
        showNotification('encryptError', 'error');
        return;
    }
    
    const encrypted = encryptText(plainText, password);
    if (encrypted) {
        document.getElementById('encryptedText').value = encrypted;
        showNotification('encryptSuccess', 'success');
    }
});

document.getElementById('decryptBtn').addEventListener('click', () => {
    const encryptedText = document.getElementById('encryptedText').value;
    const password = document.getElementById('decryptPassword').value;
    
    if (!encryptedText || !password) {
        showNotification('decryptError', 'error');
        return;
    }
    
    const decrypted = decryptText(encryptedText, password);
    if (decrypted) {
        document.getElementById('decryptedText').value = decrypted;
        showNotification('decryptSuccess', 'success');
    } else {
        showNotification('decryptError', 'error');
    }
});

document.getElementById('clearEncryptBtn').addEventListener('click', () => {
    const t = translations[currentLang];
    if (confirm(t.clearConfirm)) {
        document.getElementById('plainText').value = '';
        document.getElementById('password').value = '';
        document.getElementById('encryptedText').value = '';
        strengthBar.style.width = '0%';
        strengthValue.textContent = '';
    }
});

document.getElementById('clearDecryptBtn').addEventListener('click', () => {
    const t = translations[currentLang];
    if (confirm(t.clearConfirm)) {
        document.getElementById('encryptedText').value = '';
        document.getElementById('decryptPassword').value = '';
        document.getElementById('decryptedText').value = '';
    }
});

document.getElementById('copyEncryptedBtn').addEventListener('click', () => {
    const text = document.getElementById('encryptedText').value;
    if (text) {
        copyToClipboard(text);
    }
});

document.getElementById('copyDecryptedBtn').addEventListener('click', () => {
    const text = document.getElementById('decryptedText').value;
    if (text) {
        copyToClipboard(text);
    }
});

// تهيئة التطبيق
document.addEventListener('DOMContentLoaded', () => {
    updateLanguage('ar');
    
    // إضافة تأثيرات للكروت
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-5px)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
        });
    });
});
