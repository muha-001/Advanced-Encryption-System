// ============================================
// الحارس الأمني (Security Guard)
// منع التحليل، منع الفحص، وحماية الكود المصدري
// ============================================

(function () {
    'use strict';

    const GUARD_VERSION = 'v1.1 (Stealth)';

    // فحص التجاوز للمالك (Backdoor للمالك فقط)
    const isOwner = new URLSearchParams(window.location.search).get('admin') === 'true' ||
        localStorage.getItem('ADMIN_BYPASS') === 'true';

    if (isOwner) {
        console.log(`🔓 تم تجاوز الحماية ${GUARD_VERSION} (وضع المالك)`);
        if (new URLSearchParams(window.location.search).get('admin') === 'true') {
            localStorage.setItem('ADMIN_BYPASS', 'true');
        }
        return;
    }

    console.log(`🛡️ الحارس الأمني ${GUARD_VERSION} نشط`);

    // 1. منع الزر الأيمن (Context Menu)
    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        return false;
    });

    // 2. منع اختصارات لوحة المفاتيح للمطورين
    document.addEventListener('keydown', function (e) {
        // F12
        if (e.key === 'F12') {
            e.preventDefault();
            return false;
        }

        // Ctrl+Shift+I (Inspect), Ctrl+Shift+J (Console), Ctrl+Shift+C (Element), Ctrl+U (Source)
        if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
            e.preventDefault();
            return false;
        }

        if (e.ctrlKey && (e.key === 'U' || e.key === 'u')) {
            e.preventDefault();
            return false;
        }
    });

    // 3. كشف واجهة المطورين (DevTools Detection) & تجميدها
    // تحذير: هذا قد يزعج المستخدم إذا فتح الكونسول، ولكنه المطلوب للحماية القصوى
    setInterval(function () {
        const check = new Date();
        debugger; // فخ للمتطفلين: سيوقف السكربت إذا كان الكونسول مفتوحاً
        if (new Date() - check > 100) {
            document.body.innerHTML = '<div style="background:black;color:red;height:100vh;display:flex;justify-content:center;align-items:center;"><h1>⛔ Access Denied | تم كشف محاولة اختراق</h1></div>';
        }
    }, 1000);

    // 4. منع الطباعة
    window.addEventListener('beforeprint', function (e) {
        e.preventDefault();
        document.body.style.display = 'none';
    });

    window.addEventListener('afterprint', function () {
        document.body.style.display = 'block';
    });

})();
