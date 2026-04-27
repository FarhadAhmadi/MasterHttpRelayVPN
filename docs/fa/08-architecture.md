# ۸) معماری

## اجزای اصلی

- `main.py` — استارت، CLI، بارگذاری config
- `src/proxy_server.py` — مدیریت پروتکل‌ها و تصمیم مسیر
- `src/domain_fronter.py` — موتور رله
- `src/h2_transport.py` — ترنسپورت HTTP/2 (اختیاری)
- `src/mitm.py` — مدیریت گواهی MITM
- `src/telemetry.py` — ذخیره متریک در حافظه

## جریان

1. اتصال کلاینت به پروکسی
2. تشخیص CONNECT/HTTP/SOCKS
3. انتخاب مسیر (direct/relay/sni-rewrite)
4. اجرای رله در صورت نیاز
5. بازگشت پاسخ
6. ثبت تله‌متری و route decisions

