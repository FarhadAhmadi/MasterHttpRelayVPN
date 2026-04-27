# ۴) قابلیت‌ها

## شبکه

- شنود HTTP و SOCKS5
- قوانین `block_hosts` و `bypass_hosts`
- تونل مستقیم + fallback به رله
- مسیر SNI-rewrite برای دامنه‌های خاص

## موتور رله

- رله Apps Script
- HTTP/2 اختیاری
- batching و coalescing
- استفاده از چند script_id

## کارایی

- connection pool
- کش پاسخ برای assetهای استاتیک
- دانلود موازی range
- timeout تطبیقی برای مقصدهای دائم‌الخطا

## امنیت

- ساخت گواهی CA محلی
- احراز هویت HTTP/SOCKS5
- تنظیمات حفظ حریم خصوصی متریک‌ها

## مشاهده‌پذیری

- داشبورد داخلی
- API ادمین
- متریک Prometheus
- شمارنده تصمیم‌های مسیر و شمارنده‌های Telegram

