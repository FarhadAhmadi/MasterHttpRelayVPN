# ۳) راهنمای Telegram Desktop

## سریع‌ترین روش (پیشنهادی)

```bash
python main.py --telegram-profile
```

این دستور تنظیمات مناسب Telegram را در `config.json` اعمال می‌کند.

سپس اجرا:

```bash
python main.py
```

## تنظیمات Telegram Desktop

حالت ترجیحی:

- نوع: HTTP
- آدرس: `127.0.0.1`
- پورت: `8085`

حالت جایگزین:

- نوع: SOCKS5
- آدرس: `127.0.0.1`
- پورت: `1080`

اگر احراز هویت فعال است، `proxy_username` و `proxy_password` را وارد کنید.

## رفتار حالت Telegram

- با `telegram_desktop_mode=true` مسیرهای IP-literal ناموفق در SOCKS سریع‌تر fail می‌شوند.
- این کار باعث چرخش سریع‌تر DC در Telegram می‌شود.

