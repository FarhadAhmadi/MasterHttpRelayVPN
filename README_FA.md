# MasterHttpRelayVPN (نسخه ۱)

پروکسی محلی با رله Apps Script، حالت سازگاری Telegram Desktop، و داشبورد/متریک داخلی.

## مستندات ساختاریافته v1

- **هاب مستندات:** [`docs/README.md`](docs/README.md)
- **فهرست انگلیسی:** [`docs/en/INDEX.md`](docs/en/INDEX.md)
- **فهرست فارسی:** [`docs/fa/INDEX.md`](docs/fa/INDEX.md)
- **تغییرات نسخه‌ها:** [`CHANGELOG.md`](CHANGELOG.md)
- **Release Notes نسخه 1.2.0:** [`RELEASE_NOTES_v1.2.0.md`](RELEASE_NOTES_v1.2.0.md)

## شروع سریع

```bash
git clone https://github.com/masterking32/MasterHttpRelayVPN.git
cd MasterHttpRelayVPN
pip install -r requirements.txt
python setup.py
python main.py
```

## راه‌اندازی سریع Telegram Desktop

```bash
python main.py --telegram-profile
python main.py
```

تشخیص سریع:

```bash
python main.py --telegram-diagnose
```

پروفایل هوشمند:

```bash
python main.py --profile strict_tg
```

سپس در Telegram Desktop:

- HTTP: `127.0.0.1:8085` (پیشنهادی)
- SOCKS5: `127.0.0.1:1080`

## قابلیت‌های مهم v1

- پروکسی HTTP و SOCKS5
- موتور رله Apps Script
- حالت سازگاری Telegram Desktop
- احراز هویت HTTP/SOCKS
- داشبورد + API + متریک Prometheus
- مشاهده تصمیم‌های مسیر برای عیب‌یابی بهتر

## فایل‌های اصلی

- `main.py` — اجرای برنامه و CLI
- `setup.py` — ویزارد تنظیمات
- `config.example.json` — الگوی تنظیمات
- `apps_script/Code.gs` — کد رله گوگل
- `src/proxy_server.py` — هسته پروکسی
- `src/domain_fronter.py` — منطق رله
- `src/telemetry.py` — تله‌متری در حافظه

## مجوز

MIT
