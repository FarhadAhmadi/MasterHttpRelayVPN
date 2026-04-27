# ۲) نصب و راه‌اندازی

## پیش‌نیازها

- Python 3.10+
- حساب Google برای Apps Script

## دریافت پروژه

```bash
git clone https://github.com/masterking32/MasterHttpRelayVPN.git
cd MasterHttpRelayVPN
```

## نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

## دیپلوی `apps_script/Code.gs`

1. وارد <https://script.google.com> شوید.
2. پروژه جدید بسازید.
3. کد پیش‌فرض را با `apps_script/Code.gs` جایگزین کنید.
4. مقدار `AUTH_KEY` را امن تنظیم کنید.
5. به‌صورت Web App دیپلوی کنید.
6. Deployment ID را بردارید.

## ساخت تنظیمات

```bash
python setup.py
```

یا دستی:

```bash
cp config.example.json config.json
```

حداقل این مقادیر ضروری‌اند:

- `script_id` (یا `script_ids`)
- `auth_key` (کاملاً برابر با `AUTH_KEY` در Code.gs)

## نصب گواهی CA

```bash
python main.py --install-cert
```

## اجرا

```bash
python main.py
```

