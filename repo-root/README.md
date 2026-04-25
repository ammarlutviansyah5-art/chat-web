
# ChatApp Fullstack

Project ini memakai `index.html` yang sudah ada sebagai basis utama UI, lalu ditambah:

- autentikasi login/register/lupa password + OTP email
- database SQLite
- realtime chat via Socket.IO
- presence online/offline + last seen
- upload status foto/video ke server
- block system
- toast notifikasi pesan masuk

## Jalankan
```bash
npm install
npm start
```

Buka:
- `http://localhost:3000/` → login
- `http://localhost:3000/app` → aplikasi utama

## Environment email
Kalau mau OTP terkirim lewat email asli, isi variabel berikut:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_SECURE`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`
- `JWT_SECRET`

Kalau SMTP belum diisi, server tetap jalan dan OTP akan muncul di console sebagai fallback dev.
