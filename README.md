# Login Form — Authentication, Authorization & JWT

Aplikasi fullstack **Login Form** untuk tugas mata kuliah **Pemrograman Web Lanjut** dengan fokus pada implementasi **Authentication**, **Authorization (RBAC)**, dan **JSON Web Token (JWT)**.

## Ringkasan Konsep yang Diimplementasikan

1. **Authentication (Autentikasi)**
   - Registrasi (`POST /api/auth/register`) & Login (`POST /api/auth/login`).
   - Hashing password menggunakan **Argon2id** (`Bun.password.hash`).
   - Proteksi *brute-force* login menggunakan sliding-window rate limiter (`429 Too Many Requests` + `Retry-After`).
   - Pesan error login yang seragam (`401 INVALID_CREDENTIALS`) untuk mencegah *account enumeration*.
   - Middleware [`authenticatePlugin`](backend/src/middleware/authenticate.ts) memverifikasi Access JWT (`Authorization: Bearer <token>`) dan status aktif pengguna di PostgreSQL.

2. **Authorization (Otorisasi / RBAC)**
   - Role-Based Access Control (`user` & `admin`) dengan matriks permission di [`rbac.ts`](backend/src/security/rbac.ts):
     - `user`: `['profile:read', 'session:read']`
     - `admin`: `['profile:read', 'session:read', 'admin:panel', 'users:list']`
   - Middleware [`authorizeGuard`](backend/src/middleware/authorize.ts) menolak akses lintas role dengan **`403 Forbidden`**.
   - Role akun baru saat registrasi dipaksa menjadi `'user'` di server untuk mencegah *privilege escalation*.

3. **JWT (Access Token + Refresh Token Rotation)**
   - Signed dengan algoritma `HS256` menggunakan library `jose` (`iss`, `aud`, `sub`, `jti`, `iat`, `exp`, serta klaim `type` untuk mencegah token confusion).
   - **Access Token (15 menit)**: hanya disimpan di memori React (bukan `localStorage`) untuk memitigasi risiko XSS.
   - **Refresh Token (7 hari)**: disimpan dalam **`HttpOnly` Cookie** (`SameSite=Lax; Path=/api/auth`) dan hanya hash SHA-256-nya yang disimpan di tabel `refresh_tokens` PostgreSQL.
   - **Refresh Token Rotation & Reuse Detection**: setiap pembaruan token menerbitkan pasangan token baru dalam `family_id` yang sama dan mencabut token lama. Jika token lama dipakai ulang, seluruh sesi dalam `family_id` tersebut otomatis dicabut (`TOKEN_REUSE_DETECTED`).

## Tech Stack

- **Backend (`backend/`)**: Bun, ElysiaJS, TypeScript, Drizzle ORM, PostgreSQL, `jose`
- **Frontend (`frontend/`)**: React 19, Vite, TypeScript, Tailwind CSS v4, Lucide Icons

## Struktur Folder

```text
.
├── docker-compose.yml          # PostgreSQL 16 lokal (port 5433)
├── backend/
│   ├── drizzle.config.ts
│   ├── .env.example
│   └── src/
│       ├── app.ts              # Konfigurasi Elysia, CORS, error handler
│       ├── index.ts            # Entry point server (port 3001)
│       ├── config/env.ts       # Validasi environment variables & TTL
│       ├── db/
│       │   ├── schema.ts       # Tabel users, refresh_tokens, auth_audit_logs
│       │   ├── index.ts        # Koneksi PostgreSQL + Drizzle
│       │   └── seed.ts         # Seeder akun demo admin & user
│       ├── middleware/
│       │   ├── authenticate.ts # Validasi Access JWT & user aktif
│       │   └── authorize.ts    # Guard RBAC (role & permission)
│       ├── routes/
│       │   ├── auth.routes.ts      # /api/auth/*
│       │   └── protected.routes.ts # /api/me, /api/sessions, /api/admin/*
│       ├── security/
│       │   ├── jwt.ts          # Sign & verify Access/Refresh JWT
│       │   ├── password.ts     # Argon2id & SHA-256 token hash
│       │   ├── rateLimit.ts    # Rate limiter login
│       │   └── rbac.ts         # Role & permission matrix
│       ├── services/
│       │   └── auth.service.ts # Bisnis logic auth, rotasi & reuse detection
│       └── tests/
│           └── auth.test.ts    # Integration tests (bun test)
└── frontend/
    ├── vite.config.ts          # Proxy /api -> http://localhost:3001
    └── src/
        ├── App.tsx
        ├── context/AuthContext.tsx
        ├── lib/api.ts          # Fetch client + automatic silent refresh
        └── components/
            ├── AuthCard.tsx    # Form Masuk & Daftar + tombol akun demo
            └── LoggedInPage.tsx# Halaman putih "Anda sudah login" + uji RBAC & JWT
```

## Cara Menjalankan

### 1. Siapkan Database PostgreSQL

Gunakan Docker Compose yang tersedia (atau arahkan `DATABASE_URL` di `backend/.env` ke PostgreSQL / Supabase Anda):

```bash
docker compose up -d
```

### 2. Setup & Jalankan Backend

```bash
cd backend
cp .env.example .env
bun install
bun run db:push
bun run seed
bun run dev
```

Backend berjalan di `http://localhost:3001`.

### 3. Setup & Jalankan Frontend

Buka terminal baru:

```bash
cd frontend
bun install
bun run dev
```

Frontend berjalan di `http://localhost:5173`.

## Akun Demo (Hasil `bun run seed`)

| Role | Email | Password | Akses `/api/admin/panel` |
| --- | --- | --- | --- |
| `admin` | `admin@demo.local` | `Admin123!` | `200 OK` |
| `user` | `user@demo.local` | `User123!` | `403 Forbidden` |

## Daftar Endpoint API

| Method | Endpoint | AuthN | AuthZ | Keterangan |
| --- | --- | --- | --- | --- |
| `GET` | `/api/health` | Tidak | - | Cek status API & PostgreSQL |
| `POST` | `/api/auth/register` | Tidak | - | Daftar akun baru (role default `user`) |
| `POST` | `/api/auth/login` | Tidak | - | Login & terbitkan Access + Refresh JWT |
| `POST` | `/api/auth/refresh` | Cookie | - | Rotasi Refresh Token + Reuse Detection |
| `POST` | `/api/auth/logout` | Cookie | - | Revokasi Refresh Token saat ini |
| `POST` | `/api/auth/logout-all` | Ya | Semua role | Cabut seluruh sesi aktif user |
| `GET` | `/api/me` | Ya | Semua role | Info user & metadata klaim JWT aktif |
| `GET` | `/api/sessions` | Ya | Semua role | Daftar sesi refresh token aktif |
| `GET` | `/api/admin/panel` | Ya | `admin` (`admin:panel`) | Panel khusus admin + audit log terbaru |
| `GET` | `/api/admin/users` | Ya | `admin` (`users:list`) | Daftar akun terdaftar (tanpa password hash) |

## Menjalankan Automated Tests

```bash
cd backend
bun run typecheck
bun test
```
