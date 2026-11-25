import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { inArray, like } from 'drizzle-orm';
import { createApp } from '../app';
import { client, db } from '../db';
import { seedDemoUsers } from '../db/seed';
import { authAuditLogs, users } from '../db/schema';
import { loginRateLimiter } from '../security/rateLimit';

const app = createApp();
const BASE_URL = 'http://localhost';

function extractCookie(response: Response, cookieName: string): string | null {
  const headersObj = response.headers as Headers & { getSetCookie?: () => string[] };
  const setCookies =
    typeof headersObj.getSetCookie === 'function'
      ? headersObj.getSetCookie()
      : [response.headers.get('set-cookie') ?? ''];

  for (const raw of setCookies) {
    const match = raw.match(new RegExp(`(?:^|,)\\s*${cookieName}=([^;]*)`));
    if (match) {
      return match[1] ?? '';
    }
  }
  return null;
}

function getRawSetCookieHeader(response: Response): string {
  const headersObj = response.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headersObj.getSetCookie === 'function') {
    return headersObj.getSetCookie().join('; ');
  }
  return response.headers.get('set-cookie') ?? '';
}

async function apiRequest(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    accessToken?: string;
    refreshToken?: string;
  } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (options.accessToken) {
    headers.Authorization = `Bearer ${options.accessToken}`;
  }
  if (options.refreshToken) {
    headers.Cookie = `refresh_token=${options.refreshToken}`;
  }

  return app.handle(
    new Request(`${BASE_URL}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    }),
  );
}

async function cleanupTestData() {
  const testUsers = await db
    .select({ id: users.id })
    .from(users)
    .where(like(users.email, '%@test.local'));

  if (testUsers.length > 0) {
    await db
      .delete(users)
      .where(
        inArray(
          users.id,
          testUsers.map((u) => u.id),
        ),
      );
  }

  await db.delete(authAuditLogs).where(like(authAuditLogs.email, '%@test.local'));
}

describe('Authentication, Authorization & JWT API', () => {
  beforeAll(async () => {
    await seedDemoUsers();
    await cleanupTestData();
  });

  beforeEach(() => {
    loginRateLimiter.clearAll();
  });

  afterAll(async () => {
    await cleanupTestData();
    await client.end();
  });

  it('GET /api/health memastikan API dan PostgreSQL aktif', async () => {
    const res = await apiRequest('/api/health');
    expect(res.status).toBe(200);
    const data = (await res.json()) as { status: string };
    expect(data.status).toBe('ok');
  });

  describe('Register & Privilege Escalation Protection', () => {
    it('mendaftarkan user baru dengan role tetap "user" walau body mengirim role "admin"', async () => {
      const email = `baru-${Date.now()}@test.local`;
      const res = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          name: 'Mahasiswa Uji',
          email,
          password: 'Password123',
          role: 'admin',
        },
      });

      expect(res.status).toBe(201);
      const body = (await res.json()) as {
        accessToken: string;
        user: { email: string; role: string; passwordHash?: string };
      };

      expect(body.accessToken).toBeString();
      expect(body.user.email).toBe(email);
      expect(body.user.role).toBe('user');
      expect(body.user.passwordHash).toBeUndefined();

      const setCookieRaw = getRawSetCookieHeader(res);
      expect(setCookieRaw).toContain('HttpOnly');
      expect(extractCookie(res, 'refresh_token')).toBeTruthy();
    });

    it('menolak password lemah dan email duplikat', async () => {
      const email = `dup-${Date.now()}@test.local`;

      const weakRes = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          name: 'User Lemah',
          email,
          password: 'passwordonly',
        },
      });
      expect(weakRes.status).toBe(400);

      const firstRes = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          name: 'User Satu',
          email,
          password: 'Password123',
        },
      });
      expect(firstRes.status).toBe(201);

      const dupRes = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: {
          name: 'User Dua',
          email,
          password: 'Password123',
        },
      });
      expect(dupRes.status).toBe(409);
    });
  });

  describe('Authentication & JWT Validation', () => {
    it('menolak login dengan password salah maupun email tidak dikenal dengan pesan seragam', async () => {
      const wrongPass = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'SalahPassword1!' },
      });
      expect(wrongPass.status).toBe(401);
      const wrongPassBody = (await wrongPass.json()) as { error: { code: string; message: string } };

      const unknownEmail = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'tidakada@test.local', password: 'SalahPassword1!' },
      });
      expect(unknownEmail.status).toBe(401);
      const unknownBody = (await unknownEmail.json()) as { error: { code: string; message: string } };

      expect(wrongPassBody.error.code).toBe('INVALID_CREDENTIALS');
      expect(wrongPassBody.error.message).toBe(unknownBody.error.message);
    });

    it('menolak akses /api/me tanpa token, token palsu, atau memakai refresh token sebagai access token', async () => {
      const noToken = await apiRequest('/api/me');
      expect(noToken.status).toBe(401);

      const tampered = await apiRequest('/api/me', {
        accessToken: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.invalid-signature',
      });
      expect(tampered.status).toBe(401);

      const loginRes = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      expect(loginRes.status).toBe(200);
      const refreshCookie = extractCookie(loginRes, 'refresh_token')!;

      // Refresh token tidak boleh bisa dipakai mengakses endpoint sebagai Access JWT
      const tokenConfusion = await apiRequest('/api/me', {
        accessToken: refreshCookie,
      });
      expect(tokenConfusion.status).toBe(401);
    });
  });

  describe('Authorization (RBAC)', () => {
    it('memblokir role "user" (403 Forbidden) dan mengizinkan role "admin" (200 OK)', async () => {
      const userLogin = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      const userData = (await userLogin.json()) as { accessToken: string };

      const userMe = await apiRequest('/api/me', { accessToken: userData.accessToken });
      expect(userMe.status).toBe(200);

      const userPanel = await apiRequest('/api/admin/panel', { accessToken: userData.accessToken });
      expect(userPanel.status).toBe(403);
      const userPanelBody = (await userPanel.json()) as { error: { code: string } };
      expect(userPanelBody.error.code).toBe('FORBIDDEN');

      const userListForbidden = await apiRequest('/api/admin/users', {
        accessToken: userData.accessToken,
      });
      expect(userListForbidden.status).toBe(403);

      const adminLogin = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'admin@demo.local', password: 'Admin123!' },
      });
      const adminData = (await adminLogin.json()) as { accessToken: string };

      const adminPanel = await apiRequest('/api/admin/panel', {
        accessToken: adminData.accessToken,
      });
      expect(adminPanel.status).toBe(200);
      const adminPanelBody = (await adminPanel.json()) as { authorizedRole: string };
      expect(adminPanelBody.authorizedRole).toBe('admin');

      const adminUsers = await apiRequest('/api/admin/users', {
        accessToken: adminData.accessToken,
      });
      expect(adminUsers.status).toBe(200);
      const adminUsersBody = (await adminUsers.json()) as {
        users: Array<{ email: string; passwordHash?: string }>;
      };
      expect(adminUsersBody.users.length).toBeGreaterThanOrEqual(2);
      expect(adminUsersBody.users[0]?.passwordHash).toBeUndefined();
    });
  });

  describe('JWT Refresh Token Rotation & Reuse Detection', () => {
    it('merotasi token dan mencabut seluruh family apabila refresh token lama dipakai ulang', async () => {
      const loginRes = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      expect(loginRes.status).toBe(200);
      const loginBody = (await loginRes.json()) as { jwt: { jti: string } };
      const oldRefresh = extractCookie(loginRes, 'refresh_token')!;
      expect(oldRefresh).toBeTruthy();

      // Rotasi normal
      const refreshRes = await apiRequest('/api/auth/refresh', {
        method: 'POST',
        refreshToken: oldRefresh,
      });
      expect(refreshRes.status).toBe(200);
      const refreshBody = (await refreshRes.json()) as {
        accessToken: string;
        jwt: { jti: string };
      };
      const newRefresh = extractCookie(refreshRes, 'refresh_token')!;
      expect(newRefresh).toBeTruthy();
      expect(newRefresh).not.toBe(oldRefresh);
      expect(refreshBody.jwt.jti).not.toBe(loginBody.jwt.jti);

      // Token baru valid untuk akses /api/me
      const meRes = await apiRequest('/api/me', { accessToken: refreshBody.accessToken });
      expect(meRes.status).toBe(200);

      // Serangan replay: gunakan ulang token lama
      const reuseRes = await apiRequest('/api/auth/refresh', {
        method: 'POST',
        refreshToken: oldRefresh,
      });
      expect(reuseRes.status).toBe(401);
      const reuseBody = (await reuseRes.json()) as { error: { code: string } };
      expect(reuseBody.error.code).toBe('TOKEN_REUSE_DETECTED');

      // Token baru dalam family yang sama ikut tercabut otomatis
      const victimRes = await apiRequest('/api/auth/refresh', {
        method: 'POST',
        refreshToken: newRefresh,
      });
      expect(victimRes.status).toBe(401);
    });
  });

  describe('Logout & Rate Limiting', () => {
    it('mencabut refresh token saat logout dan logout-all', async () => {
      const login1 = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      const data1 = (await login1.json()) as { accessToken: string };
      const refresh1 = extractCookie(login1, 'refresh_token')!;

      const logoutRes = await apiRequest('/api/auth/logout', {
        method: 'POST',
        refreshToken: refresh1,
      });
      expect(logoutRes.status).toBe(200);
      expect(extractCookie(logoutRes, 'refresh_token')).toBe('');

      const refreshAfterLogout = await apiRequest('/api/auth/refresh', {
        method: 'POST',
        refreshToken: refresh1,
      });
      expect(refreshAfterLogout.status).toBe(401);

      // Login dua sesi baru lalu logout-all
      const loginA = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      const loginB = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: 'user@demo.local', password: 'User123!' },
      });
      const dataA = (await loginA.json()) as { accessToken: string };
      const refreshB = extractCookie(loginB, 'refresh_token')!;

      const logoutAllRes = await apiRequest('/api/auth/logout-all', {
        method: 'POST',
        accessToken: dataA.accessToken,
      });
      expect(logoutAllRes.status).toBe(200);

      const refreshBCheck = await apiRequest('/api/auth/refresh', {
        method: 'POST',
        refreshToken: refreshB,
      });
      expect(refreshBCheck.status).toBe(401);
      expect(data1.accessToken).toBeString();
    });

    it('membatasi percobaan login gagal beruntun dengan 429 Too Many Requests', async () => {
      const targetEmail = `brute-${Date.now()}@test.local`;

      for (let i = 0; i < 10; i++) {
        const attempt = await apiRequest('/api/auth/login', {
          method: 'POST',
          body: { email: targetEmail, password: 'WrongPassword1!' },
        });
        expect(attempt.status).toBe(401);
      }

      const blocked = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: { email: targetEmail, password: 'WrongPassword1!' },
      });
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('Retry-After')).toBeTruthy();
    });
  });
});
