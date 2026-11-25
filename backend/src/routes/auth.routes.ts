import { Elysia, t } from 'elysia';
import { env } from '../config/env';
import { authenticatePlugin } from '../middleware/authenticate';
import { loginRateLimiter } from '../security/rateLimit';
import {
  loginUser,
  logoutByRefreshToken,
  registerUser,
  revokeAllUserSessions,
  rotateRefreshSession,
  type RequestMeta,
} from '../services/auth.service';

export const REFRESH_COOKIE_NAME = 'refresh_token';

function extractRequestMeta(headers: Record<string, string | undefined>): RequestMeta {
  const forwardedFor = headers['x-forwarded-for']?.split(',')[0]?.trim();
  const realIp = headers['x-real-ip']?.trim();
  return {
    ipAddress: forwardedFor || realIp || '127.0.0.1',
    userAgent: headers['user-agent'] || 'unknown',
  };
}

function setRefreshCookie(
  cookieJar: Record<string, { set: (opts: Record<string, unknown>) => void } | undefined>,
  token: string,
): void {
  cookieJar[REFRESH_COOKIE_NAME]?.set({
    value: token,
    httpOnly: true,
    sameSite: 'lax',
    secure: env.isProduction,
    path: '/api/auth',
    maxAge: env.jwtRefreshTtlSeconds,
  });
}

function clearRefreshCookie(
  cookieJar: Record<string, { set: (opts: Record<string, unknown>) => void } | undefined>,
): void {
  cookieJar[REFRESH_COOKIE_NAME]?.set({
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: env.isProduction,
    path: '/api/auth',
    maxAge: 0,
  });
}

export const authRoutes = new Elysia({ prefix: '/api/auth' })
  .post(
    '/register',
    async ({ body, headers, cookie, status }) => {
      const meta = extractRequestMeta(headers);
      const result = await registerUser(
        {
          name: body.name,
          email: body.email,
          password: body.password,
        },
        meta,
      );

      if (!result.ok) {
        return status(result.status as 400 | 409 | 500, {
          error: {
            code: result.code,
            message: result.message,
          },
        });
      }

      setRefreshCookie(cookie, result.data.refreshToken);

      return status(201, {
        message: 'Registrasi berhasil.',
        accessToken: result.data.accessToken,
        jwt: result.data.jwt,
        user: result.data.user,
      });
    },
    {
      body: t.Object({
        name: t.String({ minLength: 2, maxLength: 120 }),
        email: t.String({ format: 'email', maxLength: 255 }),
        password: t.String({ minLength: 8, maxLength: 128 }),
      }),
    },
  )
  .post(
    '/login',
    async ({ body, headers, cookie, set, status }) => {
      const meta = extractRequestMeta(headers);
      const rateLimitKey = `${meta.ipAddress}:${body.email.trim().toLowerCase()}`;
      const limitCheck = loginRateLimiter.consume(rateLimitKey);

      if (!limitCheck.allowed) {
        set.headers['Retry-After'] = String(limitCheck.retryAfterSeconds);
        return status(429, {
          error: {
            code: 'TOO_MANY_REQUESTS',
            message: `Terlalu banyak percobaan login. Coba lagi dalam ${limitCheck.retryAfterSeconds} detik.`,
          },
        });
      }

      const result = await loginUser(
        {
          email: body.email,
          password: body.password,
        },
        meta,
      );

      if (!result.ok) {
        return status(result.status as 401 | 403, {
          error: {
            code: result.code,
            message: result.message,
          },
        });
      }

      loginRateLimiter.reset(rateLimitKey);
      setRefreshCookie(cookie, result.data.refreshToken);

      return {
        message: 'Login berhasil.',
        accessToken: result.data.accessToken,
        jwt: result.data.jwt,
        user: result.data.user,
      };
    },
    {
      body: t.Object({
        email: t.String({ format: 'email', maxLength: 255 }),
        password: t.String({ minLength: 1, maxLength: 128 }),
      }),
    },
  )
  .post('/refresh', async ({ cookie, headers, status }) => {
    const rawRefreshToken = cookie[REFRESH_COOKIE_NAME]?.value;
    if (typeof rawRefreshToken !== 'string' || !rawRefreshToken) {
      return status(401, {
        error: {
          code: 'NO_REFRESH_TOKEN',
          message: 'Refresh token tidak ditemukan.',
        },
      });
    }

    const meta = extractRequestMeta(headers);
    const result = await rotateRefreshSession(rawRefreshToken, meta);

    if (!result.ok) {
      clearRefreshCookie(cookie);
      return status(result.status as 401, {
        error: {
          code: result.code,
          message: result.message,
        },
      });
    }

    setRefreshCookie(cookie, result.data.refreshToken);

    return {
      message: 'Token berhasil diperbarui.',
      accessToken: result.data.accessToken,
      jwt: result.data.jwt,
      user: result.data.user,
    };
  })
  .post('/logout', async ({ cookie, headers }) => {
    const rawRefreshToken = cookie[REFRESH_COOKIE_NAME]?.value;
    const meta = extractRequestMeta(headers);

    await logoutByRefreshToken(
      typeof rawRefreshToken === 'string' ? rawRefreshToken : undefined,
      meta,
    );

    clearRefreshCookie(cookie);

    return {
      message: 'Logout berhasil.',
    };
  })
  .use(authenticatePlugin)
  .post('/logout-all', async ({ authUser, cookie, headers }) => {
    const meta = extractRequestMeta(headers);
    const revokedCount = await revokeAllUserSessions(authUser.id, authUser.email, meta);
    clearRefreshCookie(cookie);

    return {
      message: 'Semua sesi aktif berhasil dicabut.',
      revokedSessions: revokedCount,
    };
  });
