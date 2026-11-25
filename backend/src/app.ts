import { cors } from '@elysiajs/cors';
import { Elysia } from 'elysia';
import { sql } from 'drizzle-orm';
import { env } from './config/env';
import { db } from './db';
import { authRoutes } from './routes/auth.routes';
import { protectedRoutes } from './routes/protected.routes';

export function createApp() {
  return new Elysia()
    .use(
      cors({
        origin: env.frontendOrigin,
        credentials: true,
        allowedHeaders: ['Content-Type', 'Authorization'],
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      }),
    )
    .onError(({ code, error, set }) => {
      if (code === 'VALIDATION') {
        set.status = 400;
        return {
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Format input tidak valid. Periksa kembali data yang dikirim.',
          },
        };
      }

      if (code === 'NOT_FOUND') {
        set.status = 404;
        return {
          error: {
            code: 'NOT_FOUND',
            message: 'Endpoint tidak ditemukan.',
          },
        };
      }

      console.error('[API ERROR]', error);
      set.status = 500;
      return {
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Terjadi kesalahan pada server.',
        },
      };
    })
    .get('/api/health', async () => {
      await db.execute(sql`SELECT 1`);
      return {
        status: 'ok',
        service: 'login-form-backend',
        timestamp: new Date().toISOString(),
      };
    })
    .use(authRoutes)
    .use(protectedRoutes);
}

export type App = ReturnType<typeof createApp>;
