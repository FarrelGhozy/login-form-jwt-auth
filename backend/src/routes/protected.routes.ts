import { desc } from 'drizzle-orm';
import { Elysia } from 'elysia';
import { db } from '../db';
import { authAuditLogs, users } from '../db/schema';
import { authenticatePlugin } from '../middleware/authenticate';
import { authorizeGuard } from '../middleware/authorize';
import { getActiveUserSessions } from '../services/auth.service';

export const protectedRoutes = new Elysia({ prefix: '/api' })
  // Lapisan Authentication: semua user yang sudah login (role: user maupun admin)
  .use(authenticatePlugin)
  .get('/me', ({ authUser, jwtClaims }) => {
    return {
      message: 'Autentikasi valid.',
      user: authUser,
      jwt: {
        jti: jwtClaims.jti,
        sub: jwtClaims.sub,
        role: jwtClaims.role,
        iat: jwtClaims.iat,
        exp: jwtClaims.exp,
      },
    };
  })
  .get('/sessions', async ({ authUser }) => {
    const sessions = await getActiveUserSessions(authUser.id);
    return {
      totalActive: sessions.length,
      sessions,
    };
  })
  // Lapisan Authorization (RBAC): tiap endpoint memiliki policy role & permission terisolasi
  .group('/admin', (adminApp) =>
    adminApp
      .get(
        '/panel',
        async ({ authUser }) => {
          const recentAuditLogs = await db
            .select({
              id: authAuditLogs.id,
              email: authAuditLogs.email,
              action: authAuditLogs.action,
              ipAddress: authAuditLogs.ipAddress,
              createdAt: authAuditLogs.createdAt,
            })
            .from(authAuditLogs)
            .orderBy(desc(authAuditLogs.createdAt))
            .limit(5);

          return {
            message: `Akses Admin diizinkan untuk ${authUser.email}.`,
            authorizedRole: authUser.role,
            requiredRole: 'admin',
            recentAuditLogs,
          };
        },
        {
          beforeHandle: authorizeGuard({
            roles: ['admin'],
            permissions: ['admin:panel'],
          }),
        },
      )
      .get(
        '/users',
        async () => {
          const userList = await db
            .select({
              id: users.id,
              name: users.name,
              email: users.email,
              role: users.role,
              isActive: users.isActive,
              createdAt: users.createdAt,
            })
            .from(users)
            .orderBy(desc(users.createdAt));

          return {
            total: userList.length,
            users: userList,
          };
        },
        {
          beforeHandle: authorizeGuard({
            roles: ['admin'],
            permissions: ['users:list'],
          }),
        },
      ),
  );
