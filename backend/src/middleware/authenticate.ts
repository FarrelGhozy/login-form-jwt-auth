import { Elysia } from 'elysia';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import { users } from '../db/schema';
import { JwtVerificationError, verifyAccessToken, type AccessTokenClaims } from '../security/jwt';
import { getPermissionsForRole, type Permission, type Role } from '../security/rbac';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  permissions: Permission[];
}

export interface AuthErrorPayload {
  error: {
    code: string;
    message: string;
  };
}

function extractBearerToken(authorizationHeader?: string): string | null {
  if (!authorizationHeader) {
    return null;
  }
  const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

/**
 * Middleware Authentication:
 * Memvalidasi Access JWT dari header `Authorization: Bearer <token>`,
 * memastikan token bertipe `access`, belum expired, signature valid,
 * dan user masih aktif di database.
 */
export const authenticatePlugin = new Elysia({ name: 'authenticate-plugin' }).resolve(
  { as: 'scoped' },
  async ({ headers, status }) => {
    const token = extractBearerToken(headers.authorization);
    if (!token) {
      return status(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Autentikasi diperlukan. Header Authorization Bearer tidak ditemukan.',
        },
      } satisfies AuthErrorPayload);
    }

    let claims: AccessTokenClaims;
    try {
      claims = await verifyAccessToken(token);
    } catch (err) {
      if (err instanceof JwtVerificationError) {
        return status(401, {
          error: {
            code: err.code,
            message: err.message,
          },
        } satisfies AuthErrorPayload);
      }
      return status(401, {
        error: {
          code: 'TOKEN_INVALID',
          message: 'Access token tidak valid.',
        },
      } satisfies AuthErrorPayload);
    }

    const [user] = await db
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        isActive: users.isActive,
      })
      .from(users)
      .where(eq(users.id, claims.sub))
      .limit(1);

    if (!user || !user.isActive) {
      return status(401, {
        error: {
          code: 'USER_INACTIVE',
          message: 'Akun tidak ditemukan atau sudah dinonaktifkan.',
        },
      } satisfies AuthErrorPayload);
    }

    const authUser: AuthenticatedUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      permissions: getPermissionsForRole(user.role),
    };

    return {
      authUser,
      jwtClaims: claims,
    };
  },
);
