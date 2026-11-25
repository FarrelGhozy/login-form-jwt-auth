import { and, desc, eq, gt, isNull } from 'drizzle-orm';
import { db } from '../db';
import { authAuditLogs, refreshTokens, users } from '../db/schema';
import {
  JwtVerificationError,
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from '../security/jwt';
import { hashPassword, hashToken, verifyPassword } from '../security/password';
import { getPermissionsForRole, type Permission, type Role } from '../security/rbac';

export interface RequestMeta {
  ipAddress: string;
  userAgent: string;
}

export interface PublicUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  permissions: Permission[];
  createdAt: Date;
}

export interface SessionBundle {
  accessToken: string;
  refreshToken: string;
  refreshExpiresAt: Date;
  jwt: {
    jti: string;
    iat: number;
    exp: number;
  };
  user: PublicUser;
}

export type ServiceResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; code: string; message: string };

function toPublicUser(user: {
  id: string;
  name: string;
  email: string;
  role: Role;
  createdAt: Date;
}): PublicUser {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    permissions: getPermissionsForRole(user.role),
    createdAt: user.createdAt,
  };
}

async function recordAuditLog(params: {
  userId?: string | null;
  email: string;
  action: string;
  meta: RequestMeta;
}): Promise<void> {
  await db.insert(authAuditLogs).values({
    userId: params.userId ?? null,
    email: params.email,
    action: params.action,
    ipAddress: params.meta.ipAddress,
    userAgent: params.meta.userAgent,
  });
}

async function issueSessionForUser(
  user: {
    id: string;
    name: string;
    email: string;
    role: Role;
    createdAt: Date;
  },
  meta: RequestMeta,
): Promise<SessionBundle> {
  const familyId = crypto.randomUUID();
  const [access, refresh] = await Promise.all([
    signAccessToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    }),
    signRefreshToken({
      userId: user.id,
      familyId,
    }),
  ]);

  await db.insert(refreshTokens).values({
    userId: user.id,
    familyId,
    tokenHash: hashToken(refresh.token),
    jti: refresh.jti,
    expiresAt: refresh.expiresAt,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  return {
    accessToken: access.token,
    refreshToken: refresh.token,
    refreshExpiresAt: refresh.expiresAt,
    jwt: {
      jti: access.jti,
      iat: access.iat,
      exp: access.exp,
    },
    user: toPublicUser(user),
  };
}

export function validatePasswordStrength(password: string): string | null {
  if (password.length < 8) {
    return 'Password minimal 8 karakter.';
  }
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password harus mengandung kombinasi huruf dan angka.';
  }
  return null;
}

export async function registerUser(
  input: { name: string; email: string; password: string },
  meta: RequestMeta,
): Promise<ServiceResult<SessionBundle>> {
  const normalizedName = input.name.trim();
  const normalizedEmail = input.email.trim().toLowerCase();

  if (normalizedName.length < 2) {
    return {
      ok: false,
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Nama lengkap minimal 2 karakter.',
    };
  }

  const passwordIssue = validatePasswordStrength(input.password);
  if (passwordIssue) {
    return {
      ok: false,
      status: 400,
      code: 'WEAK_PASSWORD',
      message: passwordIssue,
    };
  }

  const existing = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, normalizedEmail))
    .limit(1);

  if (existing.length > 0) {
    return {
      ok: false,
      status: 409,
      code: 'EMAIL_ALREADY_EXISTS',
      message: 'Email sudah terdaftar. Silakan gunakan email lain atau masuk.',
    };
  }

  const passwordHash = await hashPassword(input.password);

  // Role dipaksa 'user' di sisi server untuk mencegah privilege escalation.
  const [createdUser] = await db
    .insert(users)
    .values({
      name: normalizedName,
      email: normalizedEmail,
      passwordHash,
      role: 'user',
      isActive: true,
    })
    .returning({
      id: users.id,
      name: users.name,
      email: users.email,
      role: users.role,
      createdAt: users.createdAt,
    });

  if (!createdUser) {
    return {
      ok: false,
      status: 500,
      code: 'INTERNAL_ERROR',
      message: 'Gagal membuat akun baru.',
    };
  }

  const session = await issueSessionForUser(createdUser, meta);
  await recordAuditLog({
    userId: createdUser.id,
    email: createdUser.email,
    action: 'REGISTER',
    meta,
  });

  return { ok: true, data: session };
}

export async function loginUser(
  input: { email: string; password: string },
  meta: RequestMeta,
): Promise<ServiceResult<SessionBundle>> {
  const normalizedEmail = input.email.trim().toLowerCase();

  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      passwordHash: users.passwordHash,
      role: users.role,
      isActive: users.isActive,
      createdAt: users.createdAt,
    })
    .from(users)
    .where(eq(users.email, normalizedEmail))
    .limit(1);

  if (!user) {
    await recordAuditLog({
      email: normalizedEmail,
      action: 'LOGIN_FAILED',
      meta,
    });
    return {
      ok: false,
      status: 401,
      code: 'INVALID_CREDENTIALS',
      message: 'Email atau password salah.',
    };
  }

  const passwordValid = await verifyPassword(input.password, user.passwordHash);
  if (!passwordValid) {
    await recordAuditLog({
      userId: user.id,
      email: user.email,
      action: 'LOGIN_FAILED',
      meta,
    });
    return {
      ok: false,
      status: 401,
      code: 'INVALID_CREDENTIALS',
      message: 'Email atau password salah.',
    };
  }

  if (!user.isActive) {
    await recordAuditLog({
      userId: user.id,
      email: user.email,
      action: 'LOGIN_BLOCKED_INACTIVE',
      meta,
    });
    return {
      ok: false,
      status: 403,
      code: 'ACCOUNT_DISABLED',
      message: 'Akun Anda sedang dinonaktifkan.',
    };
  }

  const session = await issueSessionForUser(user, meta);
  await recordAuditLog({
    userId: user.id,
    email: user.email,
    action: 'LOGIN_SUCCESS',
    meta,
  });

  return { ok: true, data: session };
}

export async function rotateRefreshSession(
  rawRefreshToken: string,
  meta: RequestMeta,
): Promise<ServiceResult<SessionBundle>> {
  let claims;
  try {
    claims = await verifyRefreshToken(rawRefreshToken);
  } catch (err) {
    const code = err instanceof JwtVerificationError ? err.code : 'TOKEN_INVALID';
    return {
      ok: false,
      status: 401,
      code,
      message: 'Refresh token tidak valid atau kedaluwarsa.',
    };
  }

  const tokenHash = hashToken(rawRefreshToken);

  return db.transaction(async (tx): Promise<ServiceResult<SessionBundle>> => {
    const [existing] = await tx
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .limit(1);

    if (!existing) {
      return {
        ok: false,
        status: 401,
        code: 'REFRESH_TOKEN_NOT_FOUND',
        message: 'Sesi refresh token tidak ditemukan.',
      };
    }

    const now = new Date();

    // Reuse Detection: token sudah pernah dipakai/di-revoke lalu dikirim lagi.
    // Seluruh token dalam familyId yang sama langsung dicabut agar sesi pembajak terputus.
    if (existing.revokedAt !== null) {
      await tx
        .update(refreshTokens)
        .set({ revokedAt: now })
        .where(and(eq(refreshTokens.familyId, existing.familyId), isNull(refreshTokens.revokedAt)));

      const [reusedUser] = await tx
        .select({ email: users.email })
        .from(users)
        .where(eq(users.id, existing.userId))
        .limit(1);

      await tx.insert(authAuditLogs).values({
        userId: existing.userId,
        email: reusedUser?.email ?? `user:${existing.userId}`,
        action: 'TOKEN_REUSE_DETECTED',
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
      });

      return {
        ok: false,
        status: 401,
        code: 'TOKEN_REUSE_DETECTED',
        message: 'Deteksi penggunaan ulang refresh token. Semua sesi terkait telah dicabut.',
      };
    }

    if (existing.expiresAt <= now) {
      await tx
        .update(refreshTokens)
        .set({ revokedAt: now })
        .where(eq(refreshTokens.id, existing.id));

      return {
        ok: false,
        status: 401,
        code: 'TOKEN_EXPIRED',
        message: 'Refresh token sudah kedaluwarsa. Silakan login kembali.',
      };
    }

    const [user] = await tx
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        isActive: users.isActive,
        createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.id, claims.sub))
      .limit(1);

    if (!user || !user.isActive) {
      return {
        ok: false,
        status: 401,
        code: 'USER_INACTIVE',
        message: 'Akun tidak aktif atau tidak ditemukan.',
      };
    }

    const [access, nextRefresh] = await Promise.all([
      signAccessToken({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      }),
      signRefreshToken({
        userId: user.id,
        familyId: existing.familyId,
      }),
    ]);

    const rotated = await tx
      .update(refreshTokens)
      .set({
        revokedAt: now,
        replacedByJti: nextRefresh.jti,
      })
      .where(and(eq(refreshTokens.id, existing.id), isNull(refreshTokens.revokedAt)))
      .returning({ id: refreshTokens.id });

    if (rotated.length === 0) {
      return {
        ok: false,
        status: 401,
        code: 'TOKEN_REUSE_DETECTED',
        message: 'Refresh token sudah digunakan oleh permintaan lain.',
      };
    }

    await tx.insert(refreshTokens).values({
      userId: user.id,
      familyId: existing.familyId,
      tokenHash: hashToken(nextRefresh.token),
      jti: nextRefresh.jti,
      expiresAt: nextRefresh.expiresAt,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    await tx.insert(authAuditLogs).values({
      userId: user.id,
      email: user.email,
      action: 'REFRESH',
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return {
      ok: true,
      data: {
        accessToken: access.token,
        refreshToken: nextRefresh.token,
        refreshExpiresAt: nextRefresh.expiresAt,
        jwt: {
          jti: access.jti,
          iat: access.iat,
          exp: access.exp,
        },
        user: toPublicUser(user),
      },
    };
  });
}

export async function logoutByRefreshToken(
  rawRefreshToken: string | undefined,
  meta: RequestMeta,
): Promise<void> {
  if (!rawRefreshToken) {
    return;
  }

  const tokenHash = hashToken(rawRefreshToken);
  const now = new Date();

  const [revoked] = await db
    .update(refreshTokens)
    .set({ revokedAt: now })
    .where(and(eq(refreshTokens.tokenHash, tokenHash), isNull(refreshTokens.revokedAt)))
    .returning({
      userId: refreshTokens.userId,
    });

  if (revoked) {
    const [logoutUser] = await db
      .select({ email: users.email })
      .from(users)
      .where(eq(users.id, revoked.userId))
      .limit(1);

    await recordAuditLog({
      userId: revoked.userId,
      email: logoutUser?.email ?? `user:${revoked.userId}`,
      action: 'LOGOUT',
      meta,
    });
  }
}

export async function revokeAllUserSessions(
  userId: string,
  email: string,
  meta: RequestMeta,
): Promise<number> {
  const now = new Date();
  const revoked = await db
    .update(refreshTokens)
    .set({ revokedAt: now })
    .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)))
    .returning({ id: refreshTokens.id });

  await recordAuditLog({
    userId,
    email,
    action: 'LOGOUT_ALL',
    meta,
  });

  return revoked.length;
}

export async function getActiveUserSessions(userId: string) {
  const now = new Date();
  return db
    .select({
      id: refreshTokens.id,
      jti: refreshTokens.jti,
      familyId: refreshTokens.familyId,
      ipAddress: refreshTokens.ipAddress,
      userAgent: refreshTokens.userAgent,
      createdAt: refreshTokens.createdAt,
      expiresAt: refreshTokens.expiresAt,
    })
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.userId, userId),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, now),
      ),
    )
    .orderBy(desc(refreshTokens.createdAt));
}
