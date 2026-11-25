import {
  hasRequiredPermissions,
  hasRequiredRoles,
  type Permission,
  type Role,
} from '../security/rbac';
import type { AuthErrorPayload, AuthenticatedUser } from './authenticate';

export interface AccessPolicy {
  roles?: readonly Role[];
  permissions?: readonly Permission[];
}

type StatusResponder = (code: 401 | 403, body: AuthErrorPayload) => unknown;

/**
 * Authorization Guard (RBAC):
 * Dijalankan setelah Authentication untuk memastikan user yang sudah login
 * memiliki role dan permission yang diizinkan mengakses endpoint tertentu.
 */
export function authorizeGuard(policy: AccessPolicy) {
  return ({
    authUser,
    status,
  }: {
    authUser?: AuthenticatedUser;
    status: StatusResponder;
  }) => {
    if (!authUser) {
      return status(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Autentikasi diperlukan sebelum pengecekan izin akses.',
        },
      });
    }

    const roleAllowed = hasRequiredRoles(authUser.role, policy.roles);
    const permissionAllowed = hasRequiredPermissions(authUser.role, policy.permissions);

    if (!roleAllowed || !permissionAllowed) {
      return status(403, {
        error: {
          code: 'FORBIDDEN',
          message: `Akses ditolak. Role "${authUser.role}" tidak memiliki izin untuk resource ini.`,
        },
      });
    }
  };
}
