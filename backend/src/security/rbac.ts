export type Role = 'user' | 'admin';

export type Permission = 'profile:read' | 'session:read' | 'admin:panel' | 'users:list';

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  user: ['profile:read', 'session:read'],
  admin: ['profile:read', 'session:read', 'admin:panel', 'users:list'],
};

export function getPermissionsForRole(role: Role): Permission[] {
  return [...ROLE_PERMISSIONS[role]];
}

export function hasRequiredRoles(userRole: Role, allowedRoles?: readonly Role[]): boolean {
  if (!allowedRoles || allowedRoles.length === 0) {
    return true;
  }
  return allowedRoles.includes(userRole);
}

export function hasRequiredPermissions(
  userRole: Role,
  requiredPermissions?: readonly Permission[],
): boolean {
  if (!requiredPermissions || requiredPermissions.length === 0) {
    return true;
  }
  const granted = ROLE_PERMISSIONS[userRole];
  return requiredPermissions.every((perm) => granted.includes(perm));
}
