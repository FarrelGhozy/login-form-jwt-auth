export type Role = 'user' | 'admin';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  permissions: string[];
  createdAt?: string;
}

export interface JwtMeta {
  jti: string;
  iat: number;
  exp: number;
}

export interface AuthResponse {
  message: string;
  accessToken: string;
  jwt: JwtMeta;
  user: AuthUser;
}

export interface AdminPanelResponse {
  message: string;
  authorizedRole: Role;
  requiredRole: Role;
  recentAuditLogs: Array<{
    id: string;
    email: string;
    action: string;
    ipAddress: string | null;
    createdAt: string;
  }>;
}

export interface ApiErrorBody {
  error?: {
    code?: string;
    message?: string;
  };
}
