export interface User {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  is_active: boolean;
  created_at: string;
}

export interface Membership {
  id: string;
  user_id: string;
  organization_id: string;
  role_id: string | null;
  status: 'active' | 'invited' | 'suspended';
  created_at: string;
  user_email?: string;
  user_full_name?: string;
  role_name?: string;
}

export interface AuditLog {
  id: string;
  actor_user_id: string | null;
  organization_id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  audit_metadata: Record<string, any> | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  actor_email?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface InviteUserRequest {
  email: string;
  role_id: string;
  full_name?: string;
}

export interface FeatureFlag {
  key: string;
  name: string;
  description: string | null;
  default_enabled: boolean;
  enabled: boolean;
  overridden: boolean;
  rollout_percent: number | null;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  created_at: string;
}


export interface AcceptInvitationResponse {
    message: string;
    organization: {
        id: string;
        name: string;
        slug: string;
    };
}