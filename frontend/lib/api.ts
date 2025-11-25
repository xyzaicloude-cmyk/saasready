import axios, { AxiosInstance } from 'axios';
import { authStorage } from './auth';
import type {
  User,
  Organization,
  Membership,
  AuditLog,
  LoginRequest,
  RegisterRequest,
  TokenResponse,
  InviteUserRequest,
  FeatureFlag,
  Role
} from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.client.interceptors.request.use((config) => {
      const token = authStorage.getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          authStorage.removeToken();
          if (typeof window !== 'undefined') {
            window.location.href = '/login';
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // Generic HTTP methods
  async get<T = any>(url: string, config?: any) {
    return this.client.get<T>(url, config);
  }

  async post<T = any>(url: string, data?: any, config?: any) {
    return this.client.post<T>(url, data, config);
  }

  async put<T = any>(url: string, data?: any, config?: any) {
    return this.client.put<T>(url, data, config);
  }

  async patch<T = any>(url: string, data?: any, config?: any) {
    return this.client.patch<T>(url, data, config);
  }

  async delete<T = any>(url: string, config?: any) {
    return this.client.delete<T>(url, config);
  }

  // Auth endpoints
  async register(data: RegisterRequest): Promise<TokenResponse> {
    const response = await this.client.post<TokenResponse>('/auth/register', data);
    return response.data;
  }

  async registerWithInvite(data: RegisterRequest, inviteToken: string): Promise<TokenResponse> {
    const response = await this.client.post<TokenResponse>(
      `/auth/register-with-invite?invite_token=${inviteToken}`,
      data
    );
    return response.data;
  }

  async login(data: LoginRequest): Promise<TokenResponse> {
    const response = await this.client.post<TokenResponse>('/auth/login', data);
    return response.data;
  }

  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<User>('/auth/me');
    return response.data;
  }

  // Organization endpoints
  async getOrganizations(): Promise<Organization[]> {
    const response = await this.client.get<Organization[]>('/orgs');
    return response.data;
  }

  async createOrganization(data: {
    name: string;
    slug: string;
    description?: string;
  }): Promise<Organization> {
    const response = await this.client.post<Organization>('/orgs', data);
    return response.data;
  }

  async getOrganizationMembers(orgId: string): Promise<Membership[]> {
    const response = await this.client.get<Membership[]>(`/orgs/${orgId}/members`);
    return response.data;
  }

  async inviteUser(orgId: string, data: InviteUserRequest): Promise<Membership> {
    const response = await this.client.post<Membership>(
      `/orgs/${orgId}/invite`,
      data
    );
    return response.data;
  }

  async updateMemberRole(
    orgId: string,
    membershipId: string,
    roleId: string
  ): Promise<Membership> {
    const response = await this.client.patch<Membership>(
      `/orgs/${orgId}/members/${membershipId}/role`,
      { role_id: roleId }
    );
    return response.data;
  }

  // Audit logs
  async getAuditLogs(orgId: string, limit = 100, offset = 0): Promise<AuditLog[]> {
    const response = await this.client.get<AuditLog[]>(
      `/audit/orgs/${orgId}/logs`,
      { params: { limit, offset } }
    );
    return response.data;
  }

  // Feature flags endpoints
  async getGlobalFeatureFlags(): Promise<FeatureFlag[]> {
    const response = await this.client.get<FeatureFlag[]>('/feature-flags');
    return response.data;
  }

  async createGlobalFeatureFlag(data: {
    key: string;
    name: string;
    description?: string;
    default_enabled: boolean;
  }): Promise<FeatureFlag> {
    const response = await this.client.post<FeatureFlag>('/feature-flags', data);
    return response.data;
  }

  async getOrgFeatureFlags(orgId: string): Promise<FeatureFlag[]> {
    const response = await this.client.get<FeatureFlag[]>(
      `/orgs/${orgId}/feature-flags`
    );
    return response.data;
  }

  async setOrgFeatureFlag(
    orgId: string,
    flagKey: string,
    data: { enabled: boolean; rollout_percent?: number }
  ): Promise<FeatureFlag> {
    const response = await this.client.put<FeatureFlag>(
      `/orgs/${orgId}/feature-flags/${flagKey}`,
      data
    );
    return response.data;
  }

  async deleteOrgFeatureFlag(orgId: string, flagKey: string): Promise<FeatureFlag> {
    const response = await this.client.delete<FeatureFlag>(
      `/orgs/${orgId}/feature-flags/${flagKey}`
    );
    return response.data;
  }

  async getRoles(orgId: string): Promise<Role[]> {
    const response = await this.client.get<Role[]>(`/orgs/${orgId}/roles`);
    return response.data;
  }

  async acceptInvitation(token: string): Promise<{ message: string; organization: any }> {
    const response = await this.client.post<{ message: string; organization: any }>(
      '/auth/accept-invitation',
      { token }
    );
    return response.data;
  }
}

export const api = new ApiClient();