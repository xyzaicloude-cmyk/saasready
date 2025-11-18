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
  InviteUserRequest
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

  async register(data: RegisterRequest): Promise<TokenResponse> {
    const response = await this.client.post<TokenResponse>('/auth/register', data);
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

  async getAuditLogs(orgId: string, limit = 100, offset = 0): Promise<AuditLog[]> {
    const response = await this.client.get<AuditLog[]>(
      `/audit/orgs/${orgId}/logs`,
      { params: { limit, offset } }
    );
    return response.data;
  }
}

export const api = new ApiClient();