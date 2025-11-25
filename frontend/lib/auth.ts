const TOKEN_KEY = 'saasready_token';
const INVITATION_TOKEN_KEY = 'saasready_invitation_token';

export const authStorage = {
  getToken: (): string | null => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(TOKEN_KEY);
  },

  setToken: (token: string): void => {
    if (typeof window === 'undefined') return;
    localStorage.setItem(TOKEN_KEY, token);
  },

  removeToken: (): void => {
    if (typeof window === 'undefined') return;
    localStorage.removeItem(TOKEN_KEY);
  },

  isAuthenticated: (): boolean => {
    return !!authStorage.getToken();
  },

  // Invitation token methods
  getInvitationToken: (): string | null => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(INVITATION_TOKEN_KEY);
  },

  setInvitationToken: (token: string): void => {
    if (typeof window === 'undefined') return;
    localStorage.setItem(INVITATION_TOKEN_KEY, token);
  },

  removeInvitationToken: (): void => {
    if (typeof window === 'undefined') return;
    localStorage.removeItem(INVITATION_TOKEN_KEY);
  }
};