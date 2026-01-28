import { writable, derived } from 'svelte/store';
import { client } from '$lib/api/client';

interface AuthState {
	authenticated: boolean;
	user: string | null;
	checking: boolean;
}

function createAuthStore() {
	const { subscribe, set, update } = writable<AuthState>({
		authenticated: false,
		user: null,
		checking: true
	});

	return {
		subscribe,

		async init() {
			update((s) => ({ ...s, checking: true }));
			try {
				const status = await client.checkAuth();
				set({
					authenticated: status.authenticated,
					user: status.user || null,
					checking: false
				});
			} catch {
				set({
					authenticated: false,
					user: null,
					checking: false
				});
			}
		},

		async login(user: string, token: string, encryptionKey?: string) {
			const response = await client.login({ user, token, encryptionKey });
			if (response.success) {
				set({
					authenticated: true,
					user,
					checking: false
				});
				return { success: true };
			}
			return { success: false, error: response.error };
		},

		async logout() {
			await client.logout();
			set({
				authenticated: false,
				user: null,
				checking: false
			});
		}
	};
}

export const auth = createAuthStore();
export const isAuthenticated = derived(auth, ($auth) => $auth.authenticated);
export const isCheckingAuth = derived(auth, ($auth) => $auth.checking);
