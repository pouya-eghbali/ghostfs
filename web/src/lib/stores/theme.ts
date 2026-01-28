import { writable, get } from 'svelte/store';
import { browser } from '$app/environment';

type Theme = 'light' | 'dark' | 'system';

export type { Theme };

function getSystemTheme(): 'light' | 'dark' {
	if (browser) {
		return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
	}
	return 'light';
}

function createThemeStore() {
	const stored = browser ? localStorage.getItem('ghostfs_theme') as Theme | null : null;
	const initial: Theme = stored || 'system';

	const { subscribe, set } = writable<Theme>(initial);

	function applyTheme(theme: Theme) {
		if (!browser) return;

		const resolved = theme === 'system' ? getSystemTheme() : theme;
		document.documentElement.classList.toggle('dark', resolved === 'dark');
	}

	// Apply initial theme
	if (browser) {
		applyTheme(initial);

		// Listen for system theme changes
		window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
			const currentTheme = localStorage.getItem('ghostfs_theme') as Theme | null || 'system';
			if (currentTheme === 'system') {
				applyTheme('system');
			}
		});
	}

	return {
		subscribe,
		set(newTheme: Theme) {
			if (browser) {
				localStorage.setItem('ghostfs_theme', newTheme);
				applyTheme(newTheme);
			}
			set(newTheme);
		},
		toggle() {
			const current = get({ subscribe }) as Theme;

			// Cycle: light -> dark -> system -> light
			const order: Theme[] = ['light', 'dark', 'system'];
			const currentIndex = order.indexOf(current);
			const next = order[(currentIndex + 1) % order.length];
			this.set(next);
		}
	};
}

export const theme = createThemeStore();
