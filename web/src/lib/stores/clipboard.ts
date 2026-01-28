import { writable, get } from 'svelte/store';
import { client } from '$lib/api/client';
import { files } from './files';
import type { FileEntry } from '$lib/api/types';

interface ClipboardItem {
	name: string;
	isDir: boolean;
	sourcePath: string; // Full path to the item
}

interface ClipboardState {
	items: ClipboardItem[];
	operation: 'cut' | 'copy' | null;
}

function createClipboardStore() {
	const { subscribe, set } = writable<ClipboardState>({
		items: [],
		operation: null
	});

	return {
		subscribe,

		cut(entries: FileEntry[], currentPath: string) {
			const items = entries.map((e) => ({
				name: e.name,
				isDir: e.isDir,
				sourcePath: currentPath === '/' ? `/${e.name}` : `${currentPath}/${e.name}`
			}));
			set({ items, operation: 'cut' });
		},

		copy(entries: FileEntry[], currentPath: string) {
			const items = entries.map((e) => ({
				name: e.name,
				isDir: e.isDir,
				sourcePath: currentPath === '/' ? `/${e.name}` : `${currentPath}/${e.name}`
			}));
			set({ items, operation: 'copy' });
		},

		clear() {
			set({ items: [], operation: null });
		},

		async paste(destPath: string): Promise<{ success: boolean; error?: string }> {
			const state = get({ subscribe });
			if (!state.items.length || !state.operation) {
				return { success: false, error: 'Nothing to paste' };
			}

			try {
				for (const item of state.items) {
					const destFullPath =
						destPath === '/' ? `/${item.name}` : `${destPath}/${item.name}`;

					if (state.operation === 'cut') {
						// Move = rename
						await client.rename(item.sourcePath, destFullPath);
					} else {
						// Copy
						await client.copy(item.sourcePath, destFullPath);
					}
				}

				// Clear clipboard after cut (not after copy)
				if (state.operation === 'cut') {
					set({ items: [], operation: null });
				}

				// Refresh the file list
				await files.refresh();

				return { success: true };
			} catch (err) {
				return {
					success: false,
					error: err instanceof Error ? err.message : 'Paste failed'
				};
			}
		},

		hasItems(): boolean {
			return get({ subscribe }).items.length > 0;
		}
	};
}

export const clipboard = createClipboardStore();
