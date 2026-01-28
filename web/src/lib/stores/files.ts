import { writable, derived } from 'svelte/store';
import { client } from '$lib/api/client';
import type { FileEntry } from '$lib/api/types';

interface FilesState {
	currentPath: string;
	entries: FileEntry[];
	loading: boolean;
	error: string | null;
	selectedItems: Set<string>;
	viewMode: 'grid' | 'list';
	sortBy: 'name' | 'size' | 'mtime';
	sortAsc: boolean;
}

function createFilesStore() {
	const { subscribe, set, update } = writable<FilesState>({
		currentPath: '/',
		entries: [],
		loading: false,
		error: null,
		selectedItems: new Set(),
		viewMode: 'grid',
		sortBy: 'name',
		sortAsc: true
	});

	return {
		subscribe,

		async loadDirectory(path: string, updateUrl = true) {
			update((s) => ({ ...s, loading: true, error: null, selectedItems: new Set() }));
			try {
				const entries = await client.listDir(path);
				update((s) => ({
					...s,
					currentPath: path,
					entries,
					loading: false
				}));
				// Update URL to reflect current path
				if (updateUrl && typeof window !== 'undefined') {
					const url = path === '/' ? '/' : `/browse${path}`;
					window.history.pushState({}, '', url);
				}
			} catch (err) {
				update((s) => ({
					...s,
					loading: false,
					error: err instanceof Error ? err.message : 'Failed to load directory'
				}));
			}
		},

		async refresh() {
			let path = '/';
			const unsub = subscribe((s) => {
				path = s.currentPath;
			});
			unsub();
			await this.loadDirectory(path);
		},

		toggleSelect(name: string) {
			update((s) => {
				const newSelected = new Set(s.selectedItems);
				if (newSelected.has(name)) {
					newSelected.delete(name);
				} else {
					newSelected.add(name);
				}
				return { ...s, selectedItems: newSelected };
			});
		},

		selectAll() {
			update((s) => ({
				...s,
				selectedItems: new Set(s.entries.map((e) => e.name))
			}));
		},

		clearSelection() {
			update((s) => ({ ...s, selectedItems: new Set() }));
		},

		setViewMode(mode: 'grid' | 'list') {
			update((s) => ({ ...s, viewMode: mode }));
			if (typeof window !== 'undefined') {
				localStorage.setItem('ghostfs_view_mode', mode);
			}
		},

		setSort(sortBy: 'name' | 'size' | 'mtime', sortAsc?: boolean) {
			update((s) => ({
				...s,
				sortBy,
				sortAsc: sortAsc !== undefined ? sortAsc : sortBy === s.sortBy ? !s.sortAsc : true
			}));
		},

		async createFolder(name: string) {
			let path = '/';
			const unsub = subscribe((s) => {
				path = s.currentPath;
			});
			unsub();

			const newPath = path === '/' ? `/${name}` : `${path}/${name}`;
			const response = await client.mkdir(newPath);
			if (response.success) {
				await this.refresh();
			}
			return response;
		},

		async deleteSelected() {
			let state: FilesState = {
				currentPath: '/',
				entries: [],
				loading: false,
				error: null,
				selectedItems: new Set(),
				viewMode: 'grid',
				sortBy: 'name',
				sortAsc: true
			};
			const unsub = subscribe((s) => {
				state = s;
			});
			unsub();

			const { currentPath, selectedItems, entries } = state;

			for (const name of selectedItems) {
				const entry = entries.find((e) => e.name === name);
				if (entry) {
					const fullPath = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
					await client.delete(fullPath, entry.isDir);
				}
			}

			await this.refresh();
		},

		async renameItem(oldName: string, newName: string) {
			let path = '/';
			const unsub = subscribe((s) => {
				path = s.currentPath;
			});
			unsub();

			const oldPath = path === '/' ? `/${oldName}` : `${path}/${oldName}`;
			const newPath = path === '/' ? `/${newName}` : `${path}/${newName}`;

			const response = await client.rename(oldPath, newPath);
			if (response.success) {
				await this.refresh();
			}
			return response;
		},

		initViewMode() {
			if (typeof window !== 'undefined') {
				const saved = localStorage.getItem('ghostfs_view_mode');
				if (saved === 'grid' || saved === 'list') {
					update((s) => ({ ...s, viewMode: saved }));
				}
			}
		}
	};
}

export const files = createFilesStore();

// Derived stores
export const sortedEntries = derived(files, ($files) => {
	const { entries, sortBy, sortAsc } = $files;
	const sorted = [...entries].sort((a, b) => {
		// Directories always first
		if (a.isDir !== b.isDir) {
			return a.isDir ? -1 : 1;
		}

		let cmp = 0;
		switch (sortBy) {
			case 'name':
				cmp = a.name.localeCompare(b.name);
				break;
			case 'size':
				cmp = a.size - b.size;
				break;
			case 'mtime':
				cmp = a.mtime - b.mtime;
				break;
		}
		return sortAsc ? cmp : -cmp;
	});
	return sorted;
});

export const breadcrumbs = derived(files, ($files) => {
	const parts = $files.currentPath.split('/').filter(Boolean);
	const crumbs: { name: string; path: string }[] = [{ name: 'Home', path: '/' }];

	let currentPath = '';
	for (const part of parts) {
		currentPath += '/' + part;
		crumbs.push({ name: part, path: currentPath });
	}

	return crumbs;
});
