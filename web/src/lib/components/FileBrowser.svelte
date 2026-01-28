<script lang="ts">
	import { onMount } from 'svelte';
	import { files, sortedEntries } from '$lib/stores/files';
	import { client } from '$lib/api/client';
	import { clipboard } from '$lib/stores/clipboard';
	import Toolbar from './Toolbar.svelte';
	import Breadcrumbs from './Breadcrumbs.svelte';
	import FileGrid from './FileGrid.svelte';
	import FileList from './FileList.svelte';
	import UploadDialog from './UploadDialog.svelte';
	import NewFolderDialog from './NewFolderDialog.svelte';
	import DeleteDialog from './DeleteDialog.svelte';
	import RenameDialog from './RenameDialog.svelte';
	import DropZone from './DropZone.svelte';
	import type { FileEntry } from '$lib/api/types';
	import { Loader2 } from 'lucide-svelte';

	let uploadDialogOpen = $state(false);
	let newFolderDialogOpen = $state(false);
	let deleteDialogOpen = $state(false);
	let renameDialogOpen = $state(false);
	let renameEntry = $state<FileEntry | null>(null);
	let initialUploadFiles = $state<File[]>([]);

	onMount(() => {
		files.initViewMode();

		// Get initial path from URL
		const pathname = window.location.pathname;
		let initialPath = '/';
		if (pathname.startsWith('/browse/')) {
			initialPath = pathname.slice(7); // Remove '/browse' prefix
		} else if (pathname.startsWith('/browse')) {
			initialPath = pathname.slice(7) || '/';
		}

		files.loadDirectory(initialPath, false); // Don't update URL on initial load

		// Handle browser back/forward
		const handlePopState = () => {
			const pathname = window.location.pathname;
			let path = '/';
			if (pathname.startsWith('/browse/')) {
				path = pathname.slice(7);
			} else if (pathname.startsWith('/browse')) {
				path = pathname.slice(7) || '/';
			}
			files.loadDirectory(path, false);
		};

		window.addEventListener('popstate', handlePopState);
		return () => window.removeEventListener('popstate', handlePopState);
	});

	function handleKeydown(e: KeyboardEvent) {
		// Ignore if typing in an input
		if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
			return;
		}

		const isMod = e.ctrlKey || e.metaKey;

		if (isMod && e.key === 'x') {
			// Cut
			e.preventDefault();
			const selected = $sortedEntries.filter((entry) => $files.selectedItems.has(entry.name));
			if (selected.length > 0) {
				clipboard.cut(selected, $files.currentPath);
			}
		} else if (isMod && e.key === 'c') {
			// Copy
			e.preventDefault();
			const selected = $sortedEntries.filter((entry) => $files.selectedItems.has(entry.name));
			if (selected.length > 0) {
				clipboard.copy(selected, $files.currentPath);
			}
		} else if (isMod && e.key === 'v') {
			// Paste
			e.preventDefault();
			clipboard.paste($files.currentPath);
		} else if (e.key === 'Delete' || (isMod && e.key === 'Backspace')) {
			// Delete
			if ($files.selectedItems.size > 0) {
				e.preventDefault();
				handleDelete();
			}
		} else if (isMod && e.key === 'a') {
			// Select all
			e.preventDefault();
			files.selectAll();
		}
	}

	function handleNewFolder() {
		newFolderDialogOpen = true;
	}

	function handleDelete() {
		deleteDialogOpen = true;
	}

	function handleRename(entry: FileEntry) {
		renameEntry = entry;
		renameDialogOpen = true;
	}

	function handleFileDrop(droppedFiles: File[]) {
		initialUploadFiles = droppedFiles;
		uploadDialogOpen = true;
	}

	function handleUpload() {
		initialUploadFiles = [];
		uploadDialogOpen = true;
	}

	async function handleDownload() {
		const currentPath = $files.currentPath;
		const selectedFiles = $sortedEntries.filter(
			(e) => !e.isDir && $files.selectedItems.has(e.name)
		);

		for (const entry of selectedFiles) {
			const filePath = currentPath === '/' ? `/${entry.name}` : `${currentPath}/${entry.name}`;
			try {
				const blob = await client.download(filePath);
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.href = url;
				a.download = entry.name;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			} catch (err) {
				console.error(`Download failed for ${entry.name}:`, err);
			}
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="flex h-full flex-col bg-background">
	<Toolbar
		onUpload={handleUpload}
		onNewFolder={handleNewFolder}
		onDelete={handleDelete}
		onDownload={handleDownload}
	/>

	<div class="border-b px-4 py-2">
		<Breadcrumbs />
	</div>

	<DropZone onDrop={handleFileDrop}>
		<div class="flex-1 overflow-auto">
			{#if $files.loading}
				<div class="flex h-full items-center justify-center">
					<Loader2 class="h-8 w-8 animate-spin text-primary" />
				</div>
			{:else if $files.error}
				<div class="flex h-full flex-col items-center justify-center text-destructive">
					<p class="text-lg font-medium">Error loading directory</p>
					<p class="text-sm">{$files.error}</p>
					<button
						class="mt-4 text-primary hover:underline"
						onclick={() => files.refresh()}
					>
						Try again
					</button>
				</div>
			{:else if $files.viewMode === 'grid'}
				<FileGrid onRename={handleRename} onDelete={handleDelete} />
			{:else}
				<FileList onRename={handleRename} onDelete={handleDelete} />
			{/if}
		</div>
	</DropZone>
</div>

<UploadDialog bind:open={uploadDialogOpen} {initialUploadFiles} />
<NewFolderDialog bind:open={newFolderDialogOpen} />
<DeleteDialog bind:open={deleteDialogOpen} />
<RenameDialog bind:open={renameDialogOpen} entry={renameEntry} />
