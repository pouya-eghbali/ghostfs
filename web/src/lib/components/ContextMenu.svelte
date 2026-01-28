<script lang="ts">
	import { files, sortedEntries } from '$lib/stores/files';
	import { clipboard } from '$lib/stores/clipboard';
	import { client } from '$lib/api/client';
	import {
		Scissors,
		Copy,
		ClipboardPaste,
		Pencil,
		Trash2,
		Download,
		FolderOpen
	} from 'lucide-svelte';
	import type { FileEntry } from '$lib/api/types';
	import { onMount } from 'svelte';

	interface Props {
		x: number;
		y: number;
		entry: FileEntry | null;
		onClose: () => void;
		onRename?: (entry: FileEntry) => void;
		onDelete?: () => void;
	}

	let { x, y, entry, onClose, onRename, onDelete }: Props = $props();

	let menuRef = $state<HTMLDivElement | null>(null);

	// Adjust position to keep menu on screen
	let menuX = $derived(Math.min(x, window.innerWidth - 200));
	let menuY = $derived(Math.min(y, window.innerHeight - 300));

	onMount(() => {
		// Focus the menu for keyboard navigation
		menuRef?.focus();
	});

	function handleCut() {
		if (entry) {
			clipboard.cut([entry], $files.currentPath);
		} else {
			const selected = $sortedEntries.filter((e) => $files.selectedItems.has(e.name));
			if (selected.length > 0) {
				clipboard.cut(selected, $files.currentPath);
			}
		}
		onClose();
	}

	function handleCopy() {
		if (entry) {
			clipboard.copy([entry], $files.currentPath);
		} else {
			const selected = $sortedEntries.filter((e) => $files.selectedItems.has(e.name));
			if (selected.length > 0) {
				clipboard.copy(selected, $files.currentPath);
			}
		}
		onClose();
	}

	async function handlePaste() {
		await clipboard.paste($files.currentPath);
		onClose();
	}

	function handleRename() {
		if (entry && onRename) {
			onRename(entry);
		}
		onClose();
	}

	function handleDelete() {
		if (onDelete) {
			onDelete();
		}
		onClose();
	}

	async function handleDownload() {
		if (!entry || entry.isDir) {
			onClose();
			return;
		}

		const currentPath = $files.currentPath;
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
			console.error('Download failed:', err);
		}
		onClose();
	}

	function handleOpen() {
		if (!entry) {
			onClose();
			return;
		}

		if (entry.isDir) {
			const currentPath = $files.currentPath;
			const newPath = currentPath === '/' ? `/${entry.name}` : `${currentPath}/${entry.name}`;
			files.loadDirectory(newPath);
		}
		onClose();
	}

	function handleClickOutside() {
		onClose();
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose();
		}
	}

	let hasClipboard = $derived($clipboard.items.length > 0);
</script>

<svelte:window onclick={handleClickOutside} onkeydown={handleKeydown} />

<div
	bind:this={menuRef}
	class="fixed z-50 min-w-[160px] rounded-md border bg-popover p-1 shadow-md"
	style="left: {menuX}px; top: {menuY}px;"
	onclick={(e) => e.stopPropagation()}
	onkeydown={(e) => e.stopPropagation()}
	oncontextmenu={(e) => e.preventDefault()}
	role="menu"
	tabindex="-1"
>
	{#if entry?.isDir}
		<button
			class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
			onclick={handleOpen}
			role="menuitem"
		>
			<FolderOpen class="h-4 w-4" />
			Open
		</button>
		<div class="my-1 h-px bg-border" role="separator"></div>
	{/if}

	{#if entry && !entry.isDir}
		<button
			class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
			onclick={handleDownload}
			role="menuitem"
		>
			<Download class="h-4 w-4" />
			Download
		</button>
		<div class="my-1 h-px bg-border" role="separator"></div>
	{/if}

	<button
		class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
		onclick={handleCut}
		role="menuitem"
	>
		<Scissors class="h-4 w-4" />
		Cut
	</button>

	<button
		class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
		onclick={handleCopy}
		role="menuitem"
	>
		<Copy class="h-4 w-4" />
		Copy
	</button>

	<button
		class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent disabled:opacity-50 disabled:cursor-not-allowed"
		onclick={handlePaste}
		disabled={!hasClipboard}
		role="menuitem"
	>
		<ClipboardPaste class="h-4 w-4" />
		Paste
	</button>

	<div class="my-1 h-px bg-border" role="separator"></div>

	{#if entry}
		<button
			class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
			onclick={handleRename}
			role="menuitem"
		>
			<Pencil class="h-4 w-4" />
			Rename
		</button>
	{/if}

	<button
		class="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-destructive hover:bg-accent"
		onclick={handleDelete}
		role="menuitem"
	>
		<Trash2 class="h-4 w-4" />
		Delete
	</button>
</div>
