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
		FolderOpen,
		X
	} from 'lucide-svelte';
	import type { FileEntry } from '$lib/api/types';
	import { cn } from '$lib/utils';

	interface Props {
		open: boolean;
		entry: FileEntry | null;
		onClose: () => void;
		onRename?: (entry: FileEntry) => void;
		onDelete?: () => void;
	}

	let { open, entry, onClose, onRename, onDelete }: Props = $props();

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

	function handleBackdropClick() {
		onClose();
	}

	let hasClipboard = $derived($clipboard.items.length > 0);
</script>

{#if open}
	<!-- Backdrop -->
	<button
		class="fixed inset-0 z-40 bg-black/50 transition-opacity border-0 cursor-default"
		onclick={handleBackdropClick}
		aria-label="Close menu"
	></button>

	<!-- Bottom Sheet -->
	<div
		class={cn(
			'fixed bottom-0 left-0 right-0 z-50 rounded-t-2xl bg-popover p-4 pb-8 shadow-lg',
			'transform transition-transform duration-200 ease-out',
			'safe-area-inset-bottom'
		)}
	>
		<!-- Handle -->
		<div class="mb-4 flex justify-center">
			<div class="h-1 w-12 rounded-full bg-muted-foreground/30"></div>
		</div>

		<!-- Header -->
		<div class="mb-4 flex items-center justify-between">
			<h3 class="text-lg font-semibold">
				{#if entry}
					{entry.name}
				{:else}
					Actions
				{/if}
			</h3>
			<button
				class="rounded-full p-2 hover:bg-accent"
				onclick={onClose}
			>
				<X class="h-5 w-5" />
			</button>
		</div>

		<!-- Actions Grid -->
		<div class="grid grid-cols-4 gap-4">
			{#if entry?.isDir}
				<button
					class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
					onclick={handleOpen}
				>
					<FolderOpen class="h-6 w-6 text-primary" />
					<span class="text-xs">Open</span>
				</button>
			{/if}

			{#if entry && !entry.isDir}
				<button
					class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
					onclick={handleDownload}
				>
					<Download class="h-6 w-6 text-primary" />
					<span class="text-xs">Download</span>
				</button>
			{/if}

			<button
				class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
				onclick={handleCut}
			>
				<Scissors class="h-6 w-6" />
				<span class="text-xs">Cut</span>
			</button>

			<button
				class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
				onclick={handleCopy}
			>
				<Copy class="h-6 w-6" />
				<span class="text-xs">Copy</span>
			</button>

			<button
				class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent disabled:opacity-50"
				onclick={handlePaste}
				disabled={!hasClipboard}
			>
				<ClipboardPaste class="h-6 w-6" />
				<span class="text-xs">Paste</span>
			</button>

			{#if entry}
				<button
					class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
					onclick={handleRename}
				>
					<Pencil class="h-6 w-6" />
					<span class="text-xs">Rename</span>
				</button>
			{/if}

			<button
				class="flex flex-col items-center gap-2 rounded-lg p-3 hover:bg-accent active:bg-accent"
				onclick={handleDelete}
			>
				<Trash2 class="h-6 w-6 text-destructive" />
				<span class="text-xs text-destructive">Delete</span>
			</button>
		</div>
	</div>
{/if}

<style>
	.safe-area-inset-bottom {
		padding-bottom: max(2rem, env(safe-area-inset-bottom));
	}
</style>
