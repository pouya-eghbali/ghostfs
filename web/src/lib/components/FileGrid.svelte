<script lang="ts">
	import { files, sortedEntries } from '$lib/stores/files';
	import { client } from '$lib/api/client';
	import { formatSize, cn } from '$lib/utils';
	import {
		Folder,
		File,
		FileText,
		Image,
		Film,
		Music,
		FileCode,
		FileArchive
	} from 'lucide-svelte';
	import type { FileEntry } from '$lib/api/types';
	import ContextMenu from './ContextMenu.svelte';
	import BottomSheet from './BottomSheet.svelte';

	interface Props {
		onRename?: (entry: FileEntry) => void;
		onDelete?: () => void;
	}

	let { onRename, onDelete }: Props = $props();

	// Context menu state (desktop)
	let contextMenu = $state<{ x: number; y: number; entry: FileEntry | null } | null>(null);

	// Bottom sheet state (mobile)
	let bottomSheet = $state<{ open: boolean; entry: FileEntry | null }>({ open: false, entry: null });

	// Long press state
	let longPressTimer = $state<ReturnType<typeof setTimeout> | null>(null);
	let longPressTriggered = $state(false);

	// Drag state
	let draggedEntry = $state<FileEntry | null>(null);
	let dropTarget = $state<string | null>(null);

	// Detect touch device
	let isTouchDevice = $derived(
		typeof window !== 'undefined' && ('ontouchstart' in window || navigator.maxTouchPoints > 0)
	);

	function getIcon(entry: FileEntry) {
		if (entry.isDir) return Folder;

		const ext = entry.name.split('.').pop()?.toLowerCase() || '';
		const iconMap: Record<string, typeof File> = {
			jpg: Image, jpeg: Image, png: Image, gif: Image, svg: Image, webp: Image,
			mp4: Film, avi: Film, mkv: Film, mov: Film, webm: Film,
			mp3: Music, wav: Music, flac: Music, ogg: Music,
			pdf: FileText, doc: FileText, docx: FileText, txt: FileText, md: FileText,
			js: FileCode, ts: FileCode, jsx: FileCode, tsx: FileCode, py: FileCode,
			go: FileCode, rs: FileCode, cpp: FileCode, c: FileCode, h: FileCode, java: FileCode,
			zip: FileArchive, tar: FileArchive, gz: FileArchive, rar: FileArchive
		};

		return iconMap[ext] || File;
	}

	function handleClick(entry: FileEntry, e: MouseEvent) {
		if (longPressTriggered) {
			longPressTriggered = false;
			return;
		}
		if (e.ctrlKey || e.metaKey) {
			files.toggleSelect(entry.name);
		} else {
			files.clearSelection();
			files.toggleSelect(entry.name);
		}
	}

	async function handleDoubleClick(entry: FileEntry) {
		if (entry.isDir) {
			const currentPath = $files.currentPath;
			const newPath = currentPath === '/' ? `/${entry.name}` : `${currentPath}/${entry.name}`;
			files.loadDirectory(newPath);
		} else {
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
		}
	}

	function handleContextMenu(entry: FileEntry, e: MouseEvent) {
		e.preventDefault();
		e.stopPropagation();
		if (!$files.selectedItems.has(entry.name)) {
			files.clearSelection();
			files.toggleSelect(entry.name);
		}
		// On touch devices, context menu is handled by long press
		if (!isTouchDevice) {
			contextMenu = { x: e.clientX, y: e.clientY, entry };
		}
	}

	function handleBackgroundContextMenu(e: MouseEvent) {
		e.preventDefault();
		if (!isTouchDevice) {
			files.clearSelection();
			contextMenu = { x: e.clientX, y: e.clientY, entry: null };
		}
	}

	function closeContextMenu() {
		contextMenu = null;
	}

	function closeBottomSheet() {
		bottomSheet = { open: false, entry: null };
	}

	// Long press handlers for mobile
	function handleTouchStart(entry: FileEntry, e: TouchEvent) {
		longPressTriggered = false;
		longPressTimer = setTimeout(() => {
			longPressTriggered = true;
			// Vibrate if supported
			if (navigator.vibrate) {
				navigator.vibrate(50);
			}
			if (!$files.selectedItems.has(entry.name)) {
				files.clearSelection();
				files.toggleSelect(entry.name);
			}
			bottomSheet = { open: true, entry };
		}, 500);
	}

	function handleTouchEnd() {
		if (longPressTimer) {
			clearTimeout(longPressTimer);
			longPressTimer = null;
		}
	}

	function handleTouchMove() {
		if (longPressTimer) {
			clearTimeout(longPressTimer);
			longPressTimer = null;
		}
	}

	function handleBackgroundTouchStart(e: TouchEvent) {
		longPressTriggered = false;
		longPressTimer = setTimeout(() => {
			longPressTriggered = true;
			if (navigator.vibrate) {
				navigator.vibrate(50);
			}
			files.clearSelection();
			bottomSheet = { open: true, entry: null };
		}, 500);
	}

	// Drag and drop handlers
	function handleDragStart(entry: FileEntry, e: DragEvent) {
		draggedEntry = entry;
		if (e.dataTransfer) {
			e.dataTransfer.effectAllowed = 'move';
			e.dataTransfer.setData('text/plain', entry.name);
		}
		if (!$files.selectedItems.has(entry.name)) {
			files.clearSelection();
			files.toggleSelect(entry.name);
		}
	}

	function handleDragEnd() {
		draggedEntry = null;
		dropTarget = null;
	}

	function handleDragOver(entry: FileEntry, e: DragEvent) {
		if (!entry.isDir || entry.name === draggedEntry?.name) return;
		e.preventDefault();
		if (e.dataTransfer) {
			e.dataTransfer.dropEffect = 'move';
		}
		dropTarget = entry.name;
	}

	function handleDragLeave() {
		dropTarget = null;
	}

	async function handleDrop(targetEntry: FileEntry, e: DragEvent) {
		e.preventDefault();
		dropTarget = null;

		if (!targetEntry.isDir || !draggedEntry) return;

		const currentPath = $files.currentPath;
		const targetPath =
			currentPath === '/'
				? `/${targetEntry.name}`
				: `${currentPath}/${targetEntry.name}`;

		for (const name of $files.selectedItems) {
			const oldPath = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
			const newPath = `${targetPath}/${name}`;
			try {
				await client.rename(oldPath, newPath);
			} catch (err) {
				console.error(`Failed to move ${name}:`, err);
			}
		}

		draggedEntry = null;
		await files.refresh();
	}

	function handleKeydown(entry: FileEntry, e: KeyboardEvent) {
		if (e.key === 'Enter') {
			handleDoubleClick(entry);
		} else if (e.key === 'F2') {
			onRename?.(entry);
		} else if (e.key === 'Delete') {
			if ($files.selectedItems.has(entry.name)) {
				files.deleteSelected();
			}
		}
	}
</script>

<div
	class="grid grid-cols-3 gap-2 p-2 sm:grid-cols-4 sm:gap-4 sm:p-4 md:grid-cols-5 lg:grid-cols-6 xl:grid-cols-8"
	oncontextmenu={handleBackgroundContextMenu}
	ontouchstart={handleBackgroundTouchStart}
	ontouchend={handleTouchEnd}
	ontouchmove={handleTouchMove}
	role="grid"
	aria-label="File browser"
	tabindex="-1"
>
	{#each $sortedEntries as entry (entry.name)}
		{@const Icon = getIcon(entry)}
		{@const isSelected = $files.selectedItems.has(entry.name)}
		{@const isDropTarget = dropTarget === entry.name}

		<div
			class={cn(
				'group flex cursor-pointer flex-col items-center rounded-lg p-2 sm:p-3 transition-colors touch-manipulation',
				'hover:bg-accent active:bg-accent',
				isSelected && 'bg-primary/10 ring-2 ring-primary',
				isDropTarget && 'ring-2 ring-green-500 bg-green-500/10'
			)}
			onclick={(e) => handleClick(entry, e)}
			ondblclick={() => handleDoubleClick(entry)}
			oncontextmenu={(e) => handleContextMenu(entry, e)}
			onkeydown={(e) => handleKeydown(entry, e)}
			ontouchstart={(e) => { e.stopPropagation(); handleTouchStart(entry, e); }}
			ontouchend={handleTouchEnd}
			ontouchmove={handleTouchMove}
			draggable={!isTouchDevice}
			ondragstart={(e) => handleDragStart(entry, e)}
			ondragend={handleDragEnd}
			ondragover={(e) => handleDragOver(entry, e)}
			ondragleave={handleDragLeave}
			ondrop={(e) => handleDrop(entry, e)}
			tabindex="0"
			role="button"
		>
			<div
				class={cn(
					'flex h-12 w-12 sm:h-16 sm:w-16 items-center justify-center rounded-lg',
					entry.isDir ? 'text-primary' : 'text-muted-foreground'
				)}
			>
				<Icon class="h-10 w-10 sm:h-12 sm:w-12" />
			</div>
			<span
				class="mt-1 sm:mt-2 w-full truncate text-center text-xs sm:text-sm"
				title={entry.name}
			>
				{entry.name}
			</span>
			{#if !entry.isDir}
				<span class="text-[10px] sm:text-xs text-muted-foreground">{formatSize(entry.size)}</span>
			{/if}
		</div>
	{/each}

	{#if $sortedEntries.length === 0 && !$files.loading}
		<div class="col-span-full flex flex-col items-center justify-center py-16 text-muted-foreground">
			<Folder class="h-16 w-16 mb-4 opacity-50" />
			<p>This folder is empty</p>
		</div>
	{/if}
</div>

{#if contextMenu}
	<ContextMenu
		x={contextMenu.x}
		y={contextMenu.y}
		entry={contextMenu.entry}
		onClose={closeContextMenu}
		{onRename}
		{onDelete}
	/>
{/if}

<BottomSheet
	open={bottomSheet.open}
	entry={bottomSheet.entry}
	onClose={closeBottomSheet}
	{onRename}
	{onDelete}
/>
