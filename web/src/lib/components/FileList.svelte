<script lang="ts">
	import { files, sortedEntries } from '$lib/stores/files';
	import { client } from '$lib/api/client';
	import { formatSize, formatDate, cn } from '$lib/utils';
	import {
		Folder,
		File,
		FileText,
		Image,
		Film,
		Music,
		FileCode,
		FileArchive,
		ChevronUp,
		ChevronDown
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

	function handleSort(column: 'name' | 'size' | 'mtime') {
		files.setSort(column);
	}

	function handleContextMenu(entry: FileEntry, e: MouseEvent) {
		e.preventDefault();
		e.stopPropagation();
		if (!$files.selectedItems.has(entry.name)) {
			files.clearSelection();
			files.toggleSelect(entry.name);
		}
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
	function handleTouchStart(entry: FileEntry) {
		longPressTriggered = false;
		longPressTimer = setTimeout(() => {
			longPressTriggered = true;
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
</script>

<div class="overflow-x-auto" oncontextmenu={handleBackgroundContextMenu} role="application" aria-label="File browser">
	<table class="w-full">
		<thead class="border-b bg-muted/50 text-left text-xs sm:text-sm font-medium">
			<tr>
				<th class="w-8 px-2 sm:px-4 py-2 sm:py-3">
					<input
						type="checkbox"
						class="h-4 w-4 rounded border-input"
						checked={$files.selectedItems.size === $sortedEntries.length && $sortedEntries.length > 0}
						onchange={(e) => {
							if (e.currentTarget.checked) {
								files.selectAll();
							} else {
								files.clearSelection();
							}
						}}
					/>
				</th>
				<th class="px-2 sm:px-4 py-2 sm:py-3">
					<button
						class="flex items-center gap-1 hover:text-foreground"
						onclick={() => handleSort('name')}
					>
						Name
						{#if $files.sortBy === 'name'}
							{#if $files.sortAsc}
								<ChevronUp class="h-4 w-4" />
							{:else}
								<ChevronDown class="h-4 w-4" />
							{/if}
						{/if}
					</button>
				</th>
				<th class="hidden sm:table-cell px-4 py-3 text-right">
					<button
						class="flex items-center gap-1 hover:text-foreground ml-auto"
						onclick={() => handleSort('size')}
					>
						Size
						{#if $files.sortBy === 'size'}
							{#if $files.sortAsc}
								<ChevronUp class="h-4 w-4" />
							{:else}
								<ChevronDown class="h-4 w-4" />
							{/if}
						{/if}
					</button>
				</th>
				<th class="hidden md:table-cell px-4 py-3 text-right">
					<button
						class="flex items-center gap-1 hover:text-foreground ml-auto"
						onclick={() => handleSort('mtime')}
					>
						Modified
						{#if $files.sortBy === 'mtime'}
							{#if $files.sortAsc}
								<ChevronUp class="h-4 w-4" />
							{:else}
								<ChevronDown class="h-4 w-4" />
							{/if}
						{/if}
					</button>
				</th>
			</tr>
		</thead>
		<tbody>
			{#each $sortedEntries as entry (entry.name)}
				{@const Icon = getIcon(entry)}
				{@const isSelected = $files.selectedItems.has(entry.name)}
				{@const isDropTarget = dropTarget === entry.name}

				<tr
					class={cn(
						'border-b cursor-pointer transition-colors touch-manipulation',
						'hover:bg-accent active:bg-accent',
						isSelected && 'bg-primary/10',
						isDropTarget && 'ring-2 ring-green-500 bg-green-500/10'
					)}
					onclick={(e) => handleClick(entry, e)}
					ondblclick={() => handleDoubleClick(entry)}
					oncontextmenu={(e) => handleContextMenu(entry, e)}
					ontouchstart={() => handleTouchStart(entry)}
					ontouchend={handleTouchEnd}
					ontouchmove={handleTouchMove}
					draggable={!isTouchDevice}
					ondragstart={(e) => handleDragStart(entry, e)}
					ondragend={handleDragEnd}
					ondragover={(e) => handleDragOver(entry, e)}
					ondragleave={handleDragLeave}
					ondrop={(e) => handleDrop(entry, e)}
				>
					<td class="px-2 sm:px-4 py-2">
						<input
							type="checkbox"
							class="h-4 w-4 rounded border-input"
							checked={isSelected}
							onclick={(e) => e.stopPropagation()}
							onchange={() => files.toggleSelect(entry.name)}
						/>
					</td>
					<td class="px-2 sm:px-4 py-2">
						<div class="flex items-center gap-2 sm:gap-3">
							<Icon
								class={cn('h-4 w-4 sm:h-5 sm:w-5 flex-shrink-0', entry.isDir ? 'text-primary' : 'text-muted-foreground')}
							/>
							<span class="truncate text-xs sm:text-sm" title={entry.name}>{entry.name}</span>
						</div>
					</td>
					<td class="hidden sm:table-cell px-4 py-2 text-right text-sm text-muted-foreground">
						{entry.isDir ? '--' : formatSize(entry.size)}
					</td>
					<td class="hidden md:table-cell px-4 py-2 text-right text-sm text-muted-foreground">
						{formatDate(entry.mtime)}
					</td>
				</tr>
			{/each}

			{#if $sortedEntries.length === 0 && !$files.loading}
				<tr>
					<td colspan="4" class="px-4 py-16 text-center text-muted-foreground">
						<Folder class="h-12 w-12 mx-auto mb-4 opacity-50" />
						<p>This folder is empty</p>
					</td>
				</tr>
			{/if}
		</tbody>
	</table>
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
