<script lang="ts">
	import { files, sortedEntries } from '$lib/stores/files';
	import { auth } from '$lib/stores/auth';
	import { theme } from '$lib/stores/theme';
	import Button from './ui/button.svelte';
	import {
		Upload,
		Download,
		FolderPlus,
		Trash2,
		LayoutGrid,
		List,
		RefreshCw,
		LogOut,
		Ghost,
		Sun,
		Moon,
		Monitor,
		Menu,
		X
	} from 'lucide-svelte';

	interface Props {
		onUpload?: () => void;
		onNewFolder?: () => void;
		onDelete?: () => void;
		onDownload?: () => void;
	}

	let { onUpload, onNewFolder, onDelete, onDownload }: Props = $props();

	let mobileMenuOpen = $state(false);

	// Count selected files (not directories)
	let selectedFileCount = $derived.by(() => {
		let count = 0;
		for (const name of $files.selectedItems) {
			const entry = $sortedEntries.find((e) => e.name === name);
			if (entry && !entry.isDir) {
				count++;
			}
		}
		return count;
	});

	let refreshing = $state(false);

	async function handleRefresh() {
		refreshing = true;
		await files.refresh();
		refreshing = false;
	}

	async function handleLogout() {
		await auth.logout();
	}

	function getThemeIcon() {
		if ($theme === 'light') return Sun;
		if ($theme === 'dark') return Moon;
		return Monitor;
	}

	function getThemeLabel() {
		if ($theme === 'light') return 'Light';
		if ($theme === 'dark') return 'Dark';
		return 'System';
	}
</script>

<!-- Desktop Toolbar -->
<div class="hidden sm:flex items-center justify-between border-b bg-background px-4 py-2">
	<div class="flex items-center gap-2">
		<Ghost class="h-6 w-6 text-primary" />
		<span class="text-lg font-semibold">GhostFS</span>
	</div>

	<div class="flex items-center gap-2">
		<Button variant="outline" size="sm" onclick={onUpload}>
			{#snippet children()}
				<Upload class="mr-2 h-4 w-4" />
				Upload
			{/snippet}
		</Button>

		<Button variant="outline" size="sm" onclick={onNewFolder}>
			{#snippet children()}
				<FolderPlus class="mr-2 h-4 w-4" />
				New Folder
			{/snippet}
		</Button>

		{#if selectedFileCount > 0}
			<Button variant="outline" size="sm" onclick={onDownload}>
				{#snippet children()}
					<Download class="mr-2 h-4 w-4" />
					Download ({selectedFileCount})
				{/snippet}
			</Button>
		{/if}

		{#if $files.selectedItems.size > 0}
			<Button variant="outline" size="sm" onclick={onDelete}>
				{#snippet children()}
					<Trash2 class="mr-2 h-4 w-4" />
					Delete ({$files.selectedItems.size})
				{/snippet}
			</Button>
		{/if}

		<div class="mx-2 h-6 w-px bg-border"></div>

		<Button
			variant="ghost"
			size="icon"
			onclick={handleRefresh}
			disabled={refreshing}
			title="Refresh"
		>
			{#snippet children()}
				<RefreshCw class={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
			{/snippet}
		</Button>

		<Button
			variant="ghost"
			size="icon"
			onclick={() => files.setViewMode('grid')}
			title="Grid view"
			class={$files.viewMode === 'grid' ? 'bg-accent' : ''}
		>
			{#snippet children()}
				<LayoutGrid class="h-4 w-4" />
			{/snippet}
		</Button>

		<Button
			variant="ghost"
			size="icon"
			onclick={() => files.setViewMode('list')}
			title="List view"
			class={$files.viewMode === 'list' ? 'bg-accent' : ''}
		>
			{#snippet children()}
				<List class="h-4 w-4" />
			{/snippet}
		</Button>

		<div class="mx-2 h-6 w-px bg-border"></div>

		<Button
			variant="ghost"
			size="icon"
			onclick={() => theme.toggle()}
			title={getThemeLabel()}
		>
			{#snippet children()}
				{@const Icon = getThemeIcon()}
				<Icon class="h-4 w-4" />
			{/snippet}
		</Button>

		<Button variant="ghost" size="icon" onclick={handleLogout} title="Sign out">
			{#snippet children()}
				<LogOut class="h-4 w-4" />
			{/snippet}
		</Button>
	</div>
</div>

<!-- Mobile Toolbar -->
<div class="sm:hidden border-b bg-background">
	<div class="flex items-center justify-between px-4 py-2">
		<div class="flex items-center gap-2">
			<Ghost class="h-6 w-6 text-primary" />
			<span class="text-lg font-semibold">GhostFS</span>
		</div>

		<div class="flex items-center gap-1">
			<Button
				variant="ghost"
				size="icon"
				onclick={handleRefresh}
				disabled={refreshing}
			>
				{#snippet children()}
					<RefreshCw class={`h-5 w-5 ${refreshing ? 'animate-spin' : ''}`} />
				{/snippet}
			</Button>

			<Button
				variant="ghost"
				size="icon"
				onclick={() => (mobileMenuOpen = !mobileMenuOpen)}
			>
				{#snippet children()}
					{#if mobileMenuOpen}
						<X class="h-5 w-5" />
					{:else}
						<Menu class="h-5 w-5" />
					{/if}
				{/snippet}
			</Button>
		</div>
	</div>

	<!-- Mobile Menu -->
	{#if mobileMenuOpen}
		<div class="border-t bg-background px-4 py-3 space-y-3">
			<!-- Action Buttons -->
			<div class="flex flex-wrap gap-2">
				<Button variant="outline" size="sm" onclick={() => { onUpload?.(); mobileMenuOpen = false; }}>
					{#snippet children()}
						<Upload class="mr-2 h-4 w-4" />
						Upload
					{/snippet}
				</Button>

				<Button variant="outline" size="sm" onclick={() => { onNewFolder?.(); mobileMenuOpen = false; }}>
					{#snippet children()}
						<FolderPlus class="mr-2 h-4 w-4" />
						New Folder
					{/snippet}
				</Button>

				{#if selectedFileCount > 0}
					<Button variant="outline" size="sm" onclick={() => { onDownload?.(); mobileMenuOpen = false; }}>
						{#snippet children()}
							<Download class="mr-2 h-4 w-4" />
							Download ({selectedFileCount})
						{/snippet}
					</Button>
				{/if}

				{#if $files.selectedItems.size > 0}
					<Button variant="outline" size="sm" onclick={() => { onDelete?.(); mobileMenuOpen = false; }}>
						{#snippet children()}
							<Trash2 class="mr-2 h-4 w-4" />
							Delete ({$files.selectedItems.size})
						{/snippet}
					</Button>
				{/if}
			</div>

			<!-- View and Settings -->
			<div class="flex items-center justify-between pt-2 border-t">
				<div class="flex items-center gap-1">
					<span class="text-sm text-muted-foreground mr-2">View:</span>
					<Button
						variant="ghost"
						size="icon"
						onclick={() => files.setViewMode('grid')}
						class={$files.viewMode === 'grid' ? 'bg-accent' : ''}
					>
						{#snippet children()}
							<LayoutGrid class="h-4 w-4" />
						{/snippet}
					</Button>
					<Button
						variant="ghost"
						size="icon"
						onclick={() => files.setViewMode('list')}
						class={$files.viewMode === 'list' ? 'bg-accent' : ''}
					>
						{#snippet children()}
							<List class="h-4 w-4" />
						{/snippet}
					</Button>
				</div>

				<div class="flex items-center gap-1">
					<Button
						variant="ghost"
						size="sm"
						onclick={() => theme.toggle()}
					>
						{#snippet children()}
							{@const Icon = getThemeIcon()}
							<Icon class="mr-2 h-4 w-4" />
							{getThemeLabel()}
						{/snippet}
					</Button>

					<Button variant="ghost" size="icon" onclick={handleLogout}>
						{#snippet children()}
							<LogOut class="h-4 w-4" />
						{/snippet}
					</Button>
				</div>
			</div>
		</div>
	{/if}
</div>
