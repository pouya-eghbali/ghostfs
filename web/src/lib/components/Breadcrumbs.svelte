<script lang="ts">
	import { breadcrumbs, files } from '$lib/stores/files';
	import { ChevronRight, Home, MoreHorizontal } from 'lucide-svelte';

	function navigateTo(path: string) {
		files.loadDirectory(path);
	}

	// On mobile, show only home, ellipsis (if needed), and last 2 items
	let mobileCrumbs = $derived.by(() => {
		if ($breadcrumbs.length <= 3) return $breadcrumbs;
		return [
			$breadcrumbs[0],
			{ name: '...', path: '' },
			...$breadcrumbs.slice(-2)
		];
	});
</script>

<!-- Desktop breadcrumbs -->
<nav class="hidden sm:flex items-center space-x-1 text-sm overflow-x-auto">
	{#each $breadcrumbs as crumb, i}
		{#if i > 0}
			<ChevronRight class="h-4 w-4 text-muted-foreground flex-shrink-0" />
		{/if}

		{#if i === $breadcrumbs.length - 1}
			<span class="font-medium text-foreground truncate max-w-[200px]">
				{#if i === 0}
					<Home class="h-4 w-4" />
				{:else}
					{crumb.name}
				{/if}
			</span>
		{:else}
			<button
				class="text-muted-foreground hover:text-foreground truncate max-w-[150px]"
				onclick={() => navigateTo(crumb.path)}
			>
				{#if i === 0}
					<Home class="h-4 w-4" />
				{:else}
					{crumb.name}
				{/if}
			</button>
		{/if}
	{/each}
</nav>

<!-- Mobile breadcrumbs -->
<nav class="flex sm:hidden items-center space-x-1 text-sm overflow-x-auto">
	{#each mobileCrumbs as crumb, i}
		{#if i > 0}
			<ChevronRight class="h-4 w-4 text-muted-foreground flex-shrink-0" />
		{/if}

		{#if crumb.name === '...'}
			<MoreHorizontal class="h-4 w-4 text-muted-foreground" />
		{:else if i === mobileCrumbs.length - 1}
			<span class="font-medium text-foreground truncate max-w-[120px]">
				{#if crumb.path === '/'}
					<Home class="h-4 w-4" />
				{:else}
					{crumb.name}
				{/if}
			</span>
		{:else}
			<button
				class="text-muted-foreground hover:text-foreground"
				onclick={() => navigateTo(crumb.path)}
			>
				{#if crumb.path === '/'}
					<Home class="h-4 w-4" />
				{:else}
					<span class="truncate max-w-[80px] inline-block align-middle">{crumb.name}</span>
				{/if}
			</button>
		{/if}
	{/each}
</nav>
