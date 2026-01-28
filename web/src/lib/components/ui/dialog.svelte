<script lang="ts">
	import { cn } from '$lib/utils';
	import type { Snippet } from 'svelte';
	import { X } from 'lucide-svelte';

	interface Props {
		open?: boolean;
		onclose?: () => void;
		title?: string;
		description?: string;
		children?: Snippet;
	}

	let { open = false, onclose, title, description, children }: Props = $props();

	function handleBackdropClick(e: MouseEvent) {
		if (e.target === e.currentTarget) {
			onclose?.();
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			onclose?.();
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/50 p-0 sm:p-4"
		onclick={handleBackdropClick}
	>
		<div
			class={cn(
				'relative w-full sm:max-w-lg rounded-t-2xl sm:rounded-lg border bg-background p-4 sm:p-6 shadow-lg',
				'animate-in fade-in-0 slide-in-from-bottom sm:zoom-in-95',
				'max-h-[90vh] overflow-y-auto'
			)}
			style="padding-bottom: max(1rem, env(safe-area-inset-bottom));"
		>
			<button
				class="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
				onclick={onclose}
			>
				<X class="h-4 w-4" />
				<span class="sr-only">Close</span>
			</button>

			{#if title}
				<h2 class="text-lg font-semibold leading-none tracking-tight">{title}</h2>
			{/if}

			{#if description}
				<p class="mt-2 text-sm text-muted-foreground">{description}</p>
			{/if}

			<div class="mt-4">
				{#if children}
					{@render children()}
				{/if}
			</div>
		</div>
	</div>
{/if}
