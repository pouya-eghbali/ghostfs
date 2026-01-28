<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { auth, isCheckingAuth } from '$lib/stores/auth';
	import type { Snippet } from 'svelte';
	import { Ghost } from 'lucide-svelte';

	interface Props {
		children?: Snippet;
	}

	let { children }: Props = $props();

	onMount(() => {
		auth.init();
	});
</script>

{#if $isCheckingAuth}
	<div class="flex min-h-screen items-center justify-center bg-background">
		<div class="flex flex-col items-center">
			<Ghost class="h-12 w-12 animate-pulse text-primary" />
			<p class="mt-4 text-muted-foreground">Loading...</p>
		</div>
	</div>
{:else if children}
	{@render children()}
{/if}
