<script lang="ts">
	import { auth, isAuthenticated } from '$lib/stores/auth';
	import { files } from '$lib/stores/files';
	import LoginForm from '$lib/components/LoginForm.svelte';
	import FileBrowser from '$lib/components/FileBrowser.svelte';

	let pageTitle = $derived(
		$isAuthenticated
			? `${$files.currentPath === '/' ? 'Home' : $files.currentPath} - GhostFS`
			: 'GhostFS'
	);
</script>

<svelte:head>
	<title>{pageTitle}</title>
</svelte:head>

{#if $isAuthenticated}
	<div class="h-screen">
		<FileBrowser />
	</div>
{:else}
	<LoginForm />
{/if}
