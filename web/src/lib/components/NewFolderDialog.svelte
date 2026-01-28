<script lang="ts">
	import { files } from '$lib/stores/files';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import { FolderPlus, AlertCircle } from 'lucide-svelte';

	interface Props {
		open?: boolean;
	}

	let { open = $bindable(false) }: Props = $props();

	let folderName = $state('');
	let loading = $state(false);
	let error = $state('');

	function handleClose() {
		if (!loading) {
			open = false;
			folderName = '';
			error = '';
		}
	}

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();

		if (!folderName.trim()) {
			error = 'Please enter a folder name';
			return;
		}

		// Validate folder name
		if (folderName.includes('/') || folderName.includes('\\')) {
			error = 'Folder name cannot contain slashes';
			return;
		}

		loading = true;
		error = '';

		const result = await files.createFolder(folderName.trim());

		loading = false;

		if (result.success) {
			handleClose();
		} else {
			error = result.error || 'Failed to create folder';
		}
	}
</script>

<Dialog {open} onclose={handleClose} title="New Folder">
	{#snippet children()}
		<form onsubmit={handleSubmit} class="space-y-4">
			{#if error}
				<div class="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
					<AlertCircle class="h-4 w-4" />
					{error}
				</div>
			{/if}

			<div class="space-y-2">
				<label for="folderName" class="text-sm font-medium">Folder name</label>
				<div class="relative">
					<FolderPlus class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						id="folderName"
						type="text"
						placeholder="Enter folder name"
						bind:value={folderName}
						class="pl-10"
						disabled={loading}
						autofocus
					/>
				</div>
			</div>

			<div class="flex justify-end gap-2">
				<Button variant="outline" type="button" onclick={handleClose} disabled={loading}>
					{#snippet children()}
						Cancel
					{/snippet}
				</Button>
				<Button type="submit" disabled={loading}>
					{#snippet children()}
						{#if loading}
							<span class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
							Creating...
						{:else}
							Create Folder
						{/if}
					{/snippet}
				</Button>
			</div>
		</form>
	{/snippet}
</Dialog>
