<script lang="ts">
	import { files } from '$lib/stores/files';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import { Pencil, AlertCircle } from 'lucide-svelte';
	import type { FileEntry } from '$lib/api/types';

	interface Props {
		open?: boolean;
		entry?: FileEntry | null;
	}

	let { open = $bindable(false), entry }: Props = $props();

	let newName = $state('');
	let loading = $state(false);
	let error = $state('');

	$effect(() => {
		if (open && entry) {
			newName = entry.name;
			error = '';
		}
	});

	function handleClose() {
		if (!loading) {
			open = false;
			newName = '';
			error = '';
		}
	}

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();

		if (!entry) return;

		if (!newName.trim()) {
			error = 'Please enter a name';
			return;
		}

		if (newName.includes('/') || newName.includes('\\')) {
			error = 'Name cannot contain slashes';
			return;
		}

		if (newName === entry.name) {
			handleClose();
			return;
		}

		loading = true;
		error = '';

		const result = await files.renameItem(entry.name, newName.trim());

		loading = false;

		if (result.success) {
			handleClose();
		} else {
			error = result.error || 'Failed to rename';
		}
	}
</script>

<Dialog {open} onclose={handleClose} title="Rename">
	{#snippet children()}
		<form onsubmit={handleSubmit} class="space-y-4">
			{#if error}
				<div class="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
					<AlertCircle class="h-4 w-4" />
					{error}
				</div>
			{/if}

			<div class="space-y-2">
				<label for="newName" class="text-sm font-medium">New name</label>
				<div class="relative">
					<Pencil class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						id="newName"
						type="text"
						placeholder="Enter new name"
						bind:value={newName}
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
							Renaming...
						{:else}
							Rename
						{/if}
					{/snippet}
				</Button>
			</div>
		</form>
	{/snippet}
</Dialog>
