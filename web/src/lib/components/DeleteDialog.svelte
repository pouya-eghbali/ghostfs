<script lang="ts">
	import { files } from '$lib/stores/files';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import { Trash2, AlertTriangle } from 'lucide-svelte';

	interface Props {
		open?: boolean;
	}

	let { open = $bindable(false) }: Props = $props();

	let loading = $state(false);

	let selectedCount = $derived($files.selectedItems.size);
	let selectedNames = $derived(Array.from($files.selectedItems).slice(0, 5));

	function handleClose() {
		if (!loading) {
			open = false;
		}
	}

	async function handleDelete() {
		loading = true;
		await files.deleteSelected();
		loading = false;
		handleClose();
	}
</script>

<Dialog {open} onclose={handleClose} title="Delete Items">
	{#snippet children()}
		<div class="space-y-4">
			<div class="flex items-start gap-3 rounded-lg bg-destructive/10 p-4">
				<AlertTriangle class="h-5 w-5 text-destructive mt-0.5" />
				<div>
					<p class="font-medium text-destructive">
						Are you sure you want to delete {selectedCount} item{selectedCount === 1 ? '' : 's'}?
					</p>
					<p class="mt-1 text-sm text-muted-foreground">
						This action cannot be undone. The following items will be permanently deleted:
					</p>
				</div>
			</div>

			<ul class="max-h-40 overflow-y-auto space-y-1 rounded-lg border p-3">
				{#each selectedNames as name}
					<li class="flex items-center gap-2 text-sm">
						<Trash2 class="h-4 w-4 text-muted-foreground" />
						<span class="truncate">{name}</span>
					</li>
				{/each}
				{#if selectedCount > 5}
					<li class="text-sm text-muted-foreground">
						... and {selectedCount - 5} more
					</li>
				{/if}
			</ul>

			<div class="flex justify-end gap-2">
				<Button variant="outline" onclick={handleClose} disabled={loading}>
					{#snippet children()}
						Cancel
					{/snippet}
				</Button>
				<Button variant="destructive" onclick={handleDelete} disabled={loading}>
					{#snippet children()}
						{#if loading}
							<span class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
							Deleting...
						{:else}
							<Trash2 class="mr-2 h-4 w-4" />
							Delete
						{/if}
					{/snippet}
				</Button>
			</div>
		</div>
	{/snippet}
</Dialog>
