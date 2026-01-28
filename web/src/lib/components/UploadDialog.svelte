<script lang="ts">
	import { files } from '$lib/stores/files';
	import { client } from '$lib/api/client';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import { Upload, X, Check, AlertCircle, File } from 'lucide-svelte';
	import { formatSize } from '$lib/utils';

	interface Props {
		open?: boolean;
		initialUploadFiles?: File[];
	}

	let { open = $bindable(false), initialUploadFiles = [] }: Props = $props();

	let processedInitialFiles = $state(false);

	// When dialog opens with initial files, add them (only once)
	$effect(() => {
		if (open && initialUploadFiles.length > 0 && !processedInitialFiles) {
			processedInitialFiles = true;
			// Use setTimeout to avoid state update during render
			setTimeout(() => addFiles(initialUploadFiles), 0);
		}
		if (!open) {
			processedInitialFiles = false;
		}
	});

	interface UploadItem {
		file: File;
		progress: number;
		status: 'pending' | 'uploading' | 'success' | 'error';
		error?: string;
	}

	let uploadItems = $state<UploadItem[]>([]);
	let fileInput: HTMLInputElement;
	let uploading = $state(false);

	function handleClose() {
		if (!uploading) {
			open = false;
			uploadItems = [];
		}
	}

	function handleFileSelect(e: Event) {
		const input = e.target as HTMLInputElement;
		const selectedFiles = Array.from(input.files || []);
		addFiles(selectedFiles);
	}

	function addFiles(newFiles: File[]) {
		const items: UploadItem[] = newFiles.map((file) => ({
			file,
			progress: 0,
			status: 'pending'
		}));
		uploadItems = [...uploadItems, ...items];
	}

	function removeItem(index: number) {
		uploadItems = uploadItems.filter((_, i) => i !== index);
	}

	async function startUpload() {
		uploading = true;

		for (let i = 0; i < uploadItems.length; i++) {
			const item = uploadItems[i];
			if (item.status !== 'pending') continue;

			uploadItems[i] = { ...item, status: 'uploading' };

			try {
				await client.upload(item.file, $files.currentPath, (progress) => {
					uploadItems[i] = { ...uploadItems[i], progress };
				});
				uploadItems[i] = { ...uploadItems[i], status: 'success', progress: 100 };
			} catch (err) {
				uploadItems[i] = {
					...uploadItems[i],
					status: 'error',
					error: err instanceof Error ? err.message : 'Upload failed'
				};
			}
		}

		uploading = false;
		await files.refresh();

		// Auto-close if all uploads succeeded
		const allSuccess = uploadItems.every((item) => item.status === 'success');
		if (allSuccess) {
			setTimeout(() => {
				open = false;
				uploadItems = [];
			}, 1000);
		}
	}

	function handleDrop(e: DragEvent) {
		e.preventDefault();
		const droppedFiles = Array.from(e.dataTransfer?.files || []);
		addFiles(droppedFiles);
	}

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
	}
</script>

<Dialog {open} onclose={handleClose} title="Upload Files">
	{#snippet children()}
		<div class="space-y-4">
			<!-- Drop zone -->
			<div
				class="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-muted-foreground/25 p-8 transition-colors hover:border-primary/50"
				ondrop={handleDrop}
				ondragover={handleDragOver}
				role="button"
				tabindex="0"
				onclick={() => fileInput?.click()}
				onkeydown={(e) => e.key === 'Enter' && fileInput?.click()}
			>
				<Upload class="h-8 w-8 text-muted-foreground" />
				<p class="mt-2 text-sm text-muted-foreground">
					Drag and drop files here, or click to browse
				</p>
			</div>

			<input
				type="file"
				multiple
				class="hidden"
				bind:this={fileInput}
				onchange={handleFileSelect}
			/>

			<!-- File list -->
			{#if uploadItems.length > 0}
				<div class="max-h-60 space-y-2 overflow-y-auto">
					{#each uploadItems as item, i (i)}
						<div class="flex items-center gap-3 rounded-lg border p-3">
							<File class="h-5 w-5 text-muted-foreground" />
							<div class="min-w-0 flex-1">
								<p class="truncate text-sm font-medium">{item.file.name}</p>
								<p class="text-xs text-muted-foreground">{formatSize(item.file.size)}</p>
								{#if item.status === 'uploading'}
									<div class="mt-1 h-1 overflow-hidden rounded-full bg-muted">
										<div
											class="h-full bg-primary transition-all"
											style="width: {item.progress}%"
										></div>
									</div>
								{/if}
								{#if item.status === 'error'}
									<p class="mt-1 text-xs text-destructive">{item.error}</p>
								{/if}
							</div>
							<div class="flex-shrink-0">
								{#if item.status === 'pending'}
									<button
										class="text-muted-foreground hover:text-foreground"
										onclick={() => removeItem(i)}
									>
										<X class="h-4 w-4" />
									</button>
								{:else if item.status === 'uploading'}
									<span class="text-xs text-muted-foreground">{Math.round(item.progress)}%</span>
								{:else if item.status === 'success'}
									<Check class="h-4 w-4 text-green-500" />
								{:else if item.status === 'error'}
									<AlertCircle class="h-4 w-4 text-destructive" />
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}

			<!-- Actions -->
			<div class="flex justify-end gap-2">
				<Button variant="outline" onclick={handleClose} disabled={uploading}>
					{#snippet children()}
						Cancel
					{/snippet}
				</Button>
				<Button
					onclick={startUpload}
					disabled={uploading || uploadItems.length === 0 || uploadItems.every((i) => i.status !== 'pending')}
				>
					{#snippet children()}
						{#if uploading}
							<span class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
							Uploading...
						{:else}
							Upload {uploadItems.filter((i) => i.status === 'pending').length} file(s)
						{/if}
					{/snippet}
				</Button>
			</div>
		</div>
	{/snippet}
</Dialog>
