<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Upload } from 'lucide-svelte';

	interface Props {
		onDrop?: (files: File[]) => void;
		children?: Snippet;
	}

	let { onDrop, children }: Props = $props();

	let isDragging = $state(false);
	let dragCounter = $state(0);

	function handleDragEnter(e: DragEvent) {
		e.preventDefault();
		dragCounter++;
		if (e.dataTransfer?.types.includes('Files')) {
			isDragging = true;
		}
	}

	function handleDragLeave(e: DragEvent) {
		e.preventDefault();
		dragCounter--;
		if (dragCounter === 0) {
			isDragging = false;
		}
	}

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
	}

	function handleDrop(e: DragEvent) {
		e.preventDefault();
		isDragging = false;
		dragCounter = 0;

		const files = Array.from(e.dataTransfer?.files || []);
		if (files.length > 0) {
			onDrop?.(files);
		}
	}
</script>

<div
	class="relative h-full"
	ondragenter={handleDragEnter}
	ondragleave={handleDragLeave}
	ondragover={handleDragOver}
	ondrop={handleDrop}
	role="region"
	aria-label="Drop zone"
>
	{#if children}
		{@render children()}
	{/if}

	{#if isDragging}
		<div
			class="absolute inset-0 z-50 flex items-center justify-center bg-primary/10 backdrop-blur-sm"
		>
			<div class="flex flex-col items-center rounded-lg border-2 border-dashed border-primary bg-background p-8">
				<Upload class="h-12 w-12 text-primary" />
				<p class="mt-4 text-lg font-medium">Drop files to upload</p>
				<p class="text-sm text-muted-foreground">Files will be uploaded to the current folder</p>
			</div>
		</div>
	{/if}
</div>
