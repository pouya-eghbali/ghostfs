<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { theme } from '$lib/stores/theme';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Card from './ui/card.svelte';
	import { Ghost, Lock, User, Key, AlertCircle, Sun, Moon, Monitor } from 'lucide-svelte';

	function getThemeIcon() {
		if ($theme === 'light') return Sun;
		if ($theme === 'dark') return Moon;
		return Monitor;
	}

	let user = $state('');
	let token = $state('');
	let encryptionKey = $state('');
	let showEncryption = $state(false);
	let loading = $state(false);
	let error = $state('');

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		if (!user || !token) {
			error = 'Please enter username and token';
			return;
		}

		loading = true;
		error = '';

		const result = await auth.login(user, token, showEncryption ? encryptionKey : undefined);

		loading = false;

		if (!result.success) {
			error = result.error || 'Login failed';
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-gradient-to-br from-background to-muted p-4">
	<!-- Theme toggle -->
	<Button
		variant="ghost"
		size="icon"
		class="absolute top-4 right-4"
		onclick={() => theme.toggle()}
	>
		{#snippet children()}
			{@const Icon = getThemeIcon()}
			<Icon class="h-5 w-5" />
		{/snippet}
	</Button>

	<Card class="w-full max-w-md p-6 sm:p-8">
		<div class="mb-8 flex flex-col items-center">
			<div class="flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary">
				<Ghost class="h-8 w-8" />
			</div>
			<h1 class="mt-4 text-2xl font-bold">GhostFS</h1>
			<p class="mt-1 text-sm text-muted-foreground">Sign in to access your files</p>
		</div>

		<form onsubmit={handleSubmit} class="space-y-4">
			{#if error}
				<div class="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
					<AlertCircle class="h-4 w-4" />
					{error}
				</div>
			{/if}

			<div class="space-y-2">
				<label for="user" class="text-sm font-medium">Username</label>
				<div class="relative">
					<User class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						id="user"
						type="text"
						placeholder="Enter your username"
						bind:value={user}
						class="pl-10"
						disabled={loading}
					/>
				</div>
			</div>

			<div class="space-y-2">
				<label for="token" class="text-sm font-medium">Token</label>
				<div class="relative">
					<Lock class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						id="token"
						type="password"
						placeholder="Enter your token"
						bind:value={token}
						class="pl-10"
						disabled={loading}
					/>
				</div>
			</div>

			<div class="flex items-center gap-2">
				<input
					type="checkbox"
					id="showEncryption"
					bind:checked={showEncryption}
					class="h-4 w-4 rounded border-input"
				/>
				<label for="showEncryption" class="text-sm">Enable client-side encryption</label>
			</div>

			{#if showEncryption}
				<div class="space-y-2">
					<label for="encryptionKey" class="text-sm font-medium">Encryption Key (hex)</label>
					<div class="relative">
						<Key class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
						<Input
							id="encryptionKey"
							type="password"
							placeholder="64 character hex key"
							bind:value={encryptionKey}
							class="pl-10 font-mono text-xs"
							disabled={loading}
						/>
					</div>
					<p class="text-xs text-muted-foreground">
						Enter your 256-bit encryption key in hexadecimal (64 characters)
					</p>
				</div>
			{/if}

			<Button type="submit" class="w-full" disabled={loading}>
				{#snippet children()}
					{#if loading}
						<span class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
						Signing in...
					{:else}
						Sign In
					{/if}
				{/snippet}
			</Button>
		</form>
	</Card>
</div>
