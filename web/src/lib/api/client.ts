import type {
	FileEntry,
	LoginRequest,
	LoginResponse,
	AuthStatusResponse,
	ListResponse,
	StatResponse,
	ApiResponse
} from './types';

class GhostFSClient {
	private sessionId: string | null = null;
	private baseUrl: string = '';

	constructor() {
		// Try to restore session from localStorage
		if (typeof window !== 'undefined') {
			this.sessionId = localStorage.getItem('ghostfs_session_id');
		}
	}

	setBaseUrl(url: string) {
		this.baseUrl = url;
	}

	private get headers(): HeadersInit {
		const h: HeadersInit = {
			'Content-Type': 'application/json'
		};
		if (this.sessionId) {
			h['X-Session-Id'] = this.sessionId;
		}
		return h;
	}

	private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
		const url = `${this.baseUrl}${path}`;
		const response = await fetch(url, {
			...options,
			headers: {
				...this.headers,
				...options.headers
			}
		});

		if (!response.ok) {
			const text = await response.text();
			try {
				const json = JSON.parse(text);
				throw new Error(json.error || `HTTP ${response.status}`);
			} catch {
				throw new Error(`HTTP ${response.status}: ${text}`);
			}
		}

		return response.json();
	}

	async login(req: LoginRequest): Promise<LoginResponse> {
		try {
			const response = await this.request<LoginResponse>('/api/auth/login', {
				method: 'POST',
				body: JSON.stringify(req)
			});

			if (response.success && response.sessionId) {
				this.sessionId = response.sessionId;
				if (typeof window !== 'undefined') {
					localStorage.setItem('ghostfs_session_id', response.sessionId);
				}
			}

			return response;
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Login failed'
			};
		}
	}

	async logout(): Promise<void> {
		try {
			await this.request('/api/auth/logout', { method: 'POST' });
		} finally {
			this.sessionId = null;
			if (typeof window !== 'undefined') {
				localStorage.removeItem('ghostfs_session_id');
			}
		}
	}

	async checkAuth(): Promise<AuthStatusResponse> {
		try {
			return await this.request<AuthStatusResponse>('/api/auth/status');
		} catch {
			return { authenticated: false };
		}
	}

	isAuthenticated(): boolean {
		return this.sessionId !== null;
	}

	async listDir(path: string): Promise<FileEntry[]> {
		const response = await this.request<ListResponse>(
			`/api/fs/list?path=${encodeURIComponent(path)}`
		);
		if (!response.success) {
			throw new Error(response.error || 'Failed to list directory');
		}
		return response.entries || [];
	}

	async stat(path: string): Promise<StatResponse> {
		return this.request<StatResponse>(`/api/fs/stat?path=${encodeURIComponent(path)}`);
	}

	async mkdir(path: string): Promise<ApiResponse> {
		return this.request<ApiResponse>('/api/fs/mkdir', {
			method: 'POST',
			body: JSON.stringify({ path })
		});
	}

	async delete(path: string, isDir: boolean): Promise<ApiResponse> {
		return this.request<ApiResponse>('/api/fs/delete', {
			method: 'POST',
			body: JSON.stringify({ path, isDir })
		});
	}

	async rename(oldPath: string, newPath: string): Promise<ApiResponse> {
		return this.request<ApiResponse>('/api/fs/rename', {
			method: 'POST',
			body: JSON.stringify({ oldPath, newPath })
		});
	}

	async copy(srcPath: string, destPath: string): Promise<ApiResponse> {
		return this.request<ApiResponse>('/api/fs/copy', {
			method: 'POST',
			body: JSON.stringify({ srcPath, destPath })
		});
	}

	getDownloadUrl(path: string): string {
		const url = `${this.baseUrl}/api/fs/download?path=${encodeURIComponent(path)}`;
		return url;
	}

	async download(path: string): Promise<Blob> {
		const url = this.getDownloadUrl(path);
		const response = await fetch(url, {
			headers: this.headers
		});

		if (!response.ok) {
			throw new Error(`Download failed: HTTP ${response.status}`);
		}

		return response.blob();
	}

	async upload(
		file: File,
		destPath: string,
		onProgress?: (progress: number) => void
	): Promise<ApiResponse> {
		const formData = new FormData();
		formData.append('file', file);

		const url = `${this.baseUrl}/api/fs/upload?path=${encodeURIComponent(destPath)}`;

		// For progress tracking, we need to use XMLHttpRequest
		if (onProgress) {
			return new Promise((resolve, reject) => {
				const xhr = new XMLHttpRequest();

				xhr.upload.addEventListener('progress', (e) => {
					if (e.lengthComputable) {
						onProgress((e.loaded / e.total) * 100);
					}
				});

				xhr.addEventListener('load', () => {
					if (xhr.status >= 200 && xhr.status < 300) {
						try {
							resolve(JSON.parse(xhr.responseText));
						} catch {
							resolve({ success: true });
						}
					} else {
						reject(new Error(`Upload failed: HTTP ${xhr.status}`));
					}
				});

				xhr.addEventListener('error', () => {
					reject(new Error('Upload failed: Network error'));
				});

				xhr.open('POST', url);
				if (this.sessionId) {
					xhr.setRequestHeader('X-Session-Id', this.sessionId);
				}
				xhr.send(formData);
			});
		}

		// Simple fetch without progress
		const response = await fetch(url, {
			method: 'POST',
			headers: {
				'X-Session-Id': this.sessionId || ''
			},
			body: formData
		});

		return response.json();
	}
}

export const client = new GhostFSClient();
