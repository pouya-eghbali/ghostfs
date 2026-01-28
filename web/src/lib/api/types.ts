export interface FileEntry {
	name: string;
	isDir: boolean;
	size: number;
	mtime: number;
}

export interface FileStat {
	name: string;
	isDir: boolean;
	size: number;
	mode: number;
	mtime: number;
}

export interface LoginRequest {
	user: string;
	token: string;
	encryptionKey?: string;
}

export interface LoginResponse {
	success: boolean;
	sessionId?: string;
	error?: string;
}

export interface AuthStatusResponse {
	authenticated: boolean;
	user?: string;
}

export interface ListResponse {
	success: boolean;
	entries?: FileEntry[];
	error?: string;
}

export interface StatResponse {
	success: boolean;
	stat?: FileStat;
	error?: string;
}

export interface ApiResponse {
	success: boolean;
	error?: string;
}
