import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

export function formatSize(bytes: number): string {
	if (bytes === 0) return '0 B';
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function formatDate(timestamp: number): string {
	if (!timestamp) return '';
	const date = new Date(timestamp * 1000);
	return date.toLocaleDateString(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit'
	});
}

export function getFileIcon(name: string, isDir: boolean): string {
	if (isDir) return 'folder';

	const ext = name.split('.').pop()?.toLowerCase() || '';

	const iconMap: Record<string, string> = {
		// Documents
		pdf: 'file-text',
		doc: 'file-text',
		docx: 'file-text',
		txt: 'file-text',
		md: 'file-text',
		rtf: 'file-text',

		// Spreadsheets
		xls: 'file-spreadsheet',
		xlsx: 'file-spreadsheet',
		csv: 'file-spreadsheet',

		// Images
		jpg: 'image',
		jpeg: 'image',
		png: 'image',
		gif: 'image',
		svg: 'image',
		webp: 'image',
		bmp: 'image',
		ico: 'image',

		// Video
		mp4: 'film',
		avi: 'film',
		mkv: 'film',
		mov: 'film',
		webm: 'film',

		// Audio
		mp3: 'music',
		wav: 'music',
		flac: 'music',
		ogg: 'music',
		m4a: 'music',

		// Archives
		zip: 'file-archive',
		tar: 'file-archive',
		gz: 'file-archive',
		rar: 'file-archive',
		'7z': 'file-archive',

		// Code
		js: 'file-code',
		ts: 'file-code',
		jsx: 'file-code',
		tsx: 'file-code',
		py: 'file-code',
		rb: 'file-code',
		go: 'file-code',
		rs: 'file-code',
		java: 'file-code',
		c: 'file-code',
		cpp: 'file-code',
		h: 'file-code',
		hpp: 'file-code',
		css: 'file-code',
		html: 'file-code',
		json: 'file-code',
		xml: 'file-code',
		yaml: 'file-code',
		yml: 'file-code',
		sh: 'file-code',
		bash: 'file-code'
	};

	return iconMap[ext] || 'file';
}
