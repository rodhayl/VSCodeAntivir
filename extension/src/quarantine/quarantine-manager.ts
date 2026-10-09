import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Threat } from '../scanner/models/threat';

export interface QuarantinedFile {
  id: string;
  originalPath: string;
  quarantinePath: string;
  fileName: string;
  detectedAt: string;
  threats: Threat[];
  hash: string;
  size: number;
  canRestore: boolean;
  originalMode?: number;
  state?: 'copied' | 'quarantined';
}

export interface QuarantineManifest {
  version: string;
  files: QuarantinedFile[];
}

export class QuarantineManager {
  private quarantineDir: string;
  private manifestPath: string;
  private outputChannel: vscode.OutputChannel;
  private onChanged: (() => void) | null = null;
  private changeHandlers = new Set<() => void>();
  private lastError: string | undefined;
  private storeError: string | undefined;

  constructor(outputChannel: vscode.OutputChannel, storageDir?: string) {
    this.outputChannel = outputChannel;
    const homeDir = process.env.HOME || process.env.USERPROFILE;
    if (!storageDir && !homeDir) throw new Error('No private quarantine storage directory available');
    this.quarantineDir = path.resolve(storageDir || path.join(homeDir!, '.fakeinterviewguard', 'quarantine'));
    this.manifestPath = path.join(this.quarantineDir, 'manifest.json');
    try {
      this.ensureDirectory(this.quarantineDir);
      fs.chmodSync(this.quarantineDir, 0o700);
      this.loadManifest();
    } catch (error) { this.fail(error); this.storeError = this.lastError; }
  }

  setChangeHandler(handler: () => void): void { this.onChanged = handler; }
  addChangeHandler(handler: () => void): vscode.Disposable {
    this.changeHandlers.add(handler);
    return { dispose: () => { this.changeHandlers.delete(handler); } };
  }
  getLastError(): string | undefined { return this.lastError; }
  getStoreError(): string | undefined { return this.storeError; }

  private log(message: string): void {
    try { this.outputChannel.appendLine(`[QUARANTINE] ${message}`); } catch { /* A disposed observer cannot change transaction outcomes. */ }
  }

  private fail(error: unknown): void {
    this.lastError = error instanceof Error ? error.message : String(error);
    this.log(this.lastError);
  }

  private checkPath(target: string, allowMissing = false): void {
    const resolved = path.resolve(target);
    const parsed = path.parse(resolved);
    let current = parsed.root;
    for (const part of resolved.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      try {
        if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`Refusing symbolic-link path: ${current}`);
      } catch (error) {
        if (allowMissing && (error as NodeJS.ErrnoException).code === 'ENOENT') return;
        throw error;
      }
    }
  }

  private isManagedPath(target: string): boolean {
    const relative = path.relative(this.quarantineDir, target);
    return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
  }

  private syncDirectory(directory: string): void {
    if (process.platform === 'win32') return;
    const fd = fs.openSync(directory, 'r');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }

  private ensureDirectory(directory: string): void {
    this.checkPath(directory, true);
    const firstCreated = fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    this.checkPath(directory);
    if (!firstCreated || process.platform === 'win32') return;
    const normalizedFirstCreated = firstCreated.replace(/^\\\\\?\\/, '');
    const existingParent = path.dirname(normalizedFirstCreated);
    let current = path.resolve(directory);
    while (current !== existingParent) {
      this.syncDirectory(current);
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
    this.syncDirectory(existingParent);
  }

  private readRegularFile(filePath: string, restrictPermissions = false): { content: Buffer; stat: fs.Stats } {
    this.checkPath(filePath);
    if (!fs.lstatSync(filePath).isFile()) throw new Error('Only regular files are supported');
    const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile()) throw new Error('Only regular files are supported');
      if (restrictPermissions) {
        if (stat.nlink !== 1) throw new Error('Captured file has additional hard links; recovery payload retained without changing permissions');
        if (process.platform !== 'win32') {
          fs.fchmodSync(fd, 0o600);
          fs.fsyncSync(fd);
        }
      }
      return { content: fs.readFileSync(fd), stat };
    } finally { fs.closeSync(fd); }
  }

  private payloadPath(entry: QuarantinedFile): string {
    const payload = path.join(this.quarantineDir, entry.id, entry.fileName);
    if (path.resolve(entry.quarantinePath) !== payload) throw new Error('Quarantine entry path is outside its managed location');
    this.checkPath(payload, true);
    return payload;
  }

  private loadManifest(): QuarantineManifest {
    this.checkPath(this.quarantineDir);
    this.checkPath(this.manifestPath, true);
    if (!fs.existsSync(this.manifestPath)) return { version: '1.0', files: [] };
    const manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf8')) as QuarantineManifest;
    if (manifest?.version !== '1.0' || !Array.isArray(manifest.files)) throw new Error('Invalid quarantine manifest; destructive operations are disabled');
    const ids = new Set<string>();
    for (const entry of manifest.files) {
      if (!entry || typeof entry.id !== 'string' || !/^[a-zA-Z0-9-]{1,128}$/.test(entry.id) || ids.has(entry.id) ||
          typeof entry.originalPath !== 'string' || !path.isAbsolute(entry.originalPath) ||
          path.resolve(entry.originalPath) !== entry.originalPath || this.isManagedPath(entry.originalPath) ||
          typeof entry.fileName !== 'string' || !entry.fileName || entry.fileName === '.' || entry.fileName === '..' ||
          path.basename(entry.fileName) !== entry.fileName || path.basename(entry.originalPath) !== entry.fileName || /[\\/]/.test(entry.fileName) ||
          typeof entry.quarantinePath !== 'string' || typeof entry.hash !== 'string' || !/^[a-f0-9]{64}$/.test(entry.hash) ||
          !Number.isSafeInteger(entry.size) || entry.size < 0 || typeof entry.canRestore !== 'boolean' ||
          typeof entry.detectedAt !== 'string' || !Array.isArray(entry.threats) ||
          entry.threats.some(t => !t || typeof t.ruleName !== 'string' || !Number.isInteger(t.severity) || t.severity < 0 || t.severity > 4) ||
          (entry.state !== undefined && entry.state !== 'copied' && entry.state !== 'quarantined') ||
          (entry.originalMode !== undefined && (!Number.isInteger(entry.originalMode) || entry.originalMode < 0 || entry.originalMode > 0o777))) {
        throw new Error('Invalid or duplicate quarantine entry; destructive operations are disabled');
      }
      ids.add(entry.id);
      this.payloadPath(entry);
    }
    return manifest;
  }

  private saveManifest(manifest: QuarantineManifest): void {
    this.checkPath(this.manifestPath, true);
    const temporary = path.join(this.quarantineDir, `manifest-${crypto.randomUUID()}.tmp`);
    let fd: number | undefined;
    try {
      fd = fs.openSync(temporary, 'wx', 0o600);
      fs.writeFileSync(fd, JSON.stringify(manifest, null, 2), 'utf8');
      fs.fsyncSync(fd);
      fs.closeSync(fd); fd = undefined;
      fs.renameSync(temporary, this.manifestPath);
      this.syncDirectory(this.quarantineDir);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
  }

  private transaction<T>(operation: (manifest: QuarantineManifest) => T, failure: T): T {
    const lock = path.join(this.quarantineDir, '.mutation-lock');
    let locked = false;
    try {
      this.checkPath(this.quarantineDir);
      fs.mkdirSync(lock, { mode: 0o700 });
      locked = true;
      const manifest = this.loadManifest();
      this.lastError = undefined;
      return operation(manifest);
    } catch (error) {
      this.fail(!locked && (error as NodeJS.ErrnoException).code === 'EEXIST'
        ? new Error('Quarantine is busy or an interrupted operation needs recovery; no files changed') : error);
      return failure;
    } finally {
      if (locked) {
        try { fs.rmdirSync(lock); } catch (error) { this.log(`Lock cleanup failed; further operations may need recovery: ${String(error)}`); }
        for (const handler of [...this.changeHandlers, ...(this.onChanged ? [this.onChanged] : [])]) {
          try { void Promise.resolve(handler()).catch(error => this.log(`Refresh failed: ${String(error)}`)); }
          catch (error) { this.log(`Refresh failed: ${String(error)}`); }
        }
      }
    }
  }

  private computeHash(content: Buffer): string { return crypto.createHash('sha256').update(content).digest('hex'); }

  async quarantine(filePath: string, threats: Threat[]): Promise<QuarantinedFile | null> {
    return this.transaction(manifest => {
      const originalPath = path.resolve(filePath);
      if (this.isManagedPath(originalPath)) throw new Error('Cannot quarantine the quarantine store itself');
      const { content, stat } = this.readRegularFile(originalPath);
      if (stat.nlink !== 1) throw new Error('Only singly-linked regular files can be quarantined; source retained');
      const hash = this.computeHash(content);
      const id = crypto.randomUUID();
      const fileName = path.basename(originalPath);
      const quarantinePath = path.join(this.quarantineDir, id, fileName);
      fs.mkdirSync(path.dirname(quarantinePath), { mode: 0o700 });
      const fd = fs.openSync(quarantinePath, 'wx', 0o600);
      try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      this.syncDirectory(path.dirname(quarantinePath));
      const entry: QuarantinedFile = {
        id, originalPath, quarantinePath, fileName, detectedAt: new Date().toISOString(),
        threats, hash, size: content.length, canRestore: true, originalMode: stat.mode & 0o777, state: 'copied',
      };
      manifest.files.push(entry);
      // Durable recovery metadata must exist before removing the source.
      this.saveManifest(manifest);
      this.checkPath(originalPath);
      const current = this.readRegularFile(originalPath);
      if (current.stat.dev !== stat.dev || current.stat.ino !== stat.ino ||
          this.computeHash(current.content) !== hash) {
        throw new Error('Source changed while quarantining; original retained and recovery copy recorded');
      }
      // Atomic capture preserves a source replaced after the final check. EXDEV fails closed.
      try { fs.renameSync(originalPath, quarantinePath); } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EXDEV') {
          throw new Error('Source and quarantine store must be on the same filesystem; original retained and recovery copy recorded');
        }
        throw error;
      }
      const captured = this.readRegularFile(quarantinePath, true);
      entry.hash = this.computeHash(captured.content);
      entry.size = captured.content.length;
      entry.originalMode = captured.stat.mode & 0o777;
      this.syncDirectory(path.dirname(quarantinePath));
      this.syncDirectory(path.dirname(originalPath));
      entry.state = 'quarantined';
      this.saveManifest(manifest);
      this.log(`Quarantined: ${originalPath}`);
      return { ...entry };
    }, null);
  }

  async restore(id: string, expected?: QuarantinedFile): Promise<boolean> {
    return this.transaction(manifest => {
      const entry = manifest.files.find(f => f.id === id);
      if (expected && JSON.stringify(entry) !== JSON.stringify(expected)) throw new Error('The selected quarantine entry changed; review it again');
      if (!entry || !entry.canRestore) throw new Error('The selected quarantine entry is missing or cannot be restored');
      const payload = this.payloadPath(entry);
      const { content } = this.readRegularFile(payload);
      if (content.length !== entry.size || this.computeHash(content) !== entry.hash) throw new Error('Quarantine hash mismatch; recovery copy retained');
      this.checkPath(entry.originalPath, true);
      const destinationDirectory = path.dirname(entry.originalPath);
      this.ensureDirectory(destinationDirectory);
      // Stage all bytes before publishing a destination. A failed write cannot leave a partial original.
      const temporary = path.join(destinationDirectory, `.fig-${crypto.randomUUID()}.tmp`);
      let published: fs.Stats;
      try {
        const fd = fs.openSync(temporary, 'wx', 0o600);
        try {
          fs.writeFileSync(fd, content);
          fs.fchmodSync(fd, entry.originalMode ?? 0o600);
          fs.fsyncSync(fd);
        } finally { fs.closeSync(fd); }
        this.checkPath(entry.originalPath, true);
        fs.linkSync(temporary, entry.originalPath);
        published = fs.statSync(temporary);
        this.syncDirectory(destinationDirectory);
      } finally {
        if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
      }
      const verifyDestination = () => {
        const restored = this.readRegularFile(entry.originalPath);
        if (restored.stat.dev !== published.dev || restored.stat.ino !== published.ino ||
            !restored.content.equals(content)) throw new Error('Restored destination changed; recovery payload retained');
      };
      verifyDestination();
      manifest.files = manifest.files.filter(f => f.id !== id);
      this.saveManifest(manifest);
      try { verifyDestination(); } catch (error) {
        manifest.files.push(entry);
        try { this.saveManifest(manifest); } catch {
          throw new Error(`Restored destination changed and metadata recovery failed; preserve the payload at ${payload}`);
        }
        throw error;
      }
      this.checkPath(payload);
      fs.unlinkSync(payload);
      fs.rmdirSync(path.dirname(payload));
      this.log(`Restored: ${entry.originalPath}`);
      return true;
    }, false);
  }

  async deletePermanently(id: string, expected?: QuarantinedFile): Promise<boolean> {
    return this.transaction(manifest => {
      const entry = manifest.files.find(f => f.id === id);
      if (expected && JSON.stringify(entry) !== JSON.stringify(expected)) throw new Error('The selected quarantine entry changed; review it again');
      if (!entry) throw new Error('The selected quarantine entry no longer exists');
      const payload = this.payloadPath(entry);
      if (fs.existsSync(payload)) { this.checkPath(payload); fs.unlinkSync(payload); }
      if (fs.existsSync(path.dirname(payload))) fs.rmdirSync(path.dirname(payload));
      manifest.files = manifest.files.filter(f => f.id !== id);
      this.saveManifest(manifest);
      this.log(`Permanently deleted: ${entry.originalPath}`);
      return true;
    }, false);
  }

  getQuarantinedFiles(): QuarantinedFile[] {
    try {
      const manifest = this.loadManifest();
      this.storeError = undefined;
      return manifest.files.map(entry => ({ ...entry, threats: entry.threats.map(t => ({ ...t })) }));
    } catch (error) { this.fail(error); this.storeError = this.lastError; return []; }
  }
  getById(id: string): QuarantinedFile | undefined { return this.getQuarantinedFiles().find(f => f.id === id); }
  getCount(): number { return this.getQuarantinedFiles().length; }
  isQuarantined(originalPath: string): boolean { return this.getQuarantinedFiles().some(f => f.originalPath === path.resolve(originalPath)); }
  async clearAll(): Promise<number> {
    let count = 0;
    for (const entry of this.getQuarantinedFiles()) if (await this.deletePermanently(entry.id)) count++;
    return count;
  }
}
