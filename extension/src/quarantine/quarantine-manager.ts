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
}

export interface QuarantineManifest {
  version: string;
  files: QuarantinedFile[];
}

export class QuarantineManager {
  private quarantineDir: string;
  private manifestPath: string;
  private manifest: QuarantineManifest;
  private outputChannel: vscode.OutputChannel;
  private onChanged: (() => void) | null = null;

  constructor(outputChannel: vscode.OutputChannel, storageDir?: string) {
    this.outputChannel = outputChannel;
    
    const homeDir = process.env.HOME || process.env.USERPROFILE || '';
    this.quarantineDir = storageDir || path.join(homeDir, '.fakeinterviewguard', 'quarantine');
    this.manifestPath = path.join(this.quarantineDir, 'manifest.json');
    
    this.ensureQuarantineDir();
    this.manifest = this.loadManifest();
  }

  setChangeHandler(handler: () => void): void {
    this.onChanged = handler;
  }

  private ensureQuarantineDir(): void {
    if (!fs.existsSync(this.quarantineDir)) {
      fs.mkdirSync(this.quarantineDir, { recursive: true });
    }
  }

  private loadManifest(): QuarantineManifest {
    if (fs.existsSync(this.manifestPath)) {
      try {
        return JSON.parse(fs.readFileSync(this.manifestPath, 'utf-8'));
      } catch {
        this.outputChannel.appendLine('[QUARANTINE] Failed to load manifest, creating new one');
      }
    }
    return { version: '1.0', files: [] };
  }

  private saveManifest(): void {
    fs.writeFileSync(this.manifestPath, JSON.stringify(this.manifest, null, 2), 'utf-8');
    if (this.onChanged) {
      this.onChanged();
    }
  }

  private computeHash(content: Buffer): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  async quarantine(filePath: string, threats: Threat[]): Promise<QuarantinedFile | null> {
    if (!fs.existsSync(filePath)) {
      this.outputChannel.appendLine(`[QUARANTINE] File not found: ${filePath}`);
      return null;
    }

    try {
      const content = fs.readFileSync(filePath);
      const hash = this.computeHash(content);
      const id = `${Date.now()}-${hash.substring(0, 8)}`;
      const fileName = path.basename(filePath);
      const quarantinePath = path.join(this.quarantineDir, id, fileName);

      fs.mkdirSync(path.dirname(quarantinePath), { recursive: true });
      fs.writeFileSync(quarantinePath, content);
      fs.unlinkSync(filePath);

      const entry: QuarantinedFile = {
        id,
        originalPath: filePath,
        quarantinePath,
        fileName,
        detectedAt: new Date().toISOString(),
        threats,
        hash,
        size: content.length,
        canRestore: true,
      };

      this.manifest.files.push(entry);
      this.saveManifest();

      this.outputChannel.appendLine(`[QUARANTINE] Quarantined: ${filePath} -> ${quarantinePath}`);
      return entry;
    } catch (e: any) {
      this.outputChannel.appendLine(`[QUARANTINE] Failed to quarantine ${filePath}: ${e.message}`);
      return null;
    }
  }

  async restore(id: string): Promise<boolean> {
    const entry = this.manifest.files.find(f => f.id === id);
    if (!entry) {
      this.outputChannel.appendLine(`[QUARANTINE] Entry not found: ${id}`);
      return false;
    }

    if (!entry.canRestore) {
      this.outputChannel.appendLine(`[QUARANTINE] File cannot be restored: ${id}`);
      return false;
    }

    try {
      const content = fs.readFileSync(entry.quarantinePath);
      const currentHash = this.computeHash(content);

      if (currentHash !== entry.hash) {
        this.outputChannel.appendLine(`[QUARANTINE] Hash mismatch for ${id}, file may be corrupted`);
        return false;
      }

      const originalDir = path.dirname(entry.originalPath);
      if (!fs.existsSync(originalDir)) {
        fs.mkdirSync(originalDir, { recursive: true });
      }

      fs.writeFileSync(entry.originalPath, content);
      fs.unlinkSync(entry.quarantinePath);

      const entryDir = path.dirname(entry.quarantinePath);
      if (fs.readdirSync(entryDir).length === 0) {
        fs.rmdirSync(entryDir);
      }

      this.manifest.files = this.manifest.files.filter(f => f.id !== id);
      this.saveManifest();

      this.outputChannel.appendLine(`[QUARANTINE] Restored: ${entry.originalPath}`);
      return true;
    } catch (e: unknown) {
      const msg = typeof e === 'object' && e !== null && 'message' in e ? (e as { message: string }).message : String(e);
      this.outputChannel.appendLine(`[QUARANTINE] Failed to restore ${id}: ${msg}`);
      return false;
    }
  }

  async deletePermanently(id: string): Promise<boolean> {
    const entry = this.manifest.files.find(f => f.id === id);
    if (!entry) {
      return false;
    }

    try {
      if (fs.existsSync(entry.quarantinePath)) {
        fs.unlinkSync(entry.quarantinePath);
      }

      const entryDir = path.dirname(entry.quarantinePath);
      if (fs.existsSync(entryDir) && fs.readdirSync(entryDir).length === 0) {
        fs.rmdirSync(entryDir);
      }

      this.manifest.files = this.manifest.files.filter(f => f.id !== id);
      this.saveManifest();

      this.outputChannel.appendLine(`[QUARANTINE] Permanently deleted: ${entry.originalPath}`);
      return true;
    } catch (e: unknown) {
      const msg = typeof e === 'object' && e !== null && 'message' in e ? (e as { message: string }).message : String(e);
      this.outputChannel.appendLine(`[QUARANTINE] Failed to delete ${id}: ${msg}`);
      return false;
    }
  }

  getQuarantinedFiles(): QuarantinedFile[] {
    return [...this.manifest.files];
  }

  getById(id: string): QuarantinedFile | undefined {
    return this.manifest.files.find(f => f.id === id);
  }

  getCount(): number {
    return this.manifest.files.length;
  }

  isQuarantined(originalPath: string): boolean {
    return this.manifest.files.some(f => f.originalPath === originalPath);
  }

  async clearAll(): Promise<number> {
    let count = 0;
    for (const entry of [...this.manifest.files]) {
      if (await this.deletePermanently(entry.id)) {
        count++;
      }
    }
    return count;
  }
}
