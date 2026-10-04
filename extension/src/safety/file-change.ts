import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export function regularPath(filePath: string, allowMissing = false): string {
  const target = path.resolve(filePath);
  let current = path.parse(target).root;
  for (const part of target.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) throw new Error('Symbolic-link remediation targets are not supported');
      if (current === target && !stat.isFile()) throw new Error('Remediation requires a regular file');
    } catch (error) {
      if (allowMissing && (error as NodeJS.ErrnoException).code === 'ENOENT' && current === target) return target;
      throw error;
    }
  }
  return target;
}

export function readForReview(filePath: string): string { return fs.readFileSync(regularPath(filePath), 'utf8'); }
function syncDirectory(directory: string): void {
  if (process.platform === 'win32') return;
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function writeExclusive(target: string, content: string, mode: number): void {
  const fd = fs.openSync(target, 'wx', mode);
  try { fs.writeFileSync(fd, content, 'utf8'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function recoverExclusive(capture: string, target: string): void {
  // Never overwrite a file created by a concurrent writer; retain capture on conflict.
  try {
    regularPath(capture); regularPath(target, true);
    fs.linkSync(capture, target);
    syncDirectory(path.dirname(target));
  } catch { /* The captured bytes remain available under their recorded backup name. */ }
}
interface Change { before: string | undefined; after: string; backup?: string; mode: number; device: number; inode: number; modified: number; }
export class FileChange {
  private changes = new Map<string, Change>();

  apply(filePath: string, expected: string | undefined, replacement: string): boolean {
    const target = regularPath(filePath, expected === undefined);
    const currentBytes = fs.existsSync(target) ? fs.readFileSync(target) : undefined;
    const current = currentBytes?.toString('utf8');
    if (currentBytes && !currentBytes.equals(Buffer.from(current!, 'utf8'))) throw new Error('File is not valid UTF-8; remediation refused to preserve the original bytes');
    if (current !== expected) throw new Error('File changed since inspection; inspect again before applying');
    if (replacement === current) return false;
    if (this.changes.has(target)) throw new Error('An earlier change must be restored or reviewed first');
    const mode = expected === undefined ? 0o600 : fs.statSync(target).mode & 0o777;
    const backup = expected === undefined ? undefined : target + '.fig-backup';
    if (backup) {
      regularPath(backup, true); writeExclusive(backup, expected!, 0o600);
      syncDirectory(path.dirname(backup));
    }
    const temporary = path.join(path.dirname(target), `.fig-${crypto.randomUUID()}.tmp`);
    let captured = false;
    try {
      writeExclusive(temporary, replacement, mode);
      regularPath(target, expected === undefined);
      if (backup) {
        // Capture the actual latest source atomically instead of overwriting a racing writer.
        fs.renameSync(target, backup); captured = true;
        regularPath(backup); syncDirectory(path.dirname(backup));
        if (!fs.readFileSync(backup).equals(Buffer.from(expected!, 'utf8'))) throw new Error(`Source changed; latest bytes retained in ${backup}`);
      }
      // Same-directory hard linking publishes the complete replacement without overwriting a new target.
      fs.linkSync(temporary, target);
      syncDirectory(path.dirname(target));
      const written = fs.statSync(target);
      this.changes.set(target, { before: expected, after: replacement, backup, mode, device: written.dev, inode: written.ino, modified: written.mtimeMs });
      return fs.readFileSync(target).equals(Buffer.from(replacement, 'utf8'));
    } catch (error) {
      if (captured && backup) recoverExclusive(backup, target);
      throw error;
    } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }

  restore(filePath: string): boolean {
    const target = regularPath(filePath, true);
    const change = this.changes.get(target);
    if (!change || !fs.existsSync(target) || !fs.readFileSync(target).equals(Buffer.from(change.after, 'utf8'))) return false;
    const current = fs.statSync(target);
    if (current.dev !== change.device || current.ino !== change.inode || current.mtimeMs !== change.modified) return false;
    if (change.before !== undefined && (!change.backup || !fs.readFileSync(regularPath(change.backup)).equals(Buffer.from(change.before, 'utf8')))) return false;
    const capture = path.join(path.dirname(target), `.fig-${crypto.randomUUID()}.undo`);
    const temporary = path.join(path.dirname(target), `.fig-${crypto.randomUUID()}.tmp`);
    let captured = false;
    try {
      if (change.before !== undefined) writeExclusive(temporary, change.before, change.mode);
      regularPath(target);
      fs.renameSync(target, capture); captured = true;
      regularPath(capture); syncDirectory(path.dirname(capture));
      if (!fs.readFileSync(capture).equals(Buffer.from(change.after, 'utf8'))) throw new Error(`File changed; latest bytes retained in ${capture}`);
      if (change.before !== undefined) fs.linkSync(temporary, target);
      syncDirectory(path.dirname(target));
      if (change.before !== undefined) {
        const restored = fs.readFileSync(regularPath(target));
        if (!restored.equals(Buffer.from(change.before, 'utf8')) || !restored.equals(fs.readFileSync(regularPath(change.backup!)))) {
          throw new Error('Restored bytes or backup could not be verified; backup retained');
        }
      }
      // The approved replacement, not an unverified newer file, is now safe to remove.
      fs.unlinkSync(capture); captured = false;
      if (change.backup) fs.unlinkSync(change.backup);
      this.changes.delete(target);
      return true;
    } catch (error) {
      if (captured) recoverExclusive(capture, target);
      throw error;
    } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }
}
