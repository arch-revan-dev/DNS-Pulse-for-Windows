import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';

function addDirToZip(zip: JSZip, fsDir: string, zipPrefix: string) {
  if (!fs.existsSync(fsDir)) return;
  const entries = fs.readdirSync(fsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'bin' || entry.name === 'obj' || entry.name === 'publish') continue;
    const fullPath = path.join(fsDir, entry.name);
    const relZipPath = zipPrefix ? `${zipPrefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      addDirToZip(zip, fullPath, relZipPath);
    } else {
      zip.file(relZipPath, fs.readFileSync(fullPath));
    }
  }
}

function addFileIfExists(zip: JSZip, root: string, relPath: string) {
  const full = path.join(root, relPath);
  if (fs.existsSync(full)) {
    zip.file(relPath.replaceAll('\\', '/'), fs.readFileSync(full));
  }
}

export async function buildWindowsWpfProjectZip(): Promise<Buffer> {
  const zip = new JSZip();
  const root = process.cwd();

  addDirToZip(zip, path.join(root, 'windows-wpf'), 'windows-wpf');
  addDirToZip(zip, path.join(root, '.github'), '.github');

  addFileIfExists(zip, root, 'assets/dns_catalog_1000.tsv');
  addFileIfExists(zip, root, 'README.md');
  addFileIfExists(zip, root, 'LICENSE');
  addFileIfExists(zip, root, 'CHANGELOG.md');
  addFileIfExists(zip, root, '.gitignore');

  return await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}
