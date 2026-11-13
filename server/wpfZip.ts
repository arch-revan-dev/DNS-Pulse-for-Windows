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

export async function buildWindowsWpfProjectZip(): Promise<Buffer> {
  const zip = new JSZip();
  const root = process.cwd();

  addDirToZip(zip, path.join(root, 'windows-wpf'), 'windows-wpf');

  const tsvPath = path.join(root, 'assets', 'dns_catalog_1000.tsv');
  if (fs.existsSync(tsvPath)) {
    zip.file('assets/dns_catalog_1000.tsv', fs.readFileSync(tsvPath));
  }

  const workflowPath = path.join(root, '.github', 'workflows', 'release.yml');
  if (fs.existsSync(workflowPath)) {
    zip.file('.github/workflows/release.yml', fs.readFileSync(workflowPath));
  }

  const gitignorePath = path.join(root, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    zip.file('.gitignore', fs.readFileSync(gitignorePath));
  }

  return await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}
