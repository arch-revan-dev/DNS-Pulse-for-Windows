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

  const dotnetProjects = [
    'src/DnsPulse.Core',
    'src/DnsPulse.Engine',
    'src/DnsPulse.Platform.Windows',
    'src/DnsPulse.Service',
    'src/DnsPulse.App',
  ];

  for (const projDir of dotnetProjects) {
    addDirToZip(zip, path.join(root, projDir), projDir);
  }

  addDirToZip(zip, path.join(root, 'tests'), 'tests');
  addDirToZip(zip, path.join(root, 'installer'), 'installer');
  addDirToZip(zip, path.join(root, 'assets'), 'assets');
  addDirToZip(zip, path.join(root, 'docs'), 'docs');
  addDirToZip(zip, path.join(root, '.github'), '.github');

  const rootFiles = [
    'DnsPulse.sln',
    'Directory.Build.props',
    '.editorconfig',
    'README.md',
    'README.ru.md',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'CODE_OF_CONDUCT.md',
    'SECURITY.md',
    'LICENSE',
    '.gitignore',
  ];

  for (const file of rootFiles) {
    addFileIfExists(zip, root, file);
  }

  return await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}
