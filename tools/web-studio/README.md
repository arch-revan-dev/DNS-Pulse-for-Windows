# DNS Pulse Web Studio (Optional Companion Lab)

> **Non-Primary Tooling**: The primary DNS Pulse product is the native Windows 10/11 desktop application and Windows Service under the repository root (`DnsPulse.sln`, `src/`).

This directory contains the optional Node.js / Vite / React companion web diagnostic lab and prototype (`tools/web-studio/`). It is preserved for browser-based diagnostics, prototyping, and reference, and is independent of the `.NET 9` / WPF desktop solution.

## Quick Start

Run commands from `tools/web-studio/`:

```bash
npm install
npm run dev
```

To run the companion TypeScript engine tests:

```bash
npm test
```

The companion server and tests read the shared built-in server catalog from `../../assets/dns_catalog_1000.tsv` at the repository root.
