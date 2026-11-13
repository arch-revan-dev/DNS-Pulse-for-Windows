import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { buildFullBuiltinCatalog } from './catalogSeed';
import { encodeDnsQuery, decodeDnsResponse, buildDnsAResponse } from './dnsPacket';
import {
  classifyFourStageVerdict,
  isBogonOrLoopbackIp,
  isDirectServiceIp,
  isGeoBlockedRedirect,
} from './antiDirectIp';
import {
  buildRotationQueue,
  exportServersToCsv,
  filterServers,
  getNextRotationServerId,
  parseDynamicBypassHosts,
  parseImportedServers,
  sortServers,
} from './filterSort';
import { DOMAIN_PRESETS, getPresetsForGroup } from './presets';
import { FilterState } from './types';

const tsvPath = path.resolve(process.cwd(), 'assets/dns_catalog_1000.tsv');
const tsvText = fs.readFileSync(tsvPath, 'utf8');
const allBuiltins = buildFullBuiltinCatalog(tsvText);

test('Built-in catalog has 1050+ servers, includes required Smart-DNS, zero tokens, zero default favorites', () => {
  assert.ok(allBuiltins.length >= 1050, `Expected >=1050 servers, got ${allBuiltins.length}`);

  const serialized = JSON.stringify(allBuiltins);
  assert.equal(serialized.includes('kkkrbbawqq2'), false, 'Personal token must never exist');
  assert.equal(
    allBuiltins.some((s) => s.isFavorite),
    false,
    'All built-in servers must have isFavorite = false by default'
  );
  assert.equal(
    allBuiltins.some((s) => s.isSubscription),
    false,
    'Built-in servers must not be subscription tokens'
  );

  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://dns.bezmezhau.com/dns-query'));
  for (let i = 1; i <= 20; i++) {
    assert.ok(
      allBuiltins.some((s) => s.dohUrl === `https://gemini${i}.bezmezhau.com/dns-query`),
      `Missing gemini${i}.bezmezhau.com`
    );
  }
  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://dns.magicdns.ru/dns-query'));
  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://us.geohide.ru/dns-query'));
  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://dns.malw.link/dns-query'));
  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://dns.comss.one/dns-query'));
  assert.ok(allBuiltins.some((s) => s.dohUrl === 'https://xbox-dns.ru/dns-query'));
  assert.ok(allBuiltins.some((s) => s.provider.includes('Common Network')));
});

test('Gemini is the first preset in AI and All groups', () => {
  const ai = getPresetsForGroup('ai');
  assert.equal(ai[0].id, 'gemini');
  assert.equal(ai[0].domain, 'gemini.google.com');
  assert.equal(DOMAIN_PRESETS[0].id, 'gemini');
});

test('RFC 1035 DNS packet encoder and decoder roundtrip', () => {
  const query = encodeDnsQuery('gemini.google.com', 1, 0x1234);
  assert.ok(query.length > 17);
  assert.equal((query[0] << 8) | query[1], 0x1234);

  // Construct synthetic RFC 1035 A-record response matching query + answer 192.255.159.240
  const resp = new Uint8Array(query.length + 16);
  resp.set(query, 0);
  resp[2] = 0x81; // QR=1, RD=1
  resp[3] = 0x80; // RA=1, RCODE=0
  resp[6] = 0x00;
  resp[7] = 0x01; // ANCOUNT=1
  const ansStart = query.length;
  resp.set(
    [
      0xc0, 0x0c, // Name pointer to offset 12
      0x00, 0x01, // TYPE A
      0x00, 0x01, // CLASS IN
      0x00, 0x00, 0x00, 0x3c, // TTL 60s
      0x00, 0x04, // RDLENGTH 4
      192, 255, 159, 240,
    ],
    ansStart
  );

  const decoded = decodeDnsResponse(resp);
  assert.equal(decoded.id, 0x1234);
  assert.equal(decoded.rcode, 0);
  assert.deepEqual(decoded.questionNames, ['gemini.google.com']);
  assert.deepEqual(decoded.ips, ['192.255.159.240']);

  const built = buildDnsAResponse(0x55aa, 'aistudio.google.com', ['179.254.166.171'], 60);
  const builtDecoded = decodeDnsResponse(built);
  assert.equal(builtDecoded.id, 0x55aa);
  assert.equal(builtDecoded.rcode, 0);
  assert.deepEqual(builtDecoded.questionNames, ['aistudio.google.com']);
  assert.deepEqual(builtDecoded.ips, ['179.254.166.171']);
});

test('Anti-Direct-IP and 4-stage geo-redirect classifier rejects direct Google IPs and /docs/available-regions', () => {
  assert.equal(isBogonOrLoopbackIp('127.0.0.1'), true);
  assert.equal(isBogonOrLoopbackIp('0.0.0.0'), true);
  assert.equal(isBogonOrLoopbackIp('192.255.159.240'), false);

  assert.equal(isDirectServiceIp('142.250.185.78', 'gemini.google.com'), true);
  assert.equal(isDirectServiceIp('192.255.159.240', 'gemini.google.com'), false);

  assert.equal(
    isGeoBlockedRedirect(302, 'https://aistudio.google.com/docs/available-regions'),
    true
  );

  const directVerdict = classifyFourStageVerdict({
    requiresBypass: true,
    resolvedIps: ['142.250.185.78'],
    companionPassed: true,
    port443Ok: true,
    httpStatus: 200,
    redirectLocation: null,
    targetDomain: 'gemini.google.com',
    timedOut: false,
  });
  assert.equal(directVerdict.verdict, 'DIRECT_NO_PROXY');

  const geoVerdict = classifyFourStageVerdict({
    requiresBypass: true,
    resolvedIps: ['192.255.159.240'],
    companionPassed: true,
    port443Ok: true,
    httpStatus: 302,
    redirectLocation: 'https://aistudio.google.com/docs/available-regions',
    targetDomain: 'aistudio.google.com',
    timedOut: false,
  });
  assert.equal(geoVerdict.verdict, 'GEO_REDIRECT_BLOCKED');

  const okVerdict = classifyFourStageVerdict({
    requiresBypass: true,
    resolvedIps: ['192.255.159.240'],
    companionPassed: true,
    port443Ok: true,
    httpStatus: 200,
    redirectLocation: null,
    targetDomain: 'gemini.google.com',
    timedOut: false,
  });
  assert.equal(okVerdict.verdict, 'VERIFIED_PROXY_OK');
});

test('Multi-layer filters and persisted latency/TPS sorting work without favorite bias', () => {
  const sample = allBuiltins.slice(0, 6).map((s, idx) => ({
    ...s,
    isFavorite: idx === 0, // Favorite has high ping to ensure LOWEST_PING ignores isFavorite
    lastLatencyMs: [180, 14, 42, 95, 25, 60][idx],
    lastTps: [10, 88, 65, 30, 120, 50][idx],
    verdict: (idx === 1 ? 'VERIFIED_PROXY_OK' : 'UNCHECKED') as typeof s.verdict,
  }));

  const byPing = sortServers(sample, 'LOWEST_PING');
  assert.equal(byPing[0].lastLatencyMs, 14);
  assert.equal(byPing[byPing.length - 1].lastLatencyMs, 180);

  const byTps = sortServers(sample, 'HIGHEST_TPS');
  assert.equal(byTps[0].lastTps, 120);

  const byFav = sortServers(sample, 'FAVORITES_FIRST');
  assert.equal(byFav[0].isFavorite, true);

  const filter: FilterState = {
    category: 'Smart-DNS',
    bypassOnly: true,
    favoritesOnly: false,
    encryptedOnly: true,
    freeOnly: true,
    search: 'bezmezhau',
    sortMode: 'BEST',
  };
  const filtered = filterServers(sample, filter, true);
  assert.ok(filtered.length > 0);
  assert.ok(filtered.every((s) => s.protocol === 'DoH' || s.protocol === 'DoT'));
});

test('Hosts parser, plain-text/CSV/JSON import-export, and rotation queue work reliably', () => {
  const hosts = `
# Adblock sinkhole lines must be skipped
0.0.0.0 doubleclick.net
127.0.0.1 ads.google.com
# Real proxied Smart-DNS hosts
179.254.166.171 gemini.google.com
179.254.166.171 aistudio.google.com
164.5.224.81 chatgpt.com
`;
  const parsedHosts = parseDynamicBypassHosts(hosts);
  assert.deepEqual(parsedHosts, ['gemini.google.com', 'aistudio.google.com', 'chatgpt.com']);

  const imported = parseImportedServers(
    'https://dns.bezmezhau.com/dns-query Bezmezhau\n176.99.11.77 XboxDNS'
  );
  assert.equal(imported.length, 2);
  assert.equal(imported[0].protocol, 'DoH');
  assert.equal(imported[1].protocol, 'UDP');

  const csv = exportServersToCsv(imported);
  assert.ok(csv.includes('Bezmezhau'));
  const reimported = parseImportedServers(csv);
  assert.equal(reimported.length, 2);

  const queue = buildRotationQueue(
    allBuiltins.slice(0, 5).map((s, i) => ({
      ...s,
      verdict: 'VERIFIED_PROXY_OK',
      lastLatencyMs: 50 - i * 5,
    })),
    null
  );
  assert.equal(queue.length, 5);
  const next1 = getNextRotationServerId(queue, queue[0]);
  assert.equal(next1, queue[1]);

  // Malformed DoH URLs must never crash the plain-text importer
  const malformed = parseImportedServers(
    'https://[invalid-url BadNode\nhttps://dns.bezmezhau.com/dns-query ValidNode'
  );
  assert.equal(malformed.length, 1);
  assert.equal(malformed[0].name, 'ValidNode');
});
