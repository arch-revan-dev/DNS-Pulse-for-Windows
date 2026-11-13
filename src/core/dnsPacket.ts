/**
 * Pure RFC 1035 DNS Wire Format Codec + RFC 8484 base64url helpers.
 */

export interface DnsParsedRecord {
  name: string;
  type: number;
  ttl: number;
  data: string;
}

export interface DnsParsedResponse {
  id: number;
  rcode: number;
  questions: number;
  answers: DnsParsedRecord[];
  ips: string[];
}

export function encodeDnsQuery(domain: string, qtype = 1, id?: number): Uint8Array {
  const cleanDomain = domain.trim().replace(/\.+$/, '').toLowerCase();
  if (!cleanDomain) {
    throw new Error('Domain name cannot be empty');
  }

  const labels = cleanDomain.split('.');
  const qnameBytes: number[] = [];
  for (const label of labels) {
    const encoded = new TextEncoder().encode(label);
    if (encoded.length === 0 || encoded.length > 63) {
      throw new Error(`Invalid DNS label length for "${label}"`);
    }
    qnameBytes.push(encoded.length, ...encoded);
  }
  qnameBytes.push(0); // Root label terminator

  const txId = id ?? Math.floor(Math.random() * 65535);
  const buffer = new Uint8Array(12 + qnameBytes.length + 4);
  const view = new DataView(buffer.buffer);

  view.setUint16(0, txId, false); // Transaction ID
  view.setUint16(2, 0x0100, false); // Standard query with RD=1
  view.setUint16(4, 1, false); // QDCOUNT = 1
  view.setUint16(6, 0, false); // ANCOUNT = 0
  view.setUint16(8, 0, false); // NSCOUNT = 0
  view.setUint16(10, 0, false); // ARCOUNT = 0

  buffer.set(qnameBytes, 12);
  const tailOffset = 12 + qnameBytes.length;
  view.setUint16(tailOffset, qtype, false); // QTYPE (1 = A, 28 = AAAA)
  view.setUint16(tailOffset + 2, 1, false); // QCLASS (1 = IN)

  return buffer;
}

function readDnsName(buf: Uint8Array, startOffset: number): { name: string; nextOffset: number } {
  const labels: string[] = [];
  let offset = startOffset;
  let jumped = false;
  let nextOffset = startOffset;
  let guard = 0;

  while (offset < buf.length && guard++ < 128) {
    const len = buf[offset];
    if (len === 0) {
      if (!jumped) nextOffset = offset + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= buf.length) break;
      const pointer = ((len & 0x3f) << 8) | buf[offset + 1];
      if (!jumped) nextOffset = offset + 2;
      offset = pointer;
      jumped = true;
      continue;
    }
    offset += 1;
    if (offset + len > buf.length) break;
    labels.push(new TextDecoder().decode(buf.subarray(offset, offset + len)));
    offset += len;
    if (!jumped) nextOffset = offset;
  }

  return { name: labels.join('.'), nextOffset };
}

export function decodeDnsResponse(buf: Uint8Array): DnsParsedResponse {
  if (buf.length < 12) {
    throw new Error('DNS response packet too short (< 12 bytes)');
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = view.getUint16(0, false);
  const flags = view.getUint16(2, false);
  const rcode = flags & 0x0f;
  const qdCount = view.getUint16(4, false);
  const anCount = view.getUint16(6, false);

  let offset = 12;
  for (let i = 0; i < qdCount && offset < buf.length; i++) {
    const qName = readDnsName(buf, offset);
    offset = qName.nextOffset + 4; // QTYPE + QCLASS
  }

  const answers: DnsParsedRecord[] = [];
  const ips: string[] = [];

  for (let i = 0; i < anCount && offset + 10 <= buf.length; i++) {
    const rrName = readDnsName(buf, offset);
    offset = rrName.nextOffset;
    if (offset + 10 > buf.length) break;

    const rtype = view.getUint16(offset, false);
    const _rclass = view.getUint16(offset + 2, false);
    const ttl = view.getUint32(offset + 4, false);
    const rdLength = view.getUint16(offset + 8, false);
    offset += 10;

    if (offset + rdLength > buf.length) break;
    const rdata = buf.subarray(offset, offset + rdLength);
    offset += rdLength;

    let dataStr = '';
    if (rtype === 1 && rdLength === 4) {
      dataStr = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      ips.push(dataStr);
    } else if (rtype === 28 && rdLength === 16) {
      const parts: string[] = [];
      for (let j = 0; j < 16; j += 2) {
        parts.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
      }
      dataStr = parts.join(':');
      ips.push(dataStr);
    } else if (rtype === 5) {
      dataStr = readDnsName(buf, offset - rdLength).name;
    }

    answers.push({ name: rrName.name, type: rtype, ttl, data: dataStr });
  }

  return { id, rcode, questions: qdCount, answers, ips };
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
