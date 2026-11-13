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
  questionNames: string[];
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

  const questionNames: string[] = [];
  let offset = 12;
  for (let i = 0; i < qdCount && offset < buf.length; i++) {
    const qName = readDnsName(buf, offset);
    if (qName.name) questionNames.push(qName.name);
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

  return { id, rcode, questions: qdCount, questionNames, answers, ips };
}

/**
 * Builds a clean RFC 1035 A-record DNS response packet without trailing EDNS0 records.
 */
export function buildDnsAResponse(
  txId: number,
  qname: string,
  ipv4List: string[],
  ttl = 60
): Uint8Array {
  const base = encodeDnsQuery(qname, 1, txId);
  const validV4 = ipv4List.filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip.trim()));

  if (validV4.length === 0) {
    const empty = new Uint8Array(base);
    empty[2] = 0x81;
    empty[3] = 0x80; // NOERROR, 0 answers
    return empty;
  }

  const rrSize = 16; // 2-byte pointer + 2 type + 2 class + 4 ttl + 2 rdlen + 4 ipv4
  const out = new Uint8Array(base.length + validV4.length * rrSize);
  out.set(base, 0);

  const view = new DataView(out.buffer);
  view.setUint16(2, 0x8180, false); // QR=1, RD=1, RA=1, RCODE=0
  view.setUint16(6, validV4.length, false); // ANCOUNT
  view.setUint16(8, 0, false);
  view.setUint16(10, 0, false);

  let offset = base.length;
  for (const ip of validV4) {
    const octets = ip.trim().split('.').map(Number);
    view.setUint16(offset, 0xc00c, false); // Pointer to QNAME at offset 12
    view.setUint16(offset + 2, 1, false); // TYPE A
    view.setUint16(offset + 4, 1, false); // CLASS IN
    view.setUint32(offset + 6, ttl, false);
    view.setUint16(offset + 10, 4, false); // RDLENGTH
    out[offset + 12] = octets[0];
    out[offset + 13] = octets[1];
    out[offset + 14] = octets[2];
    out[offset + 15] = octets[3];
    offset += rrSize;
  }

  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
