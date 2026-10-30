/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: decoder.js
 * 
 * Decoding and message reconstruction module.
 * Reassembles simulated DNS query chunks back into original plaintext data.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(base32Str) {
  const clean = base32Str.toUpperCase().replace(/=/g, '').trim();
  let binaryString = '';
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) {
      throw new Error(`Invalid Base32 character encountered: '${clean[i]}'`);
    }
    binaryString += val.toString(2).padStart(5, '0');
  }

  // Convert binary string to bytes (8-bit chunks)
  const bytes = [];
  for (let i = 0; i + 8 <= binaryString.length; i += 8) {
    bytes.push(parseInt(binaryString.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes).toString('utf8');
}

function decodeHex(hexStr) {
  const clean = hexStr.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Hexadecimal string must have an even number of characters');
  }
  return Buffer.from(clean, 'hex').toString('utf8');
}

function decodeBinary(binStr) {
  const clean = binStr.replace(/\s+/g, '');
  if (clean.length % 8 !== 0) {
    throw new Error('Binary string length must be a multiple of 8 bits');
  }
  const bytes = [];
  for (let i = 0; i < clean.length; i += 8) {
    bytes.push(parseInt(clean.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes).toString('utf8');
}

function decodeBase64(b64Str) {
  return Buffer.from(b64Str.trim(), 'base64').toString('utf8');
}

/**
 * Decode an encoded string using the requested method.
 * @param {string} payload - Encoded string
 * @param {string} method - 'base64' | 'hex' | 'binary' | 'base32'
 * @returns {string} Decoded plaintext
 */
function decodePayload(payload, method = 'base64') {
  if (!payload || typeof payload !== 'string') {
    throw new Error('Payload must be a non-empty string');
  }

  switch (method.toLowerCase()) {
    case 'base64':
      return decodeBase64(payload);
    case 'hex':
    case 'hexadecimal':
      return decodeHex(payload);
    case 'binary':
      return decodeBinary(payload);
    case 'base32':
      return decodeBase32(payload);
    default:
      throw new Error(`Unsupported decoding method: ${method}`);
  }
}

/**
 * Extracts the covert chunk from a simulated DNS query name.
 * Handles patterns like:
 *   - "p01.aGVsbG8=.example.local" -> "aGVsbG8="
 *   - "aGVsbG8=.example.local"     -> "aGVsbG8="
 * 
 * @param {string} queryName - Full domain name (e.g. 'p01.aGVsbG8=.example.local')
 * @param {string} baseDomain - Optional base domain to strip (e.g. 'example.local')
 * @returns {{ packetIndex: number|null, chunk: string }}
 */
function extractChunkFromQuery(queryName, baseDomain = 'example.com') {
  let domain = queryName.trim();
  const cleanBase = baseDomain.trim().replace(/^\.+|\.+$/g, '');

  // Strip trailing dot if present
  if (domain.endsWith('.')) {
    domain = domain.slice(0, -1);
  }

  // Case-insensitive check to strip baseDomain from end
  let subdomainPart = domain;
  const lowerDomain = domain.toLowerCase();
  const lowerBase = cleanBase.toLowerCase();

  if (cleanBase && lowerDomain.endsWith('.' + lowerBase)) {
    subdomainPart = domain.slice(0, -(cleanBase.length + 1));
  } else if (cleanBase && lowerDomain === lowerBase) {
    subdomainPart = '';
  } else {
    // Smart fallback: extract the first label as the subdomainPart
    const dotIdx = domain.indexOf('.');
    if (dotIdx > 0) {
      subdomainPart = domain.slice(0, dotIdx);
    }
  }

  let packetIndex = null;
  let chunk = '';

  // Check for hyphenated sequence format, e.g. "pkt01-Q09NUFVURVI" or "p01-chunk"
  const hyphenMatch = subdomainPart.match(/^(?:pkt|p)(\d+)[-](.+)$/i);
  if (hyphenMatch) {
    packetIndex = parseInt(hyphenMatch[1], 10);
    chunk = hyphenMatch[2];
  } else {
    // Dot separated format, e.g. "pkt01.chunk" or "p01.chunk"
    const parts = subdomainPart.split('.');
    if (parts.length >= 2 && /^(?:pkt|p)\d+$/i.test(parts[0])) {
      packetIndex = parseInt(parts[0].replace(/^(?:pkt|p)/i, ''), 10);
      chunk = parts.slice(1).join('.');
    } else if (parts.length >= 1) {
      chunk = parts.join('.');
    }
  }

  return { packetIndex, chunk };
}

/**
 * Reconstructs original message from an array of simulated DNS queries or chunk objects.
 * Handles packet loss detection and identifies missing sequence numbers.
 * 
 * @param {Array<string|Object>} queries - Array of domain query strings or chunk objects
 * @param {string} method - 'base64' | 'hex' | 'binary' | 'base32'
 * @param {string} baseDomain - Base domain (e.g. 'example.com')
 * @param {number|null} expectedTotal - Total expected packets for packet loss detection
 * @returns {Object} Reconstruction report
 */
function reconstructMessage(queries, method = 'base64', baseDomain = 'example.com', expectedTotal = null) {
  if (!Array.isArray(queries) || queries.length === 0) {
    return {
      success: false,
      reconstructionStatus: 'FAILED',
      encodingMethod: method.toLowerCase(),
      totalExpected: expectedTotal || 0,
      totalDelivered: 0,
      totalLost: expectedTotal || 0,
      missingPackets: expectedTotal ? Array.from({ length: expectedTotal }, (_, i) => String(i + 1).padStart(2, '0')) : [],
      assembledPayload: '',
      decodedMessage: '',
      error: 'No queries received (100% packet loss)',
      chunksExtracted: []
    };
  }

  const items = [];
  let inferredTotal = expectedTotal;

  for (let i = 0; i < queries.length; i++) {
    const q = queries[i];
    let queryName = typeof q === 'string' ? q : (q.queryName || q.chunk || '');
    let extracted;

    if (typeof q === 'object' && q.totalPackets && !inferredTotal) {
      inferredTotal = q.totalPackets;
    }

    if (typeof q === 'object' && q.chunk && q.packetNumber) {
      extracted = { packetIndex: q.packetNumber, chunk: q.chunk };
    } else if (typeof q === 'object' && q.chunk && !q.queryName) {
      extracted = { packetIndex: q.packetNumber || (i + 1), chunk: q.chunk };
    } else {
      extracted = extractChunkFromQuery(queryName, baseDomain);
    }

    items.push({
      inputOrder: i + 1,
      packetIndex: extracted.packetIndex !== null ? extracted.packetIndex : (i + 1),
      queryName: queryName,
      chunk: extracted.chunk
    });
  }

  // Sort by packet index
  items.sort((a, b) => a.packetIndex - b.packetIndex);

  // Check for missing sequence numbers (Packet Loss Detection)
  const receivedSet = new Set(items.map(it => it.packetIndex));
  const maxIdx = inferredTotal || (items.length > 0 ? Math.max(...items.map(it => it.packetIndex)) : 0);
  const missingPackets = [];

  for (let seq = 1; seq <= maxIdx; seq++) {
    if (!receivedSet.has(seq)) {
      missingPackets.push(String(seq).padStart(2, '0'));
    }
  }

  const hasPacketLoss = missingPackets.length > 0;
  const assembledPayload = items.map(item => item.chunk).join('');
  let decodedMessage = '';
  let error = null;

  if (hasPacketLoss) {
    error = `Packet Loss Detected: Missing packet(s) ${missingPackets.join(', ')}`;
    // Still attempt partial decode if possible, or provide descriptive diagnostic
    try {
      decodedMessage = decodePayload(assembledPayload, method);
    } catch {
      decodedMessage = `[RECONSTRUCTION FAILED: Missing packet(s) ${missingPackets.join(', ')}]`;
    }
  } else {
    try {
      decodedMessage = decodePayload(assembledPayload, method);
    } catch (err) {
      error = err.message;
    }
  }

  return {
    success: !hasPacketLoss && error === null,
    reconstructionStatus: hasPacketLoss ? 'FAILED' : 'SUCCESS',
    encodingMethod: method.toLowerCase(),
    totalExpected: maxIdx,
    totalDelivered: items.length,
    totalLost: missingPackets.length,
    missingPackets: missingPackets,
    assembledPayload: assembledPayload,
    decodedMessage: hasPacketLoss ? `[RECONSTRUCTION FAILED - Missing packets: ${missingPackets.join(', ')}]` : decodedMessage,
    error: error,
    chunksExtracted: items
  };
}

module.exports = {
  decodePayload,
  extractChunkFromQuery,
  reconstructMessage,
  decodeBase64,
  decodeHex,
  decodeBinary,
  decodeBase32
};
