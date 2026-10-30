/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: encoder.js
 * 
 * Educational encoding and payload chunking module.
 * Converts secret messages into simulated DNS-compatible query payloads.
 */

// RFC 4648 Base32 implementation
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encodeBase32(str) {
  const bytes = Buffer.from(str, 'utf8');
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += bytes[i].toString(2).padStart(8, '0');
  }

  let base32 = '';
  for (let i = 0; i < binaryString.length; i += 5) {
    const chunk = binaryString.substring(i, i + 5);
    if (chunk.length < 5) {
      const padded = chunk.padEnd(5, '0');
      base32 += BASE32_ALPHABET[parseInt(padded, 2)];
      // Add '=' padding to match 8-char blocks
      const padLength = (8 - (base32.length % 8)) % 8;
      base32 += '='.repeat(padLength);
      break;
    } else {
      base32 += BASE32_ALPHABET[parseInt(chunk, 2)];
    }
  }

  // Ensure Base32 padding to multiple of 8 if needed
  while (base32.length % 8 !== 0) {
    base32 += '=';
  }
  return base32;
}

function encodeHex(str) {
  return Buffer.from(str, 'utf8').toString('hex');
}

function encodeBinary(str) {
  const bytes = Buffer.from(str, 'utf8');
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += bytes[i].toString(2).padStart(8, '0');
  }
  return bin;
}

/**
 * Base64 for DNS labels: standard Base64 uses '+', '/' and '=' which are not
 * valid in hostname labels (RFC 1035 / RFC 1123 letter-digit-hyphen rule).
 * We therefore use the URL-safe alphabet (RFC 4648 section 5: '+' -> '-', '/' -> '_')
 * and drop '=' padding. Note: Base64 is still CASE-SENSITIVE, while DNS treats
 * names case-insensitively (and some resolvers randomise case, "0x20 encoding"),
 * which is why real-world DNS covert channels prefer Base32 or hex.
 */
function encodeBase64(str) {
  return Buffer.from(str, 'utf8').toString('base64url');
}

/**
 * Encode a message using the requested algorithm.
 * @param {string} message - Plaintext message
 * @param {string} method - 'base64' | 'hex' | 'binary' | 'base32'
 * @returns {string} Encoded payload string
 */
function encodeMessage(message, method = 'base64') {
  if (!message || typeof message !== 'string') {
    throw new Error('Message must be a non-empty string');
  }

  switch (method.toLowerCase()) {
    case 'base64':
      return encodeBase64(message);
    case 'hex':
    case 'hexadecimal':
      return encodeHex(message);
    case 'binary':
      return encodeBinary(message);
    case 'base32':
      // '=' padding is not a valid label character; the decoder re-derives it
      return encodeBase32(message).replace(/=+$/, '');
    default:
      throw new Error(`Unsupported encoding method: ${method}. Choose Base64, Hexadecimal, Binary, or Base32.`);
  }
}

/**
 * Splits an encoded string into chunks suitable for DNS labels.
 * RFC 1035 limits a single domain label to 63 octets and total domain name to 255 octets.
 * 
 * @param {string} encodedString - The complete encoded string
 * @param {number} chunkSize - Character count per chunk (default 16)
 * @param {string} domain - Base domain (e.g. 'example.com')
 * @param {boolean} includeSeq - Whether to include a sequence prefix (e.g. 'pkt01-')
 * @returns {Array<Object>} List of chunk items
 */
function chunkPayload(encodedString, chunkSize = 16, domain = 'example.com', includeSeq = true) {
  const cleanDomain = domain.trim().replace(/^\.+|\.+$/g, '') || 'example.com';
  const size = Math.max(4, Math.min(50, parseInt(chunkSize, 10) || 16));
  const chunks = [];
  
  for (let i = 0; i < encodedString.length; i += size) {
    chunks.push(encodedString.substring(i, i + size));
  }

  const total = chunks.length;
  const padLength = String(total).length < 2 ? 2 : String(total).length;

  return chunks.map((chunk, index) => {
    const seqNum = index + 1;
    const seqPrefix = `pkt${String(seqNum).padStart(padLength, '0')}`;
    const subdomain = includeSeq ? `${seqPrefix}-${chunk}` : chunk;
    const queryName = `${subdomain}.${cleanDomain}`;

    return {
      packetNumber: seqNum,
      totalPackets: total,
      sequenceId: seqPrefix,
      chunk: chunk,
      subdomain: subdomain,
      baseDomain: cleanDomain,
      queryName: queryName,
      payloadLength: chunk.length,
      fqdnLength: queryName.length
    };
  });
}

/**
 * Pipeline generator: Shows step-by-step transformation
 * @param {string} message
 * @param {string} method
 * @param {number} chunkSize
 * @param {string} domain
 * @param {boolean} includeSeq
 */
function processEncodingPipeline(message, method = 'base64', chunkSize = 16, domain = 'example.com', includeSeq = true) {
  const originalBytes = Buffer.from(message, 'utf8').length;
  const encodedPayload = encodeMessage(message, method);
  const chunks = chunkPayload(encodedPayload, chunkSize, domain, includeSeq);
  const totalQueryBytes = chunks.reduce((acc, c) => acc + c.fqdnLength, 0);

  return {
    originalMessage: message,
    encodingMethod: method.toLowerCase(),
    encodedPayload: encodedPayload,
    chunkSize: parseInt(chunkSize, 10) || 16,
    domain: domain,
    includeSequence: includeSeq,
    totalPackets: chunks.length,
    originalSizeBytes: originalBytes,
    encodedSizeBytes: encodedPayload.length,
    expansionRatio: Number((encodedPayload.length / (originalBytes || 1)).toFixed(2)),
    totalQueryBytes: totalQueryBytes,
    chunks: chunks
  };
}

module.exports = {
  encodeMessage,
  chunkPayload,
  processEncodingPipeline,
  encodeBase64,
  encodeHex,
  encodeBinary,
  encodeBase32
};
