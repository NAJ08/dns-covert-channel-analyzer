/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: simulator.js
 * 
 * Simulated DNS packet generator adhering to RFC 1035 specifications.
 * Generates in-memory synthetic DNS requests, responses, protocol stacks,
 * resolution flow simulations, and packet loss modeling.
 */

const crypto = require('crypto');
const { processEncodingPipeline } = require('./encoder');
const { reconstructMessage } = require('./decoder');

// Standard DNS Query Types (RFC 1035 / RFC 3596)
const DNS_TYPES = {
  'A': { id: 1, desc: 'Host Address (IPv4)' },
  'TXT': { id: 16, desc: 'Text Strings' },
  'CNAME': { id: 5, desc: 'Canonical Name' },
  'NULL': { id: 10, desc: 'Null RR (Experimental)' },
  'AAAA': { id: 28, desc: 'IPv6 Address' },
  'MX': { id: 15, desc: 'Mail Exchange' }
};

const DNS_CLASSES = {
  'IN': { id: 1, desc: 'Internet' }
};

/**
 * Encodes a FQDN string into RFC 1035 wire-format label bytes.
 * @param {string} fqdn
 * @returns {Buffer}
 */
function fqdnToWireFormat(fqdn) {
  const clean = fqdn.trim().replace(/^\.+|\.+$/g, '');
  const labels = clean.split('.');
  const buffers = [];

  for (const label of labels) {
    const len = Buffer.byteLength(label);
    const lenBuf = Buffer.alloc(1);
    lenBuf.writeUInt8(len, 0);
    buffers.push(lenBuf);
    buffers.push(Buffer.from(label, 'utf8'));
  }

  // Null terminator
  buffers.push(Buffer.alloc(1, 0));
  return Buffer.concat(buffers);
}

/**
 * Builds an RFC 1035 DNS Query packet model paired with a simulated DNS Response,
 * transport/network/data-link protocol stack details, and resolution trace.
 */
function createSimulatedPacket({
  packetNumber = 1,
  totalPackets = 1,
  queryName,
  encodedPayload = '',
  queryType = 'A',
  queryClass = 'IN',
  timestamp = null,
  srcPort = null,
  delayMs = 0,
  deliveryStatus = 'DELIVERED',
  baseDomain = 'example.com'
}) {
  const typeObj = DNS_TYPES[queryType.toUpperCase()] || DNS_TYPES['A'];
  const classObj = DNS_CLASSES[queryClass.toUpperCase()] || DNS_CLASSES['IN'];

  // Random 16-bit Transaction ID
  const txIdNum = crypto.randomInt(0x0100, 0xFFFF);
  const txIdHex = '0x' + txIdNum.toString(16).toUpperCase().padStart(4, '0');

  // Standard Query Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0 -> 0x0100
  const reqFlagsNum = 0x0100;
  const reqFlagsHex = '0x' + reqFlagsNum.toString(16).toUpperCase().padStart(4, '0');

  // Wire format generation for Request
  const headerBuf = Buffer.alloc(12);
  headerBuf.writeUInt16BE(txIdNum, 0);   // ID
  headerBuf.writeUInt16BE(reqFlagsNum, 2);  // Flags
  headerBuf.writeUInt16BE(1, 4);         // QDCOUNT
  headerBuf.writeUInt16BE(0, 6);         // ANCOUNT
  headerBuf.writeUInt16BE(0, 8);         // NSCOUNT
  headerBuf.writeUInt16BE(0, 10);        // ARCOUNT

  const qnameBuf = fqdnToWireFormat(queryName);
  const qtypeBuf = Buffer.alloc(2);
  qtypeBuf.writeUInt16BE(typeObj.id, 0);
  const qclassBuf = Buffer.alloc(2);
  qclassBuf.writeUInt16BE(classObj.id, 0);

  const fullRequestBuf = Buffer.concat([headerBuf, qnameBuf, qtypeBuf, qclassBuf]);
  const reqHexDump = fullRequestBuf.toString('hex').match(/.{1,2}/g).join(' ');

  // Standard Response Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0 -> 0x8180
  const respFlagsNum = 0x8180;
  const respFlagsHex = '0x' + respFlagsNum.toString(16).toUpperCase().padStart(4, '0');

  // Simulated Answer value (fictional local values)
  let simulatedAnswerValue = '';
  if (queryType.toUpperCase() === 'A') {
    simulatedAnswerValue = `192.0.2.${(packetNumber % 250) + 1}`; // RFC 5737 TEST-NET-1 fictional IP
  } else if (queryType.toUpperCase() === 'TXT') {
    simulatedAnswerValue = `"ack-${txIdHex.toLowerCase()}"`;
  } else if (queryType.toUpperCase() === 'CNAME') {
    simulatedAnswerValue = `ns-edge.simulated-${baseDomain}`;
  } else {
    simulatedAnswerValue = '0x00000000';
  }

  // Ephemeral port simulation
  const sourcePort = srcPort || crypto.randomInt(49152, 65535);

  // Time format
  const baseTime = timestamp || new Date(Date.now() + delayMs);
  const timeFormatted = baseTime.toISOString().split('T')[1].replace('Z', '');

  // Network Protocol Stack encapsulation
  const protocolStack = {
    application: {
      layer: 'Application Layer (L7)',
      protocol: 'DNS (RFC 1035)',
      description: 'Encapsulates the simulated query with embedded covert payload in the subdomain.',
      details: {
        transactionId: txIdHex,
        qname: queryName,
        qtype: `${queryType.toUpperCase()} (${typeObj.desc})`,
        payloadLength: `${encodedPayload.length} chars`,
        wireLength: `${fullRequestBuf.length} octets`
      }
    },
    transport: {
      layer: 'Transport Layer (L4)',
      protocol: 'UDP (User Datagram Protocol - RFC 768)',
      description: 'Provides connectionless, unreliable datagram transmission without retransmission, making packet loss possible.',
      details: {
        srcPort: sourcePort,
        dstPort: 53,
        headerLength: '8 bytes',
        totalLength: `${fullRequestBuf.length + 8} octets`,
        checksum: '0x0000 (Simulated / Optional in IPv4)'
      }
    },
    internet: {
      layer: 'Internet Layer (L3)',
      protocol: 'IPv4 (Internet Protocol - RFC 791)',
      description: 'Routes datagrams across the logical network toward the recursive resolver.',
      details: {
        srcIp: '192.168.1.105 (Simulated Client Host)',
        dstIp: '8.8.8.8 (Simulated Recursive Resolver)',
        protocolNumber: '17 (UDP)',
        ttl: 64,
        headerLength: '20 bytes'
      }
    },
    networkAccess: {
      layer: 'Network Access / Link Layer (L2)',
      protocol: 'Ethernet II / Wi-Fi (IEEE 802.3 / 802.11)',
      description: 'Frames the IP datagram for hop-by-hop transmission across physical link medium.',
      details: {
        srcMac: '02:00:5E:00:53:01 (Host NIC)',
        dstMac: '02:00:5E:00:53:FE (Default Gateway Router)',
        etherType: '0x0800 (IPv4)',
        frameSize: `${fullRequestBuf.length + 28 + 14} bytes`
      }
    }
  };

  // Simulated DNS Resolution Trace
  const tldName = '.' + (baseDomain.split('.').pop() || 'com');
  const resolutionTrace = [
    {
      step: 1,
      from: 'Client Host (192.168.1.105)',
      to: 'Local Recursive Resolver (8.8.8.8)',
      stage: 'client',
      status: 'QUERY SENT',
      message: `Emitted synthetic DNS query for ${queryName} (QTYPE: ${queryType.toUpperCase()})`
    },
    {
      step: 2,
      from: 'Recursive Resolver (8.8.8.8)',
      to: 'Root Nameserver (.)',
      stage: 'root',
      status: 'FORWARDING',
      message: `Cache miss. Query forwarded to Root DNS [a.root-servers.net] for TLD referral`
    },
    {
      step: 3,
      from: 'Root Nameserver (.)',
      to: 'Recursive Resolver (8.8.8.8)',
      stage: 'root_resp',
      status: 'REFERRAL TO TLD',
      message: `Root returns NS referral pointing to TLD nameservers for ${tldName}`
    },
    {
      step: 4,
      from: 'Recursive Resolver (8.8.8.8)',
      to: `TLD Nameserver (${tldName})`,
      stage: 'tld',
      status: 'FORWARDING',
      message: `Resolver queries TLD nameserver for authoritative delegation of ${baseDomain}`
    },
    {
      step: 5,
      from: `TLD Nameserver (${tldName})`,
      to: 'Recursive Resolver (8.8.8.8)',
      stage: 'tld_resp',
      status: 'REFERRAL TO AUTH',
      message: `TLD nameserver delegates resolution to authoritative NS for ${baseDomain}`
    },
    {
      step: 6,
      from: 'Recursive Resolver (8.8.8.8)',
      to: `Authoritative Nameserver (ns1.${baseDomain})`,
      stage: 'auth',
      status: 'AUTHORITY FOUND',
      message: `Authoritative server inspects query label containing covert chunk "${encodedPayload}"`
    },
    {
      step: 7,
      from: `Authoritative Nameserver (ns1.${baseDomain})`,
      to: 'Recursive Resolver (8.8.8.8)',
      stage: 'auth_resp',
      status: 'RESPONSE GENERATED',
      message: `Authoritative server answers with simulated ${queryType.toUpperCase()} record -> ${simulatedAnswerValue}`
    },
    {
      step: 8,
      from: 'Recursive Resolver (8.8.8.8)',
      to: 'Client Host (192.168.1.105)',
      stage: 'client_resp',
      status: 'RESPONSE RECEIVED',
      message: `Client receives standard DNS Response packet (TxID: ${txIdHex}, Answer: ${simulatedAnswerValue})`
    }
  ];

  return {
    isSimulated: true,
    packetNumber,
    totalPackets,
    queryName: queryName,
    chunk: encodedPayload,
    timestamp: timeFormatted,
    relativeOffsetMs: delayMs,
    deliveryStatus: deliveryStatus, // 'DELIVERED' or 'LOST'
    baseDomain: baseDomain,
    transport: {
      protocol: 'UDP (User Datagram Protocol)',
      srcPort: sourcePort,
      dstPort: 53,
      length: fullRequestBuf.length + 8
    },
    protocolStack: protocolStack,
    resolutionTrace: resolutionTrace,

    // Paired DNS Request and Response Models
    request: {
      transactionId: txIdHex,
      flags: reqFlagsHex,
      flagsBreakdown: {
        qr: 0,
        opcode: '0 (Standard Query - QUERY)',
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        z: 0,
        rcode: '0 (No error)'
      },
      qdcount: 1,
      ancount: 0,
      nscount: 0,
      arcount: 0,
      qname: queryName,
      queryType: `${queryType.toUpperCase()} (${typeObj.desc})`,
      queryClass: `${queryClass.toUpperCase()} (${classObj.desc})`,
      wireBytes: fullRequestBuf.length,
      hexDump: reqHexDump
    },

    response: {
      transactionId: txIdHex, // Matching TxID per RFC 1035
      flags: respFlagsHex,
      flagsBreakdown: {
        qr: 1,
        opcode: '0 (Standard Query - QUERY)',
        aa: 1,
        tc: 0,
        rd: 1,
        ra: 1,
        z: 0,
        rcode: '0 (No error)'
      },
      qdcount: 1,
      ancount: 1,
      nscount: 0,
      arcount: 0,
      qname: queryName,
      queryType: `${queryType.toUpperCase()} (${typeObj.desc})`,
      queryClass: `${queryClass.toUpperCase()} (${classObj.desc})`,
      simulatedAnswer: {
        name: queryName,
        type: queryType.toUpperCase(),
        class: queryClass.toUpperCase(),
        ttl: 300,
        rdata: simulatedAnswerValue
      }
    },

    // Backwards-compatible legacy dns property
    dns: {
      header: {
        transactionId: txIdHex,
        rawFlags: reqFlagsHex,
        flagsBreakdown: {
          qr: 0,
          opcode: '0 (Standard Query - QUERY)',
          aa: 0,
          tc: 0,
          rd: 1,
          ra: 0,
          z: 0,
          rcode: '0 (No error)'
        },
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0
      },
      question: {
        queryName: queryName,
        queryType: `${queryType.toUpperCase()} (${typeObj.desc})`,
        queryTypeId: typeObj.id,
        queryClass: `${queryClass.toUpperCase()} (${classObj.desc})`,
        queryClassId: classObj.id
      },
      payload: {
        encodedPayload: encodedPayload,
        payloadLength: encodedPayload.length,
        queryNameLength: queryName.length,
        rawPacketBytes: fullRequestBuf.length,
        hexDump: reqHexDump
      }
    }
  };
}

/**
 * Simulates a full covert channel stream from a secret message.
 * Includes configurable base domain and packet loss simulation.
 */
function simulateCovertDnsStream({
  message = 'COMPUTER NETWORKS PROJECT',
  encoding = 'base64',
  domain = 'example.com',
  chunkSize = 16,
  queryType = 'A',
  interArrivalMs = 120,
  includeSeq = true,
  packetLoss = 0
}) {
  const cleanDomain = domain.trim().replace(/^\.+|\.+$/g, '') || 'example.com';
  const pipeline = processEncodingPipeline(message, encoding, chunkSize, cleanDomain, includeSeq);
  const startTime = Date.now();
  const packets = [];
  const lossRate = Math.max(0, Math.min(30, parseInt(packetLoss, 10) || 0));

  // Determine packet loss indices deterministically / pseudo-randomly
  const totalCount = pipeline.chunks.length;
  const lostIndices = new Set();

  if (lossRate > 0 && totalCount > 1) {
    const numToDrop = Math.max(1, Math.round(totalCount * (lossRate / 100)));
    // Pick random indices to drop (avoid dropping packet 1 if multiple chunks to keep initial inspectable)
    while (lostIndices.size < numToDrop && lostIndices.size < totalCount) {
      const idx = totalCount > 2 
        ? crypto.randomInt(1, totalCount) // drop packet 2..N
        : crypto.randomInt(0, totalCount);
      lostIndices.add(idx);
    }
  }

  for (let i = 0; i < pipeline.chunks.length; i++) {
    const chunkInfo = pipeline.chunks[i];
    const jitter = Math.floor((Math.random() * 0.5 - 0.25) * interArrivalMs);
    const delay = i * interArrivalMs + (i > 0 ? jitter : 0);
    const isLost = lostIndices.has(i);

    const packet = createSimulatedPacket({
      packetNumber: chunkInfo.packetNumber,
      totalPackets: pipeline.chunks.length,
      queryName: chunkInfo.queryName,
      encodedPayload: chunkInfo.chunk,
      queryType: queryType,
      queryClass: 'IN',
      delayMs: Math.max(0, delay),
      timestamp: new Date(startTime + delay),
      deliveryStatus: isLost ? 'LOST' : 'DELIVERED',
      baseDomain: cleanDomain
    });

    packets.push(packet);
  }

  const deliveredPackets = packets.filter(p => p.deliveryStatus === 'DELIVERED');
  const lostPackets = packets.filter(p => p.deliveryStatus === 'LOST');

  // Run message reconstruction with delivered packets
  const reconstruction = reconstructMessage(deliveredPackets, encoding, cleanDomain, totalCount);

  return {
    isSimulated: true,
    safetyLabel: 'SIMULATED — NO REAL DNS REQUEST SENT',
    disclaimer: 'SIMULATION LAB TOOL ONLY - No real packets were sent over the network.',
    message: message,
    encoding: encoding,
    baseDomain: cleanDomain,
    queryType: queryType,
    chunkSize: chunkSize,
    packetLossPercent: lossRate,
    totalPackets: packets.length,
    packetsGenerated: packets.length,
    packetsDelivered: deliveredPackets.length,
    packetsLost: lostPackets.length,
    transmissionDurationMs: (pipeline.chunks.length - 1) * interArrivalMs,
    pipeline: pipeline,
    packets: packets,
    deliveredPackets: deliveredPackets,
    lostPackets: lostPackets,
    reconstruction: reconstruction
  };
}

module.exports = {
  createSimulatedPacket,
  simulateCovertDnsStream,
  DNS_TYPES,
  DNS_CLASSES,
  fqdnToWireFormat
};
