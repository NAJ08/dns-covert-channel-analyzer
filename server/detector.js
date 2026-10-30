/**
 * DNS Steganography & Covert Channel Analyzer
 * Module: detector.js
 * 
 * Transparent rule-based educational anomaly detector for simulated DNS traffic.
 * Analyzes structural, linguistic, and statistical properties of queries.
 * 
 * DISCLAIMER:
 * This detector is intended exclusively for academic lab demonstrations and teaching
 * network traffic analysis fundamentals. Real-world DNS covert channels use complex
 * stealth techniques, pacing, encryption, and tunneling protocols requiring advanced
 * machine learning and threat intelligence feeds.
 */

/**
 * Calculates the Shannon Entropy of a string.
 * Formula: H(X) = -SUM( P(x_i) * log2(P(x_i)) )
 * 
 * @param {string} str - Input string
 * @returns {number} Entropy in bits per character
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  
  const len = str.length;
  const frequencies = {};

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Calculates ratio of unusual characters (numbers, uppercase, symbols like '=')
 * in DNS hostname labels.
 * 
 * @param {string} str - String to analyze
 * @returns {number} Ratio between 0.0 and 1.0
 */
function calculateUnusualCharRatio(str) {
  if (!str || str.length === 0) return 0;

  // Normal DNS hostnames usually comprise lowercase letters and hyphens.
  // Unusual: digits, uppercase, padding '=', underscores
  let unusualCount = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (/[0-9]/.test(c) || /[A-Z]/.test(c) || /[=_\$]/.test(c)) {
      unusualCount++;
    }
  }

  return Number((unusualCount / str.length).toFixed(3));
}

/**
 * Extracts subdomains and base domain from a FQDN.
 * @param {string} fqdn
 * @returns {{ subdomain: string, baseDomain: string }}
 */
function parseDomainParts(fqdn) {
  const clean = fqdn.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const labels = clean.split('.');

  if (labels.length <= 2) {
    return { subdomain: '', baseDomain: clean };
  }

  const baseDomain = labels.slice(-2).join('.');
  const subdomain = labels.slice(0, -2).join('.');
  return { subdomain, baseDomain };
}

/**
 * Analyze an individual simulated DNS packet or query.
 * @param {Object|string} queryInput - Query name or packet object
 * @returns {Object} Individual query metrics
 */
function analyzeSingleQuery(queryInput) {
  let queryName = '';
  let queryType = 'A';
  let timestamp = null;
  let packetNumber = null;

  if (typeof queryInput === 'string') {
    queryName = queryInput;
  } else if (typeof queryInput === 'object') {
    queryName = queryInput.dns?.question?.queryName || queryInput.queryName || '';
    queryType = queryInput.dns?.question?.queryType || queryInput.queryType || 'A';
    timestamp = queryInput.timestamp || null;
    packetNumber = queryInput.packetNumber || null;
  }

  const { subdomain, baseDomain } = parseDomainParts(queryName);
  const totalLength = queryName.length;
  const subdomainLength = subdomain.length;
  const wholeEntropy = calculateShannonEntropy(queryName);
  const subdomainEntropy = calculateShannonEntropy(subdomain);
  // parseDomainParts() lowercases the name, which would hide uppercase characters
  // (e.g. Base64/Base32 payloads). Take the subdomain from the ORIGINAL-case name.
  const originalTrimmed = String(queryName).trim().replace(/^\.+|\.+$/g, '');
  const originalSubdomain = subdomain ? originalTrimmed.slice(0, subdomain.length) : '';
  const unusualCharRatio = calculateUnusualCharRatio(originalSubdomain || originalTrimmed);
  const payloadToDomainRatio = baseDomain.length > 0 
    ? Number((subdomainLength / baseDomain.length).toFixed(2)) 
    : 0;

  // Check for binary encoding signature (pure 0 and 1)
  const isBinarySignature = subdomainLength >= 8 && /^[01.]+$/.test(subdomain);

  // Per-query rule evaluation
  let individualScore = 0;
  const reasons = [];

  if (subdomainLength > 24) {
    individualScore += 25;
    reasons.push(`Subdomain length (${subdomainLength} chars) exceeds normal hostname thresholds`);
  } else if (subdomainLength > 14) {
    individualScore += 15;
    reasons.push(`Moderately long subdomain (${subdomainLength} chars)`);
  }

  if (subdomainEntropy > 3.8) {
    individualScore += 30;
    reasons.push(`Elevated Shannon entropy (${subdomainEntropy} bits/char) signals encoded or compressed payload`);
  } else if (subdomainEntropy > 3.2) {
    individualScore += 15;
    reasons.push(`Above average entropy (${subdomainEntropy} bits/char)`);
  }

  if (isBinarySignature) {
    individualScore += 30;
    reasons.push('Subdomain pattern matches pure binary bitstream encoding');
  }

  if (unusualCharRatio > 0.4) {
    individualScore += 25;
    reasons.push(`High ratio of unusual characters/case-mixing (${(unusualCharRatio * 100).toFixed(0)}%)`);
  } else if (unusualCharRatio > 0.2) {
    individualScore += 10;
    reasons.push(`Noticeable digit or symbol ratio (${(unusualCharRatio * 100).toFixed(0)}%)`);
  }

  if (payloadToDomainRatio > 1.2) {
    individualScore += 15;
    reasons.push(`High payload-to-domain ratio (${payloadToDomainRatio}x)`);
  }

  const clampedScore = Math.min(100, individualScore);
  let status = 'Normal';
  if (clampedScore > 75) status = 'Suspicious';
  else if (clampedScore > 40) status = 'Unusual';

  return {
    packetNumber,
    queryName,
    queryType,
    timestamp,
    subdomain,
    baseDomain,
    length: totalLength,
    subdomainLength,
    entropy: subdomainEntropy || wholeEntropy,
    wholeEntropy,
    unusualCharRatio,
    payloadToDomainRatio,
    isBinarySignature,
    score: clampedScore,
    status,
    reasons
  };
}

/**
 * Analyzes an entire stream/batch of DNS queries.
 * Calculates aggregate indicators and transparent suspiciousness score.
 * 
 * @param {Array<Object|string>} queryList - Array of query names or packet objects
 * @returns {Object} Comprehensive traffic analysis report
 */
function analyzeTrafficBatch(queryList) {
  if (!Array.isArray(queryList) || queryList.length === 0) {
    return {
      queriesAnalyzed: 0,
      suspicionScore: 0,
      classification: 'Normal',
      indicators: {},
      ruleContributions: [],
      queryDetails: []
    };
  }

  const queryDetails = queryList.map(q => analyzeSingleQuery(q));
  const totalCount = queryDetails.length;

  // Aggregate metrics
  const avgQueryLength = Number((queryDetails.reduce((acc, q) => acc + q.length, 0) / totalCount).toFixed(1));
  const avgSubdomainLength = Number((queryDetails.reduce((acc, q) => acc + q.subdomainLength, 0) / totalCount).toFixed(1));
  const avgEntropy = Number((queryDetails.reduce((acc, q) => acc + q.entropy, 0) / totalCount).toFixed(2));
  const avgUnusualCharRatio = Number((queryDetails.reduce((acc, q) => acc + q.unusualCharRatio, 0) / totalCount).toFixed(2));
  const avgPayloadDomainRatio = Number((queryDetails.reduce((acc, q) => acc + q.payloadToDomainRatio, 0) / totalCount).toFixed(2));

  // Count high-metric queries
  const longSubdomainsCount = queryDetails.filter(q => q.subdomainLength > 16).length;
  const highEntropyCount = queryDetails.filter(q => q.entropy > 3.6).length;
  const binarySignatureCount = queryDetails.filter(q => q.isBinarySignature).length;

  // Repeated pattern / uniqueness check
  const subdomainsSet = new Set(queryDetails.map(q => q.subdomain));
  const uniquenessRatio = Number((subdomainsSet.size / totalCount).toFixed(2));

  // Transparent Educational Rule Scoring Engine
  const ruleContributions = [];
  let rawScore = 0;

  // Rule 1: Average Query Length
  if (avgQueryLength > 40) {
    const pts = 25;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_AVG_QUERY_LENGTH_HIGH',
      featureName: 'Average Query Length',
      observedValue: `${avgQueryLength} chars`,
      threshold: '> 40 chars',
      pointsContributed: pts,
      maxPoints: 25,
      severity: 'high',
      explanation: 'Average query length is substantially higher than standard internet DNS queries (typically 12-24 chars).'
    });
  } else if (avgQueryLength > 25) {
    const pts = 15;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_AVG_QUERY_LENGTH_MED',
      featureName: 'Average Query Length',
      observedValue: `${avgQueryLength} chars`,
      threshold: '> 25 chars',
      pointsContributed: pts,
      maxPoints: 25,
      severity: 'medium',
      explanation: 'Query length is moderately elevated, suggesting encoded metadata or nested subdomains.'
    });
  } else {
    ruleContributions.push({
      ruleId: 'RULE_AVG_QUERY_LENGTH_NORMAL',
      featureName: 'Average Query Length',
      observedValue: `${avgQueryLength} chars`,
      threshold: '<= 25 chars',
      pointsContributed: 0,
      maxPoints: 25,
      severity: 'normal',
      explanation: 'Query length falls comfortably within normal web browsing profiles.'
    });
  }

  // Rule 2: Subdomain / Payload Entropy
  if (avgEntropy > 4.0 || highEntropyCount >= totalCount * 0.6) {
    const pts = 30;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_ENTROPY_HIGH',
      featureName: 'Character Shannon Entropy',
      observedValue: `${avgEntropy} bits/char avg; ${highEntropyCount}/${totalCount} queries > 3.6`,
      threshold: 'avg > 4.0 bits/char, or >= 60% of queries > 3.6',
      pointsContributed: pts,
      maxPoints: 30,
      severity: 'high',
      explanation: 'High character randomness indicates Base64/Base32/Hex obfuscation or encryption rather than natural language.'
    });
  } else if (avgEntropy > 3.4) {
    const pts = 15;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_ENTROPY_MED',
      featureName: 'Character Shannon Entropy',
      observedValue: `${avgEntropy} bits/char`,
      threshold: '> 3.4 bits/char',
      pointsContributed: pts,
      maxPoints: 30,
      severity: 'medium',
      explanation: 'Entropy is somewhat elevated above natural domain nomenclature.'
    });
  } else if (binarySignatureCount > 0) {
    const pts = 25;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_BINARY_PAYLOAD',
      featureName: 'Binary Bitstream Signature',
      observedValue: `${binarySignatureCount} queries`,
      threshold: 'Contains 0/1 binary streams',
      pointsContributed: pts,
      maxPoints: 30,
      severity: 'high',
      explanation: 'Subdomain labels are constructed from binary bit sequences (ASCII 48/49).'
    });
  } else {
    ruleContributions.push({
      ruleId: 'RULE_ENTROPY_NORMAL',
      featureName: 'Character Shannon Entropy',
      observedValue: `${avgEntropy} bits/char`,
      threshold: '<= 3.4 bits/char',
      pointsContributed: 0,
      maxPoints: 30,
      severity: 'normal',
      explanation: 'Character distribution follows natural language expectations.'
    });
  }

  // Rule 3: Unusual Character Composition
  if (avgUnusualCharRatio > 0.4) {
    const pts = 20;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_UNUSUAL_CHARS_HIGH',
      featureName: 'Unusual Character Ratio',
      observedValue: `${(avgUnusualCharRatio * 100).toFixed(0)}%`,
      threshold: '> 40%',
      pointsContributed: pts,
      maxPoints: 20,
      severity: 'high',
      explanation: 'Dense presence of digits, mixed case, or padding symbols (=) uncharacteristic of regular hostnames.'
    });
  } else if (avgUnusualCharRatio > 0.15) {
    const pts = 10;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_UNUSUAL_CHARS_MED',
      featureName: 'Unusual Character Ratio',
      observedValue: `${(avgUnusualCharRatio * 100).toFixed(0)}%`,
      threshold: '> 15%',
      pointsContributed: pts,
      maxPoints: 20,
      severity: 'medium',
      explanation: 'Noticeable proportion of non-alphabetic or uppercase characters.'
    });
  } else {
    ruleContributions.push({
      ruleId: 'RULE_UNUSUAL_CHARS_NORMAL',
      featureName: 'Unusual Character Ratio',
      observedValue: `${(avgUnusualCharRatio * 100).toFixed(0)}%`,
      threshold: '<= 15%',
      pointsContributed: 0,
      maxPoints: 20,
      severity: 'normal',
      explanation: 'Character set conforms to standard lowercase alphanumeric hostname patterns.'
    });
  }

  // Rule 4: Subdomain vs Domain Payload Ratio
  if (avgPayloadDomainRatio > 1.5) {
    const pts = 15;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_PAYLOAD_RATIO_HIGH',
      featureName: 'Payload-to-Domain Ratio',
      observedValue: `${avgPayloadDomainRatio}x`,
      threshold: '> 1.5x',
      pointsContributed: pts,
      maxPoints: 15,
      severity: 'high',
      explanation: 'The variable subdomain component is significantly larger than the base domain, typical of tunneling payloads.'
    });
  } else if (avgPayloadDomainRatio > 0.8) {
    const pts = 8;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_PAYLOAD_RATIO_MED',
      featureName: 'Payload-to-Domain Ratio',
      observedValue: `${avgPayloadDomainRatio}x`,
      threshold: '> 0.8x',
      pointsContributed: pts,
      maxPoints: 15,
      severity: 'medium',
      explanation: 'Subdomain occupies a substantial share of total query payload.'
    });
  } else {
    ruleContributions.push({
      ruleId: 'RULE_PAYLOAD_RATIO_NORMAL',
      featureName: 'Payload-to-Domain Ratio',
      observedValue: `${avgPayloadDomainRatio}x`,
      threshold: '<= 0.8x',
      pointsContributed: 0,
      maxPoints: 15,
      severity: 'normal',
      explanation: 'Subdomain length is proportional to base domain length.'
    });
  }

  // Rule 5: Volume & Pattern Randomness
  if (totalCount >= 4 && uniquenessRatio > 0.9 && avgSubdomainLength > 12) {
    const pts = 10;
    rawScore += pts;
    ruleContributions.push({
      ruleId: 'RULE_NON_CACHED_STREAM',
      featureName: 'Non-Cached Query Stream',
      observedValue: `${(uniquenessRatio * 100).toFixed(0)}% unique (${totalCount} pkts)`,
      threshold: '> 90% unique & len > 12',
      pointsContributed: pts,
      maxPoints: 10,
      severity: 'medium',
      explanation: 'Sequential burst of unique subdomains avoids DNS caching, common in exfiltration/stego channels.'
    });
  }

  // Normalize final score to 0 - 100
  const normalizedScore = Math.min(100, Math.max(0, rawScore));

  // Classification buckets
  let classification = 'Normal';
  let badgeColor = 'emerald';

  if (normalizedScore >= 81) {
    classification = 'Highly Suspicious';
    badgeColor = 'danger';
  } else if (normalizedScore >= 61) {
    classification = 'Potentially Suspicious';
    badgeColor = 'amber';
  } else if (normalizedScore >= 31) {
    classification = 'Unusual';
    badgeColor = 'cyan';
  } else {
    classification = 'Normal';
    badgeColor = 'emerald';
  }

  return {
    isEducationalDetector: true,
    disclaimer: 'Demonstration thresholds only. Not a commercial security benchmark.',
    queriesAnalyzed: totalCount,
    suspicionScore: normalizedScore,
    classification: classification,
    badgeColor: badgeColor,
    indicators: {
      averageQueryLength: avgQueryLength,
      averageSubdomainLength: avgSubdomainLength,
      averageEntropy: avgEntropy,
      averageUnusualCharRatio: avgUnusualCharRatio,
      averagePayloadDomainRatio: avgPayloadDomainRatio,
      longSubdomainCount: longSubdomainsCount,
      highEntropyCount: highEntropyCount,
      uniqueSubdomainsRatio: uniquenessRatio
    },
    ruleContributions: ruleContributions,
    queryDetails: queryDetails
  };
}

module.exports = {
  calculateShannonEntropy,
  calculateUnusualCharRatio,
  parseDomainParts,
  analyzeSingleQuery,
  analyzeTrafficBatch
};
