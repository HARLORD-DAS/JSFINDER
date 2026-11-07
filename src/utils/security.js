/**
 * Security and Data Sanitization Utilities
 */

/**
 * Escapes characters that could trigger formula execution in spreadsheet applications (CSV Injection)
 * Prepend a single quote (') if the string begins with =, +, -, @, tab, or carriage return.
 */
export function sanitizeCSVCell(val) {
  let str = String(val ?? '')
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str
  }
  return '"' + str.replace(/"/g, '""') + '"'
}

/**
 * Generates safe CSV string from scan results
 */
export function generateCSVReport(res) {
  if (!res || !Array.isArray(res.items)) return ''
  const headers = ['Target', 'Resource', 'Category', 'Finding Value']
  const rows = res.items.map(i => [
    sanitizeCSVCell(res.target),
    sanitizeCSVCell(i.resource || 'Global / Unassigned'),
    sanitizeCSVCell(i.cat),
    sanitizeCSVCell(i.value)
  ].join(','))
  return [headers.join(','), ...rows].join('\r\n')
}

/**
 * Generates structured JSON report
 */
export function generateJSONReport(res) {
  if (!res) return '{}'
  return JSON.stringify({
    scanner: 'JSLeakHunter',
    version: '2.0.0',
    target: res.target,
    scanned_at: new Date(res.time).toISOString(),
    total_findings: res.total,
    category_counts: res.counts,
    js_files_count: res.resources.length,
    js_files: res.resources.map(r => r.url),
    findings: res.items.map(({ cat, value, resource }) => ({
      category: cat,
      value,
      resource: resource || null
    })),
    disclaimer: 'Passive reconnaissance findings only. Verify vulnerabilities with explicit authorization.'
  }, null, 2)
}

/**
 * Validates that an external URL is strictly HTTP or HTTPS before rendering in an <a> tag.
 */
export function safeExternalUrl(url) {
  if (!url || typeof url !== 'string') return '#'
  const trimmed = url.trim()
  if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
    return trimmed
  }
  return '#'
}

/**
 * Determines whether a JavaScript resource belongs to the target domain or is third-party/CDN.
 */
export function getDomainInfo(resourceUrl, targetUrl) {
  try {
    const resHost = new URL(resourceUrl).hostname.toLowerCase()
    const targetHost = new URL(targetUrl).hostname.toLowerCase()
    const isFirstParty = resHost === targetHost || resHost.endsWith('.' + targetHost)
    return {
      domain: resHost,
      isFirstParty
    }
  } catch {
    return {
      domain: 'unknown',
      isFirstParty: false
    }
  }
}

/**
 * Category risk level classifications and descriptions
 */
export const CATEGORY_INFO = {
  'AWS Key': {
    severity: 'High Risk',
    badgeClass: 'badge-danger',
    color: '#ef4444',
    description: 'Exposed AWS Access Key IDs can be used to query or manipulate cloud infrastructure if paired with secret keys.'
  },
  'JWT': {
    severity: 'Medium Risk',
    badgeClass: 'badge-warning',
    color: '#a855f7',
    description: 'JSON Web Tokens may contain sensitive claims, user IDs, roles, or internal system identities.'
  },
  'Internal IP': {
    severity: 'Information',
    badgeClass: 'badge-info',
    color: '#3b82f6',
    description: 'RFC 1918 internal addresses reveal internal server topologies, subnets, and backend infrastructure layout.'
  },
  'API Endpoint': {
    severity: 'Reconnaissance',
    badgeClass: 'badge-cyan',
    color: '#06b6d4',
    description: 'Hidden API or internal routes aid reconnaissance by mapping private REST/GraphQL interfaces.'
  },
  'Email': {
    severity: 'Information',
    badgeClass: 'badge-neutral',
    color: '#10b981',
    description: 'Hardcoded developer or corporate email addresses can be targeted for credential stuffing or phishing.'
  }
}

