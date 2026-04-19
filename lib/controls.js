/**
 * ATLAS Controls Library · v2.1
 * ==============================
 *
 * Cross-mapped control catalogue covering 18 baselines:
 *   UAE:           UAE IA, NESA (ADSIC), CBUAE Info Security, DESC (Dubai Electronic Security)
 *   GCC:           SIA (Saudi-adjacent regional use), SAMA CSF (KSA), CBB Rulebook (Bahrain)
 *   Asia-Pacific:  HKMA CFI 2.0 + TM-E-1/TM-G-1 (Hong Kong), MAS TRM + Notice 655 (Singapore)
 *   International: CIS Controls v8, NIST CSF 2.0, NIST SP 800-53r5, PCI-DSS v4.0,
 *                  ISO 27001:2022, ISO 27002:2022, HIPAA Security Rule, SOC 2 TSC,
 *                  SWIFT Customer Security Programme (CSCF v2024)
 *
 * Every control in every baseline is tagged with a canonical THEME_KEY so findings
 * produced by the LLM (tagged with theme keys) can be cross-referenced against any
 * baseline. This is what powers the gap analysis and cross-mapping views.
 *
 * NOTE ON SCOPE: This library is intentionally curated to the most-cited controls
 * per baseline (~22 per baseline on average), not exhaustive. To extend: add more
 * control objects keyed by control ID within each baseline, preserving the theme_key
 * from THEMES so cross-mapping continues to work.
 */

// ============================================================
// CANONICAL THEMES — the pivot for cross-mapping
// ============================================================
// Each theme describes a control objective that appears (under different IDs and
// wording) across most baselines. Findings tag themselves with one or more
// theme keys; cross-mapping then resolves those keys to each baseline.
export const THEMES = {
  // ----- Governance & risk (8)
  GOV_POLICY:          { domain: 'governance',   label: 'Security policy & governance' },
  GOV_RISK_MGMT:       { domain: 'governance',   label: 'Information security risk management' },
  GOV_ROLES:           { domain: 'governance',   label: 'Roles, responsibilities & segregation of duties' },
  GOV_THIRD_PARTY:     { domain: 'governance',   label: 'Third-party & supplier risk management' },
  GOV_AWARENESS:       { domain: 'governance',   label: 'Security awareness & training' },
  GOV_ASSET_INV:       { domain: 'governance',   label: 'Asset inventory & classification' },
  GOV_CHANGE_MGMT:     { domain: 'governance',   label: 'Change & configuration management' },
  GOV_COMPLIANCE:      { domain: 'governance',   label: 'Regulatory compliance & audit' },

  // ----- Identity & access (8)
  IAM_ACCESS_CTRL:     { domain: 'iam',          label: 'Access control policy & enforcement' },
  IAM_LEAST_PRIV:      { domain: 'iam',          label: 'Least privilege & need-to-know' },
  IAM_MFA:             { domain: 'iam',          label: 'Multi-factor authentication' },
  IAM_PRIV_ACCESS:     { domain: 'iam',          label: 'Privileged access management' },
  IAM_IDENTITY_LIFECYCLE:{domain:'iam',          label: 'Identity lifecycle (joiners/movers/leavers)' },
  IAM_AUTH_STRENGTH:   { domain: 'iam',          label: 'Authentication strength & password policy' },
  IAM_SESSION:         { domain: 'iam',          label: 'Session management & re-authentication' },
  IAM_FEDERATION:      { domain: 'iam',          label: 'Federation & SSO' },

  // ----- Data protection (7)
  DATA_ENCRYPT_REST:   { domain: 'data',         label: 'Encryption at rest' },
  DATA_ENCRYPT_TRANSIT:{ domain: 'data',         label: 'Encryption in transit (TLS)' },
  DATA_KEY_MGMT:       { domain: 'data',         label: 'Cryptographic key management' },
  DATA_DLP:            { domain: 'data',         label: 'Data loss prevention' },
  DATA_RESIDENCY:      { domain: 'data',         label: 'Data residency & cross-border transfer' },
  DATA_CLASSIFICATION: { domain: 'data',         label: 'Data classification & handling' },
  DATA_RETENTION:      { domain: 'data',         label: 'Data retention & secure disposal' },

  // ----- Infrastructure & network (8)
  INF_NETWORK_SEG:     { domain: 'infrastructure', label: 'Network segmentation & micro-segmentation' },
  INF_PERIMETER:       { domain: 'infrastructure', label: 'Perimeter & edge protection (WAF/DDoS)' },
  INF_HARDENING:       { domain: 'infrastructure', label: 'System & configuration hardening (baselines)' },
  INF_PATCH:           { domain: 'infrastructure', label: 'Vulnerability & patch management' },
  INF_ENDPOINT:        { domain: 'infrastructure', label: 'Endpoint protection (EDR/antimalware)' },
  INF_BACKUP:          { domain: 'infrastructure', label: 'Backup & recovery' },
  INF_RESILIENCE:      { domain: 'infrastructure', label: 'High availability, DR & business continuity' },
  INF_PHYSICAL:        { domain: 'infrastructure', label: 'Physical & environmental security' },

  // ----- Application security (7)
  APP_SECURE_DEV:      { domain: 'application',  label: 'Secure SDLC & development lifecycle' },
  APP_INPUT_VAL:       { domain: 'application',  label: 'Input validation & output encoding' },
  APP_API_SEC:         { domain: 'application',  label: 'API security (authN/Z, rate limiting)' },
  APP_DEPS:            { domain: 'application',  label: 'Dependency & supply-chain management' },
  APP_SECRETS:         { domain: 'application',  label: 'Secrets management' },
  APP_APP_TESTING:     { domain: 'application',  label: 'Application security testing (SAST/DAST/pen)' },
  APP_WEB_SESSION:     { domain: 'application',  label: 'Web session & cookie security' },

  // ----- Logging, monitoring & response (6)
  LOG_CENTRAL:         { domain: 'logging',      label: 'Centralised logging & log retention' },
  LOG_INTEGRITY:       { domain: 'logging',      label: 'Log integrity & tamper protection' },
  LOG_MONITOR:         { domain: 'logging',      label: 'Continuous monitoring & SIEM' },
  LOG_DETECTION:       { domain: 'logging',      label: 'Threat detection & anomaly detection' },
  LOG_IR:              { domain: 'logging',      label: 'Incident response & forensics' },
  LOG_TIME_SYNC:       { domain: 'logging',      label: 'Clock synchronisation (NTP)' },

  // ----- Cloud-specific (6)
  CLOUD_SHARED_RESP:   { domain: 'cloud',        label: 'Cloud shared responsibility & provider assurance' },
  CLOUD_CONFIG:        { domain: 'cloud',        label: 'Cloud configuration posture (CSPM)' },
  CLOUD_IAM_PIVOT:     { domain: 'cloud',        label: 'Cloud IAM — roles, permissions, policies' },
  CLOUD_STORAGE:       { domain: 'cloud',        label: 'Cloud storage exposure (buckets, blobs)' },
  CLOUD_NATIVE_CTRL:   { domain: 'cloud',        label: 'Cloud-native control plane (org, SCP, policies)' },
  CLOUD_CONTAINERS:    { domain: 'cloud',        label: 'Container & Kubernetes security' },

  // ----- Threat & vulnerability (4)
  THREAT_THREAT_INTEL: { domain: 'threat',       label: 'Threat intelligence & modelling' },
  THREAT_VULN_MGMT:    { domain: 'threat',       label: 'Vulnerability management lifecycle' },
  THREAT_PENTEST:      { domain: 'threat',       label: 'Penetration testing & red team' },
  THREAT_EMAIL_PHISH:  { domain: 'threat',       label: 'Email & phishing protection' },

  // ----- Privacy & regulatory (4)
  PRIV_PII_HANDLING:   { domain: 'privacy',      label: 'PII handling & minimisation' },
  PRIV_CONSENT:        { domain: 'privacy',      label: 'Consent, notice & subject rights' },
  PRIV_BREACH_NOTIFY:  { domain: 'privacy',      label: 'Breach notification obligations' },
  PRIV_DP_IMPACT:      { domain: 'privacy',      label: 'Data protection impact assessment' },

  // ----- Payment-specific (4)
  PAY_CARDHOLDER_SCOPE:{ domain: 'payment',      label: 'Cardholder data scope reduction' },
  PAY_TOKENISATION:    { domain: 'payment',      label: 'Tokenisation & PAN protection' },
  PAY_SEG_NETWORK:     { domain: 'payment',      label: 'Cardholder network segmentation' },
  PAY_APPROVED_LISTS:  { domain: 'payment',      label: 'Approved crypto & vendor lists' },

  // ----- AI/ML (4)
  AI_GOV:              { domain: 'ai_ml',        label: 'AI governance & model lifecycle' },
  AI_PROMPT_INJECTION: { domain: 'ai_ml',        label: 'Prompt injection & output handling' },
  AI_TRAINING_DATA:    { domain: 'ai_ml',        label: 'Training data & PII in prompts' },
  AI_MODEL_ASSURANCE:  { domain: 'ai_ml',        label: 'Model assurance, bias & explainability' },

  // ----- Human resources (4)
  HR_SCREENING:        { domain: 'hr',           label: 'Personnel screening & vetting' },
  HR_ACCEPTABLE_USE:   { domain: 'hr',           label: 'Acceptable use & disciplinary process' },
  HR_TERMINATION:      { domain: 'hr',           label: 'Termination & revocation procedures' },
  HR_REMOTE_WORK:      { domain: 'hr',           label: 'Remote working & BYOD' },
};

// ============================================================
// BASELINES — each with curated controls tagged by theme_key
// ============================================================

// Helper to make control objects compact
const C = (id, title, themes) => ({ id, title, theme_keys: Array.isArray(themes) ? themes : [themes] });

export const BASELINES = {

  // ============================================================
  // UAE IA — Information Assurance Standards (TRA / TDRA)
  // ============================================================
  UAE_IA: {
    id: 'UAE_IA',
    name: 'UAE Information Assurance Standards',
    short: 'UAE IA',
    jurisdiction: 'UAE',
    authority: 'TDRA (formerly TRA)',
    family: 'uae',
    version: 'v1.1',
    description: 'Baseline information assurance standards for UAE federal government entities and critical sectors.',
    controls: [
      C('M1.1', 'Information Security Policy',                           ['GOV_POLICY']),
      C('M1.3', 'Risk Assessment & Treatment',                           ['GOV_RISK_MGMT']),
      C('M2.2', 'Segregation of Duties',                                 ['GOV_ROLES']),
      C('M3.1', 'Asset Inventory & Classification',                      ['GOV_ASSET_INV','DATA_CLASSIFICATION']),
      C('M4.1', 'Personnel Screening',                                   ['HR_SCREENING']),
      C('M4.4', 'Security Awareness Training',                           ['GOV_AWARENESS']),
      C('M5.1', 'Access Control Policy',                                 ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV']),
      C('M5.4', 'Privileged Access Management',                          ['IAM_PRIV_ACCESS','IAM_MFA']),
      C('M6.2', 'Cryptographic Controls',                                ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('M6.5', 'Data Residency in UAE',                                 ['DATA_RESIDENCY']),
      C('M7.2', 'Network Segmentation',                                  ['INF_NETWORK_SEG']),
      C('M7.5', 'System Hardening',                                      ['INF_HARDENING']),
      C('M8.1', 'Patch & Vulnerability Management',                      ['INF_PATCH','THREAT_VULN_MGMT']),
      C('M9.1', 'Logging & Log Retention',                               ['LOG_CENTRAL','LOG_TIME_SYNC']),
      C('M9.3', 'Security Monitoring',                                   ['LOG_MONITOR','LOG_DETECTION']),
      C('M10.1','Incident Response',                                     ['LOG_IR']),
      C('M11.1','Business Continuity & DR',                              ['INF_RESILIENCE','INF_BACKUP']),
      C('M12.2','Secure Development Lifecycle',                          ['APP_SECURE_DEV','APP_APP_TESTING']),
      C('M13.1','Third-party Security',                                  ['GOV_THIRD_PARTY']),
      C('M14.1','Physical Security',                                     ['INF_PHYSICAL']),
      C('M15.1','Personal Data Protection (PDPL alignment)',             ['PRIV_PII_HANDLING','PRIV_CONSENT']),
    ],
  },

  // ============================================================
  // NESA — Abu Dhabi Digital Authority (ADDA/ADSIC) UAE IAS adaptation
  // ============================================================
  NESA: {
    id: 'NESA',
    name: 'NESA Information Assurance Standards',
    short: 'NESA',
    jurisdiction: 'UAE (Abu Dhabi)',
    authority: 'Abu Dhabi Digital Authority (ADDA)',
    family: 'uae',
    version: 'v1.1',
    description: 'Emirate-level IA standards applied to Abu Dhabi government entities and critical information infrastructure.',
    controls: [
      C('T1.1.1', 'Security Governance Framework',                       ['GOV_POLICY','GOV_COMPLIANCE']),
      C('T1.2.1', 'Risk Management Programme',                           ['GOV_RISK_MGMT']),
      C('T1.3.1', 'Asset Management',                                    ['GOV_ASSET_INV']),
      C('T2.1.1', 'Access Control & Identity',                           ['IAM_ACCESS_CTRL','IAM_IDENTITY_LIFECYCLE']),
      C('T2.2.1', 'Authentication Mechanisms',                           ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('T2.3.1', 'Privileged User Controls',                            ['IAM_PRIV_ACCESS']),
      C('T3.1.1', 'Cryptography & Key Management',                       ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('T3.2.1', 'Data Classification',                                 ['DATA_CLASSIFICATION']),
      C('T3.3.1', 'Data Loss Prevention',                                ['DATA_DLP']),
      C('T4.1.1', 'Network Security Architecture',                       ['INF_NETWORK_SEG','INF_PERIMETER']),
      C('T4.2.1', 'System Hardening Baselines',                          ['INF_HARDENING']),
      C('T4.3.1', 'Malware & Endpoint Protection',                       ['INF_ENDPOINT']),
      C('T5.1.1', 'Vulnerability & Patch Management',                    ['INF_PATCH','THREAT_VULN_MGMT']),
      C('T5.2.1', 'Penetration Testing',                                 ['THREAT_PENTEST']),
      C('T6.1.1', 'Logging, Monitoring & SIEM',                          ['LOG_CENTRAL','LOG_MONITOR']),
      C('T6.2.1', 'Incident Management',                                 ['LOG_IR']),
      C('T7.1.1', 'Secure Software Development',                         ['APP_SECURE_DEV']),
      C('T7.2.1', 'Application Testing',                                 ['APP_APP_TESTING']),
      C('T8.1.1', 'Business Continuity & DR',                            ['INF_RESILIENCE','INF_BACKUP']),
      C('T9.1.1', 'Third-Party Risk',                                    ['GOV_THIRD_PARTY']),
      C('T9.2.1', 'Cloud Service Assurance',                             ['CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('T10.1.1','Data Residency & Cross-Border',                       ['DATA_RESIDENCY']),
    ],
  },

  // ============================================================
  // CBUAE — UAE Central Bank Information Security Regulation
  // ============================================================
  CBUAE: {
    id: 'CBUAE',
    name: 'CBUAE Information Security Regulation',
    short: 'CBUAE IS',
    jurisdiction: 'UAE',
    authority: 'Central Bank of the UAE',
    family: 'uae',
    version: '2020',
    description: 'Mandatory information security requirements for UAE-licensed financial institutions (banks, exchange houses, payment providers).',
    controls: [
      C('4.1.1', 'Board-approved Info Security Strategy',                ['GOV_POLICY']),
      C('4.2.1', 'Chief Information Security Officer (CISO)',            ['GOV_ROLES']),
      C('4.3.1', 'Risk Management Integration',                          ['GOV_RISK_MGMT']),
      C('5.1.1', 'Customer Data Confidentiality',                        ['PRIV_PII_HANDLING','DATA_CLASSIFICATION']),
      C('5.2.1', 'Data Residency — UAE',                                 ['DATA_RESIDENCY']),
      C('6.1.1', 'Customer Authentication',                              ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('6.2.1', 'Privileged Access Controls',                           ['IAM_PRIV_ACCESS']),
      C('6.3.1', 'Segregation of Duties',                                ['GOV_ROLES','IAM_LEAST_PRIV']),
      C('7.1.1', 'Encryption of Customer Data',                          ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT']),
      C('7.2.1', 'Cryptographic Key Management',                         ['DATA_KEY_MGMT']),
      C('8.1.1', 'Secure Software Development',                          ['APP_SECURE_DEV','APP_APP_TESTING']),
      C('8.2.1', 'API Security Controls',                                ['APP_API_SEC']),
      C('9.1.1', 'Network Segmentation — Customer Zones',                ['INF_NETWORK_SEG']),
      C('9.2.1', 'DDoS Protection',                                      ['INF_PERIMETER']),
      C('10.1.1','Incident Detection & Response',                        ['LOG_DETECTION','LOG_IR']),
      C('10.2.1','Regulatory Incident Notification (72-hour)',           ['PRIV_BREACH_NOTIFY']),
      C('11.1.1','Third-Party & Outsourcing Risk',                       ['GOV_THIRD_PARTY']),
      C('11.2.1','Cloud Service Adoption',                               ['CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('12.1.1','Business Continuity & Recovery Time',                  ['INF_RESILIENCE','INF_BACKUP']),
      C('13.1.1','Penetration Testing — Annual',                         ['THREAT_PENTEST']),
      C('14.1.1','Logging, Monitoring & SIEM',                           ['LOG_CENTRAL','LOG_MONITOR']),
      C('15.1.1','Security Awareness for Staff',                         ['GOV_AWARENESS']),
    ],
  },

  // ============================================================
  // DESC — Dubai Electronic Security Center · ISR
  // ============================================================
  DESC: {
    id: 'DESC',
    name: 'Dubai Information Security Regulation (ISR)',
    short: 'DESC ISR',
    jurisdiction: 'UAE (Dubai)',
    authority: 'Dubai Electronic Security Center',
    family: 'uae',
    version: 'v2',
    description: 'Mandatory information security standard for Dubai government entities and critical sectors, aligned to ISO 27001.',
    controls: [
      C('ISR-A1','Security Governance',                                  ['GOV_POLICY']),
      C('ISR-A2','Compliance & Audit',                                   ['GOV_COMPLIANCE']),
      C('ISR-B1','HR Security — Screening & Training',                   ['HR_SCREENING','GOV_AWARENESS']),
      C('ISR-C1','Asset Management & Classification',                    ['GOV_ASSET_INV','DATA_CLASSIFICATION']),
      C('ISR-D1','Access Control',                                       ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV']),
      C('ISR-D2','Privileged Access',                                    ['IAM_PRIV_ACCESS','IAM_MFA']),
      C('ISR-E1','Cryptography',                                         ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('ISR-F1','Physical Security',                                    ['INF_PHYSICAL']),
      C('ISR-G1','Operations Security — Hardening',                      ['INF_HARDENING','INF_PATCH']),
      C('ISR-G2','Logging & Monitoring',                                 ['LOG_CENTRAL','LOG_MONITOR']),
      C('ISR-H1','Communications Security — Networks',                   ['INF_NETWORK_SEG']),
      C('ISR-I1','Secure Development',                                   ['APP_SECURE_DEV']),
      C('ISR-J1','Supplier & Cloud',                                     ['GOV_THIRD_PARTY','CLOUD_SHARED_RESP']),
      C('ISR-K1','Incident Management',                                  ['LOG_IR']),
      C('ISR-L1','Continuity & DR',                                      ['INF_RESILIENCE']),
      C('ISR-M1','Data Residency (Dubai)',                               ['DATA_RESIDENCY']),
    ],
  },

  // ============================================================
  // SIA — Saudi National Cybersecurity Authority (NCA) Essential Cybersecurity Controls
  // (often referenced as "SIA" in regional use; officially NCA ECC)
  // ============================================================
  SIA: {
    id: 'SIA',
    name: 'NCA Essential Cybersecurity Controls (ECC)',
    short: 'NCA ECC',
    jurisdiction: 'Saudi Arabia',
    authority: 'National Cybersecurity Authority (NCA)',
    family: 'gcc',
    version: 'ECC-1:2018',
    description: 'Minimum cybersecurity requirements for Saudi national bodies, government entities and CNI operators.',
    controls: [
      C('1-1','Cybersecurity Strategy',                                   ['GOV_POLICY']),
      C('1-3','Cybersecurity Risk Management',                            ['GOV_RISK_MGMT']),
      C('1-5','Cybersecurity in Project Management',                      ['GOV_CHANGE_MGMT']),
      C('2-1','Asset Management',                                         ['GOV_ASSET_INV']),
      C('2-2','Identity and Access Management',                           ['IAM_ACCESS_CTRL','IAM_MFA']),
      C('2-3','Information System and Processing Facilities Protection',  ['INF_HARDENING','INF_ENDPOINT']),
      C('2-4','Email Protection',                                         ['THREAT_EMAIL_PHISH']),
      C('2-5','Networks Security Management',                             ['INF_NETWORK_SEG']),
      C('2-6','Mobile Devices Security',                                  ['HR_REMOTE_WORK']),
      C('2-7','Data and Information Protection',                          ['DATA_CLASSIFICATION','DATA_ENCRYPT_REST']),
      C('2-8','Cryptography',                                             ['DATA_KEY_MGMT','DATA_ENCRYPT_TRANSIT']),
      C('2-9','Backup and Recovery',                                      ['INF_BACKUP']),
      C('2-10','Vulnerabilities Management',                              ['INF_PATCH','THREAT_VULN_MGMT']),
      C('2-11','Penetration Testing',                                     ['THREAT_PENTEST']),
      C('2-12','Cybersecurity Event Logs and Monitoring',                 ['LOG_CENTRAL','LOG_MONITOR']),
      C('2-13','Cybersecurity Incident and Threat Management',            ['LOG_IR','THREAT_THREAT_INTEL']),
      C('2-14','Physical Security',                                       ['INF_PHYSICAL']),
      C('2-15','Web Application Security',                                ['APP_SECURE_DEV','APP_API_SEC']),
      C('4-1','Third-Party Cybersecurity',                                ['GOV_THIRD_PARTY']),
      C('4-2','Cloud Computing & Hosting Cybersecurity',                  ['CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('5-1','Industrial Control Systems (ICS) Protection',              ['INF_NETWORK_SEG']),
    ],
  },

  // ============================================================
  // SAMA CSF — Saudi Arabian Monetary Authority Cyber Security Framework
  // ============================================================
  SAMA: {
    id: 'SAMA',
    name: 'SAMA Cyber Security Framework',
    short: 'SAMA CSF',
    jurisdiction: 'Saudi Arabia',
    authority: 'Saudi Central Bank (SAMA)',
    family: 'gcc',
    version: 'v1.0',
    description: 'Mandatory cyber security framework for SAMA-regulated financial institutions.',
    controls: [
      C('3.1.1', 'Cyber Security Governance',                             ['GOV_POLICY','GOV_ROLES']),
      C('3.1.2', 'Cyber Security Strategy',                               ['GOV_POLICY']),
      C('3.1.4', 'Cyber Security Risk Management',                        ['GOV_RISK_MGMT']),
      C('3.2.1', 'Human Resources Security',                              ['HR_SCREENING','HR_TERMINATION']),
      C('3.2.2', 'Cyber Security Awareness',                              ['GOV_AWARENESS']),
      C('3.3.1', 'Identity & Access Management',                          ['IAM_ACCESS_CTRL','IAM_IDENTITY_LIFECYCLE','IAM_MFA']),
      C('3.3.2', 'Application Security',                                  ['APP_SECURE_DEV','APP_API_SEC']),
      C('3.3.3', 'Change Management',                                     ['GOV_CHANGE_MGMT']),
      C('3.3.4', 'Infrastructure Security',                               ['INF_HARDENING','INF_NETWORK_SEG']),
      C('3.3.5', 'Cryptography',                                          ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('3.3.6', 'Bring Your Own Device (BYOD)',                          ['HR_REMOTE_WORK']),
      C('3.3.7', 'Secure Disposal of Information Assets',                 ['DATA_RETENTION']),
      C('3.3.8', 'Payment Systems',                                       ['PAY_CARDHOLDER_SCOPE','PAY_TOKENISATION']),
      C('3.3.9', 'Electronic Banking Services',                           ['IAM_MFA','APP_API_SEC']),
      C('3.3.10','Cybersecurity Event Management',                        ['LOG_CENTRAL','LOG_MONITOR']),
      C('3.3.11','Cybersecurity Incident Management',                     ['LOG_IR','PRIV_BREACH_NOTIFY']),
      C('3.3.12','Threat Management',                                     ['THREAT_THREAT_INTEL','LOG_DETECTION']),
      C('3.3.13','Vulnerability Management',                              ['THREAT_VULN_MGMT','INF_PATCH']),
      C('3.4.1', 'Business Continuity Management',                        ['INF_RESILIENCE','INF_BACKUP']),
      C('3.5.1', 'Third Party & Outsourcing',                             ['GOV_THIRD_PARTY']),
      C('3.5.2', 'Cloud Computing',                                       ['CLOUD_SHARED_RESP','CLOUD_CONFIG']),
    ],
  },

  // ============================================================
  // CBB — Central Bank of Bahrain Rulebook (Volume 1 — OM: Operational Risk)
  // ============================================================
  CBB: {
    id: 'CBB',
    name: 'CBB Rulebook — Operational Risk & Cyber Security',
    short: 'CBB',
    jurisdiction: 'Bahrain',
    authority: 'Central Bank of Bahrain',
    family: 'gcc',
    version: '2022',
    description: 'Operational risk and cyber security module for CBB-licensed financial institutions in Bahrain.',
    controls: [
      C('OM-6.1.1','Cyber Security Risk Governance',                      ['GOV_POLICY']),
      C('OM-6.1.4','Board Oversight of Cyber Risk',                       ['GOV_ROLES']),
      C('OM-6.2.1','Risk Assessment',                                     ['GOV_RISK_MGMT']),
      C('OM-6.3.1','Information Classification',                          ['DATA_CLASSIFICATION']),
      C('OM-6.4.1','Identity & Access Management',                        ['IAM_ACCESS_CTRL','IAM_MFA']),
      C('OM-6.4.4','Privileged Access',                                   ['IAM_PRIV_ACCESS']),
      C('OM-6.5.1','Encryption Standards',                                ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT']),
      C('OM-6.6.1','Network Protection',                                  ['INF_NETWORK_SEG','INF_PERIMETER']),
      C('OM-6.7.1','Secure System Configuration',                         ['INF_HARDENING']),
      C('OM-6.8.1','Vulnerability Management',                            ['THREAT_VULN_MGMT','INF_PATCH']),
      C('OM-6.9.1','Security Monitoring',                                 ['LOG_MONITOR','LOG_CENTRAL']),
      C('OM-6.10.1','Incident Management',                                ['LOG_IR']),
      C('OM-6.10.3','Regulatory Notification',                            ['PRIV_BREACH_NOTIFY']),
      C('OM-6.11.1','Third Party Risk',                                   ['GOV_THIRD_PARTY']),
      C('OM-6.11.3','Cloud Services',                                     ['CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('OM-6.12.1','Data Residency',                                     ['DATA_RESIDENCY']),
      C('OM-6.13.1','BCP & DR',                                           ['INF_RESILIENCE','INF_BACKUP']),
      C('OM-6.14.1','Penetration Testing',                                ['THREAT_PENTEST']),
      C('OM-6.15.1','Customer Authentication — Strong',                   ['IAM_MFA']),
    ],
  },

  // ============================================================
  // CIS Controls v8
  // ============================================================
  CIS: {
    id: 'CIS',
    name: 'CIS Critical Security Controls',
    short: 'CIS v8',
    jurisdiction: 'International',
    authority: 'Center for Internet Security',
    family: 'international',
    version: 'v8',
    description: 'Prioritised set of 18 critical security controls for defending against the most pervasive attacks.',
    controls: [
      C('1','Inventory & Control of Enterprise Assets',                   ['GOV_ASSET_INV']),
      C('2','Inventory & Control of Software Assets',                     ['GOV_ASSET_INV','APP_DEPS']),
      C('3','Data Protection',                                            ['DATA_CLASSIFICATION','DATA_ENCRYPT_REST','DATA_DLP']),
      C('4','Secure Configuration of Enterprise Assets & Software',       ['INF_HARDENING']),
      C('5','Account Management',                                         ['IAM_IDENTITY_LIFECYCLE']),
      C('6','Access Control Management',                                  ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV','IAM_MFA']),
      C('7','Continuous Vulnerability Management',                        ['THREAT_VULN_MGMT','INF_PATCH']),
      C('8','Audit Log Management',                                       ['LOG_CENTRAL','LOG_INTEGRITY']),
      C('9','Email & Web Browser Protections',                            ['THREAT_EMAIL_PHISH']),
      C('10','Malware Defenses',                                          ['INF_ENDPOINT']),
      C('11','Data Recovery',                                             ['INF_BACKUP']),
      C('12','Network Infrastructure Management',                         ['INF_NETWORK_SEG']),
      C('13','Network Monitoring & Defense',                              ['LOG_MONITOR','LOG_DETECTION']),
      C('14','Security Awareness & Skills Training',                      ['GOV_AWARENESS']),
      C('15','Service Provider Management',                               ['GOV_THIRD_PARTY']),
      C('16','Application Software Security',                             ['APP_SECURE_DEV','APP_INPUT_VAL','APP_APP_TESTING']),
      C('17','Incident Response Management',                              ['LOG_IR']),
      C('18','Penetration Testing',                                       ['THREAT_PENTEST']),
    ],
  },

  // ============================================================
  // NIST CSF 2.0
  // ============================================================
  NIST_CSF: {
    id: 'NIST_CSF',
    name: 'NIST Cybersecurity Framework',
    short: 'NIST CSF',
    jurisdiction: 'International',
    authority: 'NIST',
    family: 'international',
    version: '2.0',
    description: 'Outcome-based framework organising cybersecurity activities into six functions: Govern, Identify, Protect, Detect, Respond, Recover.',
    controls: [
      C('GV.OC','Organizational Context',                                 ['GOV_POLICY']),
      C('GV.RM','Risk Management Strategy',                               ['GOV_RISK_MGMT']),
      C('GV.RR','Roles, Responsibilities & Authorities',                  ['GOV_ROLES']),
      C('GV.SC','Supply Chain Risk Management',                           ['GOV_THIRD_PARTY']),
      C('GV.OV','Oversight (Audit & Compliance)',                         ['GOV_COMPLIANCE']),
      C('ID.AM','Asset Management',                                       ['GOV_ASSET_INV']),
      C('ID.RA','Risk Assessment',                                        ['GOV_RISK_MGMT']),
      C('PR.AA','Identity Management, Authentication & Access Control',   ['IAM_ACCESS_CTRL','IAM_MFA','IAM_PRIV_ACCESS']),
      C('PR.AT','Awareness & Training',                                   ['GOV_AWARENESS']),
      C('PR.DS','Data Security',                                          ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_CLASSIFICATION']),
      C('PR.PS','Platform Security',                                      ['INF_HARDENING','INF_PATCH']),
      C('PR.IR','Technology Infrastructure Resilience',                   ['INF_RESILIENCE','INF_NETWORK_SEG']),
      C('DE.CM','Continuous Monitoring',                                  ['LOG_MONITOR','LOG_CENTRAL']),
      C('DE.AE','Adverse Event Analysis',                                 ['LOG_DETECTION']),
      C('RS.MA','Incident Management',                                    ['LOG_IR']),
      C('RS.AN','Incident Analysis',                                      ['LOG_IR']),
      C('RS.CO','Incident Response Communication',                        ['PRIV_BREACH_NOTIFY']),
      C('RS.MI','Incident Mitigation',                                    ['LOG_IR']),
      C('RC.RP','Recovery Plan Execution',                                ['INF_BACKUP','INF_RESILIENCE']),
      C('RC.CO','Recovery Communications',                                ['LOG_IR']),
    ],
  },

  // ============================================================
  // NIST SP 800-53 Revision 5 (curated key controls)
  // ============================================================
  NIST_800_53: {
    id: 'NIST_800_53',
    name: 'NIST Special Publication 800-53',
    short: 'NIST 800-53',
    jurisdiction: 'International',
    authority: 'NIST',
    family: 'international',
    version: 'Revision 5',
    description: 'Comprehensive catalog of security and privacy controls for federal information systems (curated key control families).',
    controls: [
      C('AC-2', 'Account Management',                                     ['IAM_IDENTITY_LIFECYCLE']),
      C('AC-3', 'Access Enforcement',                                     ['IAM_ACCESS_CTRL']),
      C('AC-6', 'Least Privilege',                                        ['IAM_LEAST_PRIV']),
      C('AC-17','Remote Access',                                          ['HR_REMOTE_WORK','IAM_MFA']),
      C('AT-2', 'Literacy Training & Awareness',                          ['GOV_AWARENESS']),
      C('AU-2', 'Event Logging',                                          ['LOG_CENTRAL']),
      C('AU-6', 'Audit Record Review, Analysis & Reporting',              ['LOG_MONITOR']),
      C('AU-9', 'Protection of Audit Information',                        ['LOG_INTEGRITY']),
      C('CA-8', 'Penetration Testing',                                    ['THREAT_PENTEST']),
      C('CM-2', 'Baseline Configuration',                                 ['INF_HARDENING']),
      C('CM-3', 'Configuration Change Control',                           ['GOV_CHANGE_MGMT']),
      C('CP-9', 'System Backup',                                          ['INF_BACKUP']),
      C('CP-10','System Recovery & Reconstitution',                       ['INF_RESILIENCE']),
      C('IA-2', 'Identification & Authentication (Organizational Users)', ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('IA-5', 'Authenticator Management',                               ['IAM_AUTH_STRENGTH']),
      C('IR-4', 'Incident Handling',                                      ['LOG_IR']),
      C('IR-6', 'Incident Reporting',                                     ['PRIV_BREACH_NOTIFY']),
      C('PL-8', 'Security Architecture',                                  ['GOV_POLICY']),
      C('RA-3', 'Risk Assessment',                                        ['GOV_RISK_MGMT']),
      C('RA-5', 'Vulnerability Monitoring & Scanning',                    ['THREAT_VULN_MGMT']),
      C('SA-11','Developer Testing & Evaluation',                         ['APP_APP_TESTING']),
      C('SA-15','Development Process, Standards & Tools',                 ['APP_SECURE_DEV']),
      C('SC-7', 'Boundary Protection',                                    ['INF_NETWORK_SEG','INF_PERIMETER']),
      C('SC-8', 'Transmission Confidentiality & Integrity',               ['DATA_ENCRYPT_TRANSIT']),
      C('SC-12','Cryptographic Key Establishment & Management',           ['DATA_KEY_MGMT']),
      C('SC-13','Cryptographic Protection',                               ['DATA_ENCRYPT_REST']),
      C('SC-28','Protection of Information at Rest',                      ['DATA_ENCRYPT_REST']),
      C('SI-2', 'Flaw Remediation',                                       ['INF_PATCH']),
      C('SI-3', 'Malicious Code Protection',                              ['INF_ENDPOINT']),
      C('SI-4', 'System Monitoring',                                      ['LOG_MONITOR','LOG_DETECTION']),
      C('SR-3', 'Supply Chain Controls & Processes',                      ['GOV_THIRD_PARTY','APP_DEPS']),
    ],
  },

  // ============================================================
  // PCI-DSS v4.0 (curated key requirements)
  // ============================================================
  PCI_DSS: {
    id: 'PCI_DSS',
    name: 'Payment Card Industry Data Security Standard',
    short: 'PCI-DSS',
    jurisdiction: 'International',
    authority: 'PCI Security Standards Council',
    family: 'international',
    version: 'v4.0',
    description: 'Mandatory security standard for entities that store, process, or transmit cardholder data.',
    controls: [
      C('1.2', 'Network Segmentation — CDE Isolation',                    ['PAY_SEG_NETWORK','INF_NETWORK_SEG']),
      C('1.4', 'Boundary Controls — Firewalls',                           ['INF_PERIMETER']),
      C('2.2', 'Secure Configuration Standards',                          ['INF_HARDENING']),
      C('3.3', 'Do Not Store Sensitive Authentication Data',              ['PAY_CARDHOLDER_SCOPE']),
      C('3.5', 'PAN Rendered Unreadable',                                 ['PAY_TOKENISATION','DATA_ENCRYPT_REST']),
      C('3.6', 'Key Management Procedures',                               ['DATA_KEY_MGMT']),
      C('3.7', 'Approved Cryptography',                                   ['PAY_APPROVED_LISTS']),
      C('4.1', 'Strong Cryptography in Transit',                          ['DATA_ENCRYPT_TRANSIT']),
      C('5.2', 'Anti-Malware Deployment',                                 ['INF_ENDPOINT']),
      C('6.2', 'Secure Development Lifecycle',                            ['APP_SECURE_DEV']),
      C('6.3', 'Vulnerability Identification',                            ['THREAT_VULN_MGMT']),
      C('6.4', 'Web Application Firewall / Code Review',                  ['APP_API_SEC','INF_PERIMETER']),
      C('7.2', 'Role-Based Access Controls',                              ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV']),
      C('8.3', 'Multi-Factor Authentication',                             ['IAM_MFA']),
      C('8.4', 'MFA for CDE Access',                                      ['IAM_MFA','IAM_PRIV_ACCESS']),
      C('9.5', 'Physical Access to CDE',                                  ['INF_PHYSICAL']),
      C('10.2','Audit Log Implementation',                                ['LOG_CENTRAL']),
      C('10.3','Audit Log Protection',                                    ['LOG_INTEGRITY']),
      C('10.6','Time Synchronization',                                    ['LOG_TIME_SYNC']),
      C('11.3','External & Internal Penetration Testing',                 ['THREAT_PENTEST']),
      C('11.5','Change-Detection / Integrity Monitoring',                 ['LOG_DETECTION']),
      C('12.3','Information Security Policy',                             ['GOV_POLICY']),
      C('12.8','Third-Party Service Provider Management',                 ['GOV_THIRD_PARTY']),
      C('12.10','Incident Response Plan',                                 ['LOG_IR']),
    ],
  },

  // ============================================================
  // ISO/IEC 27001:2022 — ISMS clauses
  // ============================================================
  ISO_27001: {
    id: 'ISO_27001',
    name: 'ISO/IEC 27001 Information Security Management',
    short: 'ISO 27001',
    jurisdiction: 'International',
    authority: 'ISO/IEC',
    family: 'international',
    version: '2022',
    description: 'International standard for establishing, implementing, maintaining and continually improving an information security management system.',
    controls: [
      C('4','Context of the Organization',                                ['GOV_POLICY']),
      C('5.1','Leadership & Commitment',                                  ['GOV_ROLES']),
      C('5.2','Information Security Policy',                              ['GOV_POLICY']),
      C('5.3','Roles, Responsibilities & Authorities',                    ['GOV_ROLES']),
      C('6.1','Risk Assessment & Treatment',                              ['GOV_RISK_MGMT']),
      C('6.2','Information Security Objectives',                          ['GOV_POLICY']),
      C('7.2','Competence',                                               ['GOV_AWARENESS']),
      C('7.3','Awareness',                                                ['GOV_AWARENESS']),
      C('8.1','Operational Planning & Control',                           ['GOV_CHANGE_MGMT']),
      C('8.2','Information Security Risk Assessment',                     ['GOV_RISK_MGMT']),
      C('9.1','Monitoring, Measurement, Analysis & Evaluation',           ['LOG_MONITOR']),
      C('9.2','Internal Audit',                                           ['GOV_COMPLIANCE']),
      C('9.3','Management Review',                                        ['GOV_POLICY']),
      C('10.1','Nonconformity & Corrective Action',                       ['GOV_COMPLIANCE']),
      C('10.2','Continual Improvement',                                   ['GOV_POLICY']),
    ],
  },

  // ============================================================
  // ISO/IEC 27002:2022 — Annex A controls (curated)
  // ============================================================
  ISO_27002: {
    id: 'ISO_27002',
    name: 'ISO/IEC 27002 Information Security Controls',
    short: 'ISO 27002',
    jurisdiction: 'International',
    authority: 'ISO/IEC',
    family: 'international',
    version: '2022',
    description: 'Code of practice providing implementation guidance for information security controls (curated key controls).',
    controls: [
      C('5.1', 'Policies for Information Security',                       ['GOV_POLICY']),
      C('5.9', 'Inventory of Information & Other Assets',                 ['GOV_ASSET_INV']),
      C('5.12','Classification of Information',                           ['DATA_CLASSIFICATION']),
      C('5.15','Access Control',                                          ['IAM_ACCESS_CTRL']),
      C('5.16','Identity Management',                                     ['IAM_IDENTITY_LIFECYCLE']),
      C('5.17','Authentication Information',                              ['IAM_AUTH_STRENGTH']),
      C('5.18','Access Rights',                                           ['IAM_LEAST_PRIV']),
      C('5.19','Information Security in Supplier Relationships',          ['GOV_THIRD_PARTY']),
      C('5.23','Information Security for use of Cloud Services',          ['CLOUD_SHARED_RESP']),
      C('5.24','Information Security Incident Planning & Prep',           ['LOG_IR']),
      C('5.30','ICT Readiness for Business Continuity',                   ['INF_RESILIENCE']),
      C('6.1', 'Screening',                                               ['HR_SCREENING']),
      C('6.3', 'Information Security Awareness, Education & Training',    ['GOV_AWARENESS']),
      C('6.5', 'Responsibilities after Termination or Change',            ['HR_TERMINATION']),
      C('6.7', 'Remote Working',                                          ['HR_REMOTE_WORK']),
      C('7.4', 'Physical Security Monitoring',                            ['INF_PHYSICAL']),
      C('8.1', 'User Endpoint Devices',                                   ['INF_ENDPOINT']),
      C('8.2', 'Privileged Access Rights',                                ['IAM_PRIV_ACCESS']),
      C('8.5', 'Secure Authentication',                                   ['IAM_MFA']),
      C('8.8', 'Management of Technical Vulnerabilities',                 ['THREAT_VULN_MGMT','INF_PATCH']),
      C('8.9', 'Configuration Management',                                ['INF_HARDENING','GOV_CHANGE_MGMT']),
      C('8.12','Data Leakage Prevention',                                 ['DATA_DLP']),
      C('8.13','Information Backup',                                      ['INF_BACKUP']),
      C('8.15','Logging',                                                 ['LOG_CENTRAL']),
      C('8.16','Monitoring Activities',                                   ['LOG_MONITOR']),
      C('8.20','Networks Security',                                       ['INF_NETWORK_SEG']),
      C('8.23','Web Filtering',                                           ['INF_PERIMETER']),
      C('8.24','Use of Cryptography',                                     ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT']),
      C('8.25','Secure Development Lifecycle',                            ['APP_SECURE_DEV']),
      C('8.28','Secure Coding',                                           ['APP_INPUT_VAL']),
      C('8.29','Security Testing in Development & Acceptance',            ['APP_APP_TESTING']),
    ],
  },

  // ============================================================
  // HIPAA Security Rule (curated safeguards)
  // ============================================================
  HIPAA: {
    id: 'HIPAA',
    name: 'HIPAA Security Rule',
    short: 'HIPAA',
    jurisdiction: 'United States',
    authority: 'HHS · OCR',
    family: 'international',
    version: '45 CFR Part 164',
    description: 'Technical, administrative and physical safeguards for electronic protected health information (ePHI).',
    controls: [
      C('164.308(a)(1)','Security Management Process',                    ['GOV_RISK_MGMT']),
      C('164.308(a)(2)','Assigned Security Responsibility',               ['GOV_ROLES']),
      C('164.308(a)(3)','Workforce Security',                             ['HR_SCREENING','HR_TERMINATION']),
      C('164.308(a)(4)','Information Access Management',                  ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV']),
      C('164.308(a)(5)','Security Awareness & Training',                  ['GOV_AWARENESS']),
      C('164.308(a)(6)','Security Incident Procedures',                   ['LOG_IR']),
      C('164.308(a)(7)','Contingency Plan',                               ['INF_RESILIENCE','INF_BACKUP']),
      C('164.308(a)(8)','Evaluation (periodic technical/non-technical)',  ['GOV_COMPLIANCE']),
      C('164.308(b)(1)','Business Associate Contracts',                   ['GOV_THIRD_PARTY']),
      C('164.310(a)(1)','Facility Access Controls',                       ['INF_PHYSICAL']),
      C('164.312(a)(1)','Access Control — Unique User ID & Auto Logoff',  ['IAM_ACCESS_CTRL','IAM_SESSION']),
      C('164.312(a)(2)','Encryption & Decryption of ePHI',                ['DATA_ENCRYPT_REST']),
      C('164.312(b)','Audit Controls',                                    ['LOG_CENTRAL']),
      C('164.312(c)','Integrity Controls for ePHI',                       ['LOG_INTEGRITY']),
      C('164.312(d)','Person or Entity Authentication',                   ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('164.312(e)','Transmission Security',                             ['DATA_ENCRYPT_TRANSIT']),
      C('164.400','Breach Notification',                                  ['PRIV_BREACH_NOTIFY']),
    ],
  },

  // ============================================================
  // SOC 2 — Trust Services Criteria
  // ============================================================
  SOC2: {
    id: 'SOC2',
    name: 'SOC 2 Trust Services Criteria',
    short: 'SOC 2',
    jurisdiction: 'International',
    authority: 'AICPA',
    family: 'international',
    version: '2017 (TSC)',
    description: 'Trust Services Criteria for service organization controls covering security, availability, processing integrity, confidentiality and privacy.',
    controls: [
      C('CC1.1','Integrity & Ethical Values',                             ['GOV_POLICY']),
      C('CC1.2','Board Oversight',                                        ['GOV_ROLES']),
      C('CC2.1','Communication of Objectives',                            ['GOV_POLICY']),
      C('CC3.1','Risk Identification',                                    ['GOV_RISK_MGMT']),
      C('CC3.2','Risk Assessment',                                        ['GOV_RISK_MGMT']),
      C('CC4.1','Ongoing & Separate Evaluations',                         ['GOV_COMPLIANCE']),
      C('CC5.1','Control Activities to Address Risks',                    ['GOV_RISK_MGMT']),
      C('CC6.1','Logical Access — Identification & Authentication',       ['IAM_ACCESS_CTRL','IAM_MFA']),
      C('CC6.2','Logical Access — Provisioning & Deprovisioning',         ['IAM_IDENTITY_LIFECYCLE']),
      C('CC6.3','Logical Access — Segregation of Duties',                 ['GOV_ROLES','IAM_LEAST_PRIV']),
      C('CC6.6','Logical Access — External Threats',                      ['INF_PERIMETER']),
      C('CC6.7','Transmission & Transport of Information',                ['DATA_ENCRYPT_TRANSIT']),
      C('CC6.8','Malicious Software Prevention',                          ['INF_ENDPOINT']),
      C('CC7.1','System Monitoring for Anomalies',                        ['LOG_MONITOR','LOG_DETECTION']),
      C('CC7.2','Monitoring of Controls',                                 ['LOG_MONITOR']),
      C('CC7.3','Incident Evaluation',                                    ['LOG_IR']),
      C('CC7.4','Incident Response',                                      ['LOG_IR']),
      C('CC7.5','Recovery from Incidents',                                ['INF_RESILIENCE']),
      C('CC8.1','Change Management',                                      ['GOV_CHANGE_MGMT']),
      C('CC9.1','Risk Mitigation — Business Disruptions',                 ['INF_RESILIENCE','INF_BACKUP']),
      C('CC9.2','Vendor & Business Partner Risk',                         ['GOV_THIRD_PARTY']),
      C('A1.2','Environmental Threats & Availability',                    ['INF_PHYSICAL','INF_RESILIENCE']),
      C('C1.1','Confidentiality — Identify & Maintain',                   ['DATA_CLASSIFICATION']),
      C('C1.2','Confidentiality — Retention & Disposal',                  ['DATA_RETENTION']),
      C('P1.1','Privacy — Notice & Communication',                        ['PRIV_CONSENT']),
    ],
  },

  // ============================================================
  // HKMA — Hong Kong Monetary Authority · Cybersecurity Fortification Initiative (CFI 2.0) + TM-E-1 / TM-G-1
  // ============================================================
  HKMA: {
    id: 'HKMA',
    name: 'HKMA Cybersecurity Fortification Initiative',
    short: 'HKMA CFI',
    jurisdiction: 'Hong Kong',
    authority: 'Hong Kong Monetary Authority',
    family: 'apac',
    version: 'CFI 2.0 / TM-E-1 / TM-G-1',
    description: 'Mandatory cyber resilience framework for HKMA-authorised institutions, combining CFI 2.0 (C-RAF/iCAST/PDSF) with TM-E-1 technology risk and TM-G-1 general IT supervisory modules.',
    controls: [
      C('CFI-GV.1',  'Cyber Resilience Governance & Board Oversight',      ['GOV_POLICY','GOV_ROLES']),
      C('CFI-GV.2',  'Inherent Risk Assessment (C-RAF)',                   ['GOV_RISK_MGMT']),
      C('CFI-GV.3',  'Cyber Strategy & Risk Appetite',                     ['GOV_POLICY']),
      C('CFI-ID.1',  'Asset & Data Identification',                        ['GOV_ASSET_INV','DATA_CLASSIFICATION']),
      C('CFI-ID.2',  'Third-Party & Supply Chain Risk',                    ['GOV_THIRD_PARTY']),
      C('CFI-PR.1',  'Identity & Access Management',                       ['IAM_ACCESS_CTRL','IAM_MFA','IAM_PRIV_ACCESS']),
      C('CFI-PR.2',  'Data Protection & Encryption',                       ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('CFI-PR.3',  'Secure Configuration & Hardening',                   ['INF_HARDENING']),
      C('CFI-PR.4',  'Network Segmentation & Perimeter',                   ['INF_NETWORK_SEG','INF_PERIMETER']),
      C('CFI-PR.5',  'Secure Software Development',                        ['APP_SECURE_DEV','APP_APP_TESTING']),
      C('CFI-PR.6',  'Cyber Awareness & Training',                         ['GOV_AWARENESS']),
      C('CFI-DE.1',  'Continuous Monitoring & SIEM',                       ['LOG_CENTRAL','LOG_MONITOR']),
      C('CFI-DE.2',  'Threat Intelligence (PDSF)',                         ['THREAT_THREAT_INTEL']),
      C('CFI-DE.3',  'Intelligence-led Attack Simulation (iCAST)',          ['THREAT_PENTEST','LOG_DETECTION']),
      C('CFI-DE.4',  'Vulnerability Management',                           ['THREAT_VULN_MGMT','INF_PATCH']),
      C('CFI-RS.1',  'Cyber Incident Response',                            ['LOG_IR']),
      C('CFI-RS.2',  'Regulatory Incident Reporting (HKMA 24-hour)',       ['PRIV_BREACH_NOTIFY']),
      C('CFI-RC.1',  'Cyber Resilience & Recovery',                        ['INF_RESILIENCE','INF_BACKUP']),
      C('TM-E-1.A',  'Technology Risk Management Framework',               ['GOV_RISK_MGMT','GOV_CHANGE_MGMT']),
      C('TM-E-1.B',  'Customer Authentication for e-Banking',              ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('TM-E-1.C',  'Transaction Monitoring & Fraud Detection',           ['LOG_DETECTION']),
      C('TM-G-1.1',  'IT Outsourcing & Cloud Computing',                   ['GOV_THIRD_PARTY','CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('TM-G-1.2',  'Data Residency & Cross-Border Data Flow',            ['DATA_RESIDENCY']),
    ],
  },

  // ============================================================
  // MAS — Monetary Authority of Singapore · Technology Risk Management Guidelines + Notice 655
  // ============================================================
  MAS: {
    id: 'MAS',
    name: 'MAS Technology Risk Management Guidelines',
    short: 'MAS TRM',
    jurisdiction: 'Singapore',
    authority: 'Monetary Authority of Singapore',
    family: 'apac',
    version: 'TRM 2021 / Notice 655',
    description: 'Mandatory technology risk management framework for MAS-regulated financial institutions in Singapore, supplemented by Notice 655 on cyber hygiene and Notice 644 on outsourcing.',
    controls: [
      C('TRM-3',   'Technology Risk Governance & Oversight',               ['GOV_POLICY','GOV_ROLES']),
      C('TRM-4',   'Risk Management Framework',                            ['GOV_RISK_MGMT']),
      C('TRM-5',   'IT Project Management',                                ['GOV_CHANGE_MGMT']),
      C('TRM-6',   'Software Application Development & Management',        ['APP_SECURE_DEV','APP_APP_TESTING']),
      C('TRM-7',   'IT Service Management — Change & Configuration',       ['GOV_CHANGE_MGMT','INF_HARDENING']),
      C('TRM-8',   'System Reliability, Availability & Recoverability',    ['INF_RESILIENCE','INF_BACKUP']),
      C('TRM-9',   'Data Centres Protection & Controls',                   ['INF_PHYSICAL']),
      C('TRM-10',  'Access Control',                                       ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV','IAM_IDENTITY_LIFECYCLE']),
      C('TRM-11',  'Cryptography',                                         ['DATA_ENCRYPT_REST','DATA_ENCRYPT_TRANSIT','DATA_KEY_MGMT']),
      C('TRM-12',  'Data & Infrastructure Security',                       ['DATA_CLASSIFICATION','INF_NETWORK_SEG','INF_HARDENING']),
      C('TRM-13',  'Cyber Security Operations',                            ['LOG_MONITOR','LOG_DETECTION','LOG_CENTRAL']),
      C('TRM-14',  'Cyber Security Assessment',                            ['THREAT_PENTEST','THREAT_VULN_MGMT']),
      C('TRM-15',  'Online Financial Services — Strong Authentication',    ['IAM_MFA','IAM_AUTH_STRENGTH']),
      C('TRM-16',  'Payment Card Security',                                ['PAY_CARDHOLDER_SCOPE','PAY_TOKENISATION']),
      C('TRM-17',  'IT Audit',                                             ['GOV_COMPLIANCE']),
      C('N655-1',  'Cyber Hygiene — Administrative Accounts',              ['IAM_PRIV_ACCESS']),
      C('N655-2',  'Cyber Hygiene — Security Patches',                     ['INF_PATCH']),
      C('N655-3',  'Cyber Hygiene — Security Standards for Systems',       ['INF_HARDENING']),
      C('N655-4',  'Cyber Hygiene — Network Perimeter Defence',            ['INF_PERIMETER']),
      C('N655-5',  'Cyber Hygiene — Malware Protection',                   ['INF_ENDPOINT']),
      C('N655-6',  'Cyber Hygiene — Multi-Factor Authentication',          ['IAM_MFA']),
      C('N644',    'Outsourcing & Cloud Arrangements',                     ['GOV_THIRD_PARTY','CLOUD_SHARED_RESP','CLOUD_CONFIG']),
      C('TRM-Inc', 'Incident Management & Notification (1-hour)',           ['LOG_IR','PRIV_BREACH_NOTIFY']),
    ],
  },

  // ============================================================
  // SWIFT CSP — Customer Security Programme · CSCF v2024
  // ============================================================
  SWIFT_CSP: {
    id: 'SWIFT_CSP',
    name: 'SWIFT Customer Security Controls Framework',
    short: 'SWIFT CSP',
    jurisdiction: 'International',
    authority: 'SWIFT',
    family: 'international',
    version: 'CSCF v2024',
    description: 'Mandatory and advisory security controls for all institutions using the SWIFT network, with annual attestation and independent assessment required.',
    controls: [
      C('1.1',  'SWIFT Environment Protection',                             ['INF_NETWORK_SEG']),
      C('1.2',  'Operating System Privileged Account Control',              ['IAM_PRIV_ACCESS']),
      C('1.3',  'Virtualisation / Cloud Platform Protection',               ['CLOUD_CONFIG','CLOUD_SHARED_RESP']),
      C('1.4',  'Restriction of Internet Access',                           ['INF_PERIMETER']),
      C('1.5',  'Customer Environment Protection (Architecture Type)',      ['INF_NETWORK_SEG','INF_HARDENING']),
      C('2.1',  'Internal Data Flow Security',                              ['DATA_ENCRYPT_TRANSIT']),
      C('2.2',  'Security Updates',                                         ['INF_PATCH']),
      C('2.3',  'System Hardening',                                         ['INF_HARDENING']),
      C('2.4A', 'Back Office Data Flow Security',                           ['DATA_ENCRYPT_TRANSIT']),
      C('2.5A', 'External Transmission Data Protection',                    ['DATA_ENCRYPT_TRANSIT','DATA_ENCRYPT_REST']),
      C('2.6',  'Operator Session Confidentiality & Integrity',             ['IAM_SESSION','DATA_ENCRYPT_TRANSIT']),
      C('2.7',  'Vulnerability Scanning',                                   ['THREAT_VULN_MGMT']),
      C('2.8',  'Critical Activity Outsourcing',                            ['GOV_THIRD_PARTY']),
      C('2.9',  'Transaction Business Controls',                            ['LOG_DETECTION']),
      C('2.10', 'Application Hardening',                                    ['APP_SECURE_DEV','INF_HARDENING']),
      C('2.11A','RMA Business Controls',                                    ['GOV_THIRD_PARTY']),
      C('3.1',  'Physical Security',                                        ['INF_PHYSICAL']),
      C('4.1',  'Password Policy',                                          ['IAM_AUTH_STRENGTH']),
      C('4.2',  'Multi-Factor Authentication',                              ['IAM_MFA']),
      C('5.1',  'Logical Access Control',                                   ['IAM_ACCESS_CTRL','IAM_LEAST_PRIV']),
      C('5.2',  'Token Management',                                         ['APP_SECRETS','IAM_AUTH_STRENGTH']),
      C('5.3A', 'Personnel Vetting Process',                                ['HR_SCREENING']),
      C('5.4',  'Physical and Logical Password Storage',                    ['APP_SECRETS','DATA_KEY_MGMT']),
      C('6.1',  'Malware Protection',                                       ['INF_ENDPOINT']),
      C('6.2',  'Software Integrity',                                       ['LOG_INTEGRITY']),
      C('6.3',  'Database Integrity',                                       ['LOG_INTEGRITY']),
      C('6.4',  'Logging and Monitoring',                                   ['LOG_CENTRAL','LOG_MONITOR']),
      C('6.5A', 'Intrusion Detection',                                      ['LOG_DETECTION']),
      C('7.1',  'Cyber Incident Response Planning',                         ['LOG_IR']),
      C('7.2',  'Security Training & Awareness',                            ['GOV_AWARENESS']),
      C('7.3A', 'Penetration Testing',                                      ['THREAT_PENTEST']),
      C('7.4A', 'Scenario-Based Risk Assessment',                           ['GOV_RISK_MGMT','THREAT_THREAT_INTEL']),
    ],
  },
};

// ============================================================
// CROSS-MAPPING & GAP-ANALYSIS FUNCTIONS
// ============================================================

/**
 * Given a theme_key, return every control across every baseline that addresses it.
 * Shape: { THEME_KEY: [{ baseline_id, baseline_short, control_id, control_title }, ...] }
 */
export function mapThemeToControls(theme_key) {
  const matches = [];
  for (const baseline of Object.values(BASELINES)) {
    for (const ctrl of baseline.controls) {
      if (ctrl.theme_keys.includes(theme_key)) {
        matches.push({
          baseline_id: baseline.id,
          baseline_short: baseline.short,
          baseline_family: baseline.family,
          control_id: ctrl.id,
          control_title: ctrl.title,
        });
      }
    }
  }
  return matches;
}

/**
 * Full cross-mapping matrix: every theme → every baseline's citations.
 */
export function buildCrossMap() {
  const matrix = {};
  for (const theme_key of Object.keys(THEMES)) {
    matrix[theme_key] = {
      theme: THEMES[theme_key],
      citations: mapThemeToControls(theme_key),
    };
  }
  return matrix;
}

/**
 * Gap analysis: given a list of findings (each with theme_keys[]) and a chosen
 * baseline_id, return a per-control status:
 *   - covered      → theme is addressed in findings (present/discussed in the review)
 *   - gap          → control exists in baseline, findings do not touch any of its themes
 *   - not-assessed → control's themes are outside the scope of this review
 *
 * Severity rolls up: if any finding tagged to a covered theme is critical/high,
 * the control is marked 'at-risk' rather than 'covered'.
 */
export function gapAnalysis(findings, baseline_id) {
  const baseline = BASELINES[baseline_id];
  if (!baseline) throw new Error(`Unknown baseline: ${baseline_id}`);

  // Collect themes present in the review with worst severity
  const themeSeverity = {}; // theme_key -> 'critical' | 'high' | 'medium' | 'low' | undefined
  const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
  for (const f of findings) {
    const keys = f.theme_keys || [];
    for (const k of keys) {
      if (!themeSeverity[k] || sevRank[f.severity] > sevRank[themeSeverity[k]]) {
        themeSeverity[k] = f.severity;
      }
    }
  }

  const results = baseline.controls.map(ctrl => {
    const addressed = ctrl.theme_keys.filter(k => k in themeSeverity);
    let status;
    let severity = null;
    if (addressed.length === 0) {
      status = 'not-assessed';
    } else {
      const worst = addressed.reduce((w, k) => {
        const s = themeSeverity[k];
        return sevRank[s] > sevRank[w] ? s : w;
      }, 'low');
      severity = worst;
      // "at-risk" if critical or high findings touch this control
      status = (worst === 'critical' || worst === 'high') ? 'at-risk' : 'covered';
    }
    return {
      control_id: ctrl.id,
      control_title: ctrl.title,
      themes: ctrl.theme_keys,
      addressed_themes: addressed,
      status,
      worst_severity: severity,
    };
  });

  const summary = {
    total: results.length,
    covered: results.filter(r => r.status === 'covered').length,
    at_risk: results.filter(r => r.status === 'at-risk').length,
    not_assessed: results.filter(r => r.status === 'not-assessed').length,
  };
  summary.coverage_pct = summary.total === 0 ? 0 : Math.round(100 * (summary.covered + summary.at_risk) / summary.total);

  return {
    baseline: {
      id: baseline.id,
      name: baseline.name,
      short: baseline.short,
      version: baseline.version,
      authority: baseline.authority,
    },
    summary,
    controls: results,
  };
}

/**
 * Summary counts for the baselines menu.
 */
export function listBaselines() {
  return Object.values(BASELINES).map(b => ({
    id: b.id,
    name: b.name,
    short: b.short,
    jurisdiction: b.jurisdiction,
    authority: b.authority,
    family: b.family,
    version: b.version,
    description: b.description,
    control_count: b.controls.length,
  }));
}

/**
 * Get a single baseline in full.
 */
export function getBaseline(id) {
  const b = BASELINES[id];
  if (!b) return null;
  return b;
}

/**
 * Theme directory for the UI.
 */
export function listThemes() {
  return Object.entries(THEMES).map(([key, t]) => ({
    key,
    domain: t.domain,
    label: t.label,
  }));
}

/**
 * Total counts for health/diagnostics.
 */
export function countTotals() {
  const baselines = Object.keys(BASELINES).length;
  const themes = Object.keys(THEMES).length;
  const controls = Object.values(BASELINES).reduce((n, b) => n + b.controls.length, 0);
  return { baselines, themes, controls };
}
