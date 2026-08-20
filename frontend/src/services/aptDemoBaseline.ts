export const APT_DEMO_BASELINE_VERSION = 'apt-two-chain-v1'

export const APT_BOUNDARY_CASE_ID = 'APT-SCRIPT-CANDIDATE-001'
export const APT_RECON_CASE_ID = 'APT-RECON-CASE-001'

export const APT_BOUNDARY_EVENT_IDS = [
  'APT-SCRIPT-001',
  'APT-SCRIPT-002',
  'APT-SCRIPT-003',
  'APT-SCRIPT-004',
] as const

export const APT_RECON_EVENT_IDS = [
  'APT-SCRIPT-005',
  'APT-SCRIPT-006',
  'APT-SCRIPT-007',
  'APT-SCRIPT-009',
  'APT-SCRIPT-010',
] as const

export function isFixedAptDemoCase(caseId: string) {
  return caseId === APT_BOUNDARY_CASE_ID || caseId === APT_RECON_CASE_ID
}
