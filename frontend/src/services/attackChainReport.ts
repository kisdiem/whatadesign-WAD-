type AttackChainReport = {
  caseId: string
  caseTitle: string
  content: string
}

function safeFilename(value: string) {
  return value.replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_').slice(0, 80) || 'attack-chain'
}

export async function downloadAttackChainReport(report: AttackChainReport) {
  const body = `# ${report.caseTitle}\n\n案件编号：${report.caseId}\n\n${report.content}\n`
  const url = URL.createObjectURL(new Blob([body], { type: 'text/markdown;charset=utf-8' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${safeFilename(report.caseId)}-攻击链分析报告.md`
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}
