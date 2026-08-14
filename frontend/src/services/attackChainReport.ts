import {
  AlignmentType,
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  TextRun,
} from 'docx'

type AttackChainReportInput = {
  caseId: string
  caseTitle: string
  content: string
}

const headingLevel = (line: string) => {
  if (line.startsWith('### ')) return HeadingLevel.HEADING_3
  if (line.startsWith('## ')) return HeadingLevel.HEADING_2
  return HeadingLevel.HEADING_1
}

const cleanFilename = (value: string) => value.replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, '_')

/** Build and download a concise, evidence-scoped attack-chain report in Word format. */
export async function downloadAttackChainReport({ caseId, caseTitle, content }: AttackChainReportInput) {
  const generatedAt = new Date().toLocaleString('zh-CN', { hour12: false })
  const body = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !/^#\s*攻击链分析报告\s*$/.test(line))
    .map((line) => {
      if (/^#{1,3}\s+/.test(line)) {
        return new Paragraph({
          text: line.replace(/^#{1,3}\s+/, ''),
          heading: headingLevel(line),
          spacing: { before: 240, after: 100 },
        })
      }
      if (/^[-*]\s+/.test(line)) {
        return new Paragraph({
          text: line.replace(/^[-*]\s+/, ''),
          bullet: { level: 0 },
          spacing: { after: 80, line: 280 },
        })
      }
      return new Paragraph({ text: line, spacing: { after: 100, line: 280 } })
    })

  const document = new Document({
    creator: 'WAD 链影寻踪',
    title: `攻击链分析报告 - ${caseId}`,
    styles: {
      default: {
        document: { run: { font: 'Microsoft YaHei', size: 22 } },
        heading1: { run: { font: 'Microsoft YaHei', size: 32, bold: true, color: '2E74B5' }, paragraph: { spacing: { before: 280, after: 120 } } },
        heading2: { run: { font: 'Microsoft YaHei', size: 26, bold: true, color: '2E74B5' }, paragraph: { spacing: { before: 220, after: 100 } } },
        heading3: { run: { font: 'Microsoft YaHei', size: 24, bold: true, color: '1F4D78' }, paragraph: { spacing: { before: 180, after: 80 } } },
      },
    },
    sections: [{
      properties: {
        page: { margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 180 },
          children: [new TextRun({ text: '攻击链分析报告', bold: true, size: 40, font: 'Microsoft YaHei', color: '1F4D78' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 280 },
          children: [new TextRun({ text: `${caseId} | ${caseTitle} | 生成时间：${generatedAt}`, size: 20, font: 'Microsoft YaHei', color: '5B6B7A' })],
        }),
        ...body,
      ],
    }],
  })

  const blob = await Packer.toBlob(document)
  const url = URL.createObjectURL(blob)
  const anchor = window.document.createElement('a')
  anchor.href = url
  anchor.download = `${cleanFilename(caseId)}_攻击链分析报告.docx`
  anchor.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
