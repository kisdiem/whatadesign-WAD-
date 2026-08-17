import { useEffect, useId, useRef, useState } from 'react'
import type { CaseGraphLink, CaseGraphNode } from './services/caseGraphs'

type Point = { x: number; y: number }

export default function InteractiveCaseGraph({
  nodes,
  links,
  height = 460,
  positions,
  onPositionsChange,
  onNodeClick,
  onEdgeClick,
}: {
  nodes: CaseGraphNode[]
  links: CaseGraphLink[]
  height?: number
  positions: Record<string, Point>
  onPositionsChange: (positions: Record<string, Point>) => void
  onNodeClick: (node: CaseGraphNode) => void
  onEdgeClick: (link: CaseGraphLink) => void
}) {
  const [localPositions, setLocalPositions] = useState<Record<string, Point>>({})
  const [view, setView] = useState({ scale: 1, x: 0, y: 0 })
  const [hoveredLink, setHoveredLink] = useState<{ link: CaseGraphLink; x: number; y: number } | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null)
  const dragRef = useRef<{ id: string; offset: Point; moved: boolean } | null>(null)
  const panRef = useRef<{ start: Point; origin: Point; moved: boolean } | null>(null)
  const positionsRef = useRef<Record<string, Point>>({})
  const svgRef = useRef<SVGSVGElement | null>(null)
  const suppressClickRef = useRef(false)
  const arrowId = useId().replace(/[^a-zA-Z0-9]/g, '')
  // 无前驱节点视为攻击起点、无后继节点视为攻击终点，用于配色突出攻防演进方向。
  const startIds = new Set(links.map((link) => String(link.source)).filter((id) => !links.some((link) => String(link.target) === id)))
  const endIds = new Set(links.map((link) => String(link.target)).filter((id) => !links.some((link) => String(link.source) === id)))

  useEffect(() => {
    setLocalPositions((current) => {
      const next = { ...current }
      nodes.forEach((node, index) => {
        if (!next[node.id]) next[node.id] = positions[node.id] || (node.x !== undefined && node.y !== undefined
          ? { x: node.x, y: node.y }
          : { x: 105 + (index % 5) * 175, y: 95 + Math.floor(index / 5) * 105 })
      })
      Object.keys(next).forEach((id) => { if (!nodes.some((node) => node.id === id)) delete next[id] })
      positionsRef.current = next
      return next
    })
  }, [nodes, positions])

  const pointFromEvent = (event: React.PointerEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect) return { x: 0, y: 0 }
    const screenPoint = { x: ((event.clientX - rect.left) / rect.width) * 1000, y: ((event.clientY - rect.top) / rect.height) * height }
    return { x: (screenPoint.x - view.x) / view.scale, y: (screenPoint.y - view.y) / view.scale }
  }

  const startDrag = (event: React.PointerEvent<SVGGElement>, node: CaseGraphNode) => {
    event.stopPropagation()
    event.currentTarget.setPointerCapture(event.pointerId)
    const point = pointFromEvent(event as unknown as React.PointerEvent<SVGSVGElement>)
    const position = localPositions[node.id] || { x: 90, y: 100 }
    suppressClickRef.current = false
    dragRef.current = { id: node.id, offset: { x: position.x - point.x, y: position.y - point.y }, moved: false }
  }

  const moveDrag = (event: React.PointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current
    if (!drag) {
      const pan = panRef.current
      if (!pan) return
      const rect = svgRef.current?.getBoundingClientRect()
      if (!rect) return
      const current = { x: event.clientX, y: event.clientY }
      const dx = ((current.x - pan.start.x) / rect.width) * 1000
      const dy = ((current.y - pan.start.y) / rect.height) * height
      pan.moved = true
      setView((value) => ({ ...value, x: pan.origin.x + dx, y: pan.origin.y + dy }))
      return
    }
    const point = pointFromEvent(event)
    const nextPoint = {
      x: Math.max(28, Math.min(972, point.x + drag.offset.x)),
      y: Math.max(28, Math.min(height - 28, point.y + drag.offset.y)),
    }
    drag.moved = true
    const nextPositions = { ...positionsRef.current, [drag.id]: nextPoint }
    positionsRef.current = nextPositions
    setLocalPositions(nextPositions)
  }

  const finishDrag = () => {
    const drag = dragRef.current
    if (drag) {
      if (drag.moved) {
        suppressClickRef.current = true
        onPositionsChange(positionsRef.current)
        window.setTimeout(() => { suppressClickRef.current = false }, 80)
      }
      dragRef.current = null
      return
    }
    panRef.current = null
  }

  const startPan = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.target !== event.currentTarget && (event.target as Element).tagName !== 'rect') return
    const point = { x: event.clientX, y: event.clientY }
    event.currentTarget.setPointerCapture(event.pointerId)
    panRef.current = { start: point, origin: { x: view.x, y: view.y }, moved: false }
  }

  const zoom = (factor: number) => {
    setView((current) => ({ ...current, scale: Math.max(0.45, Math.min(2.5, current.scale * factor)) }))
  }

  const handleWheel = (event: React.WheelEvent<SVGSVGElement>) => {
    event.preventDefault()
    zoom(event.deltaY < 0 ? 1.12 : 0.89)
  }

  const resetView = () => setView({ scale: 1, x: 0, y: 0 })

  const point = (id: string) => localPositions[id] || { x: 90, y: 100 }
  const isStart = (node: CaseGraphNode) => startIds.has(node.id)
  const isEnd = (node: CaseGraphNode) => endIds.has(node.id)
  const radius = (node: CaseGraphNode) => {
    const base = node.kind === 'technique' ? (isStart(node) ? 33 : isEnd(node) ? 30 : 28) : node.kind === 'event' ? 24 : node.kind === 'window' ? 27 : 19
    return hoveredNodeId === node.id ? base + 4 : base
  }
  const color = (node: CaseGraphNode) => node.kind === 'technique'
    ? (isStart(node) ? '#dc2626' : isEnd(node) ? '#10b981' : '#7c3aed')
    : node.kind === 'event' ? '#2563eb'
    : node.kind === 'window' ? (node.category === 0 ? '#dc2626' : '#d97706')
    : '#65a30d'

  return (
    <div className="mc-interactive-case-graph-wrap">
      <div className="mc-interactive-case-graph-tools" aria-label="图谱缩放控制">
        <button type="button" title="缩小" onClick={() => zoom(0.85)}>−</button>
        <span>{Math.round(view.scale * 100)}%</span>
        <button type="button" title="放大" onClick={() => zoom(1.18)}>＋</button>
        <button type="button" title="重置视图" onClick={resetView}>重置</button>
      </div>
      <svg ref={svgRef} className="mc-interactive-case-graph" style={{ height }} viewBox={`0 0 1000 ${height}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="安全事件关系图" onWheel={handleWheel} onPointerDown={startPan} onPointerMove={moveDrag} onPointerUp={finishDrag} onPointerCancel={finishDrag}>
        <defs>
          <marker id={`mc-arrow-strong-${arrowId}`} markerWidth="11" markerHeight="11" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#b91c1c" />
          </marker>
          <marker id={`mc-arrow-weak-${arrowId}`} markerWidth="11" markerHeight="11" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
        </defs>
        <rect width="1000" height={height} fill="#f8fafc" rx="8" />
        <g transform={`translate(${view.x},${view.y}) scale(${view.scale})`}>
          <g className="mc-graph-edges">
            {links.map((link, index) => {
              const source = point(link.source)
              const target = point(link.target)
              const strong = link.weight && link.weight >= 1
              const dx = target.x - source.x
              const dy = target.y - source.y
              const length = Math.hypot(dx, dy) || 1
              const ctrlX = (source.x + target.x) / 2 - (dy / length) * 10
              const ctrlY = (source.y + target.y) / 2 + (dx / length) * 10
              const midX = (source.x + target.x) / 2
              const midY = (source.y + target.y) / 2
              const hovered = hoveredLink?.link === link
              const path = `M ${source.x} ${source.y} Q ${ctrlX} ${ctrlY} ${target.x} ${target.y}`
              return (
                <g
                  key={`${link.source}-${link.target}-${index}`}
                  onPointerDown={(event) => event.stopPropagation()}
                  onPointerEnter={(event) => setHoveredLink({ link, x: event.clientX, y: event.clientY })}
                  onPointerMove={(event) => setHoveredLink({ link, x: event.clientX, y: event.clientY })}
                  onPointerLeave={() => setHoveredLink(null)}
                  onClick={(event) => { event.stopPropagation(); setHoveredLink(null); onEdgeClick(link) }}
                  style={{ cursor: 'pointer' }}
                >
                  <path d={path} fill="none" stroke="transparent" strokeWidth="16" />
                  <path d={path} fill="none" stroke={strong ? '#b91c1c' : '#94a3b8'} strokeWidth={hovered ? 2.8 : 1.8} strokeDasharray={strong ? undefined : '6 5'} markerEnd={`url(#mc-arrow-${strong ? 'strong' : 'weak'}-${arrowId})`} pointerEvents="none" />
                  {link.label && (
                    <g transform={`translate(${midX},${midY - 7})`} pointerEvents="none">
                      <rect x={-(link.label.length * 7.5) / 2 - 4} y={-9} width={link.label.length * 7.5 + 8} height={18} rx={9} fill="rgba(248,250,252,0.94)" stroke={strong ? '#fecaca' : '#e2e8f0'} strokeWidth="1" />
                      <text y="4" textAnchor="middle" fontSize="10.5" fontWeight="600" fill={strong ? '#b91c1c' : '#64748b'}>{link.label}</text>
                    </g>
                  )}
                </g>
              )
            })}
          </g>
          <g className="mc-graph-nodes">
            {nodes.map((node) => {
              const position = point(node.id)
              const hovered = hoveredNodeId === node.id
              return (
                <g
                  key={node.id}
                  transform={`translate(${position.x},${position.y})`}
                  onPointerDown={(event) => startDrag(event, node)}
                  onPointerEnter={() => setHoveredNodeId(node.id)}
                  onPointerLeave={() => setHoveredNodeId(null)}
                  onClick={(event) => { event.stopPropagation(); if (!suppressClickRef.current) onNodeClick(node) }}
                  style={{ cursor: 'grab' }}
                >
                  <circle r={radius(node)} fill={color(node)} stroke={hovered ? '#1e293b' : '#ffffff'} strokeWidth={hovered ? 3 : 2} />
                  <text y={radius(node) + 17} textAnchor="middle" fill="#111827" fontSize="12" fontWeight="600">{node.name}</text>
                </g>
              )
            })}
          </g>
        </g>
      </svg>
      {hoveredLink && (
        <div className="mc-graph-edge-tip" style={{ left: hoveredLink.x + 14, top: hoveredLink.y - 12 }}>
          <strong>{hoveredLink.link.label || '技术关联'}</strong>
          {(hoveredLink.link.evidence || '').split('；').filter(Boolean).map((line, index) => (
            <span key={index}>{line}</span>
          ))}
          {!hoveredLink.link.evidence && <span>{hoveredLink.link.explanation || '点击连线查看详细解释。'}</span>}
        </div>
      )}
    </div>
  )
}
