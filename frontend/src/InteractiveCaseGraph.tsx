import { useEffect, useRef, useState } from 'react'
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
  const dragRef = useRef<{ id: string; offset: Point; moved: boolean } | null>(null)
  const panRef = useRef<{ start: Point; origin: Point; moved: boolean } | null>(null)
  const positionsRef = useRef<Record<string, Point>>({})
  const svgRef = useRef<SVGSVGElement | null>(null)
  const suppressClickRef = useRef(false)

  useEffect(() => {
    setLocalPositions((current) => {
      const next = { ...current }
      nodes.forEach((node, index) => {
        if (!next[node.id]) next[node.id] = positions[node.id] || { x: 105 + (index % 5) * 175, y: 95 + Math.floor(index / 5) * 105 }
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
  const radius = (node: CaseGraphNode) => node.kind === 'technique' ? 29 : node.kind === 'event' ? 24 : node.kind === 'window' ? 27 : 19
  const color = (node: CaseGraphNode) => node.kind === 'technique' ? (node.category === 0 ? '#dc2626' : '#7c3aed') : node.kind === 'event' ? '#2563eb' : node.kind === 'window' ? (node.category === 0 ? '#dc2626' : '#d97706') : '#65a30d'

  return (
    <div className="mc-interactive-case-graph-wrap">
      <div className="mc-interactive-case-graph-tools" aria-label="图谱缩放控制">
        <button type="button" title="缩小" onClick={() => zoom(0.85)}>−</button>
        <span>{Math.round(view.scale * 100)}%</span>
        <button type="button" title="放大" onClick={() => zoom(1.18)}>＋</button>
        <button type="button" title="重置视图" onClick={resetView}>重置</button>
      </div>
      <svg ref={svgRef} className="mc-interactive-case-graph" style={{ height }} viewBox={`0 0 1000 ${height}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="安全事件关系图" onWheel={handleWheel} onPointerDown={startPan} onPointerMove={moveDrag} onPointerUp={finishDrag} onPointerCancel={finishDrag}>
        <rect width="1000" height={height} fill="#f8fafc" rx="8" />
        <g transform={`translate(${view.x},${view.y}) scale(${view.scale})`}>
          <g className="mc-graph-edges">
            {links.map((link, index) => {
              const source = point(link.source)
              const target = point(link.target)
              return (
                <g key={`${link.source}-${link.target}-${index}`} onPointerDown={(event) => event.stopPropagation()} onClick={(event) => { event.stopPropagation(); onEdgeClick(link) }}>
                  <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="transparent" strokeWidth="14" />
                  <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={link.weight && link.weight < 1 ? '#94a3b8' : '#64748b'} strokeWidth="1.8" strokeDasharray={link.weight && link.weight < 1 ? '6 5' : undefined} pointerEvents="none" />
                </g>
              )
            })}
          </g>
          <g className="mc-graph-nodes">
            {nodes.map((node) => {
              const position = point(node.id)
              return (
                <g key={node.id} transform={`translate(${position.x},${position.y})`} onPointerDown={(event) => startDrag(event, node)} onClick={(event) => { event.stopPropagation(); if (!suppressClickRef.current) onNodeClick(node) }} style={{ cursor: 'grab' }}>
                  <circle r={radius(node)} fill={color(node)} stroke="#ffffff" strokeWidth="2" />
                  <text y={radius(node) + 17} textAnchor="middle" fill="#111827" fontSize="12" fontWeight="600">{node.name}</text>
                </g>
              )
            })}
          </g>
        </g>
      </svg>
    </div>
  )
}
