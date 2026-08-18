import { useEffect, useId, useRef, useState } from 'react'
import type { CaseGraphLink, CaseGraphNode } from './services/caseGraphs'

type Point = { x: number; y: number }

export type CaseGraphLegendItem = {
  style: 'solid' | 'dashed' | 'dotted'
  color: string
  label: string
}

export type CaseGraphNodeLegendItem = {
  color: string
  label: string
}

export default function InteractiveCaseGraph({
  nodes,
  links,
  height = 460,
  positions,
  onPositionsChange,
  onNodeClick,
  onEdgeClick,
  legend,
  nodeLegend,
  candidateIds,
  onInsertAtGap,
  onExcludeNode,
  staticView,
}: {
  nodes: CaseGraphNode[]
  links: CaseGraphLink[]
  height?: number
  positions: Record<string, Point>
  onPositionsChange: (positions: Record<string, Point>) => void
  onNodeClick: (node: CaseGraphNode) => void
  onEdgeClick: (link: CaseGraphLink) => void
  legend?: CaseGraphLegendItem[]
  nodeLegend?: CaseGraphNodeLegendItem[]
  // 证据链拼装模式：候选节点可拖拽到链上任意位置插入，或拖到排除区/点 × 排除。
  candidateIds?: Set<string>
  onInsertAtGap?: (sourceId: string, afterId: string) => void
  onExcludeNode?: (nodeId: string) => void
  // 静态只读模式：图自动居中，不提供缩放/平移/节点拖动（如 M3 关联图）。
  staticView?: boolean
}) {
  const [localPositions, setLocalPositions] = useState<Record<string, Point>>({})
  const [view, setView] = useState({ scale: 1, x: 0, y: 0 })
  const [staticViewTransform, setStaticViewTransform] = useState<{ x: number; y: number; scale: number } | null>(null)
  const [hoveredLink, setHoveredLink] = useState<{ link: CaseGraphLink; x: number; y: number } | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null)
  const dragRef = useRef<{ id: string; offset: Point; moved: boolean } | null>(null)
  const panRef = useRef<{ start: Point; origin: Point; moved: boolean } | null>(null)
  const positionsRef = useRef<Record<string, Point>>({})
  const svgRef = useRef<SVGSVGElement | null>(null)
  const suppressClickRef = useRef(false)
  const arrowId = useId().replace(/[^a-zA-Z0-9]/g, '')
  // 链模式：攻击链路研判图启用端口连线 + 候选拖拽到缝隙/排除区。
  const chainMode = Boolean(onInsertAtGap && onExcludeNode)
  const candidateDragRef = useRef<{ id: string; moved: boolean } | null>(null)
  const dropTargetRef = useRef<{ kind: 'insert' | 'exclude'; afterId?: string } | null>(null)
  const [dragPoint, setDragPoint] = useState<Point | null>(null)
  const [dropTarget, setDropTarget] = useState<{ kind: 'insert' | 'exclude'; afterId?: string } | null>(null)
  // 排除区：拖拽候选证据到此即排除，置于画布右上角空白处。
  const EXCLUDE_ZONE = { x: 788, y: 22, width: 188, height: 62 }
  // 无前驱节点视为攻击起点、无后继节点视为攻击终点，用于配色突出攻防演进方向。
  const startIds = new Set(links.map((link) => String(link.source)).filter((id) => !links.some((link) => String(link.target) === id)))
  const endIds = new Set(links.map((link) => String(link.target)).filter((id) => !links.some((link) => String(link.source) === id)))
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  // 链模式下的单向链节点：按 windowIds 顺序排列的非候选节点。
  const chainNodes = chainMode ? nodes.filter((node) => !candidateIds?.has(node.id)) : []

  useEffect(() => {
    setLocalPositions((current) => {
      const next = { ...current }
      nodes.forEach((node, index) => {
        if (chainMode) {
          // 链模式使用确定性网格布局，忽略历史拖拽位置，插入/排除后节点自动回到链上正确槽位。
          next[node.id] = node.x !== undefined && node.y !== undefined
            ? { x: node.x, y: node.y }
            : (next[node.id] || { x: 105 + (index % 5) * 175, y: 95 + Math.floor(index / 5) * 105 })
          return
        }
        if (!next[node.id]) next[node.id] = positions[node.id] || (node.x !== undefined && node.y !== undefined
          ? { x: node.x, y: node.y }
          : { x: 105 + (index % 5) * 175, y: 95 + Math.floor(index / 5) * 105 })
      })
      Object.keys(next).forEach((id) => { if (!nodes.some((node) => node.id === id)) delete next[id] })
      positionsRef.current = next
      return next
    })
  }, [nodes, positions, chainMode])

  useEffect(() => {
    if (!staticView) {
      setStaticViewTransform(null)
      return
    }
    // 静态只读模式：按节点包围盒计算缩放并居中，让内容放大填充画布而非只在中间一小块。
    const pts = nodes.map((node) => localPositions[node.id]
      || (node.x !== undefined && node.y !== undefined ? { x: node.x, y: node.y } : { x: 90, y: 100 }))
    if (!pts.length) {
      setStaticViewTransform({ x: 0, y: 0, scale: 1 })
      return
    }
    const xs = pts.map((p) => p.x)
    const ys = pts.map((p) => p.y)
    const minX = Math.min(...xs)
    const maxX = Math.max(...xs)
    const minY = Math.min(...ys)
    const maxY = Math.max(...ys)
    const boxW = Math.max(maxX - minX, 1)
    const boxH = Math.max(maxY - minY, 1)
    const pad = 48
    const scale = Math.max(0.5, Math.min(1.8, Math.min((1000 - pad * 2) / boxW, (height - pad * 2) / boxH)))
    const cx = (minX + maxX) / 2
    const cy = (minY + maxY) / 2
    setStaticViewTransform({ x: 500 - cx * scale, y: height / 2 - cy * scale, scale })
  }, [staticView, nodes, localPositions, height])

  const pointFromEvent = (event: React.PointerEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect) return { x: 0, y: 0 }
    const screenPoint = { x: ((event.clientX - rect.left) / rect.width) * 1000, y: ((event.clientY - rect.top) / rect.height) * height }
    return { x: (screenPoint.x - view.x) / view.scale, y: (screenPoint.y - view.y) / view.scale }
  }

  const startDrag = (event: React.PointerEvent<SVGGElement>, node: CaseGraphNode) => {
    if (staticView) return
    event.stopPropagation()
    event.currentTarget.setPointerCapture(event.pointerId)
    const startPoint = pointFromEvent(event as unknown as React.PointerEvent<SVGSVGElement>)
    suppressClickRef.current = false
    if (chainMode) {
      // 候选证据在链模式下拖拽到缝隙/排除区，而非移动节点位置；主链节点保持固定。
      if (candidateIds?.has(node.id)) {
        candidateDragRef.current = { id: node.id, moved: false }
        dropTargetRef.current = null
        setDragPoint(startPoint)
        setDropTarget(null)
      }
      return
    }
    const position = localPositions[node.id] || { x: 90, y: 100 }
    dragRef.current = { id: node.id, offset: { x: position.x - startPoint.x, y: position.y - startPoint.y }, moved: false }
  }

  const moveDrag = (event: React.PointerEvent<SVGSVGElement>) => {
    if (candidateDragRef.current) {
      candidateDragRef.current.moved = true
      const dragPointNow = pointFromEvent(event)
      setDragPoint(dragPointNow)
      const inExcludeZone = dragPointNow.x >= EXCLUDE_ZONE.x && dragPointNow.x <= EXCLUDE_ZONE.x + EXCLUDE_ZONE.width
        && dragPointNow.y >= EXCLUDE_ZONE.y && dragPointNow.y <= EXCLUDE_ZONE.y + EXCLUDE_ZONE.height
      let nextDrop: { kind: 'insert' | 'exclude'; afterId?: string } | null = null
      if (inExcludeZone) {
        nextDrop = { kind: 'exclude' }
      } else if (chainNodes.length) {
        // 找最近的链节点，按指针在其左/右决定插到它之前还是之后。
        let nearest = chainNodes[0]
        let bestDist = Infinity
        chainNodes.forEach((node) => {
          const pos = point(node.id)
          const dist = Math.hypot(dragPointNow.x - pos.x, dragPointNow.y - pos.y)
          if (dist < bestDist) { bestDist = dist; nearest = node }
        })
        if (bestDist < 84) {
          const idx = chainNodes.findIndex((node) => node.id === nearest.id)
          const nearestPos = point(nearest.id)
          const afterId = dragPointNow.x < nearestPos.x
            ? (idx === 0 ? 'start' : chainNodes[idx - 1].id)
            : nearest.id
          nextDrop = { kind: 'insert', afterId }
        }
      }
      dropTargetRef.current = nextDrop
      setDropTarget(nextDrop)
      return
    }
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
    const cursorPoint = pointFromEvent(event)
    const nextPoint = {
      x: Math.max(28, Math.min(972, cursorPoint.x + drag.offset.x)),
      y: Math.max(28, Math.min(height - 28, cursorPoint.y + drag.offset.y)),
    }
    drag.moved = true
    const nextPositions = { ...positionsRef.current, [drag.id]: nextPoint }
    positionsRef.current = nextPositions
    setLocalPositions(nextPositions)
  }

  const finishDrag = () => {
    const candidateDrag = candidateDragRef.current
    if (candidateDrag) {
      const target = dropTargetRef.current
      if (candidateDrag.moved) {
        if (target?.kind === 'insert' && target.afterId) onInsertAtGap?.(candidateDrag.id, target.afterId)
        else if (target?.kind === 'exclude') onExcludeNode?.(candidateDrag.id)
        suppressClickRef.current = true
        window.setTimeout(() => { suppressClickRef.current = false }, 80)
      }
      candidateDragRef.current = null
      dropTargetRef.current = null
      setDragPoint(null)
      setDropTarget(null)
      return
    }
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
  // 三种事实关系用线型区分：事件涉及实体（实线）、时间先后（虚线）、同一事件共同参与（点线）。
  const lineStyleFor = (relation: string, strong: boolean): { dash?: string; color: string; marker: 'strong' | 'weak' | 'blue' } => {
    if (relation === '事件涉及实体') return { color: '#b91c1c', marker: 'strong' }
    if (relation === '时间先后') return { dash: '8 6', color: '#2563eb', marker: 'blue' }
    if (relation === '同一事件共同参与') return { dash: '3 7', color: '#94a3b8', marker: 'weak' }
    return { color: strong ? '#b91c1c' : '#94a3b8', marker: strong ? 'strong' : 'weak' }
  }
  // 边从节点边缘的端口连接，而非圆心：端口位于源/目标节点朝向对方的边界处。
  const portPoint = (fromId: string, toward: Point, r: number): Point => {
    const center = point(fromId)
    const dx = toward.x - center.x
    const dy = toward.y - center.y
    const length = Math.hypot(dx, dy)
    if (length < 1) return { x: center.x + r, y: center.y }
    return { x: center.x + (dx / length) * r, y: center.y + (dy / length) * r }
  }
  const edgePorts = (link: CaseGraphLink) => {
    const sourceNode = nodeById.get(String(link.source))
    const targetNode = nodeById.get(String(link.target))
    const sourceCenter = point(String(link.source))
    const targetCenter = point(String(link.target))
    const sourceRadius = sourceNode ? radius(sourceNode) : 19
    const targetRadius = targetNode ? radius(targetNode) : 19
    return {
      sourceCenter,
      targetCenter,
      source: portPoint(String(link.source), targetCenter, sourceRadius),
      target: portPoint(String(link.target), sourceCenter, targetRadius),
      line: lineStyleFor(link.relation || '', Boolean(link.weight && link.weight >= 1)),
    }
  }
  // 拖拽候选时的插入指示位置：插到首部/两个链节点之间/尾部。
  const insertIndicatorPosition = (afterId: string): Point => {
    if (afterId === 'start') {
      const first = chainNodes[0]
      const pos = first ? point(first.id) : { x: 110, y: 90 }
      return { x: pos.x - 76, y: pos.y }
    }
    const idx = chainNodes.findIndex((node) => node.id === afterId)
    const current = chainNodes[idx]
    if (!current) return { x: 500, y: 90 }
    const currentPos = point(current.id)
    const next = chainNodes[idx + 1]
    if (next) {
      const nextPos = point(next.id)
      return { x: (currentPos.x + nextPos.x) / 2, y: (currentPos.y + nextPos.y) / 2 }
    }
    return { x: currentPos.x + 76, y: currentPos.y }
  }
  const indicatorPos = dropTarget?.kind === 'insert' && dropTarget.afterId
    ? insertIndicatorPosition(dropTarget.afterId)
    : null

  return (
    <div className="mc-interactive-case-graph-wrap">
        {!staticView && (
          <div className="mc-interactive-case-graph-tools" aria-label="图谱缩放控制">
            <button type="button" title="缩小" onClick={() => zoom(0.85)}>−</button>
            <span>{Math.round(view.scale * 100)}%</span>
            <button type="button" title="放大" onClick={() => zoom(1.18)}>＋</button>
            <button type="button" title="重置视图" onClick={resetView}>重置</button>
          </div>
        )}
      {(nodeLegend && nodeLegend.length > 0) || (legend && legend.length > 0) ? (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', padding: '2px 4px 8px', fontSize: 12, color: '#475569' }}>
          {nodeLegend?.map((item) => (
            <span key={item.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="5" fill={item.color} stroke="#ffffff" strokeWidth="1.5" /></svg>
              {item.label}
            </span>
          ))}
          {legend?.map((item) => (
            <span key={item.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <svg width="28" height="10" viewBox="0 0 28 10" aria-hidden="true">
                <line x1="0" y1="5" x2="28" y2="5" stroke={item.color} strokeWidth="2.4" strokeDasharray={item.style === 'solid' ? undefined : item.style === 'dashed' ? '8 6' : '3 6'} strokeLinecap="round" />
              </svg>
              {item.label}
            </span>
          ))}
        </div>
      ) : null}
      <svg ref={svgRef} className="mc-interactive-case-graph" style={{ height }} viewBox={`0 0 1000 ${height}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="安全事件关系图" onWheel={staticView ? undefined : handleWheel} onPointerDown={staticView ? undefined : startPan} onPointerMove={staticView ? undefined : moveDrag} onPointerUp={staticView ? undefined : finishDrag} onPointerCancel={staticView ? undefined : finishDrag}>
        <defs>
          <marker id={`mc-arrow-strong-${arrowId}`} markerWidth="11" markerHeight="11" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#b91c1c" />
          </marker>
          <marker id={`mc-arrow-blue-${arrowId}`} markerWidth="11" markerHeight="11" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#2563eb" />
          </marker>
          <marker id={`mc-arrow-weak-${arrowId}`} markerWidth="11" markerHeight="11" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
        </defs>
        <rect width="1000" height={height} fill="#f8fafc" rx="8" />
        <g transform={staticView && staticViewTransform ? `translate(${staticViewTransform.x},${staticViewTransform.y}) scale(${staticViewTransform.scale})` : `translate(${view.x},${view.y}) scale(${view.scale})`}>
          <g className="mc-graph-edges">
            {links.map((link, index) => {
              const { source, target, sourceCenter, targetCenter, line } = edgePorts(link)
              const dx = targetCenter.x - sourceCenter.x
              const dy = targetCenter.y - sourceCenter.y
              const length = Math.hypot(dx, dy) || 1
              const ctrlX = (sourceCenter.x + targetCenter.x) / 2 - (dy / length) * 10
              const ctrlY = (sourceCenter.y + targetCenter.y) / 2 + (dx / length) * 10
              const midX = (sourceCenter.x + targetCenter.x) / 2
              const midY = (sourceCenter.y + targetCenter.y) / 2
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
                  <path d={path} fill="none" stroke={line.color} strokeWidth={hovered ? 2.8 : 1.8} strokeDasharray={line.dash} markerEnd={`url(#mc-arrow-${line.marker}-${arrowId})`} pointerEvents="none" />
                  {link.label && (
                    <g transform={`translate(${midX},${midY - 7})`} pointerEvents="none">
                      <rect x={-(link.label.length * 7.5) / 2 - 4} y={-9} width={link.label.length * 7.5 + 8} height={18} rx={9} fill="rgba(248,250,252,0.94)" stroke={line.marker === 'weak' ? '#e2e8f0' : '#fecaca'} strokeWidth="1" />
                      <text y="4" textAnchor="middle" fontSize="10.5" fontWeight="600" fill={line.color}>{link.label}</text>
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
              const isCandidate = candidateIds?.has(node.id) || false
              const nodeRadius = radius(node)
              return (
                <g
                  key={node.id}
                  transform={`translate(${position.x},${position.y})`}
                  onPointerDown={(event) => startDrag(event, node)}
                  onPointerEnter={() => setHoveredNodeId(node.id)}
                  onPointerLeave={() => setHoveredNodeId(null)}
                  onClick={(event) => { event.stopPropagation(); if (!suppressClickRef.current) onNodeClick(node) }}
                  style={{ cursor: staticView ? 'pointer' : 'grab' }}
                >
                  <circle r={nodeRadius} fill={isCandidate ? '#94a3b8' : color(node)} stroke={hovered ? '#1e293b' : '#ffffff'} strokeWidth={hovered ? 3 : 2} strokeDasharray={isCandidate ? '5 4' : undefined} />
                  <text y={nodeRadius + 17} textAnchor="middle" fill="#111827" fontSize="12" fontWeight="600">{node.name}</text>
                </g>
              )
            })}
          </g>
          <g className="mc-graph-ports" style={{ pointerEvents: 'none' }}>
            {links.map((link, index) => {
              const { source, target, line } = edgePorts(link)
              return (
                <g key={`port-${index}`}>
                  <circle cx={source.x} cy={source.y} r="3.4" fill="#ffffff" stroke={line.color} strokeWidth="2" />
                  <circle cx={target.x} cy={target.y} r="3.4" fill="#ffffff" stroke={line.color} strokeWidth="2" />
                </g>
              )
            })}
          </g>
          {chainMode && (
            <g className="mc-graph-exclude-zone" transform={`translate(${EXCLUDE_ZONE.x},${EXCLUDE_ZONE.y})`} style={{ pointerEvents: 'none' }}>
              <rect width={EXCLUDE_ZONE.width} height={EXCLUDE_ZONE.height} rx="10" fill={dropTarget?.kind === 'exclude' ? 'rgba(239,68,68,0.14)' : 'rgba(248,250,252,0.92)'} stroke={dropTarget?.kind === 'exclude' ? '#ef4444' : '#f3b8b8'} strokeWidth={dropTarget?.kind === 'exclude' ? 2.5 : 1.5} strokeDasharray="6 4" />
              <text x={EXCLUDE_ZONE.width / 2} y={EXCLUDE_ZONE.height / 2 + 4} textAnchor="middle" fontSize="13" fontWeight="600" fill={dropTarget?.kind === 'exclude' ? '#b91c1c' : '#dc2626'}>拖到此处排除</text>
            </g>
          )}
          {candidateDragRef.current && dragPoint && (
            <g className="mc-graph-drag-ghost" transform={`translate(${dragPoint.x},${dragPoint.y})`} style={{ pointerEvents: 'none' }}>
              <circle r="24" fill="rgba(148,163,184,0.92)" stroke="#64748b" strokeWidth="2" strokeDasharray="5 4" />
              <text y="4" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="600">{nodeById.get(candidateDragRef.current?.id || '')?.name || '候选证据'}</text>
            </g>
          )}
          {candidateDragRef.current && dragPoint && indicatorPos && (
            <g className="mc-graph-insert-indicator" transform={`translate(${indicatorPos.x},${indicatorPos.y})`} style={{ pointerEvents: 'none' }}>
              <circle r="13" fill="#10b981" stroke="#ffffff" strokeWidth="2" />
              <text y="4" textAnchor="middle" fill="#ffffff" fontSize="14" fontWeight="700">＋</text>
            </g>
          )}
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
