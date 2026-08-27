import React, { useState } from 'react';

/**
 * DonutChart: Renders an SVG Donut chart with legend and hover tooltips.
 * Props:
 *  - data: Array of { name, value, color }
 *  - title: Optional text displayed in the center of the donut
 */
export const DonutChart = ({ data = [], title = "Total" }) => {
  const [hoveredIdx, setHoveredIdx] = useState(null);
  
  const validData = data.filter(d => d.value > 0);
  const total = validData.reduce((acc, d) => acc + d.value, 0);
  
  if (total === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '180px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        No scan findings to display chart
      </div>
    );
  }

  const radius = 50;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  const size = 150;
  const center = size / 2;

  return (
    <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap', justifyContent: 'center' }}>
      <div style={{ position: 'relative', width: `${size}px`, height: `${size}px` }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Base circle background */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="transparent"
            stroke="var(--border-subtle)"
            strokeWidth={strokeWidth}
          />
          {validData.map((d, idx) => {
            const percentage = d.value / total;
            const strokeLength = percentage * circumference;
            const previousSum = validData.slice(0, idx).reduce((sum, item) => sum + (item.value / total) * circumference, 0);
            const angle = -90 + (previousSum / circumference) * 360;

            const isHovered = hoveredIdx === idx;
            
            return (
              <circle
                key={idx}
                cx={center}
                cy={center}
                r={radius}
                fill="transparent"
                stroke={d.color || '#475569'}
                strokeWidth={isHovered ? strokeWidth + 3 : strokeWidth}
                strokeDasharray={`${strokeLength} ${circumference}`}
                strokeDashoffset={0}
                transform={`rotate(${angle} ${center} ${center})`}
                style={{
                  transition: 'stroke-width 0.2s, stroke 0.2s',
                  cursor: 'pointer'
                }}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
              />
            );
          })}
        </svg>

        {/* Center label */}
        <div style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none'
        }}>
          {hoveredIdx !== null ? (
            <>
              <span style={{ fontSize: '1.25rem', fontWeight: 'bold', color: 'var(--text-primary)' }}>
                {validData[hoveredIdx].value}
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {validData[hoveredIdx].name}
              </span>
            </>
          ) : (
            <>
              <span style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-primary)' }}>
                {total}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {title}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Legend list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', minWidth: '130px' }}>
        {validData.map((d, idx) => {
          const pct = ((d.value / total) * 100).toFixed(0);
          const isHovered = hoveredIdx === idx;
          return (
            <div
              key={idx}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem',
                color: isHovered ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: isHovered ? 600 : 400,
                cursor: 'pointer',
                transition: 'color 0.15s'
              }}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
            >
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: d.color, display: 'inline-block' }} />
              <span style={{ flex: 1 }}>{d.name}</span>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>{d.value} ({pct}%)</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};


/**
 * BarChart: Renders an SVG vertical bar chart.
 * Props:
 *  - data: Array of { name, value, color }
 */
export const BarChart = ({ data = [], height = 180 }) => {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  const validData = data.filter(d => d.value > 0);
  const maxVal = Math.max(...validData.map(d => d.value), 0);
  
  if (validData.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: `${height}px`, color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        No scan findings to display chart
      </div>
    );
  }

  const chartHeight = height;
  const paddingBottom = 25;
  const paddingTop = 20;
  const paddingLeft = 35;
  const paddingRight = 15;
  
  const width = 360;
  const plotWidth = width - paddingLeft - paddingRight;
  const plotHeight = chartHeight - paddingTop - paddingBottom;
  
  const barWidth = Math.min(30, (plotWidth / validData.length) * 0.6);
  const barSpacing = (plotWidth - (barWidth * validData.length)) / (validData.length + 1);

  // Generate gridline levels
  const yTicks = maxVal <= 5 ? Array.from({length: maxVal + 1}, (_, i) => i) : [0, Math.round(maxVal / 2), maxVal];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
      <svg width="100%" height={chartHeight} viewBox={`0 0 ${width} ${chartHeight}`} style={{ overflow: 'visible' }}>
        {/* Y Axis Gridlines */}
        {yTicks.map((tick, i) => {
          const y = paddingTop + plotHeight - (maxVal > 0 ? (tick / maxVal) * plotHeight : 0);
          return (
            <g key={i}>
              <line
                x1={paddingLeft}
                y1={y}
                x2={width - paddingRight}
                y2={y}
                stroke="var(--border-subtle)"
                strokeDasharray="4 4"
              />
              <text
                x={paddingLeft - 8}
                y={y + 4}
                fill="var(--text-muted)"
                fontSize="9px"
                fontFamily="monospace"
                textAnchor="end"
              >
                {tick}
              </text>
            </g>
          );
        })}

        {/* Bars */}
        {validData.map((d, idx) => {
          const barHeight = maxVal > 0 ? (d.value / maxVal) * plotHeight : 0;
          const x = paddingLeft + barSpacing + idx * (barWidth + barSpacing);
          const y = paddingTop + plotHeight - barHeight;
          const isHovered = hoveredIdx === idx;

          return (
            <g
              key={idx}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              style={{ cursor: 'pointer' }}
            >
              {/* Animated rectangle bar */}
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={barHeight}
                fill={d.color || '#0284c7'}
                opacity={isHovered ? 0.95 : 0.75}
                rx={3}
                style={{
                  transition: 'y 0.3s ease, height 0.3s ease, opacity 0.15s'
                }}
              />
              
              {/* Top value labels */}
              <text
                x={x + barWidth / 2}
                y={y - 5}
                fill="var(--text-primary)"
                fontSize="10px"
                fontWeight="bold"
                textAnchor="middle"
                opacity={isHovered ? 1 : 0}
                style={{ transition: 'opacity 0.15s, y 0.15s' }}
              >
                {d.value}
              </text>

              {/* Bottom label */}
              <text
                x={x + barWidth / 2}
                y={paddingTop + plotHeight + 14}
                fill={isHovered ? 'var(--text-primary)' : 'var(--text-muted)'}
                fontSize="9px"
                textAnchor="middle"
                style={{ transition: 'fill 0.15s' }}
              >
                {d.name.length > 8 ? `${d.name.substring(0, 7)}.` : d.name}
              </text>
            </g>
          );
        })}

        {/* Base Axis Line */}
        <line
          x1={paddingLeft}
          y1={paddingTop + plotHeight}
          x2={width - paddingRight}
          y2={paddingTop + plotHeight}
          stroke="var(--border-default)"
        />
      </svg>
      {hoveredIdx !== null && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.8rem', color: 'var(--text-secondary)', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: '4px' }}>
          <strong>{validData[hoveredIdx].name}:</strong> {validData[hoveredIdx].value} findings
        </div>
      )}
    </div>
  );
};


/**
 * LineChart: Renders an SVG line chart for scan history trends.
 * Props:
 *  - data: Array of { date, value }
 */
export const LineChart = ({ data = [], height = 180, color = "#0284c7" }) => {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  if (data.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: `${height}px`, color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        No scan history data to render trend line
      </div>
    );
  }

  const chartData = data;
  const isSinglePoint = chartData.length === 1;

  const maxVal = Math.max(...chartData.map(d => d.value), 0);
  const chartHeight = height;
  const paddingLeft = 40;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 30;

  const width = 500;
  const plotWidth = width - paddingLeft - paddingRight;
  const plotHeight = chartHeight - paddingTop - paddingBottom;

  // Calculate points
  const points = chartData.map((d, idx) => {
    const x = isSinglePoint
      ? paddingLeft + plotWidth / 2
      : paddingLeft + (idx / (chartData.length - 1)) * plotWidth;
    const y = paddingTop + plotHeight - (maxVal > 0 ? (d.value / maxVal) * plotHeight : 0);
    return { x, y, date: d.date, value: d.value };
  });

  // Create path command
  const pathD = points.length > 1 ? points.reduce((acc, p, idx) => {
    return idx === 0 ? `M ${p.x} ${p.y}` : `${acc} L ${p.x} ${p.y}`;
  }, "") : "";

  // Create fill path command (close path at bottom axis)
  const areaD = points.length > 1 
    ? `${pathD} L ${points[points.length - 1].x} ${paddingTop + plotHeight} L ${points[0].x} ${paddingTop + plotHeight} Z`
    : "";

  // Gridticks
  const yTicks = maxVal <= 5 ? Array.from({length: maxVal + 1}, (_, i) => i) : [0, Math.round(maxVal / 2), maxVal];
  
  // Decide which x labels to show to prevent clutter (max 6 labels)
  const labelStep = Math.max(1, Math.ceil(chartData.length / 6));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
      <div style={{ overflowX: 'auto', width: '100%' }}>
        <svg width="100%" height={chartHeight} viewBox={`0 0 ${width} ${chartHeight}`} style={{ minWidth: '400px', overflow: 'visible' }}>
          {/* Y Axis Gridlines */}
          {yTicks.map((tick, i) => {
            const y = paddingTop + plotHeight - (maxVal > 0 ? (tick / maxVal) * plotHeight : 0);
            return (
              <g key={i}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={width - paddingRight}
                  y2={y}
                  stroke="var(--border-subtle)"
                  strokeDasharray="4 4"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 4}
                  fill="var(--text-muted)"
                  fontSize="9px"
                  fontFamily="monospace"
                  textAnchor="end"
                >
                  {tick}
                </text>
              </g>
            );
          })}

          {/* Area Fill */}
          {areaD && (
            <path
              d={areaD}
              fill={`url(#lineGradient-${color.replace('#','')})`}
              opacity={0.15}
            />
          )}

          {/* Line Path */}
          {pathD && (
            <path
              d={pathD}
              fill="transparent"
              stroke={color}
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {/* Gradient Definition */}
          <defs>
            <linearGradient id={`lineGradient-${color.replace('#','')}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* X Axis Labels */}
          {points.map((p, idx) => {
            if (!isSinglePoint && idx % labelStep !== 0) return null;
            return (
              <text
                key={idx}
                x={p.x}
                y={paddingTop + plotHeight + 18}
                fill="var(--text-muted)"
                fontSize="9px"
                textAnchor="middle"
              >
                {p.date}
              </text>
            );
          })}

          {/* Dots on line nodes */}
          {points.map((p, idx) => {
            const isHovered = hoveredIdx === idx;
            return (
              <g key={idx}>
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 6 : 4}
                  fill={isHovered ? 'var(--bg-surface)' : color}
                  stroke={isHovered ? color : 'var(--bg-surface)'}
                  strokeWidth={2}
                  style={{ cursor: 'pointer', transition: 'r 0.15s, fill 0.15s' }}
                  onMouseEnter={() => setHoveredIdx(idx)}
                  onMouseLeave={() => setHoveredIdx(null)}
                />
              </g>
            );
          })}

          {/* Base Axis Line */}
          <line
            x1={paddingLeft}
            y1={paddingTop + plotHeight}
            x2={width - paddingRight}
            y2={paddingTop + plotHeight}
            stroke="var(--border-default)"
          />
        </svg>
      </div>

      {isSinglePoint && (
        <div style={{ textAlign: 'center', marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
          Single audit date recorded ({chartData[0].date}: {chartData[0].value} findings). Trends plot over multiple scan dates.
        </div>
      )}

      {hoveredIdx !== null && (
        <div style={{ marginTop: '0.4rem', alignSelf: 'center', fontSize: '0.8rem', color: 'var(--text-secondary)', background: 'var(--bg-elevated)', padding: '4px 12px', borderRadius: '4px' }}>
          <strong>Scan Date {chartData[hoveredIdx].date}:</strong> {chartData[hoveredIdx].value} findings
        </div>
      )}
    </div>
  );
};


/**
 * MultiLineChart: Renders an SVG multi-line chart for scan history trends comparing multiple tools.
 * Props:
 *  - data: Array of { date, nmap, nuclei, nikto, gobuster, zap, sqlmap, ffuf }
 *  - seriesKeys: Array of keys to plot
 *  - colors: Object mapping series key to color string
 *  - labels: Object mapping series key to user-friendly label
 */
export const MultiLineChart = ({ data = [], seriesKeys = [], colors = {}, labels = {}, height = 180 }) => {
  const [hoveredIdx, setHoveredIdx] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  if (data.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: `${height}px`, color: 'var(--text-muted)', fontSize: '0.9rem' }}>
        No scan history data to render trend lines
      </div>
    );
  }

  const chartData = data;
  const isSinglePoint = chartData.length === 1;

  // Find max value across all series and points
  let maxVal = 0;
  chartData.forEach(d => {
    seriesKeys.forEach(key => {
      const val = d[key] || 0;
      if (val > maxVal) maxVal = val;
    });
  });

  const chartHeight = height;
  const paddingLeft = 40;
  const paddingRight = 20;
  const paddingTop = 25;
  const paddingBottom = 30;

  const width = 500;
  const plotWidth = width - paddingLeft - paddingRight;
  const plotHeight = chartHeight - paddingTop - paddingBottom;

  // Pre-calculate coordinates for each point in each series
  const seriesPoints = {};
  seriesKeys.forEach(key => {
    seriesPoints[key] = chartData.map((d, idx) => {
      const x = isSinglePoint
        ? paddingLeft + plotWidth / 2
        : paddingLeft + (idx / (chartData.length - 1)) * plotWidth;
      const y = paddingTop + plotHeight - (maxVal > 0 ? ((d[key] || 0) / maxVal) * plotHeight : 0);
      return { x, y, value: d[key] || 0 };
    });
  });

  // Calculate paths
  const paths = {};
  seriesKeys.forEach(key => {
    const points = seriesPoints[key];
    if (points.length > 1) {
      paths[key] = points.reduce((acc, p, idx) => {
        return idx === 0 ? `M ${p.x} ${p.y}` : `${acc} L ${p.x} ${p.y}`;
      }, "");
    } else {
      paths[key] = "";
    }
  });

  // Grid ticks
  const yTicks = maxVal <= 5 ? Array.from({length: maxVal + 1}, (_, i) => i) : [0, Math.round(maxVal / 2), maxVal];
  
  // X labels step
  const labelStep = Math.max(1, Math.ceil(chartData.length / 6));

  const handleMouseMove = (e) => {
    if (isSinglePoint) {
      setHoveredIdx(0);
      return;
    }
    const svgRect = e.currentTarget.getBoundingClientRect();
    const clientX = e.clientX - svgRect.left;
    const clientY = e.clientY - svgRect.top;

    const indexFloat = ((clientX - paddingLeft) / plotWidth) * (chartData.length - 1);
    let index = Math.round(indexFloat);
    if (index < 0) index = 0;
    if (index >= chartData.length) index = chartData.length - 1;

    setHoveredIdx(index);
    setTooltipPos({
      x: e.clientX - svgRect.left + 15,
      y: e.clientY - svgRect.top - 15
    });
  };

  const activeHoveredIndex = hoveredIdx !== null && hoveredIdx < chartData.length ? hoveredIdx : null;

  return (
    <div style={{ position: 'relative', width: '100%' }} onMouseLeave={() => setHoveredIdx(null)}>
      <div style={{ overflowX: 'auto', width: '100%' }}>
        <svg
          width="100%"
          height={chartHeight}
          viewBox={`0 0 ${width} ${chartHeight}`}
          style={{ minWidth: '400px', overflow: 'visible' }}
          onMouseMove={handleMouseMove}
        >
          {/* Y Axis Gridlines */}
          {yTicks.map((tick, i) => {
            const y = paddingTop + plotHeight - (maxVal > 0 ? (tick / maxVal) * plotHeight : 0);
            return (
              <g key={i}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={width - paddingRight}
                  y2={y}
                  stroke="var(--border-subtle)"
                  strokeDasharray="4 4"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 4}
                  fill="var(--text-muted)"
                  fontSize="9px"
                  fontFamily="monospace"
                  textAnchor="end"
                >
                  {tick}
                </text>
              </g>
            );
          })}

          {/* Draw lines */}
          {!isSinglePoint && seriesKeys.map(key => {
            const pathD = paths[key];
            if (!pathD) return null;
            return (
              <path
                key={key}
                d={pathD}
                fill="transparent"
                stroke={colors[key] || '#7c3aed'}
                strokeWidth={2.5}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            );
          })}

          {/* Draw dots */}
          {seriesKeys.map(key => {
            const points = seriesPoints[key];
            const color = colors[key] || '#7c3aed';
            return points.map((p, idx) => {
              if (p.value === 0 && !isSinglePoint) return null;
              const isHovered = activeHoveredIndex === idx;
              return (
                <circle
                  key={`${key}-${idx}`}
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 6 : 4}
                  fill={isHovered ? 'var(--bg-surface)' : color}
                  stroke={isHovered ? color : 'var(--bg-surface)'}
                  strokeWidth={2}
                  style={{ cursor: 'pointer', transition: 'r 0.15s, fill 0.15s' }}
                />
              );
            });
          })}

          {/* X Axis Labels */}
          {chartData.map((d, idx) => {
            if (!isSinglePoint && idx % labelStep !== 0) return null;
            const x = isSinglePoint
              ? paddingLeft + plotWidth / 2
              : paddingLeft + (idx / (chartData.length - 1)) * plotWidth;
            return (
              <text
                key={idx}
                x={x}
                y={paddingTop + plotHeight + 18}
                fill="var(--text-muted)"
                fontSize="9px"
                textAnchor="middle"
              >
                {d.date}
              </text>
            );
          })}

          {/* Base Axis Line */}
          <line
            x1={paddingLeft}
            y1={paddingTop + plotHeight}
            x2={width - paddingRight}
            y2={paddingTop + plotHeight}
            stroke="var(--border-default)"
          />
        </svg>
      </div>

      {isSinglePoint && (
        <div style={{ textAlign: 'center', marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
          Single audit date recorded ({chartData[0].date}). Multi-date trends will plot as further scans execute.
        </div>
      )}

      {/* Floating Tooltip */}
      {activeHoveredIndex !== null && (
        <div style={{
          marginTop: '6px',
          padding: '6px 12px',
          background: 'var(--card-bg)',
          border: '1px solid var(--card-border)',
          borderRadius: '6px',
          fontSize: '11px',
          display: 'flex',
          gap: '12px',
          alignItems: 'center',
          justifyContent: 'center',
          flexWrap: 'wrap'
        }}>
          <strong>Date: {chartData[activeHoveredIndex].date}</strong>
          {seriesKeys.map(k => (
            <span key={k} style={{ color: colors[k] || 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: colors[k] }} />
              {labels[k] || k}: <strong>{chartData[activeHoveredIndex][k] || 0}</strong>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};
