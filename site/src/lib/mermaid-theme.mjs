// Mermaid themes built from the interface's tokens (docs/features/ui-design.md).
// Nodes sit on the "raised" surface with a quiet border, edges in the muted
// text colour, groups on the chrome surface — the program's hierarchy by
// surface. Diagram authors can mark nodes with three classes:
//   class a,b done      exists today (number green border)
//   class c planned     not built yet (dashed border, secondary text)
//   class d here        "you are here" (ember border) — at most one per diagram
//   class e layer       a row label in a block diagram (no box, mono, muted)
// The colours of these classes live here, so they follow the theme.

const shared = {
  fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
  fontSize: '15px',
};

function theme(t) {
  return {
    theme: 'base',
    darkMode: t.dark,
    themeVariables: {
      ...shared,
      darkMode: t.dark,
      background: t.surface,
      primaryColor: t.raised,
      primaryTextColor: t.text,
      primaryBorderColor: t.border,
      secondaryColor: t.cursor,
      secondaryTextColor: t.text,
      secondaryBorderColor: t.border,
      tertiaryColor: t.group,
      tertiaryTextColor: t.text2,
      tertiaryBorderColor: t.line,
      mainBkg: t.raised,
      nodeBorder: t.border,
      nodeTextColor: t.text,
      clusterBkg: t.group,
      clusterBorder: t.line,
      titleColor: t.text2,
      lineColor: t.muted,
      textColor: t.text2,
      edgeLabelBackground: t.surface,
      noteBkgColor: t.cursor,
      noteTextColor: t.text,
      noteBorderColor: t.border,
      actorBkg: t.raised,
      actorBorder: t.border,
      actorTextColor: t.text,
      signalColor: t.muted,
      signalTextColor: t.text2,
      labelBoxBkgColor: t.raised,
      labelBoxBorderColor: t.border,
      labelTextColor: t.text,
    },
    themeCSS: `
      g, rect, path, polygon, circle, ellipse { filter: none !important; }
      .node rect, .node polygon, .node circle, .node path { stroke-width: 1.25px; }
      .cluster rect { rx: 8px; ry: 8px; stroke-width: 1px; }
      .cluster-label .nodeLabel, .cluster-label text, .cluster text { font-family: 'JetBrains Mono', monospace; font-size: 12px; letter-spacing: 0.04em; fill: ${t.muted}; color: ${t.muted}; }
      .edgeLabel, .edgeLabel p, .edgeLabel rect { background-color: ${t.surface}; fill: ${t.surface}; }
      .edgeLabel text, .edgeLabel span { fill: ${t.text2}; color: ${t.text2}; font-size: 13px; }
      .node.done rect, .node.done polygon, .node.done path { stroke: ${t.done}; stroke-width: 1.75px; }
      .node.planned rect, .node.planned polygon, .node.planned path { stroke-dasharray: 4 3; fill: ${t.surface}; }
      .node.planned .nodeLabel, .node.planned text { fill: ${t.text2}; color: ${t.text2}; }
      .node.here rect, .node.here polygon, .node.here path { stroke: ${t.accent}; stroke-width: 2px; }
      .node.layer rect, .node.layer polygon { fill: transparent; stroke: none; }
      .node.layer .nodeLabel, .node.layer text, .node.layer span { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 0.06em; fill: ${t.muted}; color: ${t.muted}; }
      .flowchart-link, .edgePath .path { stroke-width: 1.25px; }
      marker path, .arrowheadPath { fill: ${t.muted}; stroke: ${t.muted}; }
    `,
    flowchart: { htmlLabels: false, curve: 'basis', padding: 14, nodeSpacing: 34, rankSpacing: 46, diagramPadding: 8 },
    sequence: { mirrorActors: false },
  };
}

export const mermaidThemes = {
  light: theme({
    dark: false,
    surface: '#fbf8f4',
    raised: '#ffffff',
    cursor: '#f3ece4',
    group: '#f5f0e9',
    text: '#1e1814',
    text2: '#5e554e',
    muted: '#6e645c',
    border: '#cdbfb2',
    line: '#e4dbd1',
    done: '#276b1a',
    accent: '#e8551a',
  }),
  dark: theme({
    dark: true,
    surface: '#1d1815',
    raised: '#27211d',
    cursor: '#2c241f',
    group: '#191412',
    text: '#ece5dd',
    text2: '#b3a89e',
    muted: '#968c82',
    border: '#4a3f38',
    line: '#332a25',
    done: '#a8dca0',
    accent: '#ff6a2b',
  }),
};
