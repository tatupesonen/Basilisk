// Documentation Markdown links are written root-relative (`/docs/cli/`).
// This Sätteri mdast plugin prefixes them with the configured base path so
// the site works both at a domain root and under a sub-path such as
// https://<user>.github.io/basilisk/ (docs/features/site.md, Content rules).

export function baseLinksPlugin(base) {
  const prefix = base.endsWith('/') ? base.slice(0, -1) : base;
  const fix = (node, ctx) => {
    const url = node.url;
    if (prefix && typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') && !url.startsWith(prefix + '/')) {
      ctx.setProperty(node, 'url', prefix + url);
    }
  };
  return {
    name: 'bk-base-links',
    link: fix,
    image: fix,
    definition: fix,
  };
}
