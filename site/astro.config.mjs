// basilisk's website and documentation (ADR-030, ADR-031; docs/features/site.md).
// Build only through scripts/site.sh, which runs this in the site image.
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import { mermaidPlugin, mermaidIntegration } from './src/lib/mermaid.mjs';
import { baseLinksPlugin } from './src/lib/base-links.mjs';
import { codeThemes } from './src/lib/code-themes.mjs';
import { repo } from './src/lib/site-config.mjs';

// Base path: "/" at a domain root, "/basilisk/" for https://<user>.github.io/basilisk/.
const rawBase = process.env.SITE_BASE || '/';
const base = rawBase.endsWith('/') ? rawBase : rawBase + '/';

export default defineConfig({
  site: process.env.SITE_URL || 'https://tatupesonen.github.io',
  base,
  trailingSlash: 'always',
  outDir: process.env.SITE_OUT || './dist',
  publicDir: './src/generated/public',
  cacheDir: './.cache/astro',
  build: { format: 'directory', inlineStylesheets: 'auto' },
  devToolbar: { enabled: false },
  prefetch: false,
  image: {
    // Only local images; nothing is fetched from elsewhere.
    domains: [],
  },
  markdown: {
    processor: satteri({ mdastPlugins: [mermaidPlugin(), baseLinksPlugin(base)] }),
  },
  integrations: [
    starlight({
      title: 'Basilisk',
      description:
        'User documentation for Basilisk, a reimplementation of Ghidra in Rust: what works today, what is planned, and how each part works.',
      favicon: '/favicon.svg',
      head: [
        { tag: 'link', attrs: { rel: 'icon', type: 'image/png', sizes: '32x32', href: base + 'favicon-32.png' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#150f0d' } },
      ],
      customCss: ['./src/styles/tokens.css', './src/styles/components.css', './src/styles/starlight.css'],
      components: {
        SiteTitle: './src/components/starlight/SiteTitle.astro',
        ThemeSelect: './src/components/starlight/ThemeSelect.astro',
        SocialIcons: './src/components/starlight/SocialIcons.astro',
        Footer: './src/components/starlight/Footer.astro',
      },
      disable404Route: true,
      editLink: { baseUrl: `${repo}/edit/master/site/` },
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      expressiveCode: {
        themes: codeThemes,
        useStarlightDarkModeSwitch: true,
        useStarlightUiThemeColors: false,
        styleOverrides: {
          borderRadius: '8px',
          borderColor: 'var(--bk-line)',
          codeFontFamily: 'var(--bk-font-mono)',
          codeFontSize: '0.875rem',
          codeLineHeight: '1.6',
          uiFontFamily: 'var(--bk-font-sans)',
          frames: {
            shadowColor: 'transparent',
            editorTabBarBackground: 'var(--bk-chrome)',
            terminalTitlebarBackground: 'var(--bk-chrome)',
            terminalTitlebarBorderBottomColor: 'var(--bk-line)',
            editorTabBarBorderBottomColor: 'var(--bk-line)',
          },
        },
      },
      sidebar: [
        { label: 'Overview', slug: 'docs' },
        { label: 'Getting started', items: [{ autogenerate: { directory: 'docs/getting-started' } }] },
        { label: 'The interface', items: [{ autogenerate: { directory: 'docs/interface' } }] },
        { label: 'The command line', items: [{ autogenerate: { directory: 'docs/cli' } }] },
        { label: 'Analysis', items: [{ autogenerate: { directory: 'docs/analysis' } }] },
        { label: 'The decompiler', items: [{ autogenerate: { directory: 'docs/decompiler' } }] },
        { label: 'Scripting and plugins', items: [{ autogenerate: { directory: 'docs/scripting' } }] },
        { label: 'Formats and processors', items: [{ autogenerate: { directory: 'docs/formats' } }] },
        { label: 'How it works', items: [{ autogenerate: { directory: 'docs/internals' } }] },
      ],
    }),
    mermaidIntegration(),
  ],
});
