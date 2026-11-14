# Basilisk website and documentation site (`site/`)

Track `site-design` (ADR-030, ADR-031). Format of this document:
`docs/LOOP.md`, "Feature documents". The track `docs-content` fills the
documentation later; this document is its contract for structure, design
and build.

## 1. Purpose

Basilisk's public face: a product site at `/` that says what Basilisk is,
shows the real interface and states honestly what works today, and the
user documentation at `/docs/`. Both are one static Astro project, styled
as the same product as the desktop interface, built only inside a
container so no developer machine needs Node.js.

## 2. Sources

Not derived from Ghidra code. Its inputs are this repository's own files:

| Input | Used for |
|---|---|
| `assets/brand/` | The mark and wordmark (drawn inline from the same paths), the palette, clear-space rules |
| `docs/features/ui-design.md` | Colour tokens for both themes, the twelve syntax colours, type (Inter, JetBrains Mono NL), spacing scale, radii, the rule that ember marks only "where you are" |
| `crates/bk-ui/assets/fonts/` | The OFL font files, subset to WOFF2 at build time |
| `docs/features/ui-screenshots/` | Every screenshot on the site (copied at build time; regenerate them with `BK_UI_SCREENSHOT_DIR=docs/features/ui-screenshots cargo test -p bk-ui --test screenshots`) |
| `docs/PARITY.md` | The status matrix and its summary, parsed at build time |
| `docs/PLAN.md` | Goals, the milestone roadmap (parsed at build time), the data flow and crate map the diagrams show |
| `NOTICE`, `LICENSE` | The credit to Ghidra and the licence line in every footer |

Nothing is copied from Ghidra's or any other product's site or artwork.

## 3. Scope

In: `site/` (Astro project, design system, product pages, documentation
shell, container definition, build scripts), `scripts/site.sh`, the `site`
job in `.github/workflows/ci.yml`, `.github/workflows/pages.yml`, this
document, `docs/features/site-screenshots/`.

Out: the documentation's full content (track `docs-content`); generated
reference pages (key bindings from the action registry, CLI help, Python
API) — their places exist, their generators come with `docs-content`;
hosting configuration (the owner enables GitHub Pages).

## 4. Behaviour

### Structure

| Path | What |
|---|---|
| `/` | Landing page: the mark, what Basilisk is, real screenshots, status summary, why it exists, how to build and run it today, credit and licence |
| `/status/` | The full parity matrix from `docs/PARITY.md`, filterable by status without scripts (radio inputs and `:has()`) |
| `/roadmap/` | Milestones M0–M10 with their checklists from `docs/PLAN.md`; the current milestone marked in ember |
| `/docs/` | Starlight documentation; sidebar groups: Getting started, The interface, The command line, Analysis, The decompiler, Scripting and plugins, Formats and processors, How it works |
| `/404.html` | Site-styled not-found page |

Every documentation page says what exists today and what is planned.
Content goes in `site/src/content/docs/docs/<section>/`; a page's sidebar
place follows from its directory (`autogenerate`) and `sidebar.order`.

### Content rules

- **Honest.** Claims of what works come from the generated status (PARITY)
  or from what the repository runs today. Screenshots are captioned as
  the interface on its built-in demo program until real programs load.
- **Generated where possible.** Status table and roadmap are parsed from
  `docs/PARITY.md` and `docs/PLAN.md` at build time; a change in a
  heading or column layout there that the parser does not understand
  fails the build rather than showing stale or partial data.
- **No affiliation implied.** Ghidra is credited as the work Basilisk
  reimplements, with a link to its source; every footer says Basilisk is
  independent and not affiliated with or endorsed by Ghidra's authors.
- **Licence and source** in every footer: GPL-3.0-or-later and the
  repository link.
- **No external requests.** Fonts, icons, scripts and images are served
  from the site itself; no analytics, trackers or third-party hosts. The
  link checker fails on any `src`, stylesheet or script URL that leaves
  the site.
- **Links inside docs content** are written root-relative (`/docs/cli/`);
  a remark plugin adds the base path, so the site works at a domain root
  and under a sub-path (`https://<user>.github.io/basilisk/`).
- **Pages read without scripts.** Scripts exist only for search
  (Pagefind), the theme switch and the screenshot viewer; without them
  the theme follows the system and screenshots open as plain images.

### Mermaid diagrams

Fenced `mermaid` blocks in documentation Markdown are rendered to inline
SVG at build time (a Sätteri mdast plugin, `site/src/lib/mermaid.mjs`;
Sätteri is Astro 7's default Markdown pipeline), twice — light and dark, with the site's theme
variables — and CSS shows the one matching the active theme. Rendering
runs Mermaid in headless Chromium (Playwright) inside the build image, so
text is measured with the same Inter the page uses. A diagram that fails
to parse or render stops the build with its file and message. No Mermaid
code is shipped to the browser. Authors mark nodes with the classes `done`
(exists today), `planned` (dashed) and `here` (ember), and row labels of
block diagrams with `layer`; their colours live in
`site/src/lib/mermaid-theme.mjs` so they follow the theme. A
`title="…"` after the fence becomes the caption. Flowcharts whose
subgraphs are linked ignore `direction` inside the subgraphs (Mermaid's
rule); use `block-beta` for grid layouts such as the crate map. On phones
a wide diagram keeps a legible size and scrolls sideways.

## 5. Design

### Design system (`site/src/styles/`)

- **Tokens** (`tokens.css`): the interface's surfaces, text and syntax
  colours for both themes, verbatim from `ui-design.md`; the brand's
  Ember / Ember deep / Soot / Bone; spacing 2–40 px plus larger layout
  steps (64, 96, 128) for the page rhythm; radii 4/6/8. Dark is the
  default, as in the program. Starlight's `--sl-*` variables are mapped
  onto these tokens (`starlight.css`).
- **Ember marks "where you are"**, as in the program: the current page in
  navigation, the current sidebar entry, focus rings, the primary action,
  the current milestone. Statuses use the syntax colours (Done = number
  green, Partial = function gold, In progress = register blue, Replaced
  = type teal, Reused = parameter violet, Missing = muted).
- **Type**: Inter (Regular, SemiBold) for text, JetBrains Mono NL for
  code, addresses and labels; both from the repository's OFL files,
  subset to Latin and converted to WOFF2 at build time. Section labels
  are set like listing addresses (`0x10 · The interface`), the one
  reverse-engineering flourish in the type.
- **Motif**: the mark's ring and slit pupil. The pupil is the list
  bullet and the active-item marker; the ring frames the hero as faint
  concentric strokes (an iris). Flat colour only, as the brand guide
  requires.
- **Components** (`site/src/components/`): `Mark`, `Logo` (inline SVG
  from the brand paths, theme-aware), `Screenshot` (window frame,
  light/dark pair, responsive WebP from the PNG, opens full size),
  `CodeSample` (listing and decompiler lines in the twelve syntax
  colours), `StatusTable` and `StatusSummary`, `Callout`, `Kbd`
  (key-binding chips), `ThemeToggle` (sun/moon, shares Starlight's
  storage key so the choice carries between site and docs).
- **Starlight** is restyled through its CSS variables, Expressive Code
  themes built from the syntax colours, and component overrides
  (`SiteTitle`, `ThemeSelect`, `SocialIcons`, `Footer`).
- **Icons**: Phosphor (MIT), the family the program uses, inlined at
  build time from `@phosphor-icons/core`.

### Build (`scripts/site.sh`, `site/container/`)

- `scripts/site.sh build|serve|check|shoot|shell` runs the image
  `bk-site/build` (built from `site/container/Dockerfile`, itself
  `FROM` the Playwright image pinned by digest) with the repository
  mounted, as the calling user, with a time limit, removed when done.
  CPU and memory are sized from what Docker reports (`docker info`; on
  macOS that is Docker's VM, not the host): min(3, Docker's CPUs) and
  min(6 GiB, ¾ of Docker's memory), overridable with `SITE_CPUS` and
  `SITE_MEMORY`. A GitHub runner has 2 CPUs. `SITE_PLATFORM=linux/amd64`
  builds and runs the amd64 image (emulated on an arm64 Mac) to reproduce
  CI. `node_modules` is reinstalled when the lock file or the machine
  architecture changes (native packages differ per architecture).
- `npm ci` installs from the committed `site/package-lock.json` when
  `node_modules` is missing or older than the lock file.
- `site/scripts/prepare.sh` copies screenshots and brand files and makes
  the WOFF2 fonts (fontTools, in the image) into git-ignored
  `site/src/generated/`; `site/scripts/crops.mjs` trims the renderer's
  black margin from the screenshots and cuts three detail views (palette,
  hover preview, references) for the landing page's gallery — crops of
  the real images, never retouched.
- `site/src/lib/screenshots.ts` lists the screenshots the pages use (an
  imported image is emitted into the build even when unused, so only
  used ones are listed); `<Screenshot name="…">` picks the dark or light
  rendering by theme and serves responsive WebP.
- `build` → `site/dist/`. `SITE_BASE` (default `/`) and `SITE_URL` set
  the base path and canonical origin.
- `check` = build + `check-links.mjs` (every internal `href`/`src`
  resolves to a file in `dist`, fragments exist, no external
  subresources) + the diagram check (every diagram rendered, none left
  as code) — built once at the root and once under `/basilisk/`.
- `shoot` takes screenshots of the built site with Playwright's Chromium
  into `docs/features/site-screenshots/`.
- Dependencies: exact versions, lock file frozen, each published at least
  two weeks before it was added; `site/scripts/check-dep-age.mjs` checks
  every package in the lock file against the registry (network; run by
  hand when dependencies change, like `scripts/check-dep-age.py`).

### CI

- Job `site` in `ci.yml`: builds the image, runs `scripts/site.sh check`.
- `pages.yml`: manual dispatch; builds with `SITE_BASE=/<repo>/`,
  uploads `site/dist/` and deploys with GitHub's Pages actions.

## 6. Tests

`scripts/site.sh check`: the build itself (diagram parse failures, PARITY
and PLAN parse failures fail it), internal links and fragments at both
base paths, no external subresources, every Mermaid block rendered in
both themes. Visual review from `scripts/site.sh shoot` at 1440 px and
390 px, light and dark.

## 7. Acceptance

- `scripts/site.sh check` passes from a clean checkout; the Rust gate
  stays green.
- No Node, npm or browser on the host; the image is pinned by digest.
- The site works at `/` and under a sub-path; pages read without scripts;
  no external requests.
- Text contrast meets WCAG AA in both themes.
- Screenshots of the result in `docs/features/site-screenshots/`.

## 8. Differences from Ghidra

Not applicable: Ghidra's documentation is its in-program help, not a
website. Basilisk's in-program help (`PARITY.md`, "Docking, Gui, Help")
is a separate, later question.

## 9. Status

Built by track `site-design` (report: `docs/agents/site-design.md`),
2026-11-14:

- Astro 7.4.4 + Starlight 0.42.8 project under `site/`; product pages `/`,
  `/status/`, `/roadmap/`, `/404.html`; the documentation shell under
  `/docs/` with an overview page per section (Getting started has two)
  and three Mermaid diagrams (headless data flow and crate map in "How it
  works", the decompiler pipeline).
- `scripts/site.sh build|serve|check|shoot|dep-age|lock|shell`; image
  `bk-site/build:<Dockerfile hash>` from `site/container/Dockerfile`,
  `FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a7…768f`.
- `scripts/site.sh check` passes from a clean state at `/` and under
  `/basilisk/` (14 pages, 616 links and resources, 3 diagrams in both
  themes); all 468 locked package versions are at least 14 days old.
- CI job `site`; `.github/workflows/pages.yml` (manual dispatch).
- Screenshots of the result: `docs/features/site-screenshots/`.

Gaps: generated reference pages (key bindings, CLI help, Python API) and
one page per interface view are for `docs-content`; no social preview
image; Pagefind's search UI is Starlight's, restyled only through its
variables.
