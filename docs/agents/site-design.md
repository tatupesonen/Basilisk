# Track `site-design` — report

Spec: `docs/features/site.md`. Decisions: ADR-030, ADR-031.

## Status

Done, including the CI fix below. Nothing in progress. Next work belongs
to `docs-content`.

## CI fix (2026-11-14, run 43585590683)

- **Cause**: `scripts/site.sh` passed `--cpus 3 --memory 6g`, sized for
  this Mac. GitHub's `ubuntu-latest` runner has 2 CPUs, and Docker refuses
  a CPU limit above what it has (`range of CPUs is from 0.01 to 2.00`).
  The image itself built fine on the runner in about a minute, pull
  included (job log: step start 10:30:32, image done 10:31:31).
- **Fix**: limits come from `docker info` (Docker's own view, which on
  macOS is its VM): CPUs = min(3, Docker's), memory = min(6 GiB, ¾ of
  Docker's); `SITE_CPUS` / `SITE_MEMORY` override. Also: `node_modules` is
  reinstalled when the architecture differs (the stamp now includes
  `uname -m`), so switching between the arm64 and amd64 images cannot mix
  native packages; `SITE_PLATFORM=linux/amd64` runs the amd64 image.
- **Checked for other Mac assumptions**:
  - Running as the calling user: on the runner that is uid 1001, which is
    `pwuser` in the image; everything the build writes (`node_modules`,
    `dist`, `src/generated`, `.cache`) is owned by 1001 — verified on an
    ext4 volume (below). On macOS uid 501 has no passwd entry and worked.
  - Pinned digest: it is the multi-arch index; the amd64 manifest
    (`sha256:ee15712262f0…b1d0`) was pulled and built under emulation.
  - Pull and build time: about 1 minute on the runner, against
    `timeout-minutes: 30`; no caching added (not at risk).
  - Fonts: fontTools from Ubuntu's apt in the image, same on amd64; ran.
  - Chromium's sandbox: Playwright launches Chromium without the sandbox
    by default, so no `--privileged` or seccomp change is needed; rendered
    diagrams as uid 1001 under emulation.
  - Case-sensitive paths: the build and link check ran on an ext4 volume;
    no case mismatch.
  - The lock file holds the linux-x64 native packages (`@img/sharp-linux-x64`,
    `@bruits/satteri-linux-x64-gnu`, `@rolldown/binding-linux-x64-gnu`,
    `@astrojs/compiler-binding-linux-x64-gnu`, `lightningcss-linux-x64-gnu`,
    `@pagefind/linux-x64`); `npm ci` installed them on amd64.
- **What ran where**:
  1. `SITE_PLATFORM=linux/amd64 SITE_CPUS=2 SITE_MEMORY=5g scripts/site.sh check`
     on this Mac (amd64 image under emulation, bind-mounted worktree):
     passed, 8 min 43 s wall time including building the amd64 image
     (apt under emulation) and `npm ci` (41 s).
  2. A runner simulation (scratch script, not committed): the committed
     tree copied into a Docker volume (ext4), owned by 1001:1001, built and
     checked by the amd64 image as uid 1001 with `--cpus 2 --memory 5g`:
     passed in 115 s in the container (`npm ci` 55 s); peak memory sampled
     1.35 GiB, well inside the 5 GB limit and inside ¾ of any runner's
     memory the script would grant (the runner's exact memory was not
     measured); nothing written was owned by anyone
     but 1001.
  3. Native, from a clean state (no `node_modules`, `dist`, caches or
     generated files): `scripts/site.sh check` passed in 1 min 33 s.
  Nothing failed to fit; the 6 GiB cap could be lower but is harmless.

## Built

- **One Astro project, `site/`** (Astro 7.4.4, Starlight 0.42.8):
  product pages `/` (landing), `/status/` (full parity matrix), `/roadmap/`
  (milestones), `/404.html`; Starlight documentation under `/docs/` with
  the sidebar of ADR-030 — Overview, Getting started (Introduction, Build
  and run), The interface, The command line, Analysis, The decompiler,
  Scripting and plugins, Formats and processors, How it works — one honest
  page per section saying what exists today and what is planned.
- **Generated content**: the status matrix, its summary bars and the
  landing page's milestone strip are parsed at build time from
  `docs/PARITY.md` and `docs/PLAN.md` (`site/src/lib/parity.ts`,
  `plan.ts`); an unknown status or changed column layout fails the build.
  The current milestone (first incomplete one) is computed, so the hero's
  "now: M1 SLEIGH runtime" moves by itself. Screenshots come from
  `docs/features/ui-screenshots/` at build time (`prepare.sh`,
  `crops.mjs`), never committed twice.
- **Container tooling**: `scripts/site.sh build|serve|check|shoot|dep-age|lock|shell`,
  image definition `site/container/Dockerfile`. Every container: `--rm`,
  `--init`, 3 CPUs, 6 GB, runs as the calling user, `timeout` inside
  (default 1,200 s; `serve` stops after 30 minutes), removed on exit or
  Ctrl+C by a trap.
- **Design system**: `site/src/styles/tokens.css` (the interface's
  surfaces, text and twelve syntax colours for both themes, brand colours,
  spacing 2–40 px plus layout steps, radii), `components.css`, `site.css`,
  `status.css`, `starlight.css` (Starlight's variables mapped onto the
  tokens plus restyled sidebar, TOC, asides, tables, code, search, focus).
  Components: `Mark`, `Logo`, `Screenshot` (theme-paired, responsive WebP,
  dialog viewer), `CodeSample` (listing/decompiler lines in the syntax
  colours), `StatusSummary`, `StatusTable` (filter without scripts),
  `Milestones`, `Callout`, `Kbd`, `Icon` (Phosphor, inlined),
  `ThemeToggle`; Starlight overrides `SiteTitle`, `ThemeSelect`,
  `SocialIcons`, `Footer`. Expressive Code themes built from the twelve
  syntax colours (`site/src/lib/code-themes.mjs`).
- **Fonts**: Inter Regular/SemiBold and JetBrains Mono NL Regular/SemiBold
  from `crates/bk-ui/assets/fonts/`, subset (Latin, punctuation, arrows,
  box drawing, key symbols) and converted to WOFF2 at build time by
  fontTools in the image (30–47 kB each, from 210–420 kB TTFs); OFL texts served at `/fonts/`.
- **CI**: job `site` in `.github/workflows/ci.yml` (`scripts/site.sh check`,
  `timeout-minutes: 30`); `.github/workflows/pages.yml` deploys on manual
  dispatch only.
- `.gitignore`: `site/node_modules/`, `site/dist/`, `site/.astro/`,
  `site/.cache/`, `site/src/generated/`. `.gitattributes`: `*.jpg`,
  `*.woff2` binary.

## Design decisions and why

- **Same product as the program.** Colours are the interface's tokens
  verbatim (`ui-design.md` §5), type is the interface's two OFL faces,
  spacing its scale. Dark is the default, as in the program. Hierarchy by
  surface: chrome (darkest) for header, sidebar and alternate sections,
  surface for reading.
- **Ember only "where you are"**, the program's rule carried over: the
  current page (an ember rule under the nav item; the slit-pupil marker in
  the docs sidebar), the current milestone, focus rings, the primary
  button, the active status filter. Links are text-coloured with a quiet
  underline and turn ember only under the pointer. Statuses and call-outs
  use the syntax hues (Done = number green, Partial = function gold, …),
  so colour keeps meaning.
- **The basilisk twist, kept restrained**: the slit pupil is the
  "you are here" marker everywhere (an SVG mask, so it scales); the mark's
  ring becomes faint iris rings behind the hero mark; section labels are
  set like listing addresses (`0x10 · The interface`, `0xdeadbeef` on the
  404); the docs title reads `basilisk [docs]` with the stroke wordmark
  drawn inline (theme-aware, no image).
- **Real screenshots only**, captioned as the demo program; the gallery
  uses crops of the real images so the feature shown is legible; the
  renderer's black margin is trimmed so the site's frame is the only
  border. The listing/decompiler sample is set as text, copied from the
  demo program's `main` as the screenshot shows it.
- **Honest copy**: "Works today" / "Not yet" panels state only what
  `PARITY.md` and the repository support; the hero pill says "Early
  development"; Python plugins are tagged "planned"; every footer says
  basilisk is independent and not affiliated with or endorsed by Ghidra's
  authors or the NSA, with GPL-3.0-or-later and the source link.
- **No scripts needed to read**: theme follows the system without JS;
  screenshot links open the image; the status filter is radio inputs and
  `:has()`. Scripts: theme switch, screenshot dialog, Starlight's search
  and TOC.
- **Contrast** (WCAG, computed): body text 14.1 (dark) / 16.6 (light);
  secondary 8.1 / 6.1 on chrome; muted 5.7 / 4.8 on chrome (lowest: 4.8,
  dark muted on raised and light muted on chrome); primary button
  soot-on-ember 6.6 / 5.2; code-block syntax colours ≥ 4.8 on their
  backgrounds. All text ≥ 4.5:1.

## How Mermaid is rendered

At build time, in the image. A Sätteri mdast plugin
(`site/src/lib/mermaid.mjs`; Sätteri is Astro 7's default Markdown
pipeline) replaces each ```` ```mermaid ```` block with a `<figure>`
holding two inline SVGs, light and dark, and CSS shows the one matching
the theme. The renderer drives Mermaid 12.2.0 in headless Chromium through
Playwright with the site's own Inter and JetBrains Mono loaded, so boxes
are measured with the fonts the page draws (`font-feature-settings` is
reset inside diagrams for the same reason). Why a browser: Mermaid lays
out text with the browser's DOM measurement, and the Playwright image
already carries a matching Chromium, so build-time rendering was practical
(no other renderer was tried) — no client-side fallback was needed. A diagram that does not
parse fails the build with its file and Mermaid's message (verified: a
deliberately broken block made `scripts/site.sh build` exit 1). Themes:
`site/src/lib/mermaid-theme.mjs` (classes `done`, `planned`, `here`,
`layer`; no drop shadows, flat as the brand requires). The crate map uses
`block-beta` because Mermaid ignores `direction` inside linked subgraphs.
`check-site.mjs` fails if any mermaid block is left as code, if a figure
lacks either SVG, or if the count of rendered diagrams differs from the
fenced blocks in the sources.

## The image

- `site/container/Dockerfile`:
  `FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f`
  (multi-arch index: amd64 `sha256:ee15712262f0…b1d0`, arm64
  `sha256:f609973e8fd9…6197`), plus `python3-fonttools=4.46.0-1build2` and
  `python3-brotli=1.1.0-2ubuntu0.1` from Ubuntu noble. Node 26.13.0,
  npm 11.20.0, Chromium build 1248. Telemetry off
  (`ASTRO_TELEMETRY_DISABLED=1`).
- Tagged locally `bk-site/build:<first 12 hex of the Dockerfile's sha256>`
  (now `bk-site/build:96633730fa72`, image id `sha256:dcb58f157122…020`),
  so a changed Dockerfile is rebuilt automatically. Updating the digest is
  described in the Dockerfile header: pick a Playwright release ≥ 2 weeks
  old, `docker buildx imagetools inspect …`, put the index digest in
  `FROM`, set `playwright` in `site/package.json` to the same version,
  `scripts/site.sh lock`, `scripts/site.sh check`.

## Dependencies

Exact versions in `site/package.json`, lock file `site/package-lock.json`
(installed with `npm ci`, frozen). Generated with
`npm install --before=2026-10-31T00:00:00Z` (`scripts/site.sh lock`), so
npm itself refused anything younger; then checked against the registry by
`site/scripts/check-dep-age.mjs` (`scripts/site.sh dep-age`), which reads
each package's `time` map from `registry.npmjs.org`:

| Package | Version | Published |
|---|---|---|
| `astro` | 7.4.4 | 2026-10-28 |
| `@astrojs/starlight` | 0.42.8 | 2026-10-30 |
| `@astrojs/markdown-satteri` | 0.4.6 | 2026-10-28 |
| `mermaid` | 12.2.0 | 2026-10-13 |
| `playwright` | 1.64.1 | 2026-10-14 |
| `sharp` | 0.35.5 | 2026-09-27 |
| `@phosphor-icons/core` | 2.1.1 | 2024-03-29 |

All **468** package versions in the lock file (transitive included) were
checked; the newest is `@astrojs/starlight` 0.42.8 (2026-10-30, 15 days);
none could not be checked. Not checked by this script: the Playwright base
image (v1.64.1, released 2026-10-14) and the two Ubuntu packages (pinned
by version, not by date). All of it is development tooling, not part of
the product (ADR-030). Licences: Astro, Starlight, Sätteri, Playwright —
MIT/Apache-2.0; Mermaid MIT; sharp Apache-2.0 (libvips LGPL, build-time
only, not redistributed); Phosphor icons MIT (the icons are inlined into
the published pages, compatible with GPL-3.0-or-later); fonts SIL OFL 1.1.

## Verified

- `scripts/site.sh check` from a clean state (no `node_modules`, `dist`,
  caches or generated files): builds under `/basilisk/` and at `/`, both
  pass — 14 pages, 616 links and resources, 3 diagrams in both themes, no
  external subresources. Negative test: checking a `/basilisk/` build
  against base `/other/` reports 403 problems.
- No external requests at run time: `shoot.mjs` logs every request that
  leaves the local server; none in any page, theme or width.
- Screenshots (Playwright Chromium in the image), 2.7 MB total, in
  `docs/features/site-screenshots/`:
  `home-desktop-{dark,light}.jpg` (1440 px, full page),
  `home-phone-{dark,light}.jpg` (390 px, full page),
  `status-desktop-{dark,light}.jpg`, `status-phone-{dark,light}.jpg`,
  `docs-internals-desktop-{dark,light}.jpg`,
  `docs-internals-phone-{dark,light}.jpg` (the data-flow diagram),
  `roadmap-desktop-{dark,light}.jpg`. Reviewed and iterated: fixed theme
  pairing that broke the frame's display, the hero screenshot's caption
  being clipped, whitespace lost before inline links (Astro's compiler),
  unreadable gallery thumbnails (now crops), the crate map's tall layout
  (now a block diagram), tiny diagrams on phones (now scroll), the
  renderer's black margins, Mermaid's drop shadows, the bright phone menu
  button.
- `scripts/site.sh serve`: preview answered 200 on `/` and `/docs/`, 404
  on a missing page; container stopped afterwards.
- Rust gate (run again after the CI fix): `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`
  → `0` (`tests: 1708 passed, 0 failed`; cargo-deny bans, licences,
  sources ok). The gate's file-size and unsafe checks scan
  only `crates/`, so `site/` needed no exclusion.

## What the owner must do to deploy

1. GitHub → repository **Settings → Pages → Build and deployment →
   Source: "GitHub Actions"**.
2. Run the **Pages** workflow (Actions tab → Pages → Run workflow, or
   `gh workflow run Pages`). It builds with the base path GitHub reports
   (`/basilisk/` for `https://tatupesonen.github.io/basilisk/`) and deploys.
3. For a custom domain: set it under Settings → Pages; the workflow then
   builds at `/` automatically (`configure-pages` reports an empty base
   path). To deploy on every push to `master`, add `push: branches:
   [master]` to `pages.yml`.

## What I would still improve

- A social preview image (`og:image`) rendered from the hero.
- Generated reference pages (key bindings from the action registry, CLI
  help) — `docs-content`'s job; the components (`Kbd`, `CodeSample`)
  are ready for them.
- Diagrams are rendered again on every clean build; a cache keyed by the
  diagram's hash would help when there are dozens.
- The status page could link each row to its feature document when
  `PARITY.md` names one in a structured way.
- Starlight's search dialog is restyled only through variables.
- The CI job builds the image from scratch each run (≈ 2.5 GB pull);
  caching the image layer would save a few minutes.

## Follow-ups for the coordinator

- `docs-content`: write pages under `site/src/content/docs/docs/<section>/`;
  root-relative links (`/docs/cli/`) get the base path automatically; use
  `<Screenshot name="…">` in `.mdx` after adding the screenshot to
  `site/src/lib/screenshots.ts`; Mermaid classes `done`/`planned`/`here`.
- Proposed rule for `RULES.md` (ADR-030 already says it): a track that
  changes `PARITY.md` or `PLAN.md`'s format runs `scripts/site.sh check`,
  since the site parses both.

## Commits

```
df6346a docs(site): spec status and track report
4bfc4ae feat(site): phone layout polish; screenshots of the site in docs/features/site-screenshots
8a705ca ci(site): build and check the site in its container; manual GitHub Pages deployment
4aab6c5 feat(site): link, external-request and diagram checks; diagram and gallery refinements
eb15f6b feat(site): Astro + Starlight project, container build, design system, product pages and docs shell
2e1dfe2 docs(site): spec for the website and documentation site
```
(plus this report's final commit)
