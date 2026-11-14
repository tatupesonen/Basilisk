# Build image for Basilisk's website and documentation (ADR-030, ADR-031).
#
# Everything that needs Node.js runs in this image: npm, Astro, Starlight,
# the Mermaid renderer (headless Chromium through Playwright) and the
# screenshots of the built site. Nothing here is installed on a developer's
# machine. Built and run by scripts/site.sh; CI uses the same file.
#
# Base: Microsoft's Playwright image, pinned by the digest of its multi-arch
# index (linux/amd64 and linux/arm64). It carries Node.js and the Chromium
# build that the `playwright` npm package of the same version drives, so
# site/package.json pins `playwright` to exactly the version in this tag.
#
# To update: pick a Playwright release at least two weeks old, then
#   docker buildx imagetools inspect mcr.microsoft.com/playwright:vX.Y.Z-noble
# and put the index digest (the first "Digest:" line) below, set
# `playwright` in site/package.json to X.Y.Z, regenerate the lock file
# (scripts/site.sh lock), and run scripts/site.sh check.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f

# fontTools subsets the repository's OFL fonts and writes WOFF2 (brotli).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3-fonttools=4.46.0-1build2 \
      python3-brotli=1.1.0-2ubuntu0.1 \
 && rm -rf /var/lib/apt/lists/*

ENV ASTRO_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /repo/site
