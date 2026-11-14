import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// The documentation lives under src/content/docs/docs/ so that its URLs start
// with /docs/; the product pages in src/pages/ own the rest of the site.
export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
