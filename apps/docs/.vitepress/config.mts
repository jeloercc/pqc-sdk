import { transformerTwoslash } from '@shikijs/vitepress-twoslash';
import { defineConfig } from 'vitepress';

import typedocSidebar from '../api/typedoc-sidebar.json';

export default defineConfig({
  title: 'PQC SDK',
  description: 'Post-quantum cryptography for JS/TS in 30 minutes',
  lang: 'en',
  // The site is published on GitHub Pages under /pqc-sdk/ (see .github/workflows/docs.yml).
  base: '/pqc-sdk/',
  ignoreDeadLinks: true,
  markdown: {
    codeTransformers: [
      transformerTwoslash({
        twoslashOptions: {
          compilerOptions: {
            lib: ['ES2022', 'DOM'],
            types: ['node'],
          },
        },
      }),
    ],
  },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/quickstart' },
      { text: 'API', link: '/api/' },
      { text: 'Compatibility', link: '/compatibility' },
    ],
    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Quickstart (5 minutes)', link: '/guide/quickstart' },
          { text: 'Why PQC now?', link: '/guide/why-pqc' },
        ],
      },
      {
        text: 'Use-case guides',
        items: [
          { text: 'Hybrid KEM+AES encryption, explained', link: '/guide/hybrid-encryption' },
          { text: 'Encrypting files', link: '/guide/encrypt-files' },
          { text: 'Signing JWTs with ML-DSA', link: '/guide/sign-jwt' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Runtime compatibility', link: '/compatibility' },
          { text: '@pqc-sdk/core API', link: '/api/', items: typedocSidebar },
        ],
      },
    ],
  },
});
