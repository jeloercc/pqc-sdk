import { transformerTwoslash } from '@shikijs/vitepress-twoslash';
import { defineConfig } from 'vitepress';

import typedocSidebar from '../api/typedoc-sidebar.json';

export default defineConfig({
  title: 'PQC SDK',
  description: 'Criptografía post-cuántica para JS/TS en 30 minutos',
  lang: 'es',
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
      { text: 'Guía', link: '/guide/quickstart' },
      { text: 'API', link: '/api/' },
      { text: 'Compatibilidad', link: '/compatibility' },
    ],
    sidebar: [
      {
        text: 'Empezar',
        items: [
          { text: 'Quickstart (5 minutos)', link: '/guide/quickstart' },
          { text: '¿Por qué PQC ahora?', link: '/guide/why-pqc' },
        ],
      },
      {
        text: 'Guías por caso de uso',
        items: [
          { text: 'Cifrado híbrido KEM+AES, explicado', link: '/guide/hybrid-encryption' },
          { text: 'Cifrar archivos', link: '/guide/encrypt-files' },
          { text: 'Firmar JWTs con ML-DSA', link: '/guide/sign-jwt' },
        ],
      },
      {
        text: 'Referencia',
        items: [
          { text: 'Compatibilidad por runtime', link: '/compatibility' },
          { text: 'API de @pqc-sdk/core', link: '/api/', items: typedocSidebar },
        ],
      },
    ],
  },
});
