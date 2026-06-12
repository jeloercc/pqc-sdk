# Contribuir

## Correr el repo

Requisitos: Node 20+ y pnpm (la versión exacta está en el campo
`packageManager` del `package.json`; con `corepack enable` alcanza).

```bash
pnpm install
pnpm build          # turbo run build (core → cli → docs)
pnpm test           # tests con Vitest; core corre con --coverage (mínimo 90%)
pnpm lint           # eslint + tsc --noEmit
pnpm format         # prettier --write
```

Para iterar sobre un paquete: `pnpm dev --filter=@pqc-sdk/core` (o `cli`, o
`@pqc-sdk/docs` para el sitio).

## Reglas del proyecto

- **Nunca implementamos primitivas criptográficas.** Vienen de `@noble/*`;
  un PR que implemente una primitiva desde cero se rechaza directo.
- TypeScript strict. Cada función pública lleva JSDoc con ejemplo de uso.
- Defaults seguros, API zero-config.

## Commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):
`fix(core): ...`, `feat(cli): ...`, `docs: ...`, `ci: ...`, etc.

## Changesets

Todo PR que cambie un paquete publicable (`packages/*`) necesita un changeset:

```bash
pnpm changeset
```

Elegí el bump (`patch`/`minor`) y describí el cambio de cara al usuario — ese
texto va al CHANGELOG. Los cambios de docs, CI o ejemplos no lo necesitan.
El release es automático: al mergear a `main`, el bot de changesets abre un
PR de versiones y publica a npm cuando se mergea.

## Reportes de seguridad

No abras issues públicos por vulnerabilidades: ver [SECURITY.md](./SECURITY.md).
