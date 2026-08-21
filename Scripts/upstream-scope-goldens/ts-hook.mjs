import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Upstream imports its own modules with a ".js" suffix that only exists after a
// build. Remap those to the ".ts" source so the package can run unbuilt.
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context)
  } catch (err) {
    if (specifier.endsWith('.js')) {
      const ts = specifier.slice(0, -3) + '.ts'
      try {
        const r = await nextResolve(ts, context)
        return r
      } catch {}
    }
    if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
      // bare specifier whose "exports" points at a nonexistent dist
      try {
        return await nextResolve(specifier + '/src/index.ts', context)
      } catch {}
    }
    throw err
  }
}
