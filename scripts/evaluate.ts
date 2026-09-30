// Offline only: consumes saved predictions + user-confirmed labels; never calls Jev.
import { readFileSync } from 'node:fs';
import { z } from 'zod';

const row = z.object({
  id: z.string(),
  categoryId: z.string().nullable(),
  confirmedCategoryId: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  model: z.string(),
  policyVersion: z.string(),
  reviewFlags: z.array(z.string()),
});

export function evaluate(rows: z.infer<typeof row>[]) {
  const decided = rows.filter((r) => r.categoryId !== null);
  const bins = [0, 0.5, 0.8].map((lower, i) => {
    const upper = [0.5, 0.8, 1.01][i];
    const items = decided.filter((r) => r.confidence >= lower && r.confidence < upper);
    return {
      lower,
      upper: Math.min(upper, 1),
      count: items.length,
      agreement: items.length
        ? items.filter((r) => r.categoryId === r.confirmedCategoryId).length /
          items.length
        : null,
    };
  });
  return {
    count: rows.length,
    coverage: rows.length ? decided.length / rows.length : 0,
    agreement: decided.length
      ? decided.filter((r) => r.categoryId === r.confirmedCategoryId).length /
        decided.length
      : null,
    abstentions: rows.length - decided.length,
    concentrationBins: bins,
    versions: [...new Set(rows.map((r) => `${r.model}/policy-${r.policyVersion}`))],
  };
}
if (process.argv[1]?.endsWith('evaluate.ts')) {
  if (!process.argv[2])
    throw new Error('Pass a local JSON file of predictions and confirmed labels');
  const rows = z.array(row).parse(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  console.log(JSON.stringify(evaluate(rows), null, 2));
}
