import { z } from 'zod';

export interface ChoiceRequest {
  state: unknown;
  questions: Record<
    string,
    { type: 'choice'; instructions: string; criteria: Record<string, string> }
  >;
}

const answerSchema = z.object({
  type: z.literal('choice'),
  choice: z.string(),
  confidence: z.number().min(0).max(1),
  probabilities: z.record(z.string(), z.number().min(0).max(1)),
});

const responseSchema = z.object({
  model: z.string().min(1).max(100),
  answers: z.record(z.string(), answerSchema),
});

export type ChoiceResponse = z.infer<typeof responseSchema>;

export interface ChoiceClient {
  model: string;
  evaluate(request: ChoiceRequest): Promise<ChoiceResponse>;
}

export function createJevClient(
  model: string,
  getKey: () => Promise<string>,
  fetcher: typeof fetch = fetch,
): ChoiceClient {
  return {
    model,
    async evaluate(request) {
      try {
        const key = await getKey();
        // No automatic retries: an ambiguous timeout may already have incurred a charge.
        const response = await fetcher('https://api.typesafe.ai/v1/systemone', {
          method: 'POST',
          redirect: 'error',
          signal: AbortSignal.timeout(12000),
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
          body: JSON.stringify({ ...request, model }),
        });
        if (!response.ok || !response.body) throw new Error();
        const reader = response.body.getReader();
        let text = '';
        let size = 0;
        const decoder = new TextDecoder();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            if (size > 262144) throw new Error();
            text += decoder.decode(value, { stream: true });
          }
        } finally {
          await reader.cancel();
        }
        // Validate the full distribution against the requested options, not just its shape.
        const result = responseSchema.parse(JSON.parse(text + decoder.decode()));
        if (Object.keys(result.answers).length !== Object.keys(request.questions).length)
          throw new Error();
        for (const [id, q] of Object.entries(request.questions)) {
          const a = result.answers[id];
          const keys = Object.keys(q.criteria);
          if (
            !a ||
            !keys.includes(a.choice) ||
            Object.keys(a.probabilities).length !== keys.length ||
            keys.some((k) => !Object.hasOwn(a.probabilities, k))
          )
            throw new Error();
          if (
            Math.abs(Object.values(a.probabilities).reduce((x, y) => x + y, 0) - 1) >
              0.001 ||
            a.probabilities[a.choice] < Math.max(...Object.values(a.probabilities))
          )
            throw new Error();
        }
        return result;
      } catch {
        throw new Error('Inference unavailable');
      }
    },
  };
}
