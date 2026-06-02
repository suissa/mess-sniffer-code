// Positive: a recursive merge of a non-literal (attacker-shaped) source is a
// prototype-pollution candidate (CWE-1321). The merged source can carry
// `__proto__` / `constructor` keys.
import merge from "lodash.merge";

export function applyConfig(base: Record<string, unknown>, userInput: Record<string, unknown>): unknown {
  return merge(base, userInput);
}
