/**
 * Trim repeated edge characters without a backtracking regular expression.
 * These helpers are used on request- and configuration-derived strings, where
 * even a small cleanup expression should have linear, obvious behaviour.
 */
export function trimRepeatedCharacter(value: string, character: string): string {
  if (character.length !== 1) {
    throw new Error("trimRepeatedCharacter requires one character");
  }
  let start = 0;
  let end = value.length;
  while (start < end && value[start] === character) start += 1;
  while (end > start && value[end - 1] === character) end -= 1;
  return value.slice(start, end);
}

export function trimTrailingRepeatedCharacter(
  value: string,
  character: string,
): string {
  if (character.length !== 1) {
    throw new Error("trimTrailingRepeatedCharacter requires one character");
  }
  let end = value.length;
  while (end > 0 && value[end - 1] === character) end -= 1;
  return value.slice(0, end);
}
