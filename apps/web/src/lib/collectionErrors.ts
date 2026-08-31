/**
 * A provider's joined-up failure string, split back into distinct causes.
 *
 * Azure reports collection failures per evidence key, so a single missing admin
 * consent arrives as several entries carrying the same nine-hundred-character
 * sentence about ungranted Graph scopes. Grouping identical messages turns that
 * back into one fact with a list of what it cost.
 *
 * Each part is `key: message`; a part that does not look like one belongs to
 * the message before it, because provider text carries its own punctuation and
 * must never be cut in half on the way to a reader — this is the string an
 * administrator will paste into a search box.
 */
export function groupCauses(reason: string): { keys: string[]; message: string }[] {
  const parts: string[] = [];
  for (const piece of reason.split(/;\s+/)) {
    if (/^[\w.-]+:\s/.test(piece) || parts.length === 0) parts.push(piece);
    else parts[parts.length - 1] += `; ${piece}`;
  }

  const grouped = new Map<string, string[]>();
  for (const part of parts) {
    const match = /^([\w.-]+):\s*([\s\S]*)$/.exec(part.trim());
    const key = match ? match[1] : "";
    const message = (match ? match[2] : part).trim();
    const keys = grouped.get(message) ?? [];
    if (key) keys.push(key);
    grouped.set(message, keys);
  }

  return [...grouped.entries()].map(([message, keys]) => ({ keys, message }));
}
