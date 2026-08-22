import matter from "gray-matter";

export const MAX_YAML_FRONTMATTER_BYTES = 64 * 1024;

/** Parse Markdown frontmatter only after bounding the YAML presented to js-yaml. */
export function parseMarkdownMatter(raw: string, source: string): ReturnType<typeof matter> {
  const opening = /^---[\t ]*\r?\n/.exec(raw);
  if (opening !== null) {
    const closingPattern = /^---[\t ]*\r?$/gm;
    closingPattern.lastIndex = opening[0].length;
    const closing = closingPattern.exec(raw);
    const frontmatterEnd = closing?.index ?? raw.length;
    const frontmatterBytes = Buffer.byteLength(
      raw.slice(opening[0].length, frontmatterEnd),
      "utf8",
    );
    if (frontmatterBytes > MAX_YAML_FRONTMATTER_BYTES) {
      throw new Error(
        `${source}: YAML frontmatter exceeds the ${MAX_YAML_FRONTMATTER_BYTES.toLocaleString("en-US")}-byte limit`,
      );
    }
  }

  return matter(raw);
}
