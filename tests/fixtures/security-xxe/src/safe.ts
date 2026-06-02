// Negative (literal): parsing a fully-literal XML string is never captured (the
// document argument is literal), so it must NOT produce a candidate.
import libxml from "libxmljs2";

export function parseStatic(): unknown {
  return libxml.parseXmlString("<root><item>1</item></root>");
}
