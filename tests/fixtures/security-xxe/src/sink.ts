// Positive: parsing a non-literal XML document is an XXE candidate (CWE-611) when
// the parser allows external-entity / DTD expansion.
import libxml from "libxmljs2";

export function parse(userXml: string): unknown {
  return libxml.parseXmlString(userXml);
}
