// Negative (literal): extracting to a fully-literal, hard-coded destination is
// never captured (the destination argument is literal), so it must NOT produce
// a candidate.
import AdmZip from "adm-zip";

export function unpackFixed(archivePath: string): void {
  const zip = new AdmZip(archivePath);
  zip.extractAllTo("/var/app/cache");
}
