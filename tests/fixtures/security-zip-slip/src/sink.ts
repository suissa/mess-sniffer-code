// Positive: extracting an archive to a non-literal destination is a zip-slip /
// tar-traversal candidate (CWE-22). A malicious entry name can escape the dest.
import AdmZip from "adm-zip";

export function unpack(archivePath: string, destDir: string): void {
  const zip = new AdmZip(archivePath);
  zip.extractAllTo(destDir);
}
