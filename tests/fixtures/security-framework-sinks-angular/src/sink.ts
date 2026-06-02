// Positive: a non-literal value passed to Angular's bypassSecurityTrustHtml is a
// framework-scoped dangerous-html candidate (CWE-79). The @angular/platform-browser
// enabler is declared in package.json, so the framework-scoped row fires.
import { DomSanitizer, SafeHtml } from "@angular/platform-browser";

export function trust(sanitizer: DomSanitizer, userInput: string): SafeHtml {
  return sanitizer.bypassSecurityTrustHtml(userInput);
}
