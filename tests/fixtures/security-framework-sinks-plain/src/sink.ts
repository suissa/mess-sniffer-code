// Negative (precision): the SAME bypassSecurityTrustHtml call shape, but NO
// @angular/platform-browser dependency is declared. The framework-scoped row is
// gated on that enabler, so this must NOT produce a candidate: a same-named
// method on an unrelated object is not an Angular sanitizer bypass.
export function trust(obj: { bypassSecurityTrustHtml(s: string): string }, userInput: string): string {
  return obj.bypassSecurityTrustHtml(userInput);
}

// A non-literal innerHTML assignment still fires here: the GLOBAL dangerous-html
// row carries no enabler, so framework gating does not suppress global rows.
export function render(el: HTMLElement, userInput: string): void {
  el.innerHTML = userInput;
}
