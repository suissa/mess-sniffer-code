// Positive: compiling a non-literal template source is a server-side template
// injection candidate (CWE-1336). Attacker-controlled template bodies execute
// template directives on the server.
import handlebars from "handlebars";

export function buildView(userTemplate: string): unknown {
  return handlebars.compile(userTemplate);
}
