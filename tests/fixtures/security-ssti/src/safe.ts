// Negative (literal): compiling a fully-literal template string is never
// captured (the template argument is literal), so it must NOT produce a
// candidate.
import handlebars from "handlebars";

export function buildStaticView(): unknown {
  return handlebars.compile("<h1>{{title}}</h1>");
}
