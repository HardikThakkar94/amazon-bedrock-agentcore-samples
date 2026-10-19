// Executes the real renderFlow/flowStory from index.html against recorded run results.
// Usage: node flow_strip_harness.mjs <index.html> <state.json>
// Prints JSON {proposal, boundary, effect, caption, tones:{proposal,effect}} for the rendered strip.
// Minimal DOM: only what renderFlow touches (createElement, textContent, className, append,
// replaceChildren, getElementById). No framework, no network.
import { readFileSync } from "node:fs";

const [, , htmlPath, statePath] = process.argv;
const html = readFileSync(htmlPath, "utf8");
const state = JSON.parse(readFileSync(statePath, "utf8"));

function extract(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in index.html`);
  const next = html.indexOf("\nfunction ", start + 1);
  return html.slice(start, next < 0 ? undefined : next);
}

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.className = ""; this._text = ""; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join("") : this._text; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
}
const ids = {};
const document = {
  createElement: (tag) => new Node(tag),
  getElementById: (id) => (ids[id] ??= new Node("div")),
};

const src = [
  "const stages=['v0','v1','v2','v3','v4','v5'],names={v0:'Unsafe',v1:'Identity',v2:'Validate',v3:'Policy',v4:'Contain',v5:'Evidence'};",
  "const el=id=>document.getElementById(id);function node(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text??'');return n}",
  extract("flowNode"),
  extract("flowStory"),
  extract("renderFlow"),
  "renderFlow(state);",
].join("\n");
new Function("document", "state", src)(document, state);

const flow = ids.flow.children.filter((n) => n.className.startsWith("flow-node"));
const byTitle = Object.fromEntries(flow.map((n) => [n.children[0].textContent, n]));
const pick = (prefix) => Object.keys(byTitle).find((t) => t.startsWith(prefix));
const tone = (n) => n.className.replace("flow-node", "").trim();
const out = {
  proposal: byTitle.Proposal.children[1].textContent,
  boundary: byTitle[pick("Boundary")].children[1].textContent,
  effect: byTitle["Ticket effect"].children[1].textContent,
  customer: byTitle.Customer.children[1].textContent,
  caption: ids.flowCaption.textContent,
  tones: { proposal: tone(byTitle.Proposal), effect: tone(byTitle["Ticket effect"]), boundary: tone(byTitle[pick("Boundary")]) },
};
process.stdout.write(JSON.stringify(out));
