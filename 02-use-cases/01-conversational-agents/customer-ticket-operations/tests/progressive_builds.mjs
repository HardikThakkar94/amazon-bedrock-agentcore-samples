// Exercise shipped stepper, scope labels, and policy narrative without replacing runtime controls.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync('web/index.html', 'utf8');
const builds = source.split('const BUILDS = ')[1].split('/* ── edges')[0];
const ctx = vm.createContext({});
vm.runInContext(`const BUILDS = ${builds}\nthis.read = {BUILDS, POLICY_TEXT, policyReach};`, ctx);
const {BUILDS, POLICY_TEXT, policyReach} = ctx.read;
assert.equal(BUILDS[1][1], 'Guardrails');
assert.equal(BUILDS[2][1], 'Identity');
assert.match(POLICY_TEXT(1), /no policy engine/);
assert.match(POLICY_TEXT(2), /Region\/caller fence/);
assert.match(policyReach([], 1), /Cognito\/JWT admission still applies/);
assert.match(policyReach([], 2), /ENFORCE Gateway configured/);
assert.match(source, /el.hidden = build\(\) < 1/);
assert.match(source, /id="custTitle">Tickets · loading identity/);
assert.match(source, /const regionName = id => id === 'customer-a' \? 'Region A'/);

// Execute the shipped renderPanel logic, not only source text: V1 broad Gateway off,
// V2 scope-fenced Gateway on, with the screen visible for both.
const rendered = {policyOff: null, guardHidden: null};
const policyNode = {classList: {toggle: (name, value) => {
  if(name === 'off') rendered.policyOff = value;
}}};
const guardNode = {hidden: null};
const panel = {clientWidth: 800, classList: {toggle: () => {}},
  querySelectorAll: selector => selector === '[data-gr]' ? [guardNode] : []};
const nodes = new Map();
const ui = vm.createContext({
  phase: 1, panel, N: 0, RUN: null, STEPS: [], polling: null, busy: false, mode: 'step',
  fold: () => ({n: {}, arrows: {}, chips: {}, stamp: false}),
  build: () => ui.phase, who: () => 'alice',
  nodeEl: id => id === 'policy' ? policyNode : null,
  $: id => { if(!nodes.has(id)) nodes.set(id, {
    classList: {toggle: () => {}}, dataset: {}, textContent: '', innerHTML: '', disabled: false,
  }); return nodes.get(id); },
  renderTickets: () => {}, renderLines: () => {}, renderPayloads: () => {},
});
const panelScript = source.split('function renderPanel(){')[1].split('function renderTickets(st){')[0];
vm.runInContext(`function renderPanel(){${panelScript}\nthis.renderPanel = renderPanel;`, ui);
ui.renderPanel();
assert.equal(rendered.policyOff, true);
assert.equal(guardNode.hidden, false);
ui.phase = 2;
ui.renderPanel();
assert.equal(rendered.policyOff, false);
assert.equal(guardNode.hidden, false);

// The caption is a display projection. The stored event label/payload keeps real IDs.
const captionScript = source.split('function caption(step){')[1].split('/* reducer:')[0];
const cap = vm.createContext({phase: 1, build: () => cap.phase, who: () => 'alice', custName: () => 'Region A',
  esc: value => String(value), STATE: {persona: {customer_id: 'customer-a'}}});
vm.runInContext(`function caption(step){${captionScript}\nthis.caption = caption;`, cap);
const event = {kind:'store.read', label:'read A-41, A-90', payload:'{"customer_id":"customer-a"}'};
assert.match(cap.caption({events: [event]})[1], /reads Region A tickets.*A-41, A-90/);
assert.equal(event.payload, '{"customer_id":"customer-a"}');
assert.match(cap.caption({events: [{kind:'tool.invoked', label:'list_tickets'}]})[1], /No policy engine.*directly/);
cap.phase = 2;
assert.doesNotMatch(cap.caption({events: [{kind:'tool.invoked', label:'list_tickets'}]})[1], /No policy engine/);
const portal = fs.readFileSync('web/portal/index.html', 'utf8');
assert.match(portal, /Region A Ticket Portal/);
assert.match(portal, /Cross Region · close B-77/);
// Existing recorded input and actual Cedar/JWT schema identifiers are never rewritten.
assert.match(portal, /ACTION: close_ticket customer-a A-42/);
assert.match(portal, /ACTION: close_ticket customer-b B-77/);
console.log('Shipped progressive-build and Region labels: passed');
