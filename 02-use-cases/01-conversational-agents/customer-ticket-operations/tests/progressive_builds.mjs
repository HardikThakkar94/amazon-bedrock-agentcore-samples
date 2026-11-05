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
assert.match(source, /id="custTitle">Region A tickets/);
assert.match(source, /const regionName = id => id === 'customer-a' \? 'Region A'/);
const portal = fs.readFileSync('web/portal/index.html', 'utf8');
assert.match(portal, /Region A Ticket Portal/);
assert.match(portal, /Cross Region · close B-77/);
// Existing recorded input and actual Cedar/JWT schema identifiers are never rewritten.
assert.match(portal, /ACTION: close_ticket customer-a A-42/);
assert.match(portal, /ACTION: close_ticket customer-b B-77/);
console.log('Shipped progressive-build and Region labels: passed');
