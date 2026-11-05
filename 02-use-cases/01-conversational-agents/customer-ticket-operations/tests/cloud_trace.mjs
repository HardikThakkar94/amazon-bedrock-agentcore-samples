// Exercise the actual drawer renderer with hostile extra fields and failed/partial sources.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync('web/index.html', 'utf8');
const helpers = html.match(/const esc = .*?;\n/)[0];
const reach = html.split('const POLICY_TEXT = ')[1].split('/* ── edges')[0];
const fragment = html.split('const TRACE_COLS = ')[1].split('\nfunction closeTrace()')[0];
const body = { innerHTML: '' };
const drawer = { dataset: { from: 'cw' } };
const context = vm.createContext({
  $: selector => selector === '#drBody' ? body : drawer,
  build: () => 5,
  api: async () => ({run_id: 'run-1', region: 'us-east-1', sources: [
    {key: 'spans', title: 'Runtime spans', status: 'done', records: [{name: 'strands.agent.invoke', ms: '2.51', '@message': 'SECRET'}], log_groups: ['aws/spans']},
    {key: 'model', title: 'Bedrock model', status: 'done', records: [], log_groups: ['model']},
    {key: 'gateway', title: 'Gateway', status: 'error', error: 'Logs Insights: Failed', records: [], log_groups: []},
  ]}),
  RUN: { run_id: 'run-1', events: [
  { kind: 'auth.verified', source: 'api', status: 'ok', payload: 'bearer SECRET', label: 'ticket SECRET' },
  { kind: 'identity.validated', source: 'runtime', status: '<script>', payload: 'ticket SECRET' },
  { kind: 'policy.decision', source: 'runtime', status: 'denied', decision: 'DENY', detail: { ticket: 'SECRET' } },
]}, console });
vm.runInContext(`${helpers} const POLICY_TEXT = ${reach} const TRACE_COLS = ${fragment}\nthis.render = {traceTable, cloudSource, appTracePanel, cloudTrace, policyReach};`, context);
const { traceTable, cloudSource, appTracePanel, cloudTrace, policyReach } = context.render;
const table = traceTable([{ name: '<img src=x onerror=alert(1)>', '@message': 'SECRET', status: 'ok' }], [['name', 'Name'], ['status', 'Status']]);
assert.match(table, /&#60;img/);
assert.doesNotMatch(table, /<img|SECRET|@message/);
const panel = appTracePanel('Authentication / Identity', 'app events only', ['auth.verified','identity.validated']);
assert.match(panel, /API run event/);
assert.doesNotMatch(panel, /SECRET|<script>|bearer/);
const failed = cloudSource({key: 'gateway', title: 'Gateway', status: 'error', error: 'Logs Insights: Failed', records: [], log_groups: []});
assert.match(failed, /Query failed: Logs Insights: Failed/);
assert.doesNotMatch(failed, /No correlated records/);
const running = cloudSource({key: 'spans', title: 'Runtime', status: 'running', records: [], log_groups: ['aws/spans']});
assert.match(running, /Query still running/);
const empty = cloudSource({key: 'model', title: 'Bedrock', status: 'done', records: [], log_groups: ['model']});
assert.match(empty, /No correlated records ingested yet/);
const unavailable = cloudSource({key:'gateway', title:'Gateway', status:'unavailable', reason:'No verified owned-run aws/spans trace IDs yet; retry later', records:[], log_groups:['gateway']});
assert.match(unavailable, /Correlation unavailable: No verified owned-run aws\/spans trace IDs/);
assert.doesNotMatch(unavailable, /No correlated records ingested yet|Query failed/);
const partial = cloudSource({key:'gateway', title:'Gateway', status:'partial', reason:'1 unverified Gateway row(s) omitted', matched:1, records:[{decision:'ALLOW',policies:'own-policy'}], log_groups:['gateway']});
assert.match(partial, /1 projected record\(s\) of 1 verified · partial/);
assert.match(partial, /1 unverified Gateway row\(s\) omitted/);
assert.doesNotMatch(partial, /policy-other|<script>/);
const allowedRead = {kind:'policy.decision', decision:'ALLOW', tool:'list_tickets'};
assert.match(policyReach([allowedRead, {kind:'tool.skipped', tool:'add_note', label:'add_note refused · read-only'}], 5), /ALLOW list_tickets.*OPEN breaker refused write before Gateway; Policy did not evaluate that write/);
assert.match(policyReach([{kind:'approval.requested', tool:'close_ticket'}], 5), /held for operator approval before Gateway/);
assert.match(policyReach([{kind:'policy.decision', decision:'DENY', tool:'add_note'}], 5), /DENY add_note.*ENFORCE Gateway configured/);
assert.match(policyReach([], 5), /ENFORCE Gateway configured.*no decision recorded/);
await cloudTrace('run-1');
for(const section of ['Authentication / Identity', 'Runtime spans', 'Runtime controls', 'Bedrock model', 'Guardrails', 'Gateway', 'Policy (agent inference)']) assert.ok(body.innerHTML.includes(section), section);
assert.match(body.innerHTML, /Query failed: Logs Insights: Failed/);
assert.doesNotMatch(body.innerHTML, /SECRET|@message|bearer|<script>/);
console.log('CloudWatch drawer safe rendering, provenance and states: passed');
