import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import vm from 'node:vm';
import {test} from 'node:test';
import assert from 'node:assert/strict';
const source=readFileSync(resolve('internal/server/assets/app.js'),'utf8').replace(/\nstart\(\);\s*$/,'');
function context(){
 const ctx=vm.createContext({
  console,URL,URLSearchParams,Date,Intl,Number,Object,Array,Map,Set,Math,JSON,String,
  document:{addEventListener(){},querySelector(){return null}},
  window:{location:{pathname:'/diagnostics'},addEventListener(){},history:{pushState(){},replaceState(){}},scrollTo(){}},
  setInterval(){},setTimeout(){},clearTimeout(){},navigator:{},fetch(){throw Error('No HTTP calls in rendering tests')}
 });
 vm.runInContext(source,ctx);
 vm.runInContext(`S.authenticated=true;S.me={name:'Admin',role:'admin'};S.stats={total:3,version:'0.6.0-alpha.10'};S.section='diagnostics';S.config={settings:{retention_days:30,max_history:10000}};S.messages=[];`,ctx);
 return ctx;
}
test('one primary navigation without workspaces or a scrollable side rail',()=>{
 const ctx=context();const html=vm.runInContext('layout(diagSummary())',ctx);
 assert.match(html,/aria-label="Main navigation"/);
 for(const label of ['Overview','Review mail','Held mail','All messages','Protection','Diagnostics','Settings'])assert.ok(html.includes(`>${label}<`),label);
 assert.doesNotMatch(html,/WORKSPACES|sg-sidebar|sg-workspace|sg-backdrop/);
 assert.match(html,/href="\/diagnostics"/);
});
test('unmeasured diagnostics do not imply verified mail flow or healthy transport',()=>{
 const ctx=context();const html=vm.runInContext('diagSummary()',ctx);
 assert.match(html,/Connection not verified/);
 assert.match(html,/Run checks to retrieve current runtime evidence/);
 assert.match(html,/Not measured|Not checked/);
 assert.doesNotMatch(html,/"confirmed":true/);
});
test('measured failures, queue depth, and connector metrics render explicitly',()=>{
 const ctx=context();vm.runInContext(`S.runtime={services:{milter:{enabled:true,address:'127.0.0.1:38472',detail:'Configured'}} ,relay_configured:true};
 S.readiness={state:'postfix_not_connected',instance_running:false,mail_submissions_observed:4,expected_connector:'milter',postfix_connection:'wrong_port'};
 S.deliveryQueue={enabled:true,dead:2,queued:5,delivering:1,bytes:2048};
 S.telemetry={spamgate_runtime_scans_total:23,spamgate_runtime_scan_errors_total:3,byConnector:{milter:21,smtp:2}};
 S.diagnostics={relay:{tcp_reachable:false,detail:'Connection refused'}};
 S.diagnosticsCheckedAt='2026-10-28T15:15:00Z';`,ctx);
 const html=vm.runInContext('diagSummary()',ctx);
 assert.match(html,/Issues or gaps need attention/);
 assert.match(html,/wrong_port/);
 assert.match(html,/Connection refused/);
 assert.match(html,/Failed outbox jobs/);
 assert.match(html,/Postfix Milter/);
 assert.match(html,/>23<|>23<\/strong>/);
});
test('HTML from inspection services is escaped rather than inserted as markup',()=>{
 const ctx=context();vm.runInContext(`S.hostReport={mail_server:'<img src=x onerror=alert(1)>'}`,ctx);
 const html=vm.runInContext('diagSummary()',ctx);
 assert.doesNotMatch(html,/<img src=x/);
 assert.match(html,/&lt;img src=x/);
});
test('Prometheus telemetry parser ignores comments and extracts measurements',()=>{
 const ctx=context();const result=vm.runInContext(`parseMetrics('# HELP example hi\\nspamgate_runtime_scans_total 25\\nspamgate_runtime_scan_errors_total 2\\nspamgate_runtime_scan_connector_total{connector="milter"} 23\\n')`,ctx);
 assert.equal(result.spamgate_runtime_scans_total,25);
 assert.equal(result.spamgate_runtime_scan_errors_total,2);
 assert.equal(result.byConnector.milter,23);
});

test('investigation renders source evidence, escapes untrusted logs, and gates Postfix release',()=>{
 const ctx=context();
 vm.runInContext(`S.inspect={id:'scan1',mta_action:'postfix_hold_requested',mta_action_state:'requested'};
 S.investigation={scan_id:'scan1',connector:'milter',postfix_queue_id:'ABC123',
 postfix_release_enabled:true,postfix_hold_present:true,steps:[{name:'Postfix',state:'held',detail:'Queue entry verified'}],
 postfix_log_events:[{line:'<img src=x onerror=alert(1)>'}],
 actions:['Confirm mailbox before release'],limitations:['Next-hop sent is not inbox delivery']};`,ctx);
 let html=vm.runInContext('investigationPanel()',ctx);
 assert.match(html,/Mail-flow evidence/);
 assert.match(html,/Queue entry verified/);
 assert.match(html,/id="postfix-release-message"/);
 assert.match(html,/&lt;img src=x/);
 assert.doesNotMatch(html,/<img src=x/);
 vm.runInContext("S.inspect.mta_action_state='release_submitted'",ctx);
 html=vm.runInContext('investigationPanel()',ctx);
 assert.doesNotMatch(html,/id="postfix-release-message"/);
 vm.runInContext("S.inspect.mta_action_state='requested';S.investigation.postfix_hold_present=false",ctx);
 html=vm.runInContext('investigationPanel()',ctx);
 assert.doesNotMatch(html,/id="postfix-release-message"/);
 vm.runInContext("S.investigation.postfix_hold_present=true;S.investigation.postfix_release_enabled=false",ctx);
 html=vm.runInContext('investigationPanel()',ctx);
 assert.doesNotMatch(html,/id="postfix-release-message"/);
});

test('update UI only offers restart when a supervisor is confirmed',()=>{
 const ctx=context();
 vm.runInContext(`S.updateInfo={current:'0.6.0-alpha.11',latest:'v0.6.0-alpha.12',
 available:true,staged:true,install_mode:'requires_supervisor'}`,ctx);
 let html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/Base service\/container upgrade required/);
 assert.doesNotMatch(html,/id="install-update"/);
 vm.runInContext("S.updateInfo.install_mode='supervised'",ctx);
 html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/Integrated supervisor ready/);
 assert.match(html,/id="install-update"/);
 assert.match(html,/Install and restart with rollback/);
 vm.runInContext("S.updateInfo.staged=false",ctx);
 html=vm.runInContext('updatesPage()',ctx);
 assert.doesNotMatch(html,/id="install-update"/);
});

test('update screen identifies the installed worker path and protected base',()=>{
 const ctx=context();
 vm.runInContext("S.updateInfo={current:'0.6.0-alpha.12',latest:'v0.6.0-alpha.12',available:false,staged:false,install_mode:'supervised',install_path:'/var/lib/spamgate/bin/spamgate'}",ctx);
 const html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/\/var\/lib\/spamgate\/bin\/spamgate/);
 assert.match(html,/root-owned and intentionally unchanged/);
 assert.doesNotMatch(html,/id="install-update"/);
});

test('durable operations panel escapes alerts and provides actual actions',()=>{
 const ctx=context();
 vm.runInContext("S.monitorData={samples:[{at:'2026-10-28T18:00:00Z',scan_total:12,scan_errors:1,queue_enabled:false}],alerts:[{id:'alert-id',code:'queue_dead',severity:'critical',summary:'<img src=x onerror=alert(1)>',state:'open',first_seen:'2026-10-28T18:00:00Z'}]}",ctx);
 const html=vm.runInContext('monitorPanel()',ctx);
 assert.match(html,/id="monitor-refresh"/);
 assert.match(html,/data-monitor-ack="alert-id"/);
 assert.match(html,/&lt;img src=x/);
 assert.doesNotMatch(html,/<img src=x/);
 assert.match(html,/SMTP outbox not enabled/);
});
test('policy preview panel shows hypothetical results without save controls',()=>{
 const ctx=context();
 vm.runInContext("S.policyPreview={totals:{changed:1,examined:2,forced_preserved:0,multi_recipient_fallback:1},items:[{id:'scan-123',score:9,historical_action:'reject',hypothetical_action:'tag',changed:true}],limitations:['Not Postfix delivery']}",ctx);
 const html=vm.runInContext('policyPreviewPanel()',ctx);
 assert.match(html,/id="preview-policy"/);
 assert.match(html,/scan-123/);
 assert.match(html,/hypothetical|Hypothetical/);
 assert.match(html,/Not Postfix delivery/);
 assert.doesNotMatch(html,/id="settings-form"/);
});
