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
 assert.match(html,/No supervising parent detected/);
 assert.doesNotMatch(html,/id="install-update"/);
 vm.runInContext("S.updateInfo.install_mode='supervised'",ctx);
 html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/Supervisor detected/);
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
 assert.match(html,/supervisor is unchanged; only the child application executable is replaced/);
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

test('SpamGate category test lab groups 16 categories and escapes untrusted category text',()=>{
 const ctx=context();vm.runInContext('S.section="categories"; S.sgtubeCatalog={live_test_enabled:false,sample_limit:1000,recent_counts:{phishing:4},categories:[{id:"phishing",name:"<img src=x onerror=alert(1)>",group:"Fraud",description:"Deceptive links",test_marker:"SGTUBE-V1-PHISHING"}]};S.sgtubeMessages=null',ctx);
 const html=vm.runInContext('spamCategoryLab()',ctx);
 assert.match(html,/data-sgtube-simulate="phishing"/);
 assert.match(html,/data-sgtube-view="phishing"/);
 assert.match(html,/data-sgtube-copy="phishing"/);
 assert.match(html,/data-sgtube-eml="phishing"/);
 assert.match(html,/&lt;img src=x/);
 assert.doesNotMatch(html,/<img src=x/);
 assert.match(html,/Disabled by default/);
 assert.match(html,/not proof/i);
});
test('category history escapes subject and does not present sample totals as all-time',()=>{
 const ctx=context();
 vm.runInContext('S.section="categories"; S.sgtubeCatalog={categories:[{id:"phishing",name:"Phishing",group:"Fraud",description:"Test",test_marker:"x"}],sample_limit:1000};S.sgtubeSelected="phishing";S.sgtubeMessages={matched_in_recent:1,sampled_history:3,messages:[{timestamp:"2026-10-29T00:00:00Z",subject:"<script>alert(1)</script>",score:8,action:"reject",test_case:""}]}',ctx);
 const html=vm.runInContext('spamCategoryLab()',ctx);
 assert.match(html,/retained messages/);
 assert.match(html,/&lt;script&gt;alert/);
 assert.doesNotMatch(html,/<script>alert/);
 assert.match(html,/maximum 1,000/);
});

test('unsupervised native worker explains install button absence with correct filenames',()=>{
 const ctx=context();vm.runInContext('S.updateInfo={current:"0.6.0-alpha.15",latest:"v0.6.0-alpha.16",available:true,staged:true,install_mode:"requires_supervisor"};',ctx);
 const html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/No supervising parent/);
 assert.match(html,/spamgate-worker/);
 assert.match(html,/Installation is disabled/);
 assert.doesNotMatch(html,/id="install-update"/);
});
test('supervised install button appears for staged update',()=>{
 const ctx=context();vm.runInContext('S.updateInfo={current:"0.6.0-alpha.15",latest:"v0.6.0-alpha.16",available:true,staged:true,install_mode:"supervised",install_path:"/opt/spamgate/spamgate-worker"};',ctx);
 const html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/id="install-update"/);
 assert.match(html,/spamgate-worker/);
});

test('history integrity panel differentiates disk evidence and UI errors, escaping diagnostics',()=>{
 const ctx=context();
 vm.runInContext(`S.section='history';S.historyLoaded=false;S.historyRefreshError='<img src=x onerror=1>';S.historyAudit={status:'mismatch',detail:'Retained scans not found on disk',file_bytes:483184,disk_events:155,unique_scan_ids:155,loaded_retained:155};`,ctx);
 const html=vm.runInContext('historyIntegrityPanel()',ctx);
 assert.match(html,/Verify on-disk history/);
 assert.match(html,/155/);
 assert.match(html,/History needs investigation/);
 assert.match(html,/has not finished loading successfully/);
 assert.match(html,/&lt;img src=x/);
 assert.doesNotMatch(html,/<img src=x/);
});
test('optional detector failure does not blank essential message history',async()=>{
 const ctx=context();
 vm.runInContext(`
 S.section='history';S.me={role:'admin',name:'ops'};S.config={onboarding:{completed:true,activated:true}};
 render=()=>{};alertUser=()=>{};
 api=async(path)=>{
  if(path==='/api/v1/config')return {onboarding:{completed:true,activated:true}};
  if(path==='/api/v1/messages?limit=1000')return [{id:'persisted-1',action:'accept',subject:'real history'}];
  if(path==='/api/v1/statistics')return {total:155};
  if(path==='/api/v1/history/integrity')return {status:'ok',disk_events:155,loaded_retained:155};
  if(path==='/api/v1/signals')throw Error('optional detector offline');
  if(path.startsWith('/api/v1/'))throw Error('optional subsystem offline');
  return null;
 };
 `,ctx);
 await vm.runInContext('refresh()',ctx);
 assert.equal(vm.runInContext('S.historyLoaded',ctx),true);
 assert.equal(vm.runInContext('S.messages.length',ctx),1);
 assert.equal(vm.runInContext('S.stats.total',ctx),155);
 assert.equal(vm.runInContext('S.historyRefreshError',ctx),null);
});
test('failed essential history API is visible, not an empty-success condition',async()=>{
 const ctx=context();
 vm.runInContext(`
 S.section='history';S.me={role:'admin',name:'ops'};
 render=()=>{};alertUser=()=>{};
 api=async(path)=>{if(path==='/api/v1/messages?limit=1000')throw Error('history service unavailable');return {}};
 `,ctx);
 await vm.runInContext('refresh()',ctx);
 assert.equal(vm.runInContext('S.historyLoaded',ctx),false);
 assert.match(vm.runInContext('S.historyRefreshError',ctx),/history service unavailable/);
 assert.match(vm.runInContext('historyIntegrityPanel()',ctx),/Message history could not refresh/);
});

test('recipient policy UI explains uniform multi-mailbox overrides and explicit conflicts',()=>{
 const ctx=context();
 vm.runInContext(`S.config={settings:{tag_threshold:5,quarantine_threshold:10,reject_threshold:20,retention_days:30,max_history:10000},recipient_policies:[{mailbox:"alice@example.org",tag_threshold:1,quarantine_threshold:2,reject_threshold:3}]};
 S.policyPreview={totals:{changed:0,examined:2,forced_preserved:0,multi_recipient_fallback:1,uniform_shared:1},items:[],limitations:["Not proof of delivery"]};`,ctx);
 const html=vm.runInContext('settings()',ctx);
 assert.match(html,/identical effective thresholds/);
 assert.match(html,/Conflicting recipients use global thresholds/);
 assert.doesNotMatch(html,/A message sent to multiple recipients uses the global settings/);
 assert.match(html,/1 uniform multi-mailbox overrides/);
 assert.match(html,/1 multi-recipient conflicts using global thresholds/);
});

test('updates page never falsely claims a directly launched worker before local status loads',async()=>{
 const ctx=context();
 vm.runInContext("S.section='updates';S.updateInfo=null;S.updateReleaseChecked=false;",ctx);
 const initial=vm.runInContext('updatesPage()',ctx);
 assert.match(initial,/Checking local supervisor/);
 assert.doesNotMatch(initial,/Installation is disabled because the worker was launched directly/);
 assert.match(initial,/Release lookup has not been run/);
 vm.runInContext(`
  render=()=>{};
  api=async(path)=>{
   if(path==='/api/v1/update/status')return {current:'0.6.0-beta.1',install_mode:'supervised',install_path:'/opt/spamgate/spamgate-worker',staged:false};
   throw Error('Unexpected external request: '+path);
  };
 `,ctx);
 await vm.runInContext('loadLocalUpdateStatus()',ctx);
 const ready=vm.runInContext('updatesPage()',ctx);
 assert.match(ready,/Supervisor detected/);
 assert.match(ready,/\/opt\/spamgate\/spamgate-worker/);
 assert.doesNotMatch(ready,/No supervising parent detected/);
 assert.doesNotMatch(ready,/Installation is disabled because the worker was launched directly/);
 assert.match(ready,/Release lookup has not been run/);
});

test('updates page reports local status failure without asserting worker mode',async()=>{
 const ctx=context();
 vm.runInContext(`
  S.section='updates';S.updateInfo=null;S.updateReleaseChecked=false;
  render=()=>{};
  api=async()=>{throw Error('local status unavailable')};
 `,ctx);
 await vm.runInContext('loadLocalUpdateStatus()',ctx);
 const html=vm.runInContext('updatesPage()',ctx);
 assert.match(html,/Local supervisor check failed/);
 assert.match(html,/local status unavailable/);
 assert.doesNotMatch(html,/Installation is disabled because the worker was launched directly/);
});


test('review queue uses actual review status and does not mistake allowed mail for pending',()=>{
 const ctx=context();
 vm.runInContext(`
 S.section='investigate';S.search='';S.filterAction='all';S.reviewStatus='pending';S.reviewSort='newest';
 S.messages=[
  {id:'a',action:'accept',subject:'Allowed mail',score:0,timestamp:'2026-10-31T10:00:00Z'},
  {id:'b',action:'tag',subject:'Pending low',score:2,timestamp:'2026-10-31T10:01:00Z'},
  {id:'c',action:'reject',subject:'Reviewed',review_status:'correct',score:25,timestamp:'2026-10-31T10:02:00Z'},
  {id:'d',action:'quarantine',subject:'Pending high',score:14,timestamp:'2026-10-31T10:03:00Z'}
 ];`,ctx);
 const initial=vm.runInContext('investigate()',ctx);
 assert.match(initial,/Awaiting review/);
 assert.match(initial,/Pending low/);
 assert.match(initial,/Pending high/);
 assert.doesNotMatch(initial,/data-inspect="a"/);
 assert.doesNotMatch(initial,/data-inspect="c"/);
 assert.match(initial,/2 matching/);
 vm.runInContext("S.reviewStatus='reviewed'",ctx);
 const reviewed=vm.runInContext('investigate()',ctx);
 assert.match(reviewed,/data-inspect="c"/);
 assert.doesNotMatch(reviewed,/data-inspect="b"/);
 assert.match(reviewed,/1 matching/);
 vm.runInContext("S.reviewStatus='all'",ctx);
 assert.equal((vm.runInContext('investigate()',ctx).match(/data-inspect=/g)||[]).length,3);
});
test('review search respects sender, recipient, action and review status',()=>{
 const ctx=context();
 vm.runInContext(`S.messages=[
 {id:'p',action:'tag',sender:'alerts@example.org',recipients:['ops@example.org'],score:12,timestamp:'2026-10-31T15:00:00Z'},
 {id:'q',action:'reject',sender:'news@example.org',recipients:['ops@example.org'],review_status:'correct',score:14,timestamp:'2026-10-31T16:00:00Z'},
 {id:'r',action:'accept',sender:'alerts@example.org',recipients:['ops@example.org'],score:0}
 ];`,ctx);
 const ids=vm.runInContext("reviewMailRows(S.messages,'alerts','all','pending','newest').map(x=>x.id).join(',')",ctx);
 assert.equal(ids,'p');
 assert.equal(vm.runInContext("reviewMailRows(S.messages,'ops@example.org','reject','reviewed','newest').length",ctx),1);
 assert.equal(vm.runInContext("reviewMailRows(S.messages,'','accept','all','newest').length",ctx),0);
});
test('mail sorting is stable and never mutates stored evidence',()=>{
 const ctx=context();
 vm.runInContext(`S.messages=[
  {id:'a',score:1,timestamp:'2026-10-31T12:00:00Z'},
  {id:'b',score:13,timestamp:'2026-10-31T12:03:00Z'},
  {id:'c',score:5,timestamp:'2026-10-31T12:01:00Z'},
  {id:'d',score:'bad',timestamp:'invalid'}
 ];`,ctx);
 assert.equal(vm.runInContext("sortMailRows(S.messages,'score-high').map(x=>x.id).join(',')",ctx),'b,c,a,d');
 assert.equal(vm.runInContext("sortMailRows(S.messages,'oldest').map(x=>x.id).join(',')",ctx),'d,a,c,b');
 assert.equal(vm.runInContext('S.messages.map(x=>x.id).join(",")',ctx),'a,b,c,d');
});
test('review content is escaped, review counts are limited to loaded records and empty review is useful',()=>{
 const ctx=context();
 vm.runInContext(`S.section='investigate';S.messages=[{id:'r',subject:'<img src=x onerror=alert(1)>',action:'tag',review_status:'correct'}];`,ctx);
 let html=vm.runInContext('investigate()',ctx);
 assert.match(html,/All flagged/);
 assert.doesNotMatch(html,/<img src=x/);
 assert.match(html,/No matching messages/);
 assert.match(html,/All flagged messages in the loaded sample have been reviewed/);
 vm.runInContext("S.reviewStatus='all'",ctx);
 html=vm.runInContext('investigate()',ctx);
 assert.match(html,/&lt;img src=x/);
 assert.match(html,/latest 1 loaded scans/);
});
test('history sorting distinguishes paged remote results from loaded records',()=>{
 const ctx=context();
 vm.runInContext(`S.section='history';S.historyLoaded=true;S.historySort='score-high';S.messages=[
 {id:'a',action:'accept',score:2,timestamp:'2026-10-31T12:00:00Z'},
 {id:'b',action:'reject',score:17,timestamp:'2026-10-31T11:00:00Z'}
 ];`,ctx);
 let html=vm.runInContext('messageHistory()',ctx);
 assert.match(html,/Sort loaded results/);
 assert.ok(html.indexOf('data-inspect="b"')<html.indexOf('data-inspect="a"'));
 vm.runInContext(`S.historyResults={total:29,items:[{id:'remote',action:'tag',score:8}]};S.historyOffset=0;`,ctx);
 html=vm.runInContext('messageHistory()',ctx);
 assert.match(html,/Sorting this page only/);
 assert.match(html,/1–29 of 29|1–29 of 29|1–29 of 29|1–29/);
 assert.match(html,/data-inspect="remote"/);
});
test('remote saved-history API failure is explicit and preserves recently loaded records',async()=>{
 const ctx=context();
 vm.runInContext(`
 S.section='history';S.historyResults={items:[{id:'stale',action:'reject'}],total:1};S.historyLoaded=true;
 S.messages=[{id:'recent',subject:'Retained local',action:'accept'}];
 render=()=>{};
 api=async()=>{throw Error('database unavailable')};
 `,ctx);
 await vm.runInContext('runHistorySearch(0)',ctx);
 assert.equal(vm.runInContext('S.historyResults',ctx),null);
 assert.equal(vm.runInContext('S.historySearching',ctx),false);
 const html=vm.runInContext('messageHistory()',ctx);
 assert.match(html,/Saved-history search failed/);
 assert.match(html,/database unavailable/);
 assert.match(html,/data-inspect="recent"/);
 assert.doesNotMatch(html,/data-inspect="stale"/);
});


test('held-mail view separates saved originals from verified Postfix queue holds',()=>{
 const ctx=context();
 vm.runInContext(`S.section='quarantine';S.messages=[{id:'saved',delivery:'quarantined',subject:'Held original',action:'quarantine'}];
 S.postfixHold={enabled:true,detail:'Read-only Postfix queue.',messages:[
  {queue_id:'Q123',spamgate_scan_id:'linked-scan',sender:'sender@example.net',recipients:['alice@example.org']},
  {queue_id:'Q999',sender:'other@example.net',recipients:['bob@example.org']}
 ]};`,ctx);
 const html=vm.runInContext('quarantine()',ctx);
 assert.match(html,/Held original/);
 assert.match(html,/Queue Q123/);
 assert.match(html,/data-inspect="linked-scan"/);
 assert.match(html,/aria-label="Investigate correlated Postfix hold Q123"/);
 assert.match(html,/Queue Q999/);
 assert.match(html,/No verified SpamGate scan correlation/);
 assert.doesNotMatch(html,/data-inspect="Q999"/);
 assert.match(html,/released only after confirmation/);
});
test('hold inventory never interprets disabled inspection as an empty queue',()=>{
 const ctx=context();
 vm.runInContext("S.section='quarantine';S.postfixHold={enabled:false,messages:[],detail:'disabled'}",ctx);
 const html=vm.runInContext('quarantine()',ctx);
 assert.match(html,/Postfix hold inspection is disabled/);
 assert.doesNotMatch(html,/No Postfix holds reported/);
});
test('Postfix hold inventory errors and untrusted envelope data are escaped',()=>{
 const ctx=context();
 vm.runInContext(`S.section='quarantine';S.postfixHoldError='<img src=x onerror=alert(1)>';S.postfixHold=null;`,ctx);
 let html=vm.runInContext('quarantine()',ctx);
 assert.match(html,/Postfix inventory unavailable/);
 assert.match(html,/&lt;img src=x/);
 assert.doesNotMatch(html,/<img src=x/);
 vm.runInContext(`S.postfixHoldError=null;S.postfixHold={enabled:true,messages:[{
  queue_id:'Q123"><script>alert(1)</script>',spamgate_scan_id:'scan1',
  sender:'<img src=x onerror=alert(2)>',recipients:['<iframe src=x>'],recipients_truncated:true
 }]};`,ctx);
 html=vm.runInContext('quarantine()',ctx);
 assert.match(html,/Recipient list was truncated/);
 assert.match(html,/&lt;iframe src=x&gt;/);
 assert.match(html,/&lt;script&gt;/);
 assert.doesNotMatch(html,/<iframe src=x>/);
 assert.doesNotMatch(html,/<script>alert/);
});
