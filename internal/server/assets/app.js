'use strict';
const S={authenticated:false,setup:false,me:null,config:null,messages:[],stats:null,bayesStats:null,fuzzyStats:null,fuzzyEntries:[],neuralStats:null,signals:[],runtime:null,hostReport:null,section:'overview',inspect:null,search:'',filterAction:'all',onceToken:null,menu:false,deliveryQueue:null,postfixHold:null,investigation:null,historyResults:null,historyOffset:0,editRule:null,preview:null,diagnostics:null,readiness:null,wizardLoaded:false,wizardStep:0,wizardServer:'testing',wizardMode:'test',wizardPolicy:'balanced',livePollBusy:false,liveLastCheck:null,liveError:null,liveNewCount:0,overviewWindow:'24h',headerView:null,updateInfo:null,updateError:null,telemetry:null,telemetryError:null,diagnosticsCheckedAt:null,diagnosticsBusy:false,monitorData:null,monitorError:null,policyPreview:null,policyPreviewError:null,sgtubeCatalog:null,sgtubeSelected:null,sgtubeMessages:null,sgtubeResult:null,sgtubeError:null,historyAudit:null,historyAuditError:null,historyAuditBusy:false,historyLoaded:false,historyRefreshError:null};
const $=q=>document.querySelector(q);
const esc=v=>String(v??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const n=v=>Number(v||0).toLocaleString();
const fmtDate=v=>v?new Date(v).toLocaleString(undefined,{month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}):'—';
const action=v=>`<span class="action-label ${esc(v)}">${esc(({accept:'Allowed',tag:'Flagged',quarantine:'Held for review',reject:'Rejected',soft_reject:'Temporarily deferred'})[v]||'Unknown')}</span>`;
function alertUser(msg,bad=false){let prev=$('.toast');if(prev)prev.remove();const el=document.createElement('div');el.className='toast'+(bad?' fail':'');el.textContent=msg;el.setAttribute('role','status');document.body.appendChild(el);setTimeout(()=>el.remove(),5500)}
async function api(path,options={}){
  const headers={...(options.headers||{})};if(S.me?.csrf&&options.method&&options.method!=='GET')headers['X-CSRF-Token']=S.me.csrf;
  if(options.json!==undefined){headers['Content-Type']='application/json';options.body=JSON.stringify(options.json)}
  const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options,headers});let data;
  try{data=await response.json()}catch{data={error:'Unexpected response from SpamGate'}}
  if(!response.ok)throw Error(data?.error||`Request failed (${response.status})`);return data;
}
async function saveRecipientPolicies(policies){
 const expected_revision=S.config?.recipient_policies_revision;
 if(!expected_revision)throw Error('Mailbox policy revision unavailable; reload before editing');
 try{return await api('/api/v1/recipient-policies',{method:'PUT',json:{policies,expected_revision}})}
 catch(e){if(e.message.includes('changed since'))await refresh();throw e}
}
async function start(){try{const status=await api('/api/v1/status');if(!status.configured){S.setup=true;render();return}try{S.me=await api('/api/v1/me');S.authenticated=true;S.section=permitted(sectionFromLocation())?sectionFromLocation():'overview';await refresh();if(S.section==='diagnostics')void loadDiagnostics()}catch{S.authenticated=false;render()}}catch(e){$('#app').innerHTML=`<div class="auth-side"><div class="auth-panel"><h1>Cannot connect</h1><p>${esc(e.message)}</p><button class="primary" id="retry">Retry connection</button></div></div>`}}
async function refresh(){if(!S.authenticated)return;try{
 const [cfg,msg,stats]=await Promise.all([api('/api/v1/config'),api('/api/v1/messages?limit=1000'),api('/api/v1/statistics')]);
 // History is essential. Optional detector endpoints must never make a
 // successful history response disappear when a model is unavailable.
 const optional=await Promise.allSettled([
  api('/api/v1/signals'),
  S.me.role==='admin'?api('/api/v1/bayes/stats'):Promise.resolve(null),
  S.me.role==='admin'?api('/api/v1/fuzzy/stats'):Promise.resolve(null),
  S.me.role==='admin'?api('/api/v1/fuzzy/entries'):Promise.resolve([]),
  S.me.role==='admin'?api('/api/v1/neural/stats'):Promise.resolve(null)
 ]);
 const [signals,bayes,fuzzy,entries,neural]=optional.map(x=>x.status==='fulfilled'?x.value:null);
 S.historyLoaded=true;S.historyRefreshError=null;S.config=cfg;if(!S.wizardLoaded&&cfg.onboarding?.completed){S.wizardServer=cfg.onboarding.server||'testing';S.wizardMode=cfg.onboarding.mode||'test';S.wizardPolicy=cfg.onboarding.policy||'balanced';S.wizardLoaded=true;if(cfg.onboarding.mode!=='test'&&!cfg.onboarding.activated)S.wizardStep=4}if(S.me.role==='admin'&&!cfg.onboarding?.completed&&S.section==='overview'){S.section='welcome';window.history.replaceState({section:'welcome'},'','/welcome')}S.messages=Array.isArray(msg)?msg:[];S.stats=stats;S.signals=Array.isArray(signals)?signals:[];S.bayesStats=bayes;S.fuzzyStats=fuzzy;S.fuzzyEntries=Array.isArray(entries)?entries:[];S.neuralStats=neural;
    if(S.me.role==='admin') {
      try{S.runtime=await api('/api/v1/runtime')}catch{S.runtime=null}
      try{S.hostReport=await api('/api/v1/host')}catch{S.hostReport=null}
      try{S.readiness=await api('/api/v1/setup/readiness')}catch{S.readiness=null}
      try{S.deliveryQueue=await api('/api/v1/delivery-queue')}catch{S.deliveryQueue=null}
      try{S.monitorData=await api('/api/v1/operations/monitor');S.monitorError=null}catch(e){S.monitorData=null;S.monitorError=e.message}
      try{S.sgtubeCatalog=await api('/api/v1/spam-categories');S.sgtubeError=null}catch(e){S.sgtubeError=e.message}
    } else S.runtime=null;
    render();if(S.section==='history'&&S.me?.role==='admin')void loadHistoryAudit()
 }catch(e){
   S.historyRefreshError=e.message;S.historyLoaded=false;
   alertUser(e.message,true);
   if(e.message.includes('Authentication')){S.authenticated=false;render()}
   else render();
 }}
const navigation=[
 ['overview','Home','/overview','Everyday'],
 ['investigate','Review mail','/investigations','Everyday'],
 ['quarantine','Held messages','/quarantine','Everyday'],
 ['history','All messages','/messages','Everyday'],
 ['welcome','Connection wizard','/welcome','Setup'],
 ['connect','Mail integration','/connections','Setup'],
 ['settings','Settings','/settings','Setup'],
 ['updates','Software updates','/settings/updates','Setup'],
 ['policy','Protection policy','/policy','Setup'],
 ['rules','Sender & filtering rules','/rules','Advanced'],
 ['lists','Blocklists','/blocklists','Advanced'],
 ['signals','Scoring details','/signals','Advanced'],
 ['learning','Training & models','/learning','Advanced'],
 ['delivery','Delivery problems','/delivery-queue','Advanced'],
 ['threats','Threat reports','/threat-intelligence','Advanced'],
 ['users','Mailboxes','/mailboxes','Advanced'],
 ['tokens','API keys','/api-keys','Advanced'],
 ['scanlab','Message analyzer','/scan-workbench','Setup'],
 ['categories','Spam categories & tests','/categories','Advanced'],
 ['docs','Documentation','/help','Setup'],
 ['diagnostics','Diagnostics','/diagnostics','Advanced']
];
const primarySections=new Set(['overview','investigate','quarantine','history','settings']);
function permitted(id){return S.me?.role==='admin'||!['users','tokens','lists','settings','updates','policy','connect','learning','threats','delivery','welcome','diagnostics','categories'].includes(id)}
function sectionFromLocation(){return navigation.find(r=>r[2]===window.location.pathname)?.[0]||'overview'}
function routeTo(id,replace=false){if(!navigation.some(r=>r[0]===id)||!permitted(id))return;S.section=id;S.menu=false;S.inspect=null;S.search='';S.filterAction='all';S.historyResults=null;S.historyOffset=0;const path=navigation.find(r=>r[0]===id)[2];if(window.location.pathname!==path)window.history[replace?'replaceState':'pushState']({section:id},'',path);render();window.scrollTo(0,0);if(id==='diagnostics'){void loadDiagnostics();void loadMonitor()}if(id==='categories')void loadCategoryCatalog();if(id==='history'&&S.me?.role==='admin')void loadHistoryAudit() }

function authLayout(){const first=S.setup;return `<div class="auth-layout"><aside class="auth-brand"><a class="brand-lockup" href="/overview"><img class="auth-logo-image" src="/assets/spamgate-logo.png" alt="SpamGate"></a><div><div class="hero-rule" style="color:#E7BE58">YOUR EMAIL, YOUR RULES</div><h1>Less junk. More control.</h1><p>Spot spam, fix wrong decisions, and stay in control of your inbox.</p></div><div><div class="auth-graphic" aria-hidden="true"><div class="line"></div><div class="line"></div><div class="line"></div><div class="line"></div></div><small>NO HIDDEN SCORING · NO DEFAULT ADMIN PASSWORD</small></div></aside><main id="main" class="auth-side"><section class="auth-panel"><div class="overline">${first?'CREATE YOUR ACCOUNT':'WELCOME BACK'}</div><h1>${first?'First, create your account.':'Welcome back.'}</h1><p>${first?'Create your login. The setup guide comes next — no mail server changes yet.':'Sign in to review messages and manage protection.'}</p><form id="${first?'setup-form':'login-form'}">${first?`<div class="field"><label for="setupkey">First-run claim key</label><input id="setupkey" name="setup_key" required autocomplete="off" placeholder="Paste the claim key from SpamGate" spellcheck="false"></div>`:''}<div class="field"><label for="username">Administrator username</label><input id="username" name="username" required minlength="3" maxlength="48" autocomplete="username"></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="${first?'new-password':'current-password'}" required ${first?'minlength="12"':''}></div><button type="submit" class="primary">${first?'Create administrator':'Sign in'} ↗</button></form><div class="auth-foot">${first?'The claim key is unique to the current startup. Choose a password of at least 12 characters.':'Sessions expire after 12 hours. Repeated failed sign-in attempts are rate-limited.'}</div></section></main></div>`}

function layout(body){
 const active=S.readiness?.instance_running===true;
 const listening=Object.entries(S.runtime?.services||{}).some(([k,v])=>['smtp','milter','rspamd_http'].includes(k)&&v.enabled);
 const status=active?'Mail connection verified':listening?'Mail listener configured':'Mail connection unverified';
 const links=[['overview','Overview'],['investigate','Review mail'],['quarantine','Held mail'],['history','All messages'],['policy','Protection'],['diagnostics','Diagnostics'],['settings','Settings']];
 const related={
  policy:[['policy','Policy'],['rules','Filtering rules'],['lists','Blocklists'],['signals','Scoring'],['learning','Learning'],['threats','Threat intelligence'],['scanlab','Message analyzer']],
  diagnostics:[['diagnostics','System checks'],['connect','Mail connections'],['delivery','Delivery queue'],['docs','Troubleshooting guide']],
  settings:[['settings','All settings'],['updates','Software updates'],['users','Accounts'],['tokens','API keys'],['welcome','Connection setup']]
 };
 const group=Object.entries(related).find(([_,items])=>items.some(([id])=>id===S.section))?.[0];
 const navLink=(id,label,secondary=false)=>{const row=navigation.find(x=>x[0]===id);if(!row||!permitted(id))return '';
  const selected=S.section===id||(!secondary&&id===group);
  return `<a href="${row[2]}" data-route="${id}" class="${secondary?'sg-tab':'sg-nav-link'} ${selected?'sg-nav-active':''}" ${selected?'aria-current="page"':''}>${esc(label)}${id==='quarantine'&&S.messages.some(m=>m.delivery==='quarantined')?` <span class="sg-nav-count">${n(S.messages.filter(m=>m.delivery==='quarantined').length)}</span>`:''}</a>`;
 };
 const tabs=group?related[group].map(([id,label])=>navLink(id,label,true)).filter(Boolean).join(''):'';
 return `<div class="sg-shell">
  <header class="sg-topbar"><div class="sg-topbar-inner">
   <a class="sg-brand" href="/overview" data-route="overview"><img src="/assets/spamgate-icon.png" width="43" height="43" alt=""><span><strong>SpamGate<span class="sg-brand-period">.</span></strong><small>MAIL PROTECTION</small></span></a>
   <button type="button" class="sg-menu-button" id="nav-toggle" aria-expanded="${S.menu}" aria-controls="sg-primary-nav">${S.menu?'Close menu':'Menu'} <span aria-hidden="true">☰</span></button>
   <nav aria-label="Main navigation" class="sg-navigation ${S.menu?'sg-navigation-open':''}" id="sg-primary-nav">${links.map(([id,label])=>navLink(id,label)).filter(Boolean).join('')}</nav>
   <div class="sg-topbar-right"><span class="sg-connection"><span class="sg-status-dot ${active?'sg-online':''}" aria-hidden="true"></span>${esc(status)}</span><button id="reload" type="button" class="sg-toolbar-button">Refresh</button><button id="signout" type="button" class="sg-signout">Sign out</button></div>
  </div></header>
  ${tabs?`<nav aria-label="Related tools" class="sg-related"><div class="sg-related-inner">${tabs}</div></nav>`:''}
  <main id="main" tabindex="-1" class="sg-main"><div class="sg-page-intro"><span class="sg-context">${esc((navigation.find(x=>x[0]===S.section)||[])[1]||'Overview')}</span><span id="live-check" role="status" aria-live="polite" class="sg-live">Automatic message refresh enabled</span></div>${body}<footer class="defense-footer"><span>SpamGate · ${esc(S.stats?.version||'Development build')}</span><a href="/help" data-route="docs">Help and documentation</a></footer></main>
  ${S.inspect?detailView(S.inspect):''}
 </div>`;
}

function heading(title,description,extra=''){
 return `<div class="screen-title"><div><div class="screen-context">${esc((navigation.find(x=>x[0]===S.section)||[])[3]||'Operations')} / ${esc((navigation.find(x=>x[0]===S.section)||[])[1]||'Mail defense')}</div><h1>${title}</h1><p>${description}</p></div>${extra?`<div class="screen-action">${extra}</div>`:''}</div>`;
}

function empty(title,description){return `<div class="empty"><b>${title}</b><p>${description}</p></div>`}
function table(rows){if(!rows.length)return empty('Nothing in the ledger yet.','Scan an .eml file or connect a mail server. Each verdict and its scoring evidence will appear here.');return `<div class="table-shell" role="region" aria-label="Message verdicts" tabindex="0"><table><thead><tr><th scope="col">Received</th><th scope="col">Message</th><th scope="col">Recipient</th><th scope="col">Score</th><th scope="col">Verdict</th><th scope="col">Evidence</th></tr></thead><tbody>${rows.map(m=>`<tr><td>${esc(fmtDate(m.timestamp))}</td><td><div class="subject" title="${esc(m.subject||'(no subject)')}">${esc(m.subject||'(no subject)')}</div><small>${esc(m.sender||'Unknown sender')}</small></td><td>${esc((m.recipients||[]).join(', ')||'—')}</td><td class="score ${(m.score||0)>0?'pos':'neg'}">${Number(m.score||0)>0?'+':''}${Number(m.score||0).toFixed(2)}</td><td>${action(m.action)}</td><td><button class="table-link" data-inspect="${esc(m.id)}" aria-label="Review message ${esc(m.subject||m.id)}">Why this decision?</button></td></tr>`).join('')}</tbody></table></div>`}


function getQueue(){return S.messages.filter(m=>m.delivery==='quarantined')}
function topFindings(limit=7){
 const result=new Map();
 for(const m of S.messages)for(const f of m.findings||[]){
  if(!f.symbol||!Number(f.score)||['HUMAN_REVIEW','ADMIN_OVERRIDE','FORCED_ACTION'].includes(f.symbol))continue;
  const r=result.get(f.symbol)||{symbol:f.symbol,source:f.source,count:0,score:0};
  r.count++;r.score+=Number(f.score)||0;result.set(f.symbol,r);
 }
 return [...result.values()].sort((a,b)=>b.count-a.count||b.score-a.score).slice(0,limit);
}
function topSenders(limit=6){
 const result=new Map();
 for(const m of S.messages){
  const domain=String(m.sender||'').split('@').pop().toLowerCase();
  if(!domain||!domain.includes('.'))continue;
  const row=result.get(domain)||{domain,count:0,flagged:0};
  row.count++;if(['tag','quarantine','reject','soft_reject'].includes(m.action))row.flagged++;
  result.set(domain,row);
 }
 return [...result.values()].sort((a,b)=>b.flagged-a.flagged||b.count-a.count).slice(0,limit);
}
function counts(){const a={accept:0,tag:0,quarantine:0,reject:0,soft_reject:0};for(const m of S.messages)if(Object.hasOwn(a,m.action))a[m.action]++;return a}
function previewRows(rows,limit=8){return `<div class="incident-list" role="list">${rows.slice(0,limit).map(m=>`<div class="incident" role="listitem"><div class="incident-mark ${esc(m.action)}"></div><div class="incident-content"><strong>${esc(m.subject||'(No subject)')}</strong><span>${esc(m.sender||'Unknown sender')} <span aria-hidden="true">·</span> ${esc((m.recipients||[]).join(', ')||'—')}</span></div><div class="incident-evidence"><span class="incident-score ${m.score>=0?'hot':''}">${m.score>=0?'+':''}${Number(m.score||0).toFixed(1)}</span><span>${n((m.findings||[]).filter(f=>Number(f.score)!==0).length)} scored checks</span></div><div class="incident-result">${action(m.action)}<small>${esc(fmtDate(m.timestamp))}</small></div><button class="inspect-btn" data-inspect="${esc(m.id)}">Review <span aria-hidden="true">→</span></button></div>`).join('')||empty('No message records yet','Connect an MTA or use the scan workbench. All real decisions will appear here.')}</div>`}
function configurationStatus(){
 const services=S.runtime?.services||{};
 const enabled=['smtp','milter','rspamd_http'].filter(x=>services[x]?.enabled);
 const unknown=!S.runtime;
 const configured=enabled.length>0;const verified=S.readiness?.instance_running===true;
 return `<div class="integrity-strip ${configured?'configured':'attention'}"><span class="strip-symbol" aria-hidden="true">${configured?'◇':unknown?'?':'!'}</span><div><strong>${verified?'Mail connector verified and marked running':configured?'Listener configured, verification still required':unknown?'Listener status unavailable':'Mail protection is not yet configured'}</strong><p>${verified?'A new connector test was scanned, and an administrator confirmed its delivery. Continue monitoring your mail server logs and delivery errors.':configured?`The application has ${enabled.length} MTA-facing listener${enabled.length===1?'':'s'} configured. Setup verification is still required before marking it running.`:unknown?(S.me?.role==='admin'?'SpamGate could not verify the currently configured listeners. Check application logs and API permissions.':'Detailed listener status is visible to administrators. Contact your mail system administrator to verify filtering.'):'The Web UI is responding. That alone does not mean any real email is protected. Configure a trusted Milter, SMTP, or Rspamd HTTP integration.'}</p></div><a href="/connections" data-route="connect">Review integrations →</a></div>`;
}
function verdictBars(){
 const c=counts(); const total=Object.values(c).reduce((a,b)=>a+b,0);
 const labels=[['accept','Accepted'],['tag','Tagged'],['quarantine','Quarantined'],['reject','Rejected']];
 return `<div class="verdict-bars">${labels.map(([id,label])=>`<div class="verdict-line"><div><span>${label}</span><strong>${n(c[id])}</strong></div><div class="verdict-track"><span class="bar-${id}" style="width:${total?(c[id]/total*100).toFixed(2):0}%"></span></div></div>`).join('')}</div>`;
}
// Explain scores by human-readable detector names without hiding exact evidence.
const scoreNumber=x=>(Number(x||0)>=0?'+':'')+Number(x||0).toFixed(2);
const scoreSign=x=>Number(x||0)>0?'Adds suspicion':Number(x||0)<0?'Reduces suspicion':'Information only';
function scoreExplain(m){
 const fs=(m.findings||[]).filter(f=>f.symbol!=='HUMAN_REVIEW'&&f.symbol!=='ADMIN_OVERRIDE'&&f.symbol!=='FORCED_ACTION');
 const positives=fs.filter(f=>Number(f.score)>0), negatives=fs.filter(f=>Number(f.score)<0), notes=fs.filter(f=>!Number(f.score));
 const positiveTotal=positives.reduce((n,f)=>n+Number(f.score),0);
 const negativeTotal=negatives.reduce((n,f)=>n+Number(f.score),0);
 const trace=m.scoring;
 const thresholds=trace?`<div class="scoring-thresholds"><b>Thresholds used when this message was scanned</b><span>Below ${esc(trace.tag_threshold)}: allow</span><span>${esc(trace.tag_threshold)}+: flag</span><span>${esc(trace.quarantine_threshold)}+: hold</span><span>${esc(trace.reject_threshold)}+: reject</span></div>`:'<p class="score-old-data">This message was scanned before detailed scoring history was added. Current thresholds may differ from those used at scan time.</p>';
 const explainRows=(rows)=>rows.map(f=>`<div class="score-evidence-row"><div><strong>${esc(friendlyReason(f))}</strong><small>${esc(f.detail||'No detail recorded')}</small><code title="Exact detector symbol and source">${esc(f.symbol)} · ${esc(f.source||'unknown')}</code></div><b class="${Number(f.score)>0?'score-positive':Number(f.score)<0?'score-negative':'score-neutral'}">${scoreNumber(f.score)}</b></div>`).join('');
 const applied=trace?.forced_action?`<p class="score-exception">A configured rule overrode the numeric threshold and selected <strong>${esc(trace.forced_action)}</strong>. The score is still shown above for context.</p>`:'';
 const afterReview=m.original_action&&m.action!==m.original_action?`<p class="score-exception">An administrator later reclassified this record from <b>${esc(m.original_action)}</b> to <b>${esc(m.action)}</b>. The original score has not been recalculated.</p>`:'';
 return `<section class="score-explanation"><h3>How the score was calculated</h3><p>SpamGate adds and subtracts points from detected evidence. The number below explains this message's recorded result, not a simulated scan.</p>
 <div class="score-arithmetic"><div><small>Suspicious evidence</small><strong class="score-positive">+${positiveTotal.toFixed(2)}</strong></div><div><small>Legitimate evidence</small><strong class="score-negative">${negativeTotal.toFixed(2)}</strong></div><div><small>Final spam score</small><strong>${Number(m.score||0).toFixed(2)}</strong></div></div>
 ${thresholds}${applied}${afterReview}
 <h4>What increased suspicion (${positives.length})</h4>${positives.length?explainRows(positives):'<p class="score-empty">No positive scoring findings were recorded.</p>'}
 <h4>What reduced suspicion (${negatives.length})</h4>${negatives.length?explainRows(negatives):'<p class="score-empty">No negative scoring findings were recorded.</p>'}
 ${notes.length?`<details><summary>Other informational findings (${notes.length})</summary>${explainRows(notes)}</details>`:''}
 <details class="checks-checked"><summary>Which checks ran, found nothing, or were unavailable (${trace?.checks?.length||0})</summary>${trace?.checks?.length?trace.checks.map(c=>`<div class="check-result"><div><b>${esc(c.name)}</b><small>${esc(c.detail)}</small></div><span class="check-status ${esc(c.status)}">${esc(({match:'Matched',clear:'No match',pass:'Passed',fail:'Failed',softfail:'Soft fail',neutral:'Neutral',none:'None',permerror:'Policy error',temperror:'Temporary error',skipped:'Not active',info:'Checked',unverified:'Unverified',malformed:'Malformed'})[c.status]||c.status)}</span></div>`).join(''):'<p>This scan predates recorded check coverage. Only matching findings were saved.</p>'}</details>
 </section>`;
}
function signalTable(){const top=topFindings();return top.length?`<div class="signals-ranked">${top.map((f,i)=>`<div class="ranked-row"><span class="rank-number">${String(i+1).padStart(2,'0')}</span><div><b>${esc(friendlyReason(f))}</b><small>${esc(f.symbol)} · ${esc(f.source||'Scoring engine')}</small></div><strong>${n(f.count)} <small>hits</small></strong></div>`).join('')}</div>`:empty('No detection signals recorded','Symbols detected during real scans will be ranked here.');}
function senderTable(){const top=topSenders();return top.length?`<div class="signals-ranked">${top.map((f,i)=>`<div class="ranked-row"><span class="rank-number">${String(i+1).padStart(2,'0')}</span><div><b>${esc(f.domain)}</b><small>${n(f.count)} observed messages</small></div><strong>${n(f.flagged)} <small>flagged</small></strong></div>`).join('')}</div>`:empty('No sender intelligence yet','Domain patterns are calculated from locally retained message history.');}
function engineRows(){
 const rows=[['rspamd_http','Rspamd HTTP','38471'],['milter','Milter','38472'],['smtp','SMTP relay filter','38473'],['controller','Training controller','38474']];
 const svc=S.runtime?.services||{};
 return `<div class="engine-rows">${rows.map(([key,label,port])=>`<div class="engine-row"><span class="engine-indicator ${svc[key]?.enabled?'available':'off'}" aria-hidden="true"></span><div><b>${label}</b><small>${esc(svc[key]?.address||(!S.runtime?'Status unavailable':'Default '+port+' · disabled'))}</small></div><span class="engine-state">${!S.runtime?'Unverified':svc[key]?.enabled?'Configured':'Disabled'}</span></div>`).join('')}</div>`;
}


function taskIntro(kicker,title,description,links=[]){
 return `<div class="task-intro"><div><span class="task-kicker">${esc(kicker)}</span><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="task-intro-actions">${links.map(([label,route,primary])=>`<a class="${primary?'primary-link':'secondary'}" href="${esc((navigation.find(x=>x[0]===route)||[])[2]||'/overview')}" data-route="${esc(route)}">${esc(label)} <span aria-hidden="true">→</span></a>`).join('')}</div></div>`;
}
function taskStatus(){
 const observed=Number(S.readiness?.mail_submissions_observed||0)>0;
 const listener=Object.entries(S.runtime?.services||{}).some(([k,v])=>['smtp','milter','rspamd_http'].includes(k)&&v.enabled);
 const verified=S.readiness?.instance_running===true;
 const label=verified?'Connection verified':observed?'Mail is reaching SpamGate':listener?'Listener ready — testing needed':'Mail connection not verified';
 const desc=verified?'SpamGate observed a test scan and an administrator confirmed delivery.':'A listening port alone cannot prove that your mail server is filtering. Finish the guided verification before trusting automatic protection.';
 return `<div class="task-status ${verified?'is-verified':observed?'is-observed':''}" role="status"><span class="task-status-icon" aria-hidden="true">${verified?'✓':observed?'↗':'!'}</span><div><strong>${label}</strong><p>${desc}</p></div>${S.me?.role==='admin'?'<a href="/welcome" data-route="welcome">Check setup →</a>':''}</div>`;
}
function taskStat(label,value,description,route){
 const path=(navigation.find(x=>x[0]===route)||[])[2]||'/overview';
 return `<a class="task-stat" href="${path}" data-route="${esc(route)}"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(description)}</small><span class="task-stat-arrow" aria-hidden="true">→</span></a>`;
}
function quickMessageList(messages,limit=12){
 if(!messages.length)return `<div class="task-empty"><span aria-hidden="true">✉</span><h3>No messages found</h3><p>As emails are scanned they will appear here. Change your search if you expected to see something.</p></div>`;
 return `<div class="task-message-list" role="list">${messages.slice(0,limit).map(m=>{
 const score=Number(m.score||0),matched=(m.findings||[]).filter(x=>Number(x.score)>0);
 const result=m.action==='quarantine'?'Hold requested':m.action==='tag'?'Flagged':m.action==='reject'?'Rejected':m.action==='soft_reject'?'Deferred':'Allowed';
 const reviewed=!!m.review_status;
 return `<div class="task-message" role="listitem"><span class="task-message-indicator ${esc(m.action)}"></span><div class="task-message-main"><strong>${esc(m.subject||'(No subject)')}</strong><span>${esc(m.sender||'Unknown sender')}</span><small>To ${esc((m.recipients||[]).join(', ')||'unknown')} · ${esc(fmtDate(m.timestamp))}</small></div><div class="task-message-decision"><span class="task-action ${esc(m.action)}">${result}</span><small>${reviewed?'Reviewed':'Not reviewed'}</small></div><div class="task-message-score"><strong class="${score>=0?'hot':'good'}">${score>=0?'+':''}${score.toFixed(1)}</strong><small>${matched.length} concerns</small></div><button class="task-open" type="button" data-inspect="${esc(m.id)}" aria-label="Review ${esc(m.subject||m.id)}">See why <span aria-hidden="true">→</span></button></div>`
 }).join('')}</div>`;
}
function taskSearch(placeholder='Find an email by sender, subject or recipient'){
 return `<div class="task-filterbar"><label class="sr-only" for="search">Search messages</label><input id="search" type="search" placeholder="${esc(placeholder)}" value="${esc(S.search)}"><label class="sr-only" for="action-filter">Mail decision</label><select id="action-filter"><option value="all" ${S.filterAction==='all'?'selected':''}>All decisions</option>${[['accept','Allowed'],['tag','Flagged'],['quarantine','Quarantine'],['reject','Rejected'],['soft_reject','Deferred']].map(([k,label])=>`<option value="${k}" ${S.filterAction===k?'selected':''}>${label}</option>`).join('')}</select></div>`;
}

function overviewMessageTable(rows){
 if(!rows.length)return `<div class="ops-no-records">No scans in the selected interval. <a href="/messages" data-route="history">View retained history</a>.</div>`;
 return `<div class="ops-table-scroll"><table class="ops-table"><thead><tr><th>Time</th><th>Message</th><th>Score</th><th>Decision</th><th></th></tr></thead><tbody>${rows.slice(0,12).map(m=>`<tr><td class="ops-time">${esc(fmtDate(m.timestamp))}</td><td class="ops-mail-cell"><strong>${esc(m.subject||'(No subject)')}</strong><span>${esc(m.sender||'Unknown sender')} · ${esc((m.recipients||[]).join(', ')||'—')}</span></td><td class="ops-number ${Number(m.score)>0?'risk':''}">${scoreNumber(m.score)}</td><td>${action(m.action)}</td><td class="ops-right"><button type="button" class="ops-inspect" data-inspect="${esc(m.id)}">Inspect</button></td></tr>`).join('')}</tbody></table></div>`;
}
function overviewCard(label,value,sub,route){
 const routeData=navigation.find(x=>x[0]===route);
 return `<a class="ops-metric" data-route="${route}" href="${routeData?routeData[2]:'/overview'}"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(sub)}</small></a>`;
}
function dashboard(){
 const all=S.messages||[];
 const duration=S.overviewWindow==='24h'?86400000:S.overviewWindow==='7d'?604800000:0;
 const now=Date.now();
 const records=duration?all.filter(m=>{const t=Date.parse(m.timestamp||'');return Number.isFinite(t)&&t<=now+60000&&t>=now-duration;}):all;
 const tally={accept:0,tag:0,quarantine:0,reject:0,soft_reject:0};
 for(const m of records)if(Object.hasOwn(tally,m.action))tally[m.action]++;
 const flagged=tally.tag+tally.quarantine+tally.reject+tally.soft_reject;
 const outstanding=records.filter(m=>['tag','quarantine','reject','soft_reject'].includes(m.action)&&!m.review_status);
 const signals=new Map();
 for(const m of records)for(const f of m.findings||[]){
   if(!f.symbol||Number(f.score)<=0||['HUMAN_REVIEW','ADMIN_OVERRIDE','FORCED_ACTION'].includes(f.symbol))continue;
   const existing=signals.get(f.symbol)||{symbol:f.symbol,detail:friendlyReason(f),count:0};existing.count++;signals.set(f.symbol,existing);
 }
 const mostCommon=[...signals.values()].sort((a,b)=>b.count-a.count).slice(0,6);
 const settings=S.config?.settings||{};
 const ready=S.readiness?.instance_running===true;
 const observed=Number(S.readiness?.mail_submissions_observed||0)>0;
 const connected=Object.entries(S.runtime?.services||{}).some(([k,v])=>['smtp','milter','rspamd_http'].includes(k)&&v.enabled);
 const status=ready?'Verified connection':observed?'Scans observed':connected?'Listener active · mail path unverified':'No active mail connector';
 const health=(!ready&&S.config?.onboarding?.mode!=='test')?`<div class="ops-advisory"><b>Connection status: ${esc(status)}</b><span>Delivery is not verified by the application. Scanner activity and actual mailbox delivery are separate.</span>${S.me?.role==='admin'?`<a href="/connections" data-route="connect">Inspect connection</a>`:''}</div>`:'';
 return `<div class="ops-page-header"><div><span class="ops-eyebrow">OPERATIONS / MAIL FLOW</span><h1>Mail overview</h1><p>Scanner decisions from the latest ${n(all.length)} loaded records. Values below use the selected time interval.</p></div><div class="ops-page-tools"><label for="overview-window">Interval</label><select id="overview-window" aria-label="Mail overview interval"><option value="24h" ${S.overviewWindow==='24h'?'selected':''}>Last 24 hours</option><option value="7d" ${S.overviewWindow==='7d'?'selected':''}>Last 7 days</option><option value="all" ${S.overviewWindow==='all'?'selected':''}>Loaded history</option></select></div></div>
 ${health}
 ${S.me?.role==='admin'?`<div class="ops-verification-strip"><div><strong>Mail server evidence</strong><small>${ready?'A live connection has passed the verification process':observed?'Real scanner activity recorded, but final delivery is unverified':'No confirmed live mail flow yet'}</small></div><div><strong>${esc(connected?'Connector configured':'No connector verified')}</strong><small>${esc(S.runtime?.relay_configured?'SMTP relay configured':'Outbound relay not reported as configured')}</small></div><a href="/diagnostics" data-route="diagnostics">Open system diagnostics →</a></div>`:''}
 <div class="ops-metrics">${overviewCard('Scanned',n(records.length),'Message evaluations','history')}${overviewCard('Allowed',n(tally.accept),'Accepted verdicts','history')}${overviewCard('Flagged',n(tally.tag),'Tagged verdicts','investigate')}${overviewCard('Held / rejected',n(tally.quarantine+tally.reject),'Requested holds + rejects','quarantine')}${overviewCard('Pending review',n(outstanding.length),'Unreviewed flagged records','investigate')}</div>
 <div class="ops-activity-layout"><section class="ops-panel ops-activity"><div class="ops-panel-heading"><div><h2>Recent messages</h2><p>All scanner decisions, including accepted mail</p></div><a data-route="history" href="/messages">View history</a></div>${overviewMessageTable(records)}</section>
 <aside class="ops-panel ops-review"><div class="ops-panel-heading"><div><h2>Review queue</h2><p>Flagged messages awaiting feedback</p></div><a href="/investigations" data-route="investigate">Review all</a></div>${outstanding.length?`<div class="ops-review-rows">${outstanding.slice(0,6).map(m=>`<button type="button" data-inspect="${esc(m.id)}"><span class="ops-review-subject">${esc(m.subject||'(No subject)')}</span><span class="ops-review-meta">${esc(m.sender||'Unknown')} · ${scoreNumber(m.score)} · ${esc(m.action)}</span></button>`).join('')}</div>`:'<div class="ops-quiet">No unreviewed flagged messages in this interval.</div>'}</aside></div>
 <div class="ops-lower"><section class="ops-panel"><div class="ops-panel-heading"><div><h2>Detection activity</h2><p>Positive findings recorded during the interval</p></div><a href="/signals" data-route="signals">All detectors</a></div>${mostCommon.length?`<div class="ops-detector-list">${mostCommon.map(x=>`<div><span title="${esc(x.symbol)}">${esc(x.detail)}</span><strong>${n(x.count)}</strong></div>`).join('')}</div>`:'<div class="ops-quiet">No positive detection signals in this interval.</div>'}</section>
 <section class="ops-panel"><div class="ops-panel-heading"><div><h2>Enforcement policy</h2><p>Active scoring thresholds</p></div>${S.me?.role==='admin'?'<a data-route="policy" href="/policy">Edit policy</a>':''}</div><dl class="ops-policy-grid"><div><dt>Tag</dt><dd>${scoreNumber(settings.tag_threshold??5)}</dd></div><div><dt>Quarantine</dt><dd>${scoreNumber(settings.quarantine_threshold??10)}</dd></div><div><dt>Reject</dt><dd>${scoreNumber(settings.reject_threshold??20)}</dd></div></dl><p class="ops-policy-note">Delivery enforcement depends on the connected MTA. A verdict is not proof of final disposition.</p></section></div>`;
}

function quarantine(){
 const q=S.search.toLowerCase();
 const held=getQueue().filter(m=>[m.subject,m.sender,(m.recipients||[]).join(' '),m.id].join(' ').toLowerCase().includes(q));
 const inventory=S.postfixHold;
 return `${taskIntro('HELD MAIL','Messages on hold','Understand where a message is held before taking action. Postfix holds and SpamGate saved originals are different systems.',[['Review flagged mail','investigate',false]])}
 <div class="task-notice"><strong>Two different kinds of holds</strong><p>SpamGate can store an original when its SMTP relay quarantines a message. Postfix Milter quarantine puts mail in Postfix's separate hold queue. A score alone does not confirm either hold.</p></div>
 <div class="task-two-columns"><section class="task-surface"><div class="task-section-head"><div><span class="task-kicker">SAVED IN SPAMGATE</span><h2>Originals available for release <span class="task-count">${n(held.length)}</span></h2><p>You can inspect, release, or discard these saved originals.</p></div></div><div class="task-filterbar"><label for="search" class="sr-only">Find saved mail</label><input id="search" type="search" placeholder="Find saved mail" value="${esc(S.search)}"></div>${quickMessageList(held,1000)}</section>
 <section class="task-surface"><div class="task-section-head"><div><span class="task-kicker">HELD BY POSTFIX</span><h2>Mail server hold queue</h2><p>Read-only. SpamGate cannot currently release Postfix queue entries through this screen.</p></div></div><div class="task-queue-inspector">${S.me.role==='admin'?'<button class="secondary" type="button" id="inspect-postfix-hold">Check Postfix hold queue</button>':''}${inventory?`<p>${esc(inventory.detail||'Inventory returned by the local server.')}</p>${(inventory.messages||[]).length?`<div class="task-queue-list">${inventory.messages.map(v=>`<div><strong>${esc(v.queue_id)}</strong>${v.spamgate_scan_id?`<small>Matched SpamGate hold request: ${esc(v.spamgate_scan_id)}</small>`:`<small>No verified SpamGate scan ID correlation</small>`}<span>${esc(v.sender)}</span><small>${esc((v.recipients||[]).join(', '))}</small></div>`).join('')}</div>`:empty('No held Postfix messages reported','The inventory returned no held mail, or inspection is disabled.')}`:'<p>Use the button to ask the local Postfix server which emails are actually on hold. This check is disabled until explicitly enabled by the administrator.</p>'}</div></section></div>`;
}

function investigate(){
 const q=S.search.toLowerCase();
 const rows=S.messages.filter(m=>S.filterAction==='all'||m.action===S.filterAction).filter(m=>[m.sender,m.subject,m.client_ip,m.id,(m.recipients||[]).join(' ')].join(' ').toLowerCase().includes(q));
 const flagged=rows.filter(m=>['tag','quarantine','reject','soft_reject'].includes(m.action));
 const pending=flagged.filter(m=>!m.review_status);
 const reviewed=flagged.length-pending.length;
 return `<div class="ops-page-header"><div><span class="ops-eyebrow">OPERATIONS / CLASSIFICATION</span><h1>Review mail</h1><p>Review scanner verdicts, inspect contributing signals and record feedback. Review does not alter Postfix delivery history.</p></div><div class="ops-page-tools"><a class="secondary" href="/messages" data-route="history">All messages</a></div></div>
 <div class="ops-review-totals"><div><strong>${n(pending.length)}</strong><span>Pending review</span></div><div><strong>${n(reviewed)}</strong><span>Reviewed</span></div><div><strong>${n(flagged.length)}</strong><span>Flagged matches</span></div></div>
 <section class="ops-panel"><div class="ops-panel-heading"><div><h2>Classification queue</h2><p>Newest first · Open any message to inspect scoring evidence and record a correction</p></div><a href="/signals" data-route="signals">Detector settings</a></div>${taskSearch('Search mail, sender, IP or message ID')}${quickMessageList(flagged,1000)}</section>
 <p class="ops-review-footer">Allowed messages are available in <a href="/messages" data-route="history">All messages</a> for missed-spam reporting.</p>`;
}

function threats(){
 const enabled=(S.config?.dns_lists||[]).filter(x=>x.enabled);
 const frequent=topFindings(10);const senders=topSenders(8);
 return `${taskIntro('PROTECTION INSIGHTS','Threat intelligence','Recorded detector matches, sending-domain patterns, and available intelligence sources.',[['Change protection','policy',true]])}
 <div class="task-stats">${taskStat('Active custom rules',n((S.config?.rules||[]).filter(x=>x.enabled).length),'Your filtering conditions','rules')}${taskStat('Reputation sources',n(enabled.length),'Enabled DNS providers','lists')}${taskStat('Checks enabled',n((S.signals||[]).filter(x=>x.enabled).length),'Built-in checks','signals')}${taskStat('Local learning',S.bayesStats?.ready?'Trained':'Not trained','Bayesian readiness','learning')}</div>
 <div class="task-two-columns"><section class="task-surface task-side-panel"><h2>Why messages are being flagged</h2><p>Frequency does not necessarily mean danger. These are recorded matches, not predictions.</p>${frequent.length?`<ul class="task-reason-list">${frequent.map(f=>`<li>${esc(friendlyReason(f))}<small>${n(f.count)} messages · ${scoreNumber(f.score)} combined points</small></li>`).join('')}</ul>`:empty('No scoring reasons recorded','Reasons appear when a scoring check matches a real message.')}</section><section class="task-surface task-side-panel"><h2>Senders most often flagged</h2><p>Calculated from the latest ${n(S.messages.length)} visible records, not an external threat feed.</p>${senders.length?`<ul class="task-reason-list">${senders.map(r=>`<li>${esc(r.domain)}<small>${n(r.flagged)} flagged of ${n(r.count)} received</small></li>`).join('')}</ul>`:empty('No sender trends yet','Mail history will populate sender trends.')}</section></div>
 <div class="task-shortcuts"><a href="/rules" data-route="rules"><strong>Sender and filtering rules</strong><span>Control custom decisions →</span></a><a href="/blocklists" data-route="lists"><strong>Reputation checks</strong><span>Manage external providers →</span></a><a href="/learning" data-route="learning"><strong>Teach the filter</strong><span>Improve locally trained patterns →</span></a></div>`;
}


function spamCategoryLab(){
 const catalog=S.sgtubeCatalog,items=Array.isArray(catalog?.categories)?catalog.categories:[],groups=[...new Set(items.map(x=>x.group))];
 const count=id=>Number(catalog?.recent_counts?.[id]||0);
 const current=items.find(x=>x.id===S.sgtubeSelected);
 const rows=groups.map(group=>'<section class="task-surface task-side-panel"><h2>'+esc(group)+'</h2><div class="table-shell" role="region" tabindex="0" aria-label="'+esc(group)+' category list"><table><thead><tr><th>Category</th><th>Retained scans</th><th>Test actions</th></tr></thead><tbody>'+items.filter(x=>x.group===group).map(x=>'<tr><td><strong>'+esc(x.name)+'</strong><small>'+esc(x.description)+'</small></td><td>'+n(count(x.id))+'</td><td><button type="button" class="secondary" data-sgtube-view="'+esc(x.id)+'">Messages</button> <button type="button" class="secondary" data-sgtube-simulate="'+esc(x.id)+'">Run test</button> <button type="button" class="secondary" data-sgtube-copy="'+esc(x.id)+'">Copy signature</button> <button type="button" class="secondary" data-sgtube-eml="'+esc(x.id)+'">Download .eml</button></td></tr>').join('')+'</tbody></table></div></section>').join('');
 const recent=Array.isArray(S.sgtubeMessages?.messages)?S.sgtubeMessages.messages:[];
 const messages=current?'<section class="task-surface task-side-panel"><h2>'+esc(current.name)+' — retained messages</h2><p>'+n(S.sgtubeMessages?.matched_in_recent||0)+' matching messages from the latest '+n(S.sgtubeMessages?.sampled_history||0)+' retained records (maximum 1,000). This does not imply all-time totals.</p><div class="table-shell" role="region" tabindex="0"><table><thead><tr><th>Date</th><th>Subject</th><th>Score</th><th>Verdict</th><th>Source</th></tr></thead><tbody>'+recent.map(m=>'<tr><td>'+esc(fmtDate(m.timestamp))+'</td><td>'+esc(m.subject)+'</td><td>'+Number(m.score).toFixed(2)+'</td><td>'+esc(m.action)+'</td><td>'+(m.test_case?'Synthetic test':'Detection evidence')+'</td></tr>').join('')+'<tr></tr></tbody></table></div></section>':'';
 const outcome=S.sgtubeResult?.message?'<section class="task-surface task-side-panel" role="status"><h2>Laboratory result</h2><p><strong>'+esc(S.sgtubeResult.message.category)+'</strong> · '+esc(S.sgtubeResult.message.action)+' · score '+Number(S.sgtubeResult.message.score).toFixed(2)+'</p><p>'+esc(S.sgtubeResult.warning)+'</p><p>Scan performed only in memory; no message was delivered, saved, or held.</p></section>':'';
 return taskIntro('SPAM CLASSIFICATION','Categories & test lab','Browse evidence-backed category lists and run safe SGTUBE tests for each threat family.',[['Analyze actual email','scanlab',false]])+
 '<section class="task-surface task-side-panel"><h2>How to test SpamGate</h2><p><strong>Laboratory:</strong> Run test scans here without delivering mail. <strong>Download .eml:</strong> generate a harmless, full RFC 5322 email for a designated test mailbox. <strong>Real Postfix:</strong> set SPAMGATE_TEST_RECIPIENTS to that exact mailbox before starting SpamGate, then send from an external account and confirm actual Milter action in Postfix logs.</p>'+
 '<p class="task-notice slim">Synthetic category tests are <strong>not proof</strong> that a genuine phishing, malware or scam sample will be detected. Ordinary recipients never interpret SGTUBE tokens. Public GTUBE is recognized only under the same test-mailbox restrictions.</p>'+
 '<p>Live test-mailbox mode: <strong>'+(catalog?.live_test_enabled?'Configured (test recipients set)':'Disabled by default')+'</strong>. Classification of ordinary mail is indicative and does not independently force a new action.</p>'+
 '<button type="button" class="secondary" id="sgtube-refresh">Refresh categories</button></section>'+
 (S.sgtubeError?'<p role="alert">'+esc(S.sgtubeError)+'</p>':'')+
 (!catalog?'<p>Loading category catalog…</p>':'<p>Showing '+n(items.length)+' stable categories. Counts from up to '+n(catalog.sample_limit)+' recent retained messages. Older alpha releases may have unclassified history.</p>')+
 rows+outcome+messages;
}
async function loadCategoryCatalog(){try{S.sgtubeCatalog=await api('/api/v1/spam-categories');S.sgtubeError=null}catch(e){S.sgtubeError=e.message}if(S.section==='categories')render()}

function scanlab(){return `${taskIntro('TESTING','Analyze an email','Evaluate an RFC 822 message locally, without sending or modifying live mail.',[['Review mail','investigate',false]])}<div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><span class="task-kicker">HOW THIS WORKS</span><h2>Scan a copy of a message</h2><ol class="task-numbered"><li><b>Save a message as an .eml file.</b><span>Use a message you are authorized to inspect.</span></li><li><b>Upload it and add the SMTP details.</b><span>These help the authentication checks evaluate the right sender.</span></li><li><b>Open the result under All messages.</b><span>See the score, evidence and thresholds for that scan.</span></li></ol><div class="task-notice slim"><strong>This does not filter live mail.</strong><p>An uploaded message is an advisory scan only. It will not release, reject or hold a copy on your mail server.</p></div></section><section class="task-surface task-side-panel"><h2>Choose the email to test</h2><form id="scan-form"><div class="field"><label for="scan-file">Original email (.eml, up to 10 MiB)</label><input id="scan-file" name="eml" type="file" accept=".eml,message/rfc822" required></div><div class="field"><label for="scan-sender">SMTP envelope sender</label><input id="scan-sender" name="sender" placeholder="sender@example.com"></div><div class="field"><label for="scan-recipient">Recipient email</label><input id="scan-recipient" name="recipients" placeholder="recipient@example.com"></div><details class="task-settings-fold"><summary><b>Optional: original sending IP</b></summary><div><label for="scan-ip">Public sending IP (for SPF or DNSBL checks)</label><input id="scan-ip" name="client_ip" placeholder="203.0.113.10"><p>Use the public connecting IP, not a private server address or one from a forwarded header.</p></div></details><button class="primary" type="submit">Analyze email</button></form></section></div>`}

async function loadHistoryAudit(){
 if(S.me?.role!=='admin')return;
 S.historyAuditBusy=true;S.historyAuditError=null;
 try{S.historyAudit=await api('/api/v1/history/integrity')}
 catch(e){S.historyAuditError=e.message;S.historyAudit=null}
 finally{S.historyAuditBusy=false;if(S.section==='history')render()}
}
function historyIntegrityPanel(){
 if(S.me?.role!=='admin')return '';
 const h=S.historyAudit;
 const fields=h?'<p><strong>Disk events: '+n(h.disk_events)+'</strong> · Unique scans: '+n(h.unique_scan_ids)+' · Loaded retained: '+n(h.loaded_retained)+' · Journal: '+n(h.file_bytes)+' bytes</p>'+
 '<p><strong>Storage status: '+esc(h.status)+'</strong> — '+esc(h.detail)+'</p>':'<p>No on-disk integrity result yet. Verify history to distinguish an empty list from missing or unreadable storage.</p>';
 const warning=h&&h.status!=='ok'?'<p role="alert"><strong>History needs investigation.</strong> The audit reports '+esc(h.status)+'. Preserve events.jsonl and inspect storage before attempting recovery or compaction.</p>':'';
 const countMismatch=h&&Number(h.loaded_retained)>0&&S.historyLoaded&&S.messages.length===0?'<p role="alert">The store reports retained scans, but the browser has an empty message list. Refresh and investigate the API before assuming records were deleted.</p>':'';
 return '<section class="task-surface task-side-panel"><h2>Saved history integrity</h2>'+
 (S.historyRefreshError?'<p role="alert">Message history could not refresh: '+esc(S.historyRefreshError)+'. The previous list may be stale or incomplete.</p>':'')+
 (!S.historyLoaded?'<p role="alert">Message history has not finished loading successfully. Empty results are not evidence of missing data.</p>':'')+
 (S.historyAuditError?'<p role="alert">History audit unavailable: '+esc(S.historyAuditError)+'</p>':'')+
 warning+countMismatch+fields+
 '<button type="button" class="secondary" id="history-audit" '+(S.historyAuditBusy?'disabled':'')+'>'+(S.historyAuditBusy?'Verifying…':'Verify on-disk history')+'</button></section>';
}

function messageHistory(){
 const q=S.search.toLowerCase();
 const remote=!!S.historyResults;
 const matched=remote?(S.historyResults.items||[]):S.messages.filter(m=>(S.filterAction==='all'||S.filterAction===m.action)&&[m.sender,m.subject,m.action,(m.recipients||[]).join(' '),m.id].join(' ').toLowerCase().includes(q));
 const total=remote?S.historyResults.total:S.messages.length;
 return `${taskIntro('MAIL HISTORY','Message history','Search retained scan records, evidence, and transport action requests.',[['Review flagged mail','investigate',false]])}
 <section class="task-surface"><div class="task-section-head"><div><h2>All messages</h2><p>${remote?'Searching retained history':'Showing the latest '+n(S.messages.length)+' messages'} · ${n(matched.length)} matching entries. Past decisions are never silently rewritten.</p></div>${S.me.role==='admin'?'<a class="secondary" href="/api/v1/export" download>Export history</a>':''}</div>
 ${historyIntegrityPanel()}
 ${taskSearch('Search sender, recipient, subject or message ID')}
 <div class="task-history-tools"><button class="secondary" id="search-full" type="button">Search entire saved history</button><span>Results shown newest first</span></div>${quickMessageList(matched,1000)}
 ${remote?`<div class="task-pagination"><button class="secondary" id="search-prev" ${S.historyOffset===0?'disabled':''}>Previous</button><span>${n(S.historyOffset+1)}–${n(Math.min(S.historyOffset+50,total))} of ${n(total)}</span><button class="secondary" id="search-next" ${S.historyOffset+50>=total?'disabled':''}>Next</button></div>`:''}</section>`;
}

function rules(){
 const items=S.config?.rules||[],admin=S.me.role==='admin',edit=S.editRule;
 const kinds=admin?['sender_email','sender_domain','recipient_email','client_ip','subject_contains','body_contains','url_domain','header_contains']:['sender_email','sender_domain'];
 return `${taskIntro('PERSONALIZE PROTECTION','Filtering rules','Manage match conditions, scoring adjustments, action overrides and expiry.',[['Review mail','investigate',false]])}
 <div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><div class="task-section-head"><div><h2>Rules in use <span class="task-count">${n(items.filter(x=>x.enabled).length)} active</span></h2><p>Highest priority rules take precedence. Use Edit to inspect the exact match and score.</p></div></div>${items.length?`<div class="task-rule-list">${items.map(x=>`<div class="task-rule"><div><b>${esc(x.name)}</b><small>${esc(x.kind.replaceAll('_',' '))}: ${esc(x.value)}</small><span>${x.enabled?'Enabled':'Disabled'} · ${Number(x.score)>0?'+':''}${Number(x.score).toFixed(1)} points${x.action?' · Action '+esc(x.action):''}</span></div><div class="task-rule-actions"><button class="secondary" data-edit-rule="${esc(x.id)}">Edit</button><button class="secondary" data-toggle-rule="${esc(x.id)}">${x.enabled?'Pause':'Enable'}</button><button class="danger" data-delete-rule="${esc(x.id)}">Delete</button></div></div>`).join('')}</div>`:empty('No custom rules yet','Start with reviewing real mail. Add a rule only when you know which sender or pattern you need to treat differently.')}</section>
 <section class="task-surface task-side-panel" id="rule-editor"><span class="task-kicker">${edit?'EDIT RULE':'NEW RULE'}</span><h2>${edit?'Update this rule':'Add a filtering rule'}</h2><p>Choose what to match, then decide how many points it should affect. A forced action overrides ordinary scoring.</p><form id="rule-form"><div class="field"><label>Rule name<input name="name" required maxlength="100" value="${esc(edit?.name||'')}"></label></div><div class="field"><label>Match against<select name="kind">${kinds.map(k=>`<option value="${k}" ${edit?.kind===k?'selected':''}>${esc(k.replaceAll('_',' '))}</option>`).join('')}</select></label></div><div class="field"><label>Match value<input name="value" required maxlength="256" value="${esc(edit?.value||'')}"></label></div>${admin?`<div class="field"><label>Score adjustment<input name="score" type="number" min="-100" max="100" step="0.1" value="${Number(edit?.score??5)}" required></label><small>Positive points make a message more suspicious; negative points reduce suspicion.</small></div><div class="field"><label>Rule priority<input name="priority" type="number" min="-1000" max="1000" value="${Number(edit?.priority||0)}"></label></div>`:''}<div class="field"><label>Expiry date (optional)<input name="expires_at" type="datetime-local" value="${edit?.expires_at?esc(edit.expires_at.slice(0,16)):''}"></label></div><div class="field"><label>Action override<select name="action">${(admin?['','accept','tag','quarantine','reject']:['accept','quarantine']).map(k=>`<option value="${k}" ${edit?.action===k?'selected':''}>${esc(k||'None — use score')}</option>`).join('')}</select></label></div><div class="form-actions"><button type="submit" class="primary">${edit?'Save changes':'Add rule'}</button>${edit?'<button type="button" id="cancel-rule-edit" class="secondary">Cancel</button>':''}</div></form></section></div>`;
}

function lists(){
 const sources=S.config?.dns_lists||[];
 return `${taskIntro('EXTERNAL REPUTATION','Reputation providers','Manage configured DNSBL, RHSBL and URIBL services and their scoring weights.',[['Protection settings','settings',false]])}
 <div class="task-notice"><strong>External lookups share sender information with your DNS resolver and providers.</strong><p>Use a licensed provider and select the correct list type. DNS reputation checks only run when the global reputation switch is on and a provider is enabled.</p></div>
 <div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><h2>Configured reputation providers <span class="task-count">${n(sources.length)}</span></h2>${sources.length?`<div class="task-rule-list">${sources.map(r=>`<div class="task-rule"><div><b>${esc(r.zone)}</b><small>${esc(({ip:'Sending IP (DNSBL)',domain:'Sender domain (RHSBL)',url:'Link domains (URIBL)'})[r.kind||'ip']||r.kind)}</small><span>${r.enabled?'Enabled':'Disabled'} · ${Number(r.score)>=0?'+':''}${Number(r.score).toFixed(1)} points per match</span></div><button class="danger" data-delete-dns="${esc(r.zone)}">Remove</button></div>`).join('')}</div>`:empty('No reputation providers configured','SpamGate will not query external reputation services until you add and enable one.')}</section>
 <section class="task-surface task-side-panel"><h2>Add a provider</h2><p>Check your provider's query format, response codes, and terms before activating it.</p><form id="dns-form"><div class="field"><label>DNS zone</label><input name="zone" required placeholder="dnsbl.example.net"></div><div class="field"><label>What should be checked?</label><select name="kind"><option value="ip">Sending IP (DNSBL)</option><option value="domain">Envelope sender domain (RHSBL)</option><option value="url">Domains in message links (URIBL)</option></select></div><div class="field"><label>Points for a positive listing</label><input name="score" type="number" step="0.1" min="-100" max="100" value="3" required></div><div class="toggle"><input type="checkbox" name="enabled" id="dns-enabled"><label for="dns-enabled">Enable this source now</label></div><button class="primary">Add reputation provider</button></form></section></div>`;
}

function users(){
 const us=S.config?.users||[];
 return `${taskIntro('ACCOUNT ACCESS','Accounts & access','Manage mailbox-level access and administrator permissions.',[['Mail activity','history',false]])}
 <div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><h2>Existing accounts <span class="task-count">${n(us.length)}</span></h2>${us.length?`<div class="task-rule-list">${us.map(u=>`<div class="task-rule"><div><b>${esc(u.name)}</b><small>${esc(u.email||'No specific mailbox')} · ${esc(u.role)}</small></div>${u.role==='admin'?'<span>Admin account</span>':`<button class="danger" data-delete-user="${esc(u.name)}">Remove</button>`}</div>`).join('')}</div>`:empty('No additional mailbox users','Create a mailbox account for a person who needs to review their own mail.')}</section><section class="task-surface task-side-panel"><h2>Add a mailbox account</h2><p>This maps a local user to an exact email address. Directory sync and external login providers are not supported yet.</p><form id="user-form"><div class="field"><label>Username</label><input name="name" required minlength="3" maxlength="48" autocomplete="off"></div><div class="field"><label>Mailbox email</label><input name="email" required type="email" placeholder="person@example.com"></div><div class="field"><label>Temporary password</label><input name="password" type="password" minlength="12" required autocomplete="new-password"></div><button class="primary">Create mailbox account</button></form></section></div>`;
}

function tokens(){
 const ts=S.config?.tokens||[];
 return `${taskIntro('INTEGRATION CREDENTIALS','API access keys','These credentials are for software integrations—not for a person signing into the SpamGate Web UI.',[['Mail server setup','connect',false]])}
 <div class="task-notice"><strong>Keys are sensitive.</strong><p>Keys are stored as hashes, shown only once when created, and should be scoped to scanning unless full administrator API access is necessary.</p></div>
 <div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><h2>Issued integration keys <span class="task-count">${n(ts.length)}</span></h2>${ts.length?`<div class="task-rule-list">${ts.map(x=>`<div class="task-rule"><div><b>${esc(x.name)}</b><small>${esc(x.scope)} · Created ${esc(fmtDate(x.created))}</small></div><button class="danger" data-delete-token="${esc(x.name)}">Revoke</button></div>`).join('')}</div>`:empty('No integration keys','No keys have been created for external scanning services.')}</section><section class="task-surface task-side-panel"><h2>Create a key</h2><form id="token-form"><div class="field"><label>Name this integration</label><input name="name" required placeholder="Postfix scanner"></div><div class="field"><label>Access level</label><select name="scope"><option value="scan">Scan messages only</option><option value="admin">Full administrator API</option></select></div><button class="primary">Generate key</button></form>${S.onceToken?`<div class="task-notice"><strong>Copy this key now—it won't be shown again.</strong><p class="codeblock" style="user-select:all;overflow-wrap:anywhere">${esc(S.onceToken)}</p><button class="secondary" type="button" id="copy-token">Copy key</button></div>`:''}</section></div>`;
}

function settingsHome(){return `${taskIntro('APPLICATION SETTINGS','Settings','Manage SpamGate configuration, accounts, maintenance and software updates.',[])}<div class="settings-directory"><a href="/settings/updates" data-route="updates"><strong>Software updates</strong><span>Check, download, verify, install and restart SpamGate.</span></a><a href="/policy" data-route="policy"><strong>Protection policy</strong><span>Thresholds, detector controls, retention and quarantine rules.</span></a><a href="/connections" data-route="connect"><strong>Mail connections</strong><span>Inspect Milter, SMTP and relay integrations.</span></a><a href="/mailboxes" data-route="users"><strong>Accounts and mailboxes</strong><span>Manage access to message history and administration.</span></a><a href="/api-keys" data-route="tokens"><strong>API keys</strong><span>Manage external integration credentials.</span></a><a href="/diagnostics" data-route="diagnostics"><strong>System diagnostics</strong><span>Live connector checks, scanner errors, queue health, and troubleshooting steps.</span></a><a href="/delivery-queue" data-route="delivery"><strong>Delivery queue</strong><span>Inspect failed and retrying delivery operations.</span></a></div>`}
function updatesPage(){return `${taskIntro('APPLICATION MAINTENANCE','Software updates','Download verified worker releases; the permanent SpamGate launcher installs them.',[['All settings','settings',false]])}
<section class="task-surface task-side-panel"><h2>Software updates</h2><p>SpamGate checks official GitHub Releases, downloads the matching platform binary, and verifies its SHA-256 checksum before staging. Live installation requires restarting the process or service; your data and sessions remain in the same directory.</p><p>Supervisor status: <strong>${esc(S.updateInfo?.install_mode==='supervised'?'Supervisor detected':'No supervising parent detected')}</strong></p>${S.updateInfo?.install_path?`<p>Installed executable used by the supervised worker: <code>${esc(S.updateInfo.install_path)}</code>. The supervisor is unchanged; only the child application executable is replaced.</p>`:''}${S.updateInfo?.last_update?`<p>Last update: ${esc(S.updateInfo.last_update.state)} · ${esc(S.updateInfo.last_update.detail)}</p>`:''}${S.updateInfo?.install_mode!=='supervised'?`<div class="task-notice slim"><strong>Installation is disabled because the worker was launched directly.</strong><p>For native foreground installations, <code>./spamgate</code> must be the launcher and <code>./spamgate-worker</code> must be its child (alpha.16+). Stop the standalone application before migrating. A staged download alone cannot replace a running executable.</p></div>`:''}<p>Current version: <strong>${esc(S.updateInfo?.current||'Check for installed version')}</strong></p>${S.updateInfo?`<p>Latest release: <strong>${esc(S.updateInfo.latest||'No published release')}</strong> · ${S.updateInfo.available?'Update available':'Up to date'}${S.updateInfo.staged?' · Download verified and staged':''}</p>`:''}${S.updateError?`<p role="alert">${esc(S.updateError)}</p>`:''}<div class="form-actions"><button type="button" class="secondary" id="check-update">Check for updates</button>${S.updateInfo?.available&&!S.updateInfo?.staged?'<button type="button" class="primary" id="stage-update">Download and verify update</button>':''}${S.updateInfo?.staged&&S.updateInfo?.install_mode==='supervised'?'<button type="button" class="primary" id="install-update">Install and restart with rollback</button>':''}</div><small>Supervised installations keep the parent running, verify the replacement, and roll back startup failures. Unsupervised installs never terminate the process through the update button.</small></section>`}

function settings(){
 const x=S.config?.settings||{};
 const option=(key,value,text)=>`<option value="${value}" ${(x[key]||'hold')===value?'selected':''}>${text}</option>`;
 const toggle=(key,label,note)=>`<label class="task-toggle"><input type="checkbox" name="${key}" ${x[key]?'checked':''}><span><strong>${label}</strong><small>${note}</small></span></label>`;
 return `${taskIntro('PROTECTION POLICY','Protection policy','Score thresholds, delivery actions, detection modules, and recipient overrides. Changes apply to new scans only.',[['Find an email','history',false]])}
 <form id="settings-form" class="task-settings-form"><section class="task-surface task-settings-primary"><span class="task-kicker">DECISION THRESHOLDS</span><h2>Score thresholds</h2><p>Thresholds used to select the scanner verdict and requested MTA action.</p><div class="task-threshold-grid"><label>Flag / mark as spam at<input name="tag_threshold" type="number" min="0" step="0.1" value="${esc(x.tag_threshold)}" required><small>Mark and add explanatory spam headers</small></label><label>Quarantine at<input name="quarantine_threshold" type="number" step="0.1" value="${esc(x.quarantine_threshold)}" required><small>Ask the mail server to hold or route to Junk</small></label><label>Reject at<input name="reject_threshold" type="number" step="0.1" value="${esc(x.reject_threshold)}" required><small>Reject the email during SMTP</small></label></div><div class="task-notice slim"><strong>Threshold ordering</strong><p>Keep the thresholds in ascending order. A score is a recommendation until your MTA successfully enforces it.</p></div></section>
 <section class="task-surface task-settings-primary"><span class="task-kicker">DELIVERY ACTIONS</span><h2>Quarantine enforcement</h2><div class="field"><label>When the quarantine score is reached</label><select name="quarantine_mode">${option('quarantine_mode','hold','Ask Postfix to hold the message')}${option('quarantine_mode','junk','Add SpamGate headers for a Junk-folder rule')}</select></div><p class="task-context">Postfix hold and a mailbox Junk folder are different. Junk routing requires a separate Dovecot Sieve rule; SpamGate does not silently edit your mail-server configuration.</p>${toggle('subject_rewrite','Prefix tagged subjects with [SPAM]','Optional; changing a Subject header may invalidate DKIM signatures.')}</section>
 <details class="task-settings-fold"><summary><span><b>Detection modules</b><small>External reputation, suspicious links and reviewed sender evidence</small></span></summary><div>${toggle('dnsbl_enabled','Query enabled DNS reputation providers','Off by default. Configure providers under Reputation sources.')}${toggle('attachment_inspection','Inspect attachment contents and archives','Opt-in; bounded ZIP inspection and executable signatures.')}${toggle('threat_feed_enabled','Use a dated external threat feed','Requires SPAMGATE_THREAT_FEED_FILE; sources and expiration checked before scoring.')}${toggle('external_fuzzy_enabled','External fuzzy reputation','Requires SPAMGATE_FUZZY_URL (HTTPS) and SPAMGATE_FUZZY_TOKEN; sends a content fingerprint, not message text.')}${toggle('phishing_links','Detect misleading HTML links','Tracking and redirect links may produce false positives.')}${toggle('reviewed_reputation','Use reputation from reviewed mail','Only uses qualified, DMARC-authenticated samples.')}</div></details>
 <details class="task-settings-fold"><summary><span><b>SMTP abuse controls</b><small>Greylisting and connection rate limits may delay legitimate mail</small></span></summary><div><p>Enable these only when you understand the effect on shared sending servers and retries.</p><div class="task-threshold-grid"><label>Greylist retry delay (minutes)<input name="greylist_wait_minutes" type="number" min="1" max="120" value="${Number(x.greylist_wait_minutes)||5}"></label><label>Maximum messages per sender IP/hour<input name="rate_limit_per_hour" type="number" min="10" max="100000" value="${Number(x.rate_limit_per_hour)||240}"></label></div>${toggle('greylist_enabled','Temporarily defer suspicious first-time senders','A legitimate email may be delayed while the sending server retries.')}${toggle('rate_limit_enabled','Limit incoming volume by sender IP','Large providers share IPs; use with care.')}</div></details>
 <details class="task-settings-fold"><summary><span><b>Retention and routing</b><small>Retention limits and a copyable Dovecot Junk example</small></span></summary><div class="task-threshold-grid"><label>Days to retain history<input type="number" min="1" max="3650" name="retention_days" value="${esc(x.retention_days)}" required></label><label>Maximum saved scan records<input type="number" min="100" max="500000" name="max_history" value="${esc(x.max_history)}" required></label></div><div class="task-code-help"><h3>Example: route SpamGate spam headers to Junk with Dovecot Sieve</h3><p>Only apply this after selecting Junk mode and confirming Sieve integration and the mailbox's folder name.</p><pre class="codeblock">require ["fileinto"];
if header :is "X-SpamGate-Action" "quarantine" {
  fileinto "Junk";
  stop;
}</pre></div></details>
 <div class="task-savebar"><div><b>SpamGate protection settings</b><small>Saving only affects new email scans. Your product name remains SpamGate.</small></div><button class="primary" type="submit">Save protection settings</button></div></form>
 <section class="task-surface task-side-panel"><h2>Mailbox-specific scoring</h2><p>Optional thresholds for mail sent to a single mailbox. A message sent to multiple recipients uses the global settings because Postfix cannot apply separate Milter actions in one SMTP transaction.</p>
 <div class="task-rule-list">${(S.config?.recipient_policies||[]).map(p=>`<div class="task-rule"><div><b>${esc(p.mailbox)}</b><small>Flag ${n(p.tag_threshold)} · Quarantine ${n(p.quarantine_threshold)} · Reject ${n(p.reject_threshold)}</small></div><button class="secondary" data-remove-recipient-policy="${esc(p.mailbox)}">Remove</button></div>`).join('')||empty('No mailbox overrides','All mailboxes use the global score thresholds.')}</div>
 <form id="recipient-form" class="task-threshold-grid"><label>Mailbox address<input name="mailbox" type="email" placeholder="user@example.com" required></label><label>Flag at<input name="tag_threshold" type="number" step="0.1" min="0" required></label><label>Quarantine at<input name="quarantine_threshold" type="number" step="0.1" min="0" required></label><label>Reject at<input name="reject_threshold" type="number" step="0.1" min="0" required></label><button class="primary" type="submit">Save mailbox policy</button></form></section>${policyPreviewPanel()}`;
}

function connect(){
 const h=S.hostReport||{},services=S.runtime?.services||{};
 const seen=Number(S.readiness?.mail_submissions_observed||0)>0;
 return `${taskIntro('MAIL SERVER CONNECTION','Mail integrations','Local connector state, observed scanner activity, and MTA diagnostics.',S.config?.onboarding?.completed?[]:[['Open connection wizard','welcome',false]])}
 ${taskStatus()}
 <div class="task-two-columns"><section class="task-surface task-side-panel"><span class="task-kicker">CURRENT CONNECTION</span><h2>What SpamGate can verify</h2><div class="task-check-grid"><div class="task-check"><strong>Mail server</strong><span>${esc(h.mail_server||'Unknown')}</span><small>${esc(h.panel&&h.panel!=='none'?h.panel:'No hosting panel confirmed')}</small></div><div class="task-check"><strong>Local Milter</strong><span>${services.milter?.enabled?'Configured':'Not configured'}</span><small>${esc(services.milter?.address||'Not listening')}</small></div><div class="task-check"><strong>Mail observed</strong><span>${seen?'Yes':'Not confirmed'}</span><small>A mail scan is separate from successful final delivery.</small></div><div class="task-check"><strong>Marked running</strong><span>${S.readiness?.instance_running?'Yes':'Not yet'}</span><small>Requires a unique mail test and administrator delivery confirmation.</small></div></div>${h.notes?.length?`<details class="task-settings-fold"><summary><b>Local inspection notes</b></summary><div>${h.notes.map(x=>`<p>${esc(x)}</p>`).join('')}</div></details>`:''}</section>
 <section class="task-surface task-side-panel"><span class="task-kicker">CONNECTION MANAGEMENT</span><h2>${S.config?.onboarding?.completed?'Connector administration':'Initial connection setup'}</h2>${S.config?.onboarding?.completed?`<div class="task-check-grid"><div class="task-check"><strong>Listener</strong><span>${services.milter?.enabled?'Online':'Offline'}</span><small>${esc(services.milter?.address||'No local Milter listener')}</small></div><div class="task-check"><strong>Verification</strong><span>${S.readiness?.instance_running?'Verified':'Not verified'}</span><small>${seen?'Message scans observed':'No observed mail scans'}</small></div></div><p>Change or reverify the connection only when necessary. A listening port is not proof of final delivery.</p>`:`<p>Configure the selected mail server, then verify that a message reaches the scanner before activation.</p>`}<a class="secondary" href="/welcome" data-route="welcome">${S.config?.onboarding?.completed?'Reconfigure / verify':'Open connection wizard'}</a></section></div>
 <details class="task-settings-fold"><summary><span><b>Advanced connection diagnostics</b><small>Probe relay reachability and view local integration information</small></span></summary><div><button class="secondary" id="test-integration" type="button">Run configured relay diagnostics</button>${S.diagnostics?`<pre class="codeblock">${esc(JSON.stringify(S.diagnostics,null,2))}</pre>`:''}<p>Postfix is currently the guided Milter integration. Native Exim/cPanel enforcement is not yet verified and requires a separate supported integration.</p></div></details>`;
}

async function loadDiagnostics(){
 if(!S.authenticated||S.me?.role!=='admin'||S.diagnosticsBusy)return;
 S.diagnosticsBusy=true;S.telemetryError=null;render();
 const jobs=[
  ['runtime',()=>api('/api/v1/runtime')],['readiness',()=>api('/api/v1/setup/readiness')],
  ['hostReport',()=>api('/api/v1/host')],['deliveryQueue',()=>api('/api/v1/delivery-queue')],
  ['diagnostics',()=>api('/api/v1/integrations/diagnostics')],
  ['telemetry',async()=>{const response=await fetch('/api/v1/metrics',{credentials:'same-origin',cache:'no-store'});if(!response.ok)throw Error('Metrics endpoint: HTTP '+response.status);return parseMetrics(await response.text())}]
 ];
 const results=await Promise.allSettled(jobs.map(([,fn])=>fn()));
 const failures=[];for(let i=0;i<jobs.length;i++){
  const [key]=jobs[i];if(results[i].status==='fulfilled')S[key]=results[i].value;
  else{S[key]=null;failures.push(key+': '+results[i].reason.message)}
 }
 S.telemetryError=failures.length?failures.join(' · '):null;
 S.diagnosticsCheckedAt=new Date().toISOString();S.diagnosticsBusy=false;
 if(S.section==='diagnostics')render();
}
function parseMetrics(raw){
 const metrics={};
 for(const line of String(raw).split('\n')){
  const match=/^([a-z_][a-z0-9_]*)(?:\{([^}]*)\})?\s+(-?(?:\d+(?:\.\d+)?|Inf|NaN))$/.exec(line.trim());
  if(!match)continue;
  const name=match[1],label=match[2];
  if(!label)metrics[name]=Number(match[3]);
  else if(name==='spamgate_runtime_scan_connector_total'){
   const connector=/^connector="([a-z0-9_-]+)"$/.exec(label);
   if(connector){metrics.byConnector??={};metrics.byConnector[connector[1]]=Number(match[3])}
  }
 }
 return metrics;
}
function diagnosticNumber(value){return value===undefined||value===null||!Number.isFinite(Number(value))?'Not measured':n(value)}
function diagLine(label,value,detail='',tone='normal'){
 return `<div class="dg-line"><div><strong>${esc(label)}</strong>${detail?`<small>${esc(detail)}</small>`:''}</div><span class="dg-value ${tone}">${esc(String(value))}</span></div>`;
}

function monitorPanel(){
 const d=S.monitorData,samples=Array.isArray(d?.samples)?d.samples:[],alerts=Array.isArray(d?.alerts)?d.alerts:[],latest=samples.at(-1),open=alerts.filter(a=>a.state==='open'),stale=!latest||Date.now()-new Date(latest.at).getTime()>15*60*1000;
 const formatted=alerts.slice(-20).reverse().map(a=>'<tr><td>'+esc(a.severity)+'</td><td>'+esc(a.summary)+'<small>'+esc(a.code)+'</small></td><td>'+esc(a.state)+(a.acknowledged_at?' · acknowledged by '+esc(a.acknowledged_by):'')+'</td><td>'+(a.acknowledged_at?'—':'<button type="button" class="secondary" data-monitor-ack="'+esc(a.id)+'">Acknowledge</button>')+'</td></tr>').join('');
 const lines=samples.slice(-36).reverse().map(x=>'<tr><td>'+esc(fmtDate(x.at))+'</td><td>'+n(x.scan_total)+'</td><td>'+n(x.scan_errors)+'</td><td>'+(x.queue_enabled?(x.queue_available?n(x.queue_queued)+' queued, '+n(x.queue_dead)+' dead':'Queue inventory unavailable'):'Postfix/Milter mode; SMTP outbox not enabled')+'</td></tr>').join('');
 return '<section class="dg-section" aria-label="Persistent operations"><div class="dg-section-heading"><h2>Historical measurements and alerts</h2><button type="button" class="secondary" id="monitor-refresh">Capture measurement now</button></div>'+
 '<p>Five-minute automatic sampling. Evidence survives worker restarts; at most 2,016 samples are retained. This is SpamGate processing and its own SMTP queue, not proof of Postfix mailbox delivery.</p>'+
 (S.monitorError?'<p role="alert">Monitoring unavailable: '+esc(S.monitorError)+'; existing evidence was not reset.</p>':'')+
 (latest?'<p><strong>'+n(open.length)+' open alerts</strong> · Last captured '+esc(fmtDate(latest.at))+(stale?' (stale)':'')+' · '+n(latest.scan_total)+' scans / '+n(latest.scan_errors)+' scan failures since this worker started.</p>':'<p>No monitoring samples recorded yet.</p>')+
 '<h3>Operational alerts and acknowledgement audit</h3><div class="table-shell" role="region" aria-label="Alert history" tabindex="0"><table><thead><tr><th>Severity</th><th>Evidence</th><th>State</th><th>Operator</th></tr></thead><tbody>'+(formatted||'<tr><td colspan="4">No alerts recorded</td></tr>')+'</tbody></table></div>'+
 '<details><summary>Recent sample history ('+samples.length+')</summary><div class="table-shell" role="region" tabindex="0" aria-label="Processing trends"><table><thead><tr><th>Measured</th><th>Scans</th><th>Failures</th><th>Queue</th></tr></thead><tbody>'+(lines||'<tr><td colspan="4">No recorded measurements</td></tr>')+'</tbody></table></div></details></section>';
}
async function loadMonitor(){try{S.monitorData=await api('/api/v1/operations/monitor');S.monitorError=null}catch(e){S.monitorError=e.message}if(S.section==='diagnostics')render()}
function policyPreviewPanel(){
 const d=S.policyPreview,items=Array.isArray(d?.items)?d.items:[],changed=items.filter(i=>i.changed).slice(0,60);
 return '<section class="task-surface task-side-panel"><h2>Preview pending threshold changes</h2><p>Compare form thresholds against up to 500 saved mail scores without saving changes or delivering any mail. Historical forced actions are preserved; detectors are not rerun.</p><button type="button" class="secondary" id="preview-policy">Preview these values</button>'+
 (S.policyPreviewError?'<p role="alert">'+esc(S.policyPreviewError)+'</p>':'')+
 (d?'<p><strong>'+n(d.totals.changed)+' predicted changes</strong> among '+n(d.totals.examined)+' saved scores · '+n(d.totals.forced_preserved)+' forced actions retained · '+n(d.totals.multi_recipient_fallback)+' multi-recipient global fallbacks.</p><div class="table-shell" tabindex="0" role="region" aria-label="Hypothetical policy outcomes"><table><thead><tr><th>Scan ID</th><th>Score</th><th>Historical</th><th>Hypothetical</th></tr></thead><tbody>'+(changed.map(x=>'<tr><td><code>'+esc(x.id)+'</code></td><td>'+Number(x.score).toFixed(2)+'</td><td>'+esc(x.historical_action)+'</td><td>'+esc(x.hypothetical_action)+'</td></tr>').join('')||'<tr><td colspan="4">No predicted changes in sample</td></tr>')+'</tbody></table></div><p>'+esc((d.limitations||[]).join(' '))+'</p>':'')+'</section>';
}

function diagSummary(){
 const r=S.readiness||{},services=S.runtime?.services||{},d=S.diagnostics?.relay,q=S.deliveryQueue,tele=S.telemetry;
 const connectorNames=[['milter','Postfix Milter'],['smtp','SMTP intake'],['rspamd_http','Rspamd-compatible HTTP'],['controller','Controller']];
 const measured=S.diagnosticsCheckedAt;
 const state=r.state||'unknown',verified=r.instance_running===true;
 const expected=String(r.expected_connector||'Not configured');
 const total=Number(tele?.spamgate_runtime_scans_total||0),errors=Number(tele?.spamgate_runtime_scan_errors_total||0);
 const scanRate=total?Math.round(10000*errors/total)/100:0;
 const outcome=r.instance_running?'Verified test + administrator delivery confirmation':r.mail_submissions_observed>0?'Scanner activity observed; delivery confirmation not established':'No end-to-end verification recorded';
 const guide=[
  ['No messages appear','Check the local listener address, Postfix smtpd_milters/non_smtpd_milters, and whether messages have reached the scanner.','sudo postconf -n | grep -E "^(smtpd_milters|non_smtpd_milters|milter_default_action|milter_protocol)"'],
  ['Postfix cannot reach SpamGate','Compare the configured Milter address with the active listener. Port 38472 is Milter; 38471 is HTTP. A reachable port alone does not prove mail scanning.','sudo ss -ltnp | grep -E ":3847[1-4]"'],
  ['Messages are held but cannot be released','SpamGate saved originals, the durable SMTP outbox, and the Postfix hold queue are different storage locations. Identify the actual owner before releasing or deleting.','sudo postqueue -p'],
  ['Spam scoring seems wrong','Open the message in All messages, inspect every positive and negative score, check the policy snapshot and authentication trace, then use Review to record a false positive.',''],
  ['Mail is delayed or rejected','Inspect the specific verdict and queue ID, then look up that ID in Postfix logs. A scanner verdict is not proof of a final SMTP outcome.','sudo journalctl -u postfix --since "1 hour ago" --no-pager'],
  ['Updater cannot find a release','Software updates uses published GitHub Releases with the exact platform binary and SHA256SUMS.txt. A commit, tag, or chat attachment is not enough.',''],
  ['I am logged out after an update','Sessions persist in SpamGate’s data directory for their original lifetime. Confirm that updates reuse the exact same -data directory and browser origin.','']
 ];
 const example=guide.map(([title,description,command])=>`<details class="dg-guide"><summary>${esc(title)}</summary><div><p>${esc(description)}</p>${command?`<pre class="dg-command">${esc(command)}</pre><small>Read-only diagnostic command. Run on the applicable Linux mail server.</small>`:''}</div></details>`).join('');
 const conn=connectorNames.map(([key,label])=>{const svc=services[key];return diagLine(label,svc?.enabled?'Configured':'Not configured',svc?.detail||svc?.address||'No active configuration reported',svc?.enabled?'ok':'neutral')}).join('');
 const qstate=q?.enabled===false?'Disabled':q?.enabled===true||q?.jobs?'Available':'Not measured';
 const qDetails=q?`Queued ${diagnosticNumber(q.queued)} · Delivering ${diagnosticNumber(q.delivering)} · Failed ${diagnosticNumber(q.dead)} · ${diagnosticNumber(q.bytes)} bytes`:'Unable to retrieve delivery queue information';
 const problem=!!(q?.dead>0||errors>0||S.telemetryError||r.state==='listener_missing'||r.state==='postfix_not_connected');
 return `<section class="dg-head"><div><h1>System diagnostics</h1><p>Actual observations, incomplete checks, and the next place to investigate. No guesswork about whether Postfix delivered an email.</p></div><button type="button" id="diagnostics-recheck" class="primary" ${S.diagnosticsBusy?'disabled':''}>${S.diagnosticsBusy?'Checking…':'Run all checks'}</button></section>
 <div class="dg-status ${problem?'dg-status-warning':''}" role="status"><div><strong>${problem?'Issues or gaps need attention':verified?'Connection verified':'Connection not verified'}</strong><span>${esc(outcome)}</span></div><small>${measured?'Last checked '+esc(fmtDate(measured)):'Run checks to retrieve current runtime evidence'}</small></div>
 ${S.telemetryError?`<div class="dg-error" role="alert">Some checks could not complete: ${esc(S.telemetryError)}. Unavailable values are not interpreted as healthy.</div>`:''}
 <div class="dg-kpis"><div><span>Scans since process start</span><strong>${tele?diagnosticNumber(total):'—'}</strong><small>Resets when SpamGate restarts</small></div><div><span>Scanner errors</span><strong>${tele?diagnosticNumber(errors):'—'}</strong><small>${tele?scanRate+'% of attempts':'Metrics unavailable'}</small></div><div><span>Retained decisions</span><strong>${diagnosticNumber(S.stats?.total)}</strong><small>History retained in the data directory</small></div><div><span>Failed outbox jobs</span><strong>${q?diagnosticNumber(q.dead):'—'}</strong><small>Durable SMTP relay queue, if enabled</small></div></div>
 <div class="dg-columns"><section class="dg-section"><div class="dg-section-heading"><h2>Mail path</h2><a href="/connections" data-route="connect">Connection setup</a></div>${diagLine('Verification state',state,'State recorded by the onboarding readiness checker',verified?'ok':'warn')}${diagLine('Expected connector',expected,'From the configured onboarding plan')}${diagLine('MTA inspection',S.hostReport?.mail_server||'Unavailable','Read-only local host detection')}${diagLine('Postfix integration',r.postfix_connection||'Unknown','Local Milter configuration check; not proof of final delivery')}${diagLine('Mail scans observed',diagnosticNumber(r.mail_submissions_observed),'Does not count as recipient mailbox delivery')}${r.listeners_configured?.length?diagLine('Configured listener names',r.listeners_configured.join(', ')):''}</section>
 <section class="dg-section"><div class="dg-section-heading"><h2>Local services</h2><span>Configuration, not socket health</span></div>${conn}${diagLine('Relay configured',S.runtime?(S.runtime.relay_configured?'Yes':'No'):'Not measured','SMTP relay configured for outbound delivery')}${diagLine('Relay TCP probe',!d?'Not checked':d.tcp_reachable?'Reachable':'Not reachable',d?.detail||'Run all checks to test transport connectivity',d?.tcp_reachable?'ok':'warn')}${d?.checked_at?`<p class="dg-footnote">Relay check at ${esc(fmtDate(d.checked_at))}. TCP reachability does not validate SMTP, TLS or authentication.</p>`:''}</section></div>
 <div class="dg-columns"><section class="dg-section"><div class="dg-section-heading"><h2>Delivery and retention</h2><a href="/delivery-queue" data-route="delivery">Delivery queue</a></div>${diagLine('Outbox state',qstate,qDetails,q?.dead>0?'warn':'normal')}${diagLine('History retention',String(S.config?.settings?.retention_days??'—')+' days','Stored scan decisions; not the same as raw mail')}${diagLine('History limit',diagnosticNumber(S.config?.settings?.max_history),'Oldest records are pruned according to retention policy')}${diagLine('Held originals',diagnosticNumber(S.messages.filter(x=>x.delivery==='quarantined').length),'Within the latest loaded records only')}
 <p class="dg-footnote">Postfix Milter holds are stored by Postfix. SpamGate SMTP quarantined originals are managed separately. Never infer that a score confirms either hold.</p></section>
 <section class="dg-section"><div class="dg-section-heading"><h2>Processing activity</h2><a href="/messages" data-route="history">Inspect decisions</a></div>${(tele?.byConnector&&Object.keys(tele.byConnector).length)?Object.entries(tele.byConnector).sort((a,b)=>b[1]-a[1]).map(([key,count])=>diagLine(key,diagnosticNumber(count),'Scans by this connector since startup')).join(''):'<p class="dg-footnote">Run all checks to load connector-level scanner counters.</p>'}${diagLine('Time window','Process lifetime','These counters reset after every binary upgrade or restart')}</section></div>
 ${monitorPanel()}<section class="dg-guide-section"><h2>Find and fix a problem</h2><p>Open a problem below for the checks that actually narrow down its cause.</p><div class="dg-guide-grid">${example}</div></section>
 <div class="dg-limitations"><strong>What these checks cannot prove</strong><p>A configured listener, passing DNS lookup, scanner verdict, or Postfix next-hop “sent” entry is not proof of final mailbox delivery. Verify delivery at the destination and correlate individual queue IDs in the mail server logs.</p></div>`;
}

function docs(){return `${taskIntro('SPAMGATE HELP','Documentation','Reference material for scoring, mail disposition, authentication, and integration.',S.config?.onboarding?.completed?[['Run system diagnostics','diagnostics',false]]:[['Open setup guide','welcome',false]])}
 <div class="task-shortcuts"><a href="/messages" data-route="history"><strong>Scoring & evidence</strong><span>Find the message and open See why →</span></a><a href="/investigations" data-route="investigate"><strong>Classification review</strong><span>Record a review and optionally tune future scoring →</span></a><a href="/connections" data-route="connect"><strong>Postfix integration</strong><span>View connection checks and run the wizard →</span></a></div>
 <div class="task-help-list"><details class="task-settings-fold"><summary><b>What do spam scores mean?</b></summary><div><p>Every matched detection adds or removes points. Your thresholds decide when to mark, quarantine or reject. An explicit rule may override the score. Open any message for the evidence and exact recorded score.</p></div></details><details class="task-settings-fold"><summary><b>Does quarantine put mail in my Junk folder?</b></summary><div><p>Not by default. Postfix Milter quarantine requests a hold in Postfix. Junk-header mode requires a Dovecot Sieve rule to deliver into Junk. These are different paths, and neither is established by a score alone.</p></div></details><details class="task-settings-fold"><summary><b>Where does SpamGate get its intelligence?</b></summary><div><p>Built-in sender authentication, local rules, and opt-in locally trained models are included. External DNS reputation services must be configured and enabled. There is no shared fuzzy network connected by default.</p></div></details><details class="task-settings-fold"><summary><b>Where is my email history stored?</b></summary><div><p>Scan decisions and scoring metadata are retained in SpamGate's on-disk journal. Complete originals are not saved by default; they are retained for SpamGate's SMTP quarantine when needed. Postfix holds originals in its separate queue.</p></div></details><details class="task-settings-fold"><summary><b>Can I reverse a mistaken decision?</b></summary><div><p>Review feedback preserves the original historical decision. It does not silently release or deliver a message. A reversible sender-scoring adjustment can change future decisions.</p></div></details><details class="task-settings-fold"><summary><b>What is not yet implemented?</b></summary><div><p>See the version in the binary or the release notes for qualification status, compatibility and known limitations.</p></div></details></div>`}

function friendlyReason(f){
 const key=String(f.symbol||'');
 if(key==='HUMAN_REVIEW'||key==='ADMIN_OVERRIDE')return 'Previous administrator decision';
 if(key==='R_SPF_ALLOW')return 'The sender passed the SPF authorization check';
 if(key==='R_DKIM_ALLOW')return 'The email passed its DKIM signature check';
 if(key==='DMARC_PASS')return 'The sender passed DMARC identity alignment';
 if(key==='R_SPF_PERMERROR')return 'SPF policy could not be evaluated because of a policy error';
 if(key==='DMARC_PERMERROR')return 'DMARC policy had a permanent validation error';
 if(key==='ARC_UNVERIFIED')return 'Forwarding headers were inspected but could not be authenticated';
 if(key==='UNKNOWN_RECIPIENT')return 'The scanner did not receive the envelope recipient';
 if(key==='EMPTY_HTML')return 'The HTML email contained no usable text';
 if(key==='IP_URL')return 'A web link contains an IP address instead of a domain name';
 if(key==='PUNYCODE_URL')return 'A web link contains an internationalized domain name';
 if(key==='LONG_HOSTNAME')return 'A web link contains an unusually long hostname';
 if(key==='MANY_LINK_DOMAINS')return 'The message links to many different domains';
 if(key==='PHISHING_VISIBLE_LINK')return 'A link displays one website but leads to a different domain';
 if(key==='REVIEWED_DOMAIN_REPUTATION')return 'Verified human reviews of this authenticated sender domain affected the score';
 if(key==='TEMPORARY_POLICY_DEFERRAL')return 'Greylisting or rate limiting temporarily deferred this email';
 if(key==='UNTRUSTED_SPAMGATE_HEADER')return 'This email attempted to supply its own SpamGate control headers';
 if(key.startsWith('NEURAL_'))return 'The trained local classifier recognized a scoring pattern';
 if(key==='R_SPF_FAIL')return 'The sending server did not pass the domain’s identity check (SPF)';
 if(key==='R_SPF_SOFTFAIL')return 'The sender’s domain did not clearly authorize this server';
 if(key==='R_DKIM_REJECT')return 'The message signature could not be verified (DKIM)';
 if(key==='DMARC_FAIL')return 'The From address failed the domain’s authentication policy (DMARC)';
 if(key==='CLAMAV_MALWARE')return 'Antivirus reported a malicious file';
 if(key==='RISKY_ATTACHMENT')return 'The email contains a potentially dangerous file type';
 if(key==='DOUBLE_EXTENSION')return 'An attachment disguises its file type';
 if(key==='MISSING_FROM')return 'The email has no sender address';
 if(key==='MISSING_MESSAGE_ID')return 'The email is missing a normal identification header';
 if(key==='MISSING_DATE')return 'The email has no date header';
 if(key.startsWith('CONTENT_'))return 'The message contains wording commonly used in scams';
 if(key.startsWith('DNSBL_'))return 'The sender’s IP address appears on a configured blocklist';
 if(key.startsWith('BAYES_'))return 'The filter recognized patterns from manually trained messages';
 if(key.startsWith('FUZZY_'))return 'The message resembles another trained email';
 if(key.startsWith('CUSTOM_'))return 'One of your filtering rules matched';
 if(key.includes('URL'))return 'A link in the message may be suspicious';
 return (f.detail||'A detection check matched this email');
}
// Only an administrator can request retained raw headers. Display is escaped
// and never rendered as message HTML. These are inbound headers, not an MTA
// delivery receipt or a DKIM/SPF verification result.
function headerSummary(raw){
 const fields=[];
 for(const line of String(raw||'').split(/\r?\n/)){
  if(/^[ \t]/.test(line)&&fields.length){fields[fields.length-1].value+=' '+line.trim();continue}
  const mark=line.indexOf(':');if(mark>0){fields.push({name:line.slice(0,mark),value:line.slice(mark+1).trim()})}
 }
 const names=new Set(['received','return-path','from','to','reply-to','message-id','date','authentication-results','received-spf','dkim-signature','arc-authentication-results','arc-seal','subject']);
 const useful=fields.filter(f=>names.has(f.name.toLowerCase()));
 const received=fields.filter(f=>f.name.toLowerCase()==='received').length;
 return `<div class="header-highlights"><strong>${fields.length} fields · ${received} Received hops</strong><div class="header-fields">${useful.map(f=>`<div><b>${esc(f.name)}</b><span>${esc(f.value)}</span></div>`).join('')}</div></div>`;
}
function rawHeaderPanel(){
 const h=S.headerView;
 if(!h)return '';
 if(h.error)return `<section class="headers-inspector" aria-label="Original message headers"><div class="headers-inspector-title"><h3>Original headers unavailable</h3></div><p>${esc(h.error)}</p><p>SpamGate cannot reconstruct headers for older accepted messages that did not have a saved header snapshot.</p></section>`;
 return `<section class="headers-inspector" aria-label="Original message headers"><div class="headers-inspector-title"><div><h3>Original email headers</h3><p>${esc(h.source)} · ${n(h.bytes)} bytes${h.truncated?' · Truncated at 256 KiB':''}</p></div><div class="headers-inspector-actions"><button type="button" id="copy-headers" class="secondary">Copy headers</button><button type="button" id="download-headers" class="secondary">Save .txt</button></div></div><p>Captured before delivery. These headers may differ from those in the delivered mailbox. Sender-supplied headers are not automatically trustworthy. No message body is stored or displayed here.</p>${headerSummary(h.raw)}<details class="raw-headers" open><summary>Raw header source · preserved order and folding</summary><pre id="header-raw-text" tabindex="0">${esc(h.raw)}</pre></details></section>`;
}
function deliveryEvidencePanel(){
 const d=S.deliveryEvidence;
 if(!d)return '';
 if(d.error)return `<section class="headers-inspector"><h3>Postfix delivery evidence unavailable</h3><p>${esc(d.error)}</p></section>`;
 return `<section class="headers-inspector" aria-label="Postfix delivery evidence"><h3>Postfix delivery evidence · ${esc(d.queue_id||'')}</h3><p>${esc(d.detail||'')}${d.truncated?' Log evidence was truncated.':''}</p>${!d.enabled?'<p>Log inspection is not enabled on this installation.</p>':d.events?.length?`<pre class="raw-headers" tabindex="0" style="white-space:pre-wrap;overflow-wrap:anywhere">${d.events.map(e=>esc(e.line)).join('\n')}</pre>`:'<p>No matching entries in the available log window. This is not proof that the message was delivered or lost.</p>'}</section>`;
}
function investigationPanel(){
 const v=S.investigation;
 if(!v)return '';
 if(v.error)return '<section class="headers-inspector"><h3>Investigation unavailable</h3><p>'+esc(v.error)+'</p></section>';
 const steps=(v.steps||[]).map(st=>'<li><strong>'+esc(st.name)+' · '+esc(st.state)+'</strong><p>'+esc(st.detail)+'</p>'+(st.at?'<small>'+esc(fmtDate(st.at))+'</small>':'')+'</li>').join('');
 const events=(v.postfix_log_events||[]).map(e=>esc(e.line)).join('\n');
 const canRelease=v.postfix_release_enabled===true && v.postfix_hold_present===true && S.inspect?.mta_action==='postfix_hold_requested' && !['release_attempted','release_submitted'].includes(S.inspect?.mta_action_state||'');
 return '<section class="headers-inspector" aria-label="Message investigation"><h3>Mail-flow evidence · '+esc(v.scan_id)+'</h3><p>Queue: '+esc(v.postfix_queue_id||'Not recorded')+' · Connector: '+esc(v.connector||'Unknown')+'</p><ol class="investigation-timeline">'+steps+'</ol><h4>Postfix log evidence</h4>'+(events?'<pre class="raw-headers" tabindex="0">'+events+'</pre>':'<p>No matching Postfix events currently available.</p>')+(v.postfix_log_truncated?'<p>Log window truncated; older evidence may be missing.</p>':'')+'<h4>Next checks</h4><ul>'+(v.actions||[]).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><h4>Verification limits</h4><ul>'+(v.limitations||[]).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>'+(canRelease?'<button class="secondary" type="button" id="postfix-release-message">Release this verified Postfix hold</button><small>Postfix release is not delivery. Explicit confirmation and a reason are required.</small>':'<p>Postfix release is unavailable unless local hold actions are enabled and the exact queue entry is verified.</p>')+'</section>';
}
function detailView(m){
 const admin=S.me?.role==='admin';
 const flagged=['tag','quarantine','reject','soft_reject'].includes(m.action);
 const risks=(m.findings||[]).filter(f=>Number(f.score)>0 && !['HUMAN_REVIEW','ADMIN_OVERRIDE'].includes(f.symbol));
 const top=risks.slice(0,5);
 const reasons=top.length?top.map(f=>`<li><div><strong>${esc(friendlyReason(f))}</strong><small>${esc(f.detail||f.source)} · ${Number(f.score).toFixed(1)} points</small></div></li>`).join(''):'<li>No positive spam signals were recorded for this email.</li>';
 const held=m.delivery==='quarantined';
 const milterStatus=m.connector==='milter'?(m.mta_action_note||'This scan predates MTA-action recording. A scored verdict alone does not prove Postfix held or delivered the message.'):' ';
 const state=m.review_status==='not_spam'?'You marked this a false positive.':m.review_status==='spam'?'You marked this as missed spam.':m.review_status==='correct'?'You confirmed the decision.':'Read the reasons, then tell SpamGate whether it was right.';
 const stateNote=m.review_status?'The original verdict and delivery record are unchanged.':'';
 return `<div class="detail-layer" id="detail-layer"><section class="detail-panel readable-detail" role="dialog" aria-modal="true" aria-labelledby="inspect-title" tabindex="-1"><button class="icon-button detail-close" id="close-detail" aria-label="Close message review">×</button><span class="eyebrow">REVIEW AN EMAIL</span><h2 id="inspect-title">${esc(m.subject||'No subject')}</h2><p class="detail-from">From <b>${esc(m.sender||'Unknown sender')}</b> · ${esc(fmtDate(m.timestamp))}</p><div class="header-entrypoint">${admin?'<button type="button" class="secondary" id="open-headers">View raw email headers</button><button type="button" class="secondary" id="load-investigation">Investigate mail flow</button>':''}<span>Full inbound headers · no message body</span></div>${admin?rawHeaderPanel():''}${admin?deliveryEvidencePanel():''}${admin?investigationPanel():''}<div class="verdict-callout"><div>${action(m.action)}<h3>${flagged?'SpamGate flagged this email':'SpamGate allowed this email'}</h3><p>${esc(state)} ${esc(stateNote)}</p></div><strong>${Number(m.score||0).toFixed(1)}<small>spam score</small></strong></div><h3 class="reasons-title">${flagged?'Why was it flagged?':'Why was it allowed?'}</h3><p class="review-explain">${flagged?'SpamGate detected these signals:':'The final score stayed below the flagging threshold, or an explicit rule allowed it.'}</p><ol class="human-reasons">${reasons}</ol>${admin?`<div class="decision-actions"><h3>Did SpamGate get it right?</h3><p>One click records your feedback. Nothing is silently delivered, blocked or deleted.</p><div class="decision-buttons"><button class="secondary" id="review-correct" ${m.review_status&&m.review_status!=='correct'?'disabled':''}>✓ Yes, correct</button><button class="primary" id="${flagged?'review-notspam':'review-spam'}" ${m.review_status&&m.review_status!==(flagged?'not_spam':'spam')?'disabled':''}>${flagged?'✕ No, this is legitimate':'✕ No, this was spam'}</button></div><div class="trust-option"><label><input id="adjust-sender" type="checkbox"> ${flagged?'Reduce the spam score for future mail from this address':'Increase the spam score for future mail from this address'}</label><p>This creates a visible, reversible scoring rule for the exact sender address—not an automatic allow or block. Sender addresses can be forged. No training sample is created without an original email.</p></div>${m.review_status?`<p class="review-explain"><b>Reviewed by ${esc(m.reviewed_by||'administrator')}</b> · ${esc(fmtDate(m.reviewed_at))}</p>`:''}${m.connector==='milter'?`<details class="task-message-transport"><summary>What did SpamGate ask Postfix to do?</summary><div class="task-message-transport-body"><h3>Mail server action</h3><p><b>SpamGate decision:</b> ${esc(m.action)} · <b>Postfix action requested:</b> ${esc(m.mta_action||'Not recorded by this version')}</p>${m.mta_queue_id?`<p><b>Postfix queue ID supplied to Milter:</b> ${esc(m.mta_queue_id)} (not a confirmed hold)</p><button type="button" class="secondary" id="load-delivery-evidence">View Postfix log evidence</button>`:""}<p>${esc(milterStatus)}</p><p>For a held message, check the Postfix hold queue. This does not move a message into your Junk folder. Only Postfix logs and mailbox delivery records can establish the final outcome.</p></div></details>`:''}<details class="task-scoring-fold"><summary><span>How was the score calculated?</span><small>Every matched check, point change and detector source</small></summary>${scoreExplain(m)}</details><details class="technical-details"><summary>See full scoring details and message information</summary><dl class="info-grid"><dt>To</dt><dd>${esc((m.recipients||[]).join(', ')||'Unknown')}</dd><dt>How scanned</dt><dd>${esc(({milter:'Postfix Milter',smtp:'SMTP relay',http:'Manual or API scan',rspamd:'Rspamd-compatible API'})[m.connector]||m.connector||'Unknown')}</dd><dt>Delivery</dt><dd>${esc(m.delivery||(m.connector==='milter'?'Postfix controls final delivery; verify in your mail log':'Verdict recorded; no delivery receipt in SpamGate'))}</dd><dt>Sending IP</dt><dd>${esc(m.client_ip||'Unknown')}</dd><dt>Message ID</dt><dd>${esc(m.message_id||m.id)}</dd></dl>${(m.findings||[]).map(f=>`<div class="finding"><span class="weight">${Number(f.score).toFixed(1)}</span><span class="symbol">${esc(f.symbol)}</span><span class="detail">${esc(f.detail)}</span></div>`).join('')}</details>${held?`<div class="held-action"><b>This original email is still held.</b><p>Reviewing it does not send it. Release is a separate action requiring an outbound relay.</p><button class="secondary" id="release">Release held message</button><button class="danger" id="discard-quarantine">Delete held message</button></div>`:''}</div>`:''}</section></div>`;
}

function signals(){
 const admin=S.me.role==='admin';
 const groups=new Map();
 for(const d of S.signals||[]){const key=String(d.source||'Other checks').replaceAll('_',' ');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(d)}
 return `${taskIntro('SCORING CONTROLS','Which checks affect the score?','See the built-in checks and how many points each one adds or removes. Expand a category to adjust individual checks for future mail.',[['Mail analysis','threats',false]])}
 <div class="task-notice"><strong>Adjust with care.</strong><p>Changing a score does not change what the detector examines. Changes only affect future messages; previous decisions remain in your history.</p></div>
 <div class="task-signal-groups">${[...groups.entries()].map(([group,items])=>`<details class="task-settings-fold"><summary><span><b>${esc(group)}</b><small>${n(items.length)} checks · ${n(items.filter(x=>x.enabled).length)} currently enabled</small></span></summary><div><div class="task-signal-list">${items.map(d=>`<div class="task-signal"><div><b>${esc(d.description||d.symbol)}</b><small>${esc(d.symbol)} · Default: ${Number(d.default_score||0).toFixed(1)} points</small></div><form class="signal-form" data-symbol="${esc(d.symbol)}"><label>Points<input name="score" type="number" step="0.1" min="-100" max="100" required value="${Number(d.score)}" ${admin?'':'disabled'}></label><label class="task-signal-enabled"><input name="enabled" type="checkbox" ${d.enabled?'checked':''} ${admin?'':'disabled'}> On</label>${admin?'<button type="submit" class="secondary">Save</button>':''}</form></div>`).join('')}</div></div></details>`).join('')||empty('No built-in checks available','Detector definitions could not be loaded from SpamGate.')}</div>`;
}

function learning(){
 const b=S.bayesStats||{},f=S.fuzzyStats||{},nn=S.neuralStats||{};
 return `${taskIntro('LOCAL LEARNING','Teach SpamGate what good and bad mail looks like','Use confirmed examples to improve locally trained detectors. SpamGate does not share these samples with a public fuzzy network.',[['Review messages','investigate',false]])}
 <div class="task-stats">${taskStat('Spam examples',n(b.spam),'Bayesian training samples','learning')}${taskStat('Legitimate examples',n(b.ham),'Bayesian training samples','learning')}${taskStat('Fuzzy patterns',n((f.spam||0)+(f.ham||0)),'Local fingerprints','learning')}${taskStat('Model readiness',b.ready?'Trained':'Learning','Requires enough balanced samples','learning')}</div>
 <div class="task-notice"><strong>Only train on messages you have verified.</strong><p>Wrong labels make filtering worse. Training is additive; the Bayes model does not yet offer per-sample unlearning. Do not upload private mail without permission.</p></div>
 <div class="task-two-columns task-rule-layout"><section class="task-surface task-side-panel"><span class="task-kicker">STEP 1</span><h2>Train from a real message</h2><p>Provide a complete .eml file and label it as legitimate or spam. At least 10 examples of each type are needed for Bayesian scoring.</p><form id="bayes-form"><div class="field"><label for="training-eml">Choose message (.eml)</label><input id="training-eml" name="eml" type="file" accept=".eml,message/rfc822" required></div><div class="field"><label for="training-label">What was this email?</label><select id="training-label" name="label"><option value="spam">Definitely spam</option><option value="ham">Legitimate email</option></select></div><button class="primary" type="submit">Train SpamGate</button></form></section>
 <section class="task-surface task-side-panel"><span class="task-kicker">STEP 2 / OPTIONAL</span><h2>Teach near-duplicate patterns</h2><p>Save a local fuzzy fingerprint of a confirmed message. This is not a subscription to an external fuzzy feed, and the original text is not stored.</p><form id="fuzzy-form"><div class="field"><label for="fuzzy-eml">Reference message (.eml)</label><input id="fuzzy-eml" name="eml" type="file" accept=".eml,message/rfc822" required></div><div class="field"><label for="fuzzy-label">What was this email?</label><select id="fuzzy-label" name="label"><option value="spam">Definitely spam</option><option value="ham">Legitimate email</option></select></div><button class="primary" type="submit">Save local fingerprint</button></form></section></div>
 <details class="task-settings-fold"><summary><span><b>Manage trained fuzzy patterns</b><small>${n(S.fuzzyEntries?.length)} stored examples; fingerprints expire automatically</small></span></summary><div class="task-rule-list">${S.fuzzyEntries?.length?S.fuzzyEntries.map(e=>`<div class="task-rule"><div><b>${esc(e.label)} · ${esc(e.id.slice(0,12))}</b><small>${n(e.shingles)} shingles · ${esc(fmtDate(e.created))}</small></div><button class="danger" data-fuzzy-delete="${esc(e.id)}">Delete</button></div>`).join(''):empty('No saved fuzzy examples','You have not trained any fingerprint samples yet.')}</div></details>
 <details class="task-settings-fold"><summary><span><b>Experimental neural learning</b><small>${n(nn.spam)} spam / ${n(nn.ham)} legitimate examples · ${nn.ready?'Scoring':'Collecting data'}</small></span></summary><div><p>This CPU-only classifier learns combinations of scoring symbols from confirmed historical messages. It needs 10 examples of each class before affecting scores. It is not compatible with Rspamd neural models.</p><a href="/messages" data-route="history">Open history and review examples →</a></div></details>`;
}

function deliveryQueue(){
 const q=S.deliveryQueue;
 const title=taskIntro('SMTP RELAY DELIVERY','Delivery problems','Only messages handled by the optional SpamGate SMTP relay appear here. Postfix-held mail is inspected separately.',[['Held messages','quarantine',false]]);
 if(!q||q.enabled===false)return title+`<div class="task-notice"><strong>SpamGate's SMTP relay queue is not enabled.</strong><p>If you are using Postfix Milter mode, ordinary mail delivery is managed by Postfix. You will not see its queue here.</p></div><section class="task-surface task-side-panel"><h2>Looking for a message?</h2><p>Use All messages for scan decisions, or Held messages for the read-only Postfix hold inventory.</p><a href="/messages" data-route="history">Find the message →</a></section>`;
 const jobs=q.jobs||[];
 return title+`<div class="task-stats">${taskStat('Waiting to retry',n(q.queued),'Not yet delivered','delivery')}${taskStat('Sending now',n(q.delivering),'Delivery attempts underway','delivery')}${taskStat('Failed permanently',n(q.dead),'Needs administrator review','delivery')}${taskStat('Originals stored',n(q.total),'On disk in SpamGate','delivery')}</div><div class="task-notice"><strong>Retries can duplicate mail.</strong><p>The SMTP queue provides at-least-once delivery. A crash after the recipient server accepts a message can cause it to be retried. Check the mail logs before retrying.</p></div>
 <section class="task-surface task-side-panel"><h2>Pending and failed deliveries</h2>${jobs.length?`<div class="task-rule-list">${jobs.map(x=>`<div class="task-rule"><div><b>${esc(x.subject||'No subject')}</b><small>${esc(x.sender)} → ${esc((x.recipients||[]).join(', '))}</small><span>${esc(x.state)} · ${n(x.attempts)} attempt(s) · Next: ${esc(fmtDate(x.next_attempt))}</span>${x.last_error?`<small>${esc(x.last_error)}</small>`:''}</div><div class="task-rule-actions"><button class="secondary" data-queue-retry="${esc(x.id)}" ${x.state==='delivering'?'disabled':''}>Retry</button><button class="danger" data-queue-discard="${esc(x.id)}" ${['delivering','delivered'].includes(x.state)?'disabled':''}>Discard</button></div></div>`).join('')}</div>`:empty('No delayed deliveries','There are no queued or failed originals waiting for action.')}</section>`;
}

async function runHistorySearch(offset=0){
 const params=new URLSearchParams({q:S.search,action:S.filterAction,offset:String(offset),limit:'50'});
 S.historyResults=await api('/api/v1/history/search?'+params.toString());S.historyOffset=offset;render();
}
const serverChoices=[
 ['testing','Just testing','Try standalone before connecting a mail server'],
 ['postfix','Postfix','Regular Linux mail server'],
 ['ispconfig','ISPConfig','Postfix managed by ISPConfig'],
 ['cpanel','cPanel / WHM','Exim managed by your hosting panel'],
 ['exim','Exim','Standalone Exim mail server'],
 ['custom','Other mail server','Custom integration or remote service']
];
function wizardInstructions(){
 const s=S.wizardServer;const mode=S.wizardMode;
 if(mode==='test'||s==='testing')return {title:'Test SpamGate before changing anything',steps:['Keep your existing email service unchanged.','Go to Test an email and select a saved .eml message.','Open the result and review its reasons, then correct it if needed.'],note:'A test scan cannot intercept, quarantine, or deliver incoming mail. The application can run independently from /opt/spamgate.'};
 if(s==='cpanel')return {title:'cPanel needs an Exim adapter',steps:['SpamGate runs on the same Linux server, separate from WHM.','The Exim adapter is not yet fully supported. Do not change WHM mail routing to use SpamGate.','Use standalone testing while the integration is developed and verified.'],note:'Never edit a cPanel-generated Exim configuration directly. SpamGate is not protecting this server yet.'};
 if(s==='exim')return {title:'Connect a standalone Exim server',steps:['Use a private HTTP scanning endpoint with a verified Exim ACL adapter.','Exim must enforce SpamGate’s returned decision and handle errors safely.','Until that adapter is qualified, run standalone tests only.'],note:'There is no certified turnkey Exim adapter in this build.'};
 if(s==='custom')return {title:'Connect your mail application',steps:['Use the authenticated raw-email scanning API or a supported Milter/SMTP connector.','Your mail application must apply the verdict and retain original mail if quarantine is needed.','Run a controlled delivery test before enabling real traffic.'],note:'API scanning alone does not intercept live mail; private networking and access controls are required.'};
 return {title:s==='ispconfig'?'Connect ISPConfig’s Postfix safely':'Connect your Postfix server',steps:['On this machine, check your detected server under Mail server.','Enable the SpamGate Milter listener on 127.0.0.1:38472, with SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32, then restart SpamGate.','Review existing smtpd_milters in postconf -n. Append inet:127.0.0.1:38472 using your Postfix/panel-approved method; validate and reload Postfix. Do not remove existing Milters.'],note:s==='ispconfig'?'ISPConfig may overwrite direct Postfix changes. Do not automatically attach or edit panel-managed settings.':'A Milter listener must be enabled and Postfix configured separately. Setup choices do not modify Postfix.'};
}
// Local Postfix configuration is explicit and copyable; never pretend an
// HTTP Rspamd scanner port (38471) is a Milter socket (38472).
function milterConfigWizard(){
 const h=S.hostReport;
 const local=S.wizardMode==='local';
 const isPostfix=['postfix','ispconfig'].includes(S.wizardServer);
 if(!isPostfix||S.wizardMode==='test')return '';
 if(!local)return `<section class="wizard-config"><h3>Remote filtering requires different addresses</h3><p>Do not paste localhost settings. The Milter must bind to a private interface on the SpamGate host and trust only the Postfix server's source IP. Set Postfix to the SpamGate host's real private IP, not <code>127.0.0.1</code>. Only use this on a firewalled private network. Remote Milter transport is not encrypted by SpamGate.</p></section>`;
 const existing=h?.mail_server==='postfix'?h.existing_milters:null;
 const other=h?.mail_server==='postfix'?h.non_smtpd_milters:null;
 const repaired=value=>{
   if(value===null||value===undefined)return 'inet:127.0.0.1:38472';
   const components=value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean);
   const kept=components.filter(x=>!['inet:127.0.0.1:38471','inet:localhost:38471','inet:127.0.0.1:38472','inet:localhost:38472'].includes(x));
   return [...kept,'inet:127.0.0.1:38472'].join(', ');
 };
 const daemon=`cd /opt/spamgate
SPAMGATE_MILTER_LISTEN=127.0.0.1:38472 \
SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32 \
./spamgate -data /opt/spamgate/data -listen 0.0.0.0:38470`;
 const postfix=`smtpd_milters = ${repaired(existing)}
non_smtpd_milters = ${repaired(other)}
milter_protocol = 6
milter_default_action = tempfail`;
 const verify=`sudo ss -ltnp | grep ':38472'
postconf -n | grep -E '^(smtpd_milters|non_smtpd_milters|milter_protocol|milter_default_action) ='
postconf -P | grep -i milter || true
sudo postfix check
sudo postfix reload`;
 const obs=!!h&&h.mail_server==='postfix';
 const wrong=obs&&((h.existing_milters||'').includes('38471')||(h.non_smtpd_milters||'').includes('38471'));
 const runner=!!S.runtime?.services?.milter?.enabled;
 const reachable=!!h?.milter_ready;
 const report=obs&&!!h.postfix_configured;
 const diagnostic=`<div class="milter-readiness"><p><strong>${runner?'✓':'!'}</strong> SpamGate Milter: ${!runner?'Not enabled. Restart SpamGate with the variables below.':reachable?'TCP listener responds on localhost:38472':'Configured, but local TCP probe did not connect. Check startup logs and firewall.'}</p><p><strong>${report?'✓':'!'}</strong> Postfix: ${!obs?'Settings not available — verify on your mail server':report?'Configured for port 38472':'Not confirmed for port 38472'}</p>${wrong?'<p class="setup-warning"><strong>Incorrect port detected!</strong> Postfix references 38471, which serves HTTP scanning and cannot work as a Milter. Change to 38472.</p>':''}${h?.milter_default_action==='accept'?'<p class="setup-warning">Postfix currently allows mail through if a Milter fails (<code>milter_default_action = accept</code>). After the local Milter is listening and tested, use <code>tempfail</code> to prevent silent bypass. During outages this temporarily delays email.</p>':''}</div>`;
 const block=(name,title,body,detail)=>`<div class="config-step"><h3>${title}</h3><p>${detail}</p><pre class="codeblock selectable-config" id="setup-config-${name}" tabindex="0">${esc(body)}</pre><button type="button" class="secondary" data-copy-setup="${name}">Copy ${title.toLowerCase()}</button></div>`;
 const panelWarning=S.wizardServer==='ispconfig'?'<div class="setup-warning"><strong>ISPConfig-managed mail:</strong> First check how ISPConfig persists Postfix settings on your server. Direct edits to main.cf may be overwritten. This guide does not change panel configuration.</div>':'';
 const conflict=(existing===null||other===null)?'<p class="hint">Existing Milter settings were not readable. The example below assumes no other Milters; preserve and append to existing entries rather than replacing them.</p>':'<p class="hint">Generated from the currently observed Postfix Milter entries. Review other installed filters before applying. Recheck after any hosting-panel update.</p>';
 return `<section class="wizard-config"><h3>Copy these exact settings into your local setup</h3><p>SpamGate uses <strong>38472 for Milter</strong>. Port 38471 is a different HTTP service. Make sure both sides use the same Milter port. The <strong>Web UI listens on 0.0.0.0:38470</strong>; Milter stays on localhost. Restrict access to the Web UI with your firewall or HTTPS reverse proxy.</p>${diagnostic}${block('daemon','Start SpamGate',daemon,'Stop the current standalone SpamGate process first, then run this in /opt/spamgate. Keep the process running while testing.')}${panelWarning}${conflict}${block('postfix','Postfix main.cf',postfix,'Add these values to /etc/postfix/main.cf, using your hosting panel’s supported method where applicable. Preserve any other Milters. Do not apply the tempfail policy until the SpamGate listener is ready.')}${block('verify','Verify and reload',verify,'Run these commands on the Postfix server after saving the configuration. A successful TCP connection alone is not a mail scan.')}${(h?.notes||[]).filter(x=>/WRONG PORT|bypass|overrides|Milter|Postfix/.test(x)).map(x=>`<p class="hint">${esc(x)}</p>`).join('')}<p><strong>Final step:</strong> Select “Start monitoring incoming mail”, send the unique subject through Postfix, and confirm the message is recorded and delivered. Until then SpamGate will not mark the integration running.</p></section>`;
}
function milterSnippet(which){
 if(!['daemon','postfix','verify'].includes(which))return '';
 const element=document.getElementById('setup-config-'+which);
 return element?.textContent||'';
}
function wizard(){
 const step=S.wizardStep,ready=S.readiness||{};
 const recentConnector=S.messages.filter(m=>['milter','smtp','rspamd'].includes(m.connector)).slice(0,5);
 const choices=serverChoices.map(([id,label,detail])=>`<label class="choice-card ${S.wizardServer===id?'chosen':''}"><input type="radio" name="server-choice" value="${id}" ${S.wizardServer===id?'checked':''}><span><strong>${esc(label)}</strong><small>${esc(detail)}</small></span></label>`).join('');
 const workflow=wizardInstructions();
 const live=S.wizardMode!=='test'&&S.wizardServer!=='testing';
 const state=ready.state||'not_configured';
 const supported=['postfix','ispconfig','custom'].includes(S.wizardServer);
 const watching=state==='watching';
 const passed=state==='test_detected'||state==='running';
 const stepLabel={'not_configured':'Save your choices first','listener_missing':'SpamGate Milter is not running','postfix_not_connected':'Postfix is not sending mail to SpamGate','test_not_delivered':'The test email was stopped before delivery','unsupported_connector':'Connector not available yet','ready_to_test':'Ready to monitor incoming mail','watching':'Watching for your test message','test_detected':'Test message received and scanned','running':'Connection marked as running','standalone_test':'Standalone testing — no live mail'}[state]||'Waiting for setup';
 const checkPostfix=['postfix','ispconfig'].includes(S.wizardServer)&&S.wizardMode==='local';
 const postfix=ready.postfix_connection||'unknown';
 const connectionNotice=checkPostfix?`<div class="milter-readiness"><p><strong>${S.runtime?.services?.milter?.enabled?'✓':'!'}</strong> SpamGate listener: ${S.runtime?.services?.milter?.enabled?'Enabled on port 38472':'Not enabled'}</p><p><strong>${postfix==='connected'?'✓':'!'}</strong> Postfix routing: ${postfix==='connected'?'Both Milter settings point to SpamGate':postfix==='wrong_port'?'Incorrect port detected (38471 is HTTP, not Milter)':postfix==='disconnected'?'Postfix is not connected to SpamGate':'Could not inspect Postfix settings automatically'}</p><p><strong>${passed?'✓':'!'}</strong> Test scan: ${passed?'Matching message scanned':`Not detected${ready.connector_messages_since_test>0?'; '+n(ready.connector_messages_since_test)+' other messages scanned since the test started':''}`}</p></div>`:'';
 const missingPostfix=checkPostfix&&['disconnected','wrong_port'].includes(postfix);
 const connectionHelp=missingPostfix?`<div class="setup-warning"><strong>Action needed:</strong> Postfix is currently delivering without SpamGate. Copy the exact Postfix settings below, apply them through your mail panel if applicable, then run <code>sudo postfix check &amp;&amp; sudo postfix reload</code>. The Milter must already be listening. The wizard will detect the change. <details><summary>Show exact Postfix configuration and verification commands</summary>${milterConfigWizard()}</details></div>`:checkPostfix&&postfix==='unknown'?'<p class="hint">SpamGate cannot read Postfix configuration from this host. Run <code>postconf -n | grep milter</code> on the mail server and check both settings before activation.</p>':'';
 const observedHint=watching&&ready.connector_messages_since_test>0?`<p class="hint">SpamGate has scanned ${n(ready.connector_messages_since_test)} other message(s) since this test began. Please send a NEW message with the exact subject above; delivery alone does not satisfy the test.</p>`:'';
 const blockedHint=state==='test_not_delivered'?`<p class="setup-warning">SpamGate saw the test subject but gave it a ${esc(ready.blocked_test?.action||'blocking')} verdict. Inspect Message history; this test cannot demonstrate successful delivery. Start a fresh test after correcting the cause.</p>`:'';
 const recentSamples=live?`<div class="wizard-traffic"><h3>Messages seen by SpamGate</h3><p>This is real scanner activity. Seeing mail here does not mean the unique verification test passed or the recipient got the email.</p>${recentConnector.length?recentConnector.map(m=>`<div class="wizard-traffic-item"><span>${esc(fmtDate(m.timestamp))}</span><strong>${esc(m.subject||'(No subject)')}</strong>${action(m.action)}<button type="button" data-inspect="${esc(m.id)}">Explain score</button></div>`).join(''):'<p>No incoming connector messages in the most recently loaded history.</p>'}</div>`:'';
 const nextAction=step===3?'Save choices and verify →':'Continue →';
 const body=[
 `<h2>What are you connecting SpamGate to?</h2><p>Choose your mail server. You can test standalone without touching the existing mail server.</p><fieldset class="choice-grid"><legend class="sr-only">Mail server</legend>${choices}</fieldset>`,
 `<h2>How would you like to use SpamGate?</h2><p>Only your selected test messages should be used until you've verified the connection.</p><fieldset class="choice-grid"><legend class="sr-only">Deployment method</legend>${[['test','Standalone testing','Test saved emails without connecting to live mail'],['local','On this mail server','Filter through a local mail-server connector'],['remote','On another server','Use a trusted private connection to the mail server']].map(([id,label,detail])=>`<label class="choice-card ${S.wizardMode===id?'chosen':''}"><input type="radio" name="mode-choice" value="${id}" ${S.wizardMode===id?'checked':''}><span><strong>${label}</strong><small>${detail}</small></span></label>`).join('')}</fieldset>`,
 `<h2>How carefully should SpamGate filter?</h2><p>Start with Balanced. You can change these thresholds later.</p><fieldset class="choice-grid"><legend class="sr-only">Protection level</legend>${[['careful','More careful','Fewer false positives'],['balanced','Balanced','Recommended'],['strict','More strict','Flags more mail']].map(([id,label,detail])=>`<label class="choice-card ${S.wizardPolicy===id?'chosen':''}"><input type="radio" name="policy-choice" value="${id}" ${S.wizardPolicy===id?'checked':''}><span><strong>${label}</strong><small>${detail}</small></span></label>`).join('')}</fieldset>`,
 `<h2>${esc(workflow.title)}</h2><p>Follow these steps on the mail server. SpamGate will not change Postfix, Exim, or your hosting panel automatically.</p><ol class="setup-instructions">${workflow.steps.map(x=>`<li>${esc(x)}</li>`).join('')}</ol><div class="setup-warning">${esc(workflow.note)}</div>${milterConfigWizard()}<p><b>Next:</b> Save these choices and check for a real incoming test message. If this is just a standalone test, no connection is required.</p>`,
 `<h2>${live?'Verify incoming mail before activation':'Start standalone testing'}</h2><p>${live?'SpamGate must see a new message arriving through the selected connector. Older mail and manual .eml uploads do not count.':'Standalone testing is not live mail protection. You can use the message tester without connecting an MTA.'}</p>${live&&state==='listener_missing'?milterConfigWizard():''}<div class="readiness-panel" aria-live="polite"><h3>${esc(stepLabel)}</h3>${live?`<p><strong>Expected connector:</strong> ${esc(ready.expected_connector||'Not selected')}</p>${connectionNotice}${connectionHelp}${blockedHint}${recentSamples}<p>${ready.listeners_configured?.length?'SpamGate listeners: '+esc(ready.listeners_configured.join(', ')):'The mail connector listener is not configured or running.'}</p>${watching||passed||state==='postfix_not_connected'||state==='test_not_delivered'?`<div class="test-subject"><span>Send a brand-new test email through your actual mail server, with this exact subject:</span><code>${esc(ready.probe_subject||'')}</code><button type="button" id="wizard-copy-subject" class="secondary">Copy subject</button></div><small>${watching||missingPostfix?'Monitoring updates automatically every 4 seconds. The challenge expires after 20 minutes.': 'SpamGate recorded a test message after monitoring began.'}</small>${observedHint}`:''}${passed?`<p class="test-success"><strong>Received:</strong> ${esc(ready.observed_message?.subject||'Verified test message')} — ${esc(ready.observed_message?.action||'scanned')} via ${esc(ready.observed_message?.connector||'mail connector')}</p><p>Check that the message arrived in the receiving mailbox, then confirm that below. A scan result alone cannot prove delivery.</p>`:''}${!passed&&state!=='running'?`<button id="wizard-arm" type="button" class="primary" ${!supported||state==='listener_missing'||state==='unsupported_connector'||missingPostfix?'disabled':''}>${watching?'Start a new 20-minute test':'Start monitoring incoming mail'}</button>`:''}${!supported?'<p class="setup-warning">This connector is not implemented for live activation. Choose Standalone testing until an adapter is verified.</p>':''}${passed&&!ready.instance_running?`<label class="verify-delivery"><input type="checkbox" id="wizard-delivered"> I checked the destination mailbox and confirmed that this test email was delivered.</label><button type="button" class="primary" id="wizard-activate" disabled>Mark this connection as running</button>`:''}${ready.instance_running?'<p class="test-success">This instance has been marked running after a verified connector test and your delivery confirmation.</p>':''}`:'<p>SpamGate will remain in standalone test mode. No active mail connection will be claimed.</p>'}<div class="setup-check-actions"><button type="button" id="wizard-check" class="secondary">Check connection now</button></div></div>`
 ][step];
 const button=step===4?(live?(ready.instance_running?'<button type="button" class="primary" id="wizard-complete">Open SpamGate</button>':'<button type="button" class="primary" disabled>Waiting for verification</button>'):'<button type="button" class="primary" id="wizard-complete">Open standalone tester</button>'):`<button type="button" class="primary" id="wizard-next">${nextAction}</button>`;
 return `<div class="wizard-outer"><div class="wizard-top"><span class="eyebrow">WELCOME TO SPAMGATE</span><h1>Make sure your email is protected.</h1><p>Choose your setup, connect your mail server, and verify a real test before activation.</p></div><div class="wizard-progress" aria-label="Setup progress">${['Mail server','Location','Filtering','Connect','Verify & activate'].map((x,i)=>`<span class="${i===step?'current':i<step?'done':''}"><b>${i+1}</b>${x}</span>`).join('')}</div><div class="wizard-card">${body}<div class="wizard-actions"><button type="button" class="secondary" id="wizard-back" ${step===0?'disabled':''}>Back</button>${button}</div></div></div>`;
}
function render(){const app=$('#app');if(!S.authenticated){app.innerHTML=authLayout();return}const views={overview:dashboard,investigate,quarantine,threats,scanlab,categories:spamCategoryLab,history:messageHistory,delivery:deliveryQueue,rules,signals,learning,lists,users,tokens,settings:settingsHome,updates:updatesPage,policy:settings,connect,docs,diagnostics:diagSummary,welcome:wizard};app.innerHTML=layout((views[S.section]||dashboard)());document.title=`${(navigation.find(x=>x[0]===S.section)||navigation[0])[1]} | SpamGate` }
window.addEventListener('popstate',()=>{const requested=sectionFromLocation();S.section=permitted(requested)?requested:'overview';S.inspect=null;render()});
document.addEventListener('click',async event=>{const el=event.target.closest('button,[data-section],[data-route]');if(!el)return;const id=el.id;try{
  if(el.dataset.route){event.preventDefault();routeTo(el.dataset.route);return}if(id==='retry'){start();return}if(id==='nav-toggle'){S.menu=!S.menu;render();return}if(id==='diagnostics-recheck'){await loadDiagnostics();return}if(el.dataset.section){routeTo(el.dataset.section);return}
  if(id==='wizard-next'){
    if(S.wizardStep===3){const result=await api('/api/v1/onboarding',{method:'PUT',json:{completed:true,server:S.wizardServer,mode:S.wizardMode,policy:S.wizardPolicy}});S.config.onboarding=result.onboarding;S.readiness=await api('/api/v1/setup/readiness')}
    S.wizardStep=Math.min(4,S.wizardStep+1);render();return
  }
  if(id==='wizard-back'){S.wizardStep=Math.max(0,S.wizardStep-1);render();return}
  if(id==='wizard-check'){try{[S.readiness,S.hostReport,S.diagnostics]=await Promise.all([api('/api/v1/setup/readiness'),api('/api/v1/host'),api('/api/v1/integrations/diagnostics')])}catch(e){S.diagnostics={message:e.message}}render();return}
  if(id==='wizard-arm'){S.readiness=await api('/api/v1/setup/monitor',{method:'POST',json:{}});render();alertUser('Watching for a fresh test email from your mail server.');return}
  if(el.dataset.copySetup){const content=milterSnippet(el.dataset.copySetup);if(!content)return;try{await navigator.clipboard.writeText(content);alertUser('Configuration copied. Review existing Milter settings before saving.')}catch{alertUser('Select and copy the code block above.')}return}
  if(id==='wizard-copy-subject'){if(S.readiness?.probe_subject){try{await navigator.clipboard.writeText(S.readiness.probe_subject);alertUser('Test subject copied')}catch{alertUser('Select and copy the test subject displayed above.')}}return}
  if(id==='wizard-activate'){if(!$('#wizard-delivered')?.checked)return;await api('/api/v1/setup/activate',{method:'POST',json:{delivery_confirmed:true}});S.readiness=await api('/api/v1/setup/readiness');S.config.onboarding.activated=true;render();alertUser('Connection marked running; SpamGate observed the test message.');return}
  if(id==='wizard-complete'){if(S.wizardMode!=='test'&&!S.readiness?.instance_running)throw Error('Verify a real test email first.');routeTo(S.wizardMode==='test'?'scanlab':'overview');return}
  if(['review-correct','review-notspam','review-spam'].includes(id)){if(!S.inspect)return;const decision=id==='review-correct'?'correct':id==='review-spam'?'spam':'not_spam';const adjust=decision!=='correct'&&$('#adjust-sender')?.checked===true;if(adjust&&!confirm('Add a reversible score adjustment for this exact sender address? This does not authenticate the sender or guarantee a future verdict.'))return;const result=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/review',{method:'POST',json:{decision,adjust_sender:adjust}});S.inspect=result.message;await refresh();render();alertUser(adjust?'Review saved with a reversible sender-scoring rule':decision==='correct'?'Original verdict confirmed':decision==='spam'?'Missed spam recorded':'False positive recorded. Existing delivery unchanged.');return}
  if(id==='load-investigation'){
    if(!S.inspect)return;
    try{S.investigation=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/investigation')}
    catch(err){S.investigation={error:err.message||'Investigation unavailable'}}
    render();return
  }
  if(id==='postfix-release-message'){
    if(!S.inspect||!S.investigation?.postfix_queue_id)return;
    const queue=S.investigation.postfix_queue_id;
    const reason=prompt('Reason for releasing this Postfix-held message (minimum 12 characters):');
    if(!reason||reason.trim().length<12)return;
    const exact='release Postfix hold '+queue;
    if(prompt('Type this exact confirmation:\n'+exact)!==exact)return;
    const result=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/postfix-release',{method:'POST',json:{queue_id:queue,confirm:exact,reason:reason.trim()}});
    S.inspect=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id));
    S.investigation=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/investigation');
    render();alertUser(result.detail||'Postfix hold release submitted; delivery remains unverified');return
  }
  if(id==='load-delivery-evidence'){
    if(!S.inspect)return;
    try{S.deliveryEvidence=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/delivery-evidence')}catch(err){S.deliveryEvidence={error:err.message||'Log evidence unavailable'}}
    render();return
  }
  if(id==='open-headers'){
    if(!S.inspect)return;
    try{S.headerView=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/headers')}
    catch(err){S.headerView={error:err.message||'No retained headers'}}
    render();$('#header-raw-text')?.focus();return
  }
  if(id==='copy-headers'){
    if(S.headerView?.raw){await navigator.clipboard.writeText(S.headerView.raw);alertUser('Original headers copied')}return
  }
  if(id==='download-headers'){
    if(!S.headerView?.raw || !S.inspect)return;
    const blob=new Blob([S.headerView.raw+'\r\n'],{type:'text/plain;charset=utf-8'});
    const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='spamgate-headers-'+S.inspect.id+'.txt';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);return
  }
  if(id==='reload'){await refresh();alertUser('Message history refreshed');return}
  if(id==='history-audit'){await loadHistoryAudit();return}
  if(id==='search-full'){await runHistorySearch(0);return}
  if(id==='sgtube-refresh'){await loadCategoryCatalog();return}
  if(el.dataset.sgtubeCopy){const c=S.sgtubeCatalog?.categories?.find(x=>x.id===el.dataset.sgtubeCopy);if(!c)throw Error('Unknown category');await navigator.clipboard.writeText(c.test_marker);alertUser('SGTUBE category test signature copied');return}
  if(el.dataset.sgtubeEml){const c=S.sgtubeCatalog?.categories?.find(x=>x.id===el.dataset.sgtubeEml);if(!c)throw Error('Unknown category');const mailbox=prompt('Enter an approved single test mailbox (do not use real customer mailboxes):');if(!mailbox)return;if(!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(mailbox))throw Error('Enter a valid mailbox address');window.location.href='/api/v1/spam-categories/'+encodeURIComponent(c.id)+'/sample.eml?recipient='+encodeURIComponent(mailbox);return}
  if(el.dataset.sgtubeView){S.sgtubeSelected=el.dataset.sgtubeView;S.sgtubeResult=null;try{S.sgtubeMessages=await api('/api/v1/spam-categories/'+encodeURIComponent(S.sgtubeSelected)+'/messages?limit=100');S.sgtubeError=null}catch(e){S.sgtubeError=e.message;S.sgtubeMessages=null}render();return}
  if(el.dataset.sgtubeSimulate){const id=el.dataset.sgtubeSimulate;try{S.sgtubeResult=await api('/api/v1/spam-categories/'+encodeURIComponent(id)+'/simulate',{method:'POST'});S.sgtubeError=null}catch(e){S.sgtubeError=e.message;S.sgtubeResult=null}render();return}
  if(id==='monitor-refresh'){try{S.monitorData=await api('/api/v1/operations/monitor/sample',{method:'POST'});S.monitorError=null}catch(e){S.monitorError=e.message}render();return}
  if(el.dataset.monitorAck){const reason=prompt('Audit reason for acknowledgement (12–512 characters):');if(!reason)return;await api('/api/v1/operations/monitor/alerts/'+encodeURIComponent(el.dataset.monitorAck)+'/ack',{method:'POST',json:{reason}});S.monitorData=await api('/api/v1/operations/monitor');render();return}
  if(id==='preview-policy'){const form=$('#settings-form');if(!form)throw Error('Policy form unavailable');const field=k=>Number(form.querySelector('[name="'+k+'"]')?.value);try{S.policyPreview=await api('/api/v1/policy/preview',{method:'POST',json:{tag_threshold:field('tag_threshold'),quarantine_threshold:field('quarantine_threshold'),reject_threshold:field('reject_threshold'),limit:500}});S.policyPreviewError=null}catch(e){S.policyPreviewError=e.message;S.policyPreview=null}render();return}
  if(id==='test-integration'){S.diagnostics=await api('/api/v1/integrations/diagnostics');render();return}
  if(id==='check-update'){try{S.updateInfo=await api('/api/v1/update');S.updateError=null}catch(e){S.updateError=e.message}render();return}
  if(id==='install-update'){if(!confirm('Install the verified update now? SpamGate will briefly restart and active mail connections may be interrupted.'))return;try{await api('/api/v1/update/install',{method:'POST',headers:{'X-Confirm-Update':'install verified update'}});alertUser('Update installation started. The page will reconnect after restart.');setTimeout(()=>location.reload(),4500)}catch(e){S.updateError=e.message;render()}return}
  if(id==='stage-update'){if(!confirm('Download and verify the published SpamGate release? This will not restart the mail filter.'))return;try{S.updateInfo=await api('/api/v1/update/stage',{method:'POST'});S.updateError=null}catch(e){S.updateError=e.message}render();return}
  if(id==='inspect-postfix-hold'){S.postfixHold=await api('/api/v1/postfix/hold-queue');render();return}
  if(id==='search-next'){await runHistorySearch(S.historyOffset+50);return}
  if(id==='search-prev'){await runHistorySearch(Math.max(0,S.historyOffset-50));return}
  if(el.dataset.queueRetry){if(!confirm('Attempt delivery of this queued message now? A previous uncertain SMTP result could cause duplicate delivery.'))return;await api('/api/v1/delivery-queue/'+encodeURIComponent(el.dataset.queueRetry)+'/retry',{method:'POST'});await refresh();alertUser('Queued delivery scheduled');return}
  if(el.dataset.queueDiscard){if(!confirm('Permanently discard this queued original? It cannot be recovered or delivered.'))return;await api('/api/v1/delivery-queue/'+encodeURIComponent(el.dataset.queueDiscard),{method:'DELETE',headers:{'X-Confirm-Discard':'discard queued original'}});await refresh();alertUser('Queued original discarded');return}
  if(el.dataset.editRule){S.editRule=(S.config?.rules||[]).find(x=>x.id===el.dataset.editRule)||null;render();$('#rule-form input[name=name]')?.focus();return}
  if(el.dataset.toggleRule){const x=(S.config?.rules||[]).find(x=>x.id===el.dataset.toggleRule);if(!x)return;await api('/api/v1/rules/'+encodeURIComponent(x.id),{method:'PUT',json:{...x,enabled:!x.enabled}});await refresh();alertUser('Rule state updated');return}
  if(id==='cancel-rule-edit'){S.editRule=null;render();return}
  if(id==='preview-quarantine'){if(!S.inspect)return;S.preview=await api('/api/v1/messages/'+encodeURIComponent(S.inspect.id)+'/preview');render();$('#preview-text')?.focus();return}

  if(id==='signout'){await api('/api/v1/logout',{method:'POST'});S.authenticated=false;S.me=null;S.onceToken=null;render();return}
  if(el.dataset.inspect){S.lastInspectedId=el.dataset.inspect;S.preview=null;S.headerView=null;S.deliveryEvidence=null;S.investigation=null;S.inspect=S.messages.find(m=>m.id===el.dataset.inspect)||await api('/api/v1/messages/'+encodeURIComponent(el.dataset.inspect));render();$('#close-detail')?.focus();return}
  if(id==='close-detail'||id==='detail-layer'){S.preview=null;S.headerView=null;S.deliveryEvidence=null;S.investigation=null;S.inspect=null;render();restoreInspectionFocus();return}
  if(id==='copy-token'){await navigator.clipboard.writeText(S.onceToken);alertUser('Key copied');return}
  if(el.dataset.neuralLabel){const label=el.dataset.neuralLabel;if(!S.inspect || !confirm(`Train the neural model with this confirmed ${label} message? This modifies future scoring.`))return;await api('/api/v1/neural/train/'+encodeURIComponent(S.inspect.id)+'?label='+label,{method:'POST'});await refresh();alertUser('Neural classifier trained');return}
  if(el.dataset.removeRecipientPolicy){const mailbox=el.dataset.removeRecipientPolicy;if(!confirm('Remove special scoring thresholds for '+mailbox+'?'))return;const policies=(S.config?.recipient_policies||[]).filter(p=>p.mailbox.toLowerCase()!==mailbox.toLowerCase());await saveRecipientPolicies(policies);await refresh();alertUser('Mailbox policy removed');return}
  if(el.dataset.fuzzyDelete){if(!confirm('Delete this fuzzy fingerprint? Future scans will no longer match it.'))return;await api('/api/v1/fuzzy/entries/'+encodeURIComponent(el.dataset.fuzzyDelete),{method:'DELETE'});await refresh();alertUser('Fingerprint deleted');return}
  if(id==='discard-quarantine'){if(!confirm('Permanently delete this quarantined email? The original cannot be recovered or released afterward.'))return;const discarded=await api('/api/v1/messages/'+S.inspect.id+'/quarantine',{method:'DELETE'});await refresh();S.inspect=discarded;render();alertUser('Quarantined original permanently deleted');return}
  if(id==='release'){if(!confirm('Release this original quarantined message to its recipient(s)? This cannot be undone.'))return;const updated=await api('/api/v1/messages/'+S.inspect.id+'/release',{method:'POST'});await refresh();S.inspect=updated;render();alertUser('Message released to the SMTP relay');return}
  const deletion=[['delete-rule','rules'],['delete-dns','dns-lists'],['delete-user','users'],['delete-token','tokens']].find(([attr])=>el.dataset[attr]!==undefined);
  if(deletion){const [attr,path]=deletion;const target=el.dataset[attr];if(!confirm(`Remove ${target}? This action cannot be undone.`))return;await api('/api/v1/'+path+'/'+encodeURIComponent(target),{method:'DELETE'});await refresh();alertUser('Removed successfully')}
}catch(e){alertUser(e.message,true)}});
document.addEventListener('change',event=>{if(event.target.id==='overview-window'){S.overviewWindow=event.target.value;render();return}if(event.target.name==='server-choice'){S.wizardServer=event.target.value;if(S.wizardServer==='testing')S.wizardMode='test';render();return}if(event.target.name==='mode-choice'){S.wizardMode=event.target.value;render();return}if(event.target.name==='policy-choice'){S.wizardPolicy=event.target.value;render();return}if(event.target.id==='wizard-delivered'){const b=$('#wizard-activate');if(b)b.disabled=!event.target.checked;return}if(event.target.id==='action-filter'){S.filterAction=event.target.value;S.historyResults=null;render()}});
document.addEventListener('input',event=>{if(event.target.id==='search'){const pos=event.target.selectionStart;S.search=event.target.value;S.historyResults=null;render();const el=$('#search');if(el){el.focus();el.setSelectionRange(pos,pos)}}});
function restoreInspectionFocus(){const target=[...document.querySelectorAll('[data-inspect]')].find(el=>el.dataset.inspect===S.lastInspectedId);target?.focus()}
document.addEventListener('keydown',event=>{
  if(!S.inspect)return;
  if(event.key==='Escape'){S.inspect=null;render();restoreInspectionFocus();return}
  if(event.key!=='Tab')return;
  const dialog=document.querySelector('.detail-panel');
  if(!dialog)return;
  const els=[...dialog.querySelectorAll('a[href],button:not(:disabled),input:not(:disabled),textarea:not(:disabled),select:not(:disabled),[tabindex="0"]')].filter(el=>el.getClientRects().length);
  if(!els.length)return;
  const first=els[0],last=els[els.length-1];
  if(event.shiftKey&&(document.activeElement===first||!dialog.contains(document.activeElement))){event.preventDefault();last.focus()}
  else if(!event.shiftKey&&(document.activeElement===last||!dialog.contains(document.activeElement))){event.preventDefault();first.focus()}
});
document.addEventListener('submit',async event=>{const form=event.target;if(!(form instanceof HTMLFormElement))return;event.preventDefault();const id=form.id;const submit=form.querySelector('[type="submit"],button:not([type])');if(submit)submit.disabled=true;
  try{const fields=Object.fromEntries(new FormData(form).entries());let data;
    if(form.classList.contains('signal-form')){
      const symbol=form.dataset.symbol;
      data={score:Number(fields.score),enabled:fields.enabled==='on'};
      await api('/api/v1/signals/'+encodeURIComponent(symbol),{method:'PUT',json:data});
      await refresh();alertUser('Built-in scoring signal updated');return;
    }
    switch(id){
    case 'setup-form':await api('/api/v1/setup',{method:'POST',json:{...fields,site_name:'SpamGate'}});S.setup=false;S.me=await api('/api/v1/me');S.authenticated=true;S.section='welcome';window.history.replaceState({},'','/welcome');await refresh();alertUser('Account created. Complete the setup guide.');break;
    case 'login-form':await api('/api/v1/login',{method:'POST',json:fields});S.me=await api('/api/v1/me');S.authenticated=true;S.section=permitted(sectionFromLocation())?sectionFromLocation():'overview';await refresh();break;
    case 'scan-form':{
      const file=fields.eml;if(!file||file.size>10485760)throw Error('Select an .eml file smaller than 10 MiB');
      const headers={'Content-Type':'message/rfc822','X-SpamGate-Sender':String(fields.sender||''),'X-SpamGate-Recipients':String(fields.recipients||''),'X-SpamGate-Client-IP':String(fields.client_ip||'' )};data=await api('/api/v1/scan',{method:'POST',headers,body:await file.arrayBuffer()});await refresh();S.inspect=data;render();alertUser('Message scanned and recorded');break}
    case 'fuzzy-form':{
      const file=form.elements.eml.files[0];if(!file||file.size>10*1024*1024)throw Error('Choose a .eml file under 10 MiB');
      await api('/api/v1/fuzzy/train?label='+encodeURIComponent(fields.label),{method:'POST',headers:{'Content-Type':'message/rfc822'},body:await file.arrayBuffer()});await refresh();alertUser('Near-duplicate reference fingerprint trained');break}
    case 'bayes-form':{
      const file=fields.eml;if(!file||file.size>10485760)throw Error('Select an .eml file smaller than 10 MiB');
      await api('/api/v1/bayes/train?label='+encodeURIComponent(fields.label),{method:'POST',headers:{'Content-Type':'message/rfc822'},body:await file.arrayBuffer()});await refresh();alertUser('Classifier trained with confirmed '+fields.label+' sample');break}
    case 'rule-form':data={name:fields.name,kind:fields.kind,value:fields.value,score:Number(fields.score||0),action:fields.action,priority:Number(fields.priority||0),expires_at:fields.expires_at?new Date(fields.expires_at).toISOString():undefined,enabled:S.editRule?S.editRule.enabled:true};if(S.editRule){await api('/api/v1/rules/'+encodeURIComponent(S.editRule.id),{method:'PUT',json:data});S.editRule=null}else await api('/api/v1/rules',{method:'POST',json:data});await refresh();alertUser('Rule saved');break;
    case 'dns-form':data={zone:fields.zone,kind:fields.kind||'ip',score:Number(fields.score),enabled:fields.enabled==='on'};await api('/api/v1/dns-lists',{method:'POST',json:data});await refresh();alertUser('DNS blocklist added');break;
    case 'user-form':await api('/api/v1/users',{method:'POST',json:fields});await refresh();alertUser('Mailbox account created');break;
    case 'token-form':data=await api('/api/v1/tokens',{method:'POST',json:fields});S.onceToken=data.token;await refresh();alertUser('API key generated');break;
    case 'recipient-form':{
      const policy={mailbox:String(fields.mailbox).trim().toLowerCase(),tag_threshold:Number(fields.tag_threshold),quarantine_threshold:Number(fields.quarantine_threshold),reject_threshold:Number(fields.reject_threshold)};
      const policies=(S.config?.recipient_policies||[]).filter(p=>p.mailbox.toLowerCase()!==policy.mailbox);
      policies.push(policy);
      await saveRecipientPolicies(policies);
      await refresh();alertUser('Mailbox policy saved');break;
    }
    case 'settings-form':data={site_name:'SpamGate',tag_threshold:Number(fields.tag_threshold),quarantine_threshold:Number(fields.quarantine_threshold),reject_threshold:Number(fields.reject_threshold),retention_days:Number(fields.retention_days),max_history:Number(fields.max_history),dnsbl_enabled:fields.dnsbl_enabled==='on',quarantine_mode:fields.quarantine_mode||'hold',subject_rewrite:fields.subject_rewrite==='on',phishing_links:fields.phishing_links==='on',attachment_inspection:fields.attachment_inspection==='on',external_fuzzy_enabled:fields.external_fuzzy_enabled==='on',threat_feed_enabled:fields.threat_feed_enabled==='on',reviewed_reputation:fields.reviewed_reputation==='on',greylist_enabled:fields.greylist_enabled==='on',greylist_wait_minutes:Number(fields.greylist_wait_minutes)||5,rate_limit_enabled:fields.rate_limit_enabled==='on',rate_limit_per_hour:Number(fields.rate_limit_per_hour)||240};await api('/api/v1/settings',{method:'PUT',json:data});await refresh();alertUser('Policy saved');break;
    case 'override-form':data={action:fields.action,reason:fields.reason};const changed=await api('/api/v1/messages/'+S.inspect.id+'/override',{method:'POST',json:data});await refresh();S.inspect=changed;render();alertUser('Decision reclassified and audited');break;
    }
  }catch(e){alertUser(e.message,true)}finally{if(submit)submit.disabled=false}
});
// Poll only while the verification step is visible. Never count manual HTTP scans.
let wizardPollBusy=false;
setInterval(async()=>{
  if(wizardPollBusy||!S.authenticated||S.me?.role!=='admin'||S.section!=='welcome'||S.wizardStep!==4||document.visibilityState!=='visible')return;
  wizardPollBusy=true;
  try{
    const next=await api('/api/v1/setup/readiness');
    const previous=JSON.stringify(S.readiness);
    const changed=JSON.stringify(next)!==previous;
    S.readiness=next;
    const inspectPostfix=S.wizardMode==='local'&&['postfix','ispconfig'].includes(S.wizardServer);
    if(inspectPostfix&&changed){try{S.hostReport=await api('/api/v1/host')}catch{ /* leave diagnostics marked unknown */ }}
    if(changed)render();
  }catch(e){console.warn('Setup monitor:',e.message)}finally{wizardPollBusy=false}
},4000);
// Lightweight latest-record check avoids refetching configuration and training models on every tick.
// When the newest ID changes, reload full message history and counters. Admin
// review dialogs/forms are never rerendered by background activity.
let liveErrorReported=false;
setInterval(async()=>{
 if(!S.authenticated||S.livePollBusy||document.visibilityState!=='visible')return;
 S.livePollBusy=true;
 try{
  const latest=await api('/api/v1/messages?limit=1');
  const latestId=Array.isArray(latest)&&latest[0]?.id||null;
  const storedId=S.messages[0]?.id||null;
  const changed=latestId!==storedId;
  S.liveLastCheck=new Date();S.liveError=null;liveErrorReported=false;
  const indicator=$('#live-check');if(indicator){indicator.textContent='● Live · checked '+S.liveLastCheck.toLocaleTimeString();indicator.classList.remove('offline')}
  if(changed){
   const [messages,stats]=await Promise.all([api('/api/v1/messages?limit=1000'),api('/api/v1/statistics')]);
   S.messages=Array.isArray(messages)?messages:[];S.stats=stats;
   if(S.section==='history'&&S.historyResults){
    const params=new URLSearchParams({q:S.search,action:S.filterAction,offset:String(S.historyOffset),limit:'50'});
    try{S.historyResults=await api('/api/v1/history/search?'+params)}catch(err){console.warn('Retained-history refresh:',err.message)}
   }
   const typing=document.activeElement?.matches('input,textarea,select,[contenteditable="true"]');
   const reader=!!S.inspect;
   if(reader||typing){const tip=$('#live-check');if(tip)tip.textContent='● New mail captured · refresh to display';}
   else if(['overview','history','investigate','quarantine','threats','welcome'].includes(S.section)){
    const oldScroll=window.scrollY;render();window.scrollTo(0,oldScroll);
    const indicator2=$('#live-check');if(indicator2)indicator2.textContent='● Updated with new mail · '+new Date().toLocaleTimeString();
   }
  }
 }catch(err){S.liveError=err.message;const indicator=$('#live-check');if(indicator){indicator.textContent='⚠ Live updates paused · click Refresh now';indicator.classList.add('offline')}if(!liveErrorReported){console.warn('SpamGate live mail poll:',err.message);liveErrorReported=true}}
 finally{S.livePollBusy=false}
},4000);
start();
