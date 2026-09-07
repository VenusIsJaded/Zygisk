/* SPDX-License-Identifier: Apache-2.0 */
'use strict';
const ICONS = {
  grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  box:'m12 3 9 5-9 5-9-5 9-5Z M3 8v9l9 5 9-5V8 M12 13v9 M7.5 5.5l9 5',
  layers:'m12 3 9 5-9 5-9-5 9-5Z M3 12l9 5 9-5 M3 16l9 5 9-5',
  activity:'M3 12h4l3-8 4 16 3-8h4', terminal:'M4 4h16v16H4z m4 4 3 3-3 3 M13 16h4',
  shield:'m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6l8-3Z m-4 9 3 3 5-6',
  info:'M12 8h.01 M12 11v6 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  'arrow-up-right':'M7 17 17 7 M7 7h10v10', arrow:'M4 12h16 m-5-5 5 5-5 5', chevron:'m9 6 6 6-6 6',
  github:'M9 19c-4 1-4-2-6-2 M15 22v-4c0-1-.3-2-1-2 4 0 7-2 7-6 0-2-1-3-2-4 0-1 0-2-.5-3-2 0-3 1-4 1a13 13 0 0 0-5 0C8 3 7 3 5.5 3 5 4 5 5 5 6c-1 1-2 2-2 4 0 4 3 6 7 6-.7 0-1 1-1 2v4',
  refresh:'M20 8a8 8 0 0 0-14-3L3 8 M3 3v5h5 M4 16a8 8 0 0 0 14 3l3-3 M21 21v-5h-5',
  download:'M12 3v12 m-5-5 5 5 5-5 M4 15v6h16v-6', play:'m8 4 12 8-12 8V4Z',
  check:'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0 m-15 0 3 3 6-6',
  alert:'m12 3 10 18H2L12 3Z M12 9v5 M12 17h.01', cpu:'M6 6h12v12H6z M9 9h6v6H9z M9 2v4 M15 2v4 M9 18v4 M15 18v4 M2 9h4 M2 15h4 M18 9h4 M18 15h4',
  phone:'M7 2h10a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1Z M10 18h4',
  search:'M20 20l-5-5 M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0', x:'m6 6 12 12 M6 18 18 6',
  code:'m8 7-5 5 5 5 m8-10 5 5-5 5 M14 4l-4 16', clock:'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0 M12 6v6l4 2', copy:'M8 8h13v13H8z M16 8V3H3v13h5'
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[name] || ICONS.info}"/></svg>`;
const escapeHtml = value => String(value == null ? '' : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const STARTUP_IDS = ['root','enabled','boot','bridge','mount','pending','daemon','socket','denylist','debug','inventory'];
const STATE_LABELS = {pass:'Passed',warn:'Review',fail:'Failed',unknown:'Unverified'};
const badge = (status, label) => `<span class="badge ${hasOwn(STATE_LABELS,status) ? status : 'unknown'}"><i></i>${escapeHtml(label || STATE_LABELS[status] || 'Unverified')}</span>`;
const checkIcon = status => icon(status === 'pass' ? 'check' : status === 'fail' || status === 'warn' ? 'alert' : 'info');
const RUNTIME = [
  ['nativebridge','NativeBridge initialization','ART must load and initialize the installed native bridge.','Use a native Debug build and inspect ZygiskStudy bootstrap logs. The property and file checks alone cannot verify ART initialization.'],
  ['moduleload','Module entry point / dlopen','Library loading and the zygisk_module factory run inside zygote.','Use a Debug build to inspect dlopen failures, missing zygisk_module symbols and null factory returns. Standard upstream API v4 modules are not automatically compatible with this study API v2.'],
  ['onLoad','onLoad()','Receives the API and a live JNIEnv before specialization.','Requires native instrumentation or a purpose-built test module. No per-module callback counters are exposed by this loader.'],
  ['preAppSpecialize','preAppSpecialize()','Runs in the forked app child before the privilege drop.','Use a test module on a recoverable test device to observe callback entry and supplied arguments. This dashboard never injects or forks test apps.'],
  ['postAppSpecialize','postAppSpecialize()','Runs after the application privilege drop.','Observe callback completion in a native test module. A running daemon cannot verify this callback.'],
  ['preServerSpecialize','preServerSpecialize()','Runs before system_server specialization.','Requires native instrumentation on a recoverable test device. The WebUI does not probe or restart system_server.'],
  ['postServerSpecialize','postServerSpecialize()','Runs after system_server specialization.','Requires native instrumentation; testing system_server callbacks can cause a boot loop. Do not test on a device you depend on.'],
  ['connectCompanion','connectCompanion()','Returns a companion-channel file descriptor to a loaded module.','Verify from a native module in its actual SELinux context. A socket on disk does not prove IPC works from zygote.'],
  ['getModuleDir','getModuleDir()','Returns the running module directory.','Call from a native test module and compare with the expected directory. Disk discovery does not exercise this function.'],
  ['getProcessName','getProcessName()','Returns the running process name.','Call from a native test module in the target process. This WebUI cannot infer per-process API results.'],
  ['hookJniEnv','hookJniEnv()','Replaces a thread-local JNI function table.','Verify the return code and a harmless intercepted call in a native test module. This cannot be safely exercised from a WebView.'],
  ['setOption','setOption()','Configures loader behavior, including DenyList unmount.','Requires a native test module and post-specialization mount inspection. A readable DenyList does not prove enforcement.'],
  ['cleanTrace','cleanTrace()','Schedules per-fork cleanup of module traces.','Requires child-process native instrumentation; this dashboard does not change mounts or memory mappings.'],
  ['apiVersion','apiVersion()','Negotiates this project’s study API, currently version 2.','The source defines API v2. Verifying the installed runtime return value requires a native module.'],
  ['caps','caps()','Declares module capabilities used by the loader.','Requires a loaded test module to report capabilities and observe the corresponding callback behavior.']
].map(([id,title,detail,fix]) => ({id,status:'unknown',title,detail,fix,group:'runtime'}));
function decodeField(value) {
  const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  return new TextDecoder('utf-8').decode(bytes);
}
function parseSnapshot(text) {
  if (typeof text !== 'string' || text.length > 5000000) throw new Error('Invalid diagnostic response.');
  const result = {meta:{},checks:[],modules:[],logs:[]};
  const counts = {meta:2,check:5,module:9,log:1};
  const checkIds = new Set(), moduleIds = new Set();
  for (const line of text.trim().split('\n')) {
    const [kind,...encoded] = line.replace(/\r$/, '').split('\t');
    if (!hasOwn(counts,kind) || encoded.length !== counts[kind]) throw new Error('Unexpected diagnostic record.');
    if (result.meta.complete) throw new Error('Records after snapshot completion.');
    const f = encoded.map(decodeField);
    if (kind === 'meta') {
      if (!['protocol','collected','model','android','kernel','version','abi','selinux','logStatus','complete'].includes(f[0])) throw new Error('Unexpected metadata field.');
      if (hasOwn(result.meta,f[0])) throw new Error('Duplicate metadata field.');
      result.meta[f[0]] = f[1];
    }
    if (kind === 'check') {
      const [id,status,title,detail,fix] = f;
      if (!hasOwn(STATE_LABELS,status)) throw new Error('Invalid check state.');
      if (![...STARTUP_IDS,'inventory_limit'].includes(id) || checkIds.has(id)) throw new Error('Invalid or duplicate check ID.');
      checkIds.add(id);
      result.checks.push({id,status,title,detail,fix,group:'startup'});
    }
    if (kind === 'module') {
      const [id,name,version,author,description,abis,layout,flags,eligible] = f;
      if (moduleIds.has(id) || !id || result.modules.length >= 256 ||
          !['study','standard','none'].includes(layout) || !['enabled','disabled','removing'].includes(flags) ||
          !['yes','no'].includes(eligible)) throw new Error('Invalid module record.');
      moduleIds.add(id);
      result.modules.push({id,name,version,author,description,abis,layout,flags,eligible});
    }
    if (kind === 'log') result.logs.push(f[0]);
  }
  if (result.meta.protocol !== '1' || result.meta.complete !== '1' || !STARTUP_IDS.every(id => checkIds.has(id))) throw new Error('The diagnostic snapshot was incomplete.');
  result.checks.push(...RUNTIME.map(c => ({...c})));
  return result;
}
function moduleState(m) {
  if (m.flags !== 'enabled') return {status:'warn',label:m.flags === 'removing' ? 'Pending removal' : 'Disabled marker',filter:'review'};
  if (m.layout !== 'study') return {status:'warn',label:m.layout === 'standard' ? 'Unsupported API' : 'ABI unavailable',filter:'review'};
  return {status:'unknown',label:'Load unverified',filter:'compatible'};
}
function demoSnapshot() {
  const checks = [
    ['root','pass','Root access','Collector is running with UID 0.','No action needed.'],
    ['enabled','pass','Loader enabled','No disable or remove marker is present.','This is not proof of injection.'],
    ['boot','pass','Android boot','Android reports boot completed.','No action needed.'],
    ['bridge','pass','Native bridge property','The native bridge property matches the installed loader.','Matching configuration does not prove ART initialized the bridge.'],
    ['mount','pass','System loader visibility','The loader is readable in the collector mount namespace.','Zygote may have a different mount namespace.'],
    ['pending','pass','Mount handoff','No pending mount marker was found.','Absence of a marker is not proof of mount success.'],
    ['daemon','unknown','Companion daemon process','The recorded PID cannot be verified.','Check the PID record, daemon ABI and service startup. Inaccessible process data does not necessarily mean failure.'],
    ['socket','pass','Companion socket','A Unix socket exists at the session endpoint.','Socket presence does not prove companion IPC is responsive.'],
    ['denylist','pass','DenyList configuration','2 entries; configuration is readable.','This does not verify DenyList enforcement.'],
    ['debug','warn','Boot-script logging','Optional boot-script diagnostics are off.','Create .debug in the installed module directory before a controlled reboot to enable shell diagnostics. Native logs require a Debug build.'],
    ['inventory','pass','Module inventory','The installed module directory is accessible.','Discovery is disk-based, not proof of module loading.']
  ].map(([id,status,title,detail,fix]) => ({id,status,title,detail,fix,group:'startup'}));
  return {meta:{model:'Pixel 8 Pro (sample)',android:'15',abi:'arm64-v8a',kernel:'6.1.99-android14',version:'v0.1.0',selinux:'Enforcing',collected:new Date().toISOString(),logStatus:'available'},checks:[...checks,...RUNTIME.map(c=>({...c}))],modules:[
    {id:'sample_companion',name:'Companion example',version:'v1.2.0',author:'Sample module',description:'Illustrative module for the study companion API. This is sample data, not an installed module.',abis:'arm64-v8a, armeabi-v7a',layout:'study',flags:'enabled',eligible:'yes'},
    {id:'sample_jni',name:'JNI inspector',version:'v0.8.1',author:'Sample module',description:'Illustrative JNI function table inspection module.',abis:'arm64-v8a',layout:'study',flags:'enabled',eligible:'yes'},
    {id:'sample_process',name:'Process observer',version:'v2.0.0',author:'Sample module',description:'Illustrative process lifecycle observer.',abis:'arm64-v8a, x86_64',layout:'study',flags:'enabled',eligible:'yes'},
    {id:'sample_legacy',name:'Standard-layout example',version:'v1.0.3',author:'Sample module',description:'Illustrates a standard Zygisk library layout that the current study daemon does not enumerate.',abis:'arm64-v8a',layout:'standard',flags:'enabled',eligible:'no'},
    {id:'sample_disabled',name:'Disabled example',version:'v0.3.0',author:'Sample module',description:'Illustrates a disable marker. Excluded from new registry snapshots; existing mappings require a reboot.',abis:'arm64-v8a',layout:'study',flags:'disabled',eligible:'no'}
  ],logs:['09-06 10:24:08.120  1842  1842 I ZygiskStudy: [SAMPLE] native bridge bootstrap','09-06 10:24:08.124  1842  1842 I ZygiskStudy: [SAMPLE] payload initialization','09-06 10:24:09.031  2015  2015 I ZygiskStudy: [SAMPLE] daemon socket check complete','09-06 10:24:09.038  2015  2015 W ZygiskStudy: [SAMPLE] module layout requires review']};
}
// The only executable command is constant. No module metadata, URL parameter,
// search text, or report content is ever interpolated into a root shell.
const COLLECT_COMMAND = 'sh /data/adb/modules/zygisk_study/webroot/diagnostics.sh';
let callbackId = 0;
function collectDevice() {
  return new Promise((resolve,reject) => {
    const name = `zs_snapshot_${Date.now()}_${callbackId++}`;
    const cleanup = () => { clearTimeout(timer); delete window[name]; };
    const timer = setTimeout(() => { cleanup(); reject(new Error('Device collection timed out. Check the WebUI manager and root access, then retry.')); },30000);
    window[name] = (errno,stdout,stderr) => {
      cleanup();
      if (Number(errno) !== 0) reject(new Error(String(stderr || `Collector exited with code ${errno}.`).slice(0,1500)));
      else { try { resolve(parseSnapshot(stdout)); } catch (error) { reject(error); } }
    };
    try { window.ksu.exec(COLLECT_COMMAND,'{}',name); }
    catch (error) { cleanup(); reject(error); }
  });
}
let snapshot = null, busy = false, view = 'overview', checkTab = 'all', moduleQuery = '', moduleFilter = 'all', logQuery = '', logFilter = 'all';
const live = typeof window !== 'undefined' && !!window.ksu && typeof window.ksu.exec === 'function';
const $ = selector => document.querySelector(selector);
const all = selector => [...document.querySelectorAll(selector)];
function toast(text) { $('#toast').textContent=text; $('#toast').classList.add('visible'); clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('#toast').classList.remove('visible'),3500); }
function counts() { const c={pass:0,warn:0,fail:0,unknown:0}; snapshot.checks.forEach(x=>c[x.status]++); return c; }
function attention() { return snapshot.checks.filter(c=>c.status==='warn'||c.status==='fail').length + snapshot.modules.filter(m=>moduleState(m).filter==='review').length; }
function heading(title,description) {
  return `<section class="page-heading"><div><div class="eyebrow">YOUR ZYGISK WORKSPACE</div><h1>${title}</h1><p>${description}</p></div><div class="heading-actions"><button class="button" data-action="export">${icon('download')}Export report</button><button class="button primary" data-action="refresh" ${busy?'disabled':''}>${icon(busy?'refresh':'play')}${busy?'Checking…':'Run diagnostics'}</button></div></section>`;
}
function panelHeading(title,ic,extra='') { return `<div class="panel-heading"><h2 class="panel-title">${icon(ic)}${title}</h2>${extra}</div>`; }
function deviceDetails() {
  const m=snapshot.meta;
  return `<dl class="device-list">${[['Device',m.model],['Android version',m.android],['Architecture',m.abi],['Kernel',m.kernel],['Module version',m.version],['SELinux',m.selinux]].map(([k,v])=>`<div><dt>${k}</dt><dd>${k==='Architecture'?`<code>${escapeHtml(v||'Unavailable')}</code>`:escapeHtml(v||'Unavailable')}</dd></div>`).join('')}</dl>`;
}
function timeLabel() { const d=new Date(snapshot.meta.collected); return Number.isNaN(d.getTime())?'Time unavailable':d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function moduleRows(modules) {
  const colors=['green','violet','','orange'];
  return modules.map(m=>{const s=moduleState(m),idx=snapshot.modules.indexOf(m);return `<tr><td><div class="module-cell"><span class="module-avatar ${colors[idx%4]}">${escapeHtml(m.name.slice(0,1).toUpperCase())}</span><div><button class="module-name" data-module="${idx}">${escapeHtml(m.name)}</button><div class="module-id">${escapeHtml(m.id)}</div></div></div></td><td><span class="mono">${escapeHtml(m.version||'—')}</span></td><td><span class="mono">${escapeHtml(m.abis||'None detected')}</span></td><td>${badge(s.status,s.label)}</td><td><button class="row-arrow" data-module="${idx}" aria-label="Inspect ${escapeHtml(m.name)}">${icon('chevron')}</button></td></tr>`;}).join('');
}
function moduleTable(modules) {return `<div class="table-wrap"><table><thead><tr><th>MODULE</th><th>VERSION</th><th>ARCHITECTURE</th><th>STATUS</th><th><span class="small-label">DETAILS</span></th></tr></thead><tbody>${moduleRows(modules)}</tbody></table>${!modules.length?`<div class="empty">${icon('box')}No matching Zygisk modules.<br>Try another filter, or run diagnostics to scan again.</div>`:''}</div>`;}
function overview() {
  const c=counts(), issues=attention(), startup=snapshot.checks.filter(x=>x.group==='startup');
  const highlight=['bridge','mount','daemon','socket'];
  return heading('A clearer view of Zygisk.','Your modules, runtime health, and diagnostics. All in one place.')+
    `<section class="stats-grid" aria-label="Diagnostic summary">
    <article class="stat-card"><div class="stat-heading">Zygisk status<span class="stat-icon">${icon('activity')}</span></div><div class="stat-value status-value"><span class="dot"></span>${c.fail?'Issues detected':issues?'Needs review':'Not fully verified'}</div><div class="stat-caption">${live?'Device snapshot':'Preview snapshot'} <span>· Runtime unverified</span></div></article>
    <article class="stat-card"><div class="stat-heading">Zygisk modules<span class="stat-icon">${icon('box')}</span></div><div class="stat-value">${snapshot.modules.length}</div><div class="stat-caption"><span class="accent">${snapshot.modules.filter(m=>m.layout==='study').length} study-layout</span><span>· Discovered on disk</span></div></article>
    <article class="stat-card"><div class="stat-heading">Checks passed<span class="stat-icon">${icon('check')}</span></div><div class="stat-value">${c.pass}<span class="small-label">/ ${snapshot.checks.length}</span></div><div class="stat-caption"><span class="accent">Observed prerequisites</span><span>· Not API tests</span></div></article>
    <article class="stat-card"><div class="stat-heading">Needs attention<span class="stat-icon">${icon('alert')}</span></div><div class="stat-value">${issues.toString().padStart(2,'0')}</div><div class="stat-caption"><span class="amber">Checks & module notices</span></div></article></section>
    <section class="main-grid"><article class="panel">${panelHeading('Runtime health','activity',`<span class="small-label">SNAPSHOT</span>`)}<div class="health-intro"><span class="health-symbol">${icon('shield')}</span><div><h3>${c.fail?'Let’s trace what needs attention.':'The basics are visible. Dig a little deeper.'}</h3><p>${c.pass} prerequisite checks passed. ${c.unknown} checks remain unverified.</p></div></div><div class="health-track"><div class="track-label"><span>Startup & environment</span><strong>${startup.filter(x=>x.status==='pass').length} of ${startup.length} checks passed</strong></div><div class="segmented-track">${startup.map(x=>`<span class="${x.status}" title="${escapeHtml(x.title)}: ${STATE_LABELS[x.status]}"></span>`).join('')}</div></div><div class="health-checks">${highlight.map(id=>snapshot.checks.find(x=>x.id===id)).filter(Boolean).map(x=>`<div class="health-row"><span class="${x.status}-text">${checkIcon(x.status)}</span>${escapeHtml(x.title)}${badge(x.status)}<button data-check="${escapeHtml(x.id)}" aria-label="Details for ${escapeHtml(x.title)}">${icon('chevron')}</button></div>`).join('')}</div><div class="panel-footer"><span>Last checked at ${escapeHtml(timeLabel())}</span><a href="#diagnostics" class="text-link">View diagnostics ${icon('arrow')}</a></div></article>
    <article class="panel">${panelHeading('Device environment','phone')}${deviceDetails()}<div class="device-note">${icon('info')}<span>${live?'Collected through the root-manager bridge.':'Sample environment. Open in a compatible manager for device data.'}</span></div></article></section>
    <section class="panel table-panel">${panelHeading(`Zygisk modules <span class="count-label">${snapshot.modules.length}</span>`,'box',`<a href="#modules" class="text-link">View all modules ${icon('arrow')}</a>`)}${moduleTable(snapshot.modules.slice(0,4))}<div class="panel-footer"><span>${snapshot.modules.length?`Showing ${Math.min(snapshot.modules.length,4)} of ${snapshot.modules.length} discovered modules`:'No module directories discovered'}</span><span>Discovery ≠ successful loading</span></div></section>
    <section class="insight"><span>${icon('code')}</span><div><strong>Is a specific function failing?</strong><p>Explore the API checklist, understand what each function does, and find the next step.</p></div><a href="#diagnostics" class="text-link">Open debug menu ${icon('arrow')}</a></section>`;
}
function modulesPage() {
  return heading('Your Zygisk modules.','See what uses Zygisk, how it is installed, and what needs a closer look.')+
  `<div class="notice">${icon('info')}<span><strong>Installed does not mean loaded.</strong> The study daemon expects <code>zygisk/&lt;abi&gt;/libzygisk-module.so</code>, not standard <code>zygisk/&lt;abi&gt;.so</code>. Upstream Zygisk API modules (including LSPosed and zygisk-detach) are not supported by this study API v2. Renaming libraries cannot fix this. Disabled/removing modules are excluded from new registry snapshots; reboot to unload any existing mappings.</span></div><section class="panel">${panelHeading('Module inventory','box',`<span class="count-label">${snapshot.modules.length} discovered</span>`)}<div class="toolbar"><label class="search">${icon('search')}<input id="module-search" placeholder="Search modules, IDs, or authors…" aria-label="Search modules" value="${escapeHtml(moduleQuery)}"></label><select id="module-filter" aria-label="Filter modules"><option value="all">All modules</option><option value="compatible">Study layout</option><option value="review">Needs review</option></select><span class="filter-count" id="module-count"></span></div><div id="module-results"></div><div class="panel-footer"><span>Read-only · No modules are enabled or disabled here</span><span>${live?'Device inventory':'Sample inventory'}</span></div></section>`;
}
function updateModuleResults() {
  const q=moduleQuery.toLowerCase();
  const list=snapshot.modules.filter(m=>`${m.name} ${m.id} ${m.author}`.toLowerCase().includes(q)&&(moduleFilter==='all'||moduleState(m).filter===moduleFilter));
  $('#module-results').innerHTML=moduleTable(list); $('#module-count').textContent=`${list.length} results`; $('#module-filter').value=moduleFilter;
}
function diagnosticPage() {
  return heading('Find the missing piece.','Follow the startup path, inspect each function, and turn signals into next steps.')+
  `<div class="notice">${icon('shield')}<span><strong>Honest diagnostics, by design.</strong> Passed means the stated observation was confirmed. Native callbacks cannot be tested from a WebView and remain <strong>Unverified</strong>. Expand a check for evidence and troubleshooting guidance.</span></div><section class="panel">${panelHeading('Diagnostic checklist','activity',`<span class="count-label">${snapshot.checks.length} checks</span>`)}<div class="tabs" role="tablist" aria-label="Diagnostic categories">${[['all','All checks'],['startup','Startup & environment'],['runtime','Functions & callbacks'],['attention','Needs attention']].map(([id,label])=>`<button class="tab ${checkTab===id?'active':''}" data-tab="${id}" role="tab" aria-selected="${checkTab===id}">${label}</button>`).join('')}</div><div class="check-list" id="check-results"></div><div class="panel-footer"><span>${counts().unknown} checks remain unverified</span><a class="text-link" href="#logs">Inspect logs ${icon('arrow')}</a></div></section>`;
}
function updateChecks() {
  const list=snapshot.checks.filter(c=>checkTab==='all'||c.group===checkTab||(checkTab==='attention'&&['warn','fail'].includes(c.status)));
  $('#check-results').innerHTML=list.length?list.map(c=>`<details class="check-item" id="check-${escapeHtml(c.id)}"><summary><span class="${c.status}-text">${checkIcon(c.status)}</span><span class="check-name">${escapeHtml(c.title)}<small>${escapeHtml(c.detail)}</small></span>${badge(c.status)}<span class="chevron">${icon('chevron')}</span></summary><div class="check-detail"><strong>WHAT TO DO NEXT</strong>${escapeHtml(c.fix)}</div></details>`).join(''):`<div class="empty">${icon('check')}No failed or review checks in this snapshot.<br>Unverified functions still require native testing.</div>`;
}
function logLevel(line) {return /\s[EF]\sZygiskStudy:/.test(line)?'error':/\sW\sZygiskStudy:/.test(line)?'warning':'info';}
function logsPage() {
  return heading('Follow the signals.','A focused look at ZygiskStudy logs. No noise from unrelated apps.')+
    `<div class="notice">${icon('info')}<span><strong>Quiet does not mean healthy.</strong> Native Release builds compile out log messages. The <code>.debug</code> marker enables boot-script logs only. Native function debugging requires a Debug build and a recoverable test device.</span></div><section class="panel">${panelHeading('Diagnostic log','terminal',`<span class="small-label">${live?'DEVICE SNAPSHOT':'SAMPLE LOGS'} · LAST 150 LINES</span>`)}<div class="toolbar"><label class="search">${icon('search')}<input id="log-search" aria-label="Search logs" placeholder="Search log messages…" value="${escapeHtml(logQuery)}"></label><select id="log-filter" aria-label="Log level"><option value="all">All levels</option><option value="error">Errors</option><option value="warning">Warnings</option><option value="info">Info & other</option></select><span class="filter-count" id="log-count"></span></div><div class="log-console" id="log-results" tabindex="0" aria-label="Log output"></div><div class="panel-footer"><span>Tag: ZygiskStudy · Snapshot, not a live stream</span><button class="text-link" data-action="refresh">Refresh logs ${icon('refresh')}</button></div></section>`;
}
function updateLogs() {
  const list=snapshot.logs.map((text,i)=>({text,i,level:logLevel(text)})).filter(l=>l.text.toLowerCase().includes(logQuery.toLowerCase())&&(logFilter==='all'||l.level===logFilter));
  const empty=snapshot.meta.logStatus==='denied'?'Log access was denied by the device. Check manager permissions.':snapshot.meta.logStatus==='unavailable'?'logcat is not available in this environment.':snapshot.logs.length?'No messages match your filters.':'No ZygiskStudy messages were returned. Release builds may have no native logging; an empty log is not proof of success.';
  $('#log-results').innerHTML=list.length?list.map(l=>`<div class="log-line ${l.level}"><span class="log-number">${String(l.i+1).padStart(2,'0')}</span><span class="log-message">${escapeHtml(l.text)}</span></div>`).join(''):`<div class="console-empty">${escapeHtml(empty)}</div>`;
  $('#log-count').textContent=`${list.length} lines`; $('#log-filter').value=logFilter;
}
function showDialog(content) {
  $('#dialog-content').innerHTML=content;
  const dialog=$('#detail-dialog');
  if (!dialog.open) { if (typeof dialog.showModal==='function') dialog.showModal(); else dialog.setAttribute('open',''); }
}
function closeDialog() {
  const dialog=$('#detail-dialog');
  if (typeof dialog.close==='function') dialog.close(); else dialog.removeAttribute('open');
}
function showModule(index) {
  const m=snapshot.modules[index]; if(!m)return;
  const s=moduleState(m);
  showDialog(`<h2>${escapeHtml(m.name)}</h2>${badge(s.status,s.label)}<p>${escapeHtml(m.description||'No description supplied by this module.')}</p><dl class="device-list">${[['Module ID',m.id],['Version',m.version],['Author',m.author],['Architectures',m.abis],['Disk layout',m.layout],['Manager marker',m.flags],['Daemon path candidate',m.eligible==='yes'?'Yes (disk pattern only)':'No']].map(([k,v])=>`<div><dt>${k}</dt><dd>${escapeHtml(v||'Not supplied')}</dd></div>`).join('')}</dl><div class="notice">${icon('info')}<span>${m.flags!=='enabled'?'Excluded from new daemon registry snapshots. Existing process mappings are not unloaded by this marker; reboot to fully deactivate. ':''}${m.layout==='standard'?'This is an upstream Zygisk layout/API, not this loader’s study API v2. LSPosed and zygisk-detach require an upstream-compatible Zygisk provider. Disable/remove this loader before switching providers; never run both. Renaming the binary does not provide ABI compatibility. ':''}No per-process load telemetry is available. This inventory cannot confirm successful loading or callback execution.</span></div>`);
}
function report(includeLogs=false) {return JSON.stringify({project:'Zygisk Study',mode:live?'device':'sample-preview',notice:'Read-only observations. Unverified is not a pass. Review this report before sharing.',...snapshot,logs:includeLogs?snapshot.logs:[],logsIncluded:includeLogs},null,2);}
function exportDialog() {
  showDialog(`<h2>Export diagnostic report</h2><p>A local JSON snapshot of the environment, module inventory, and checks. Module names and device details may be identifying. Review before sharing; nothing is uploaded.</p><label class="checkbox-label"><input id="include-logs" type="checkbox"> Include logs (may contain paths or process details)</label><textarea id="report-preview" class="report-preview" aria-label="Diagnostic report" readonly></textarea><div class="dialog-actions"><button class="button primary" id="download-report">${icon('download')}Download JSON</button><button class="button" id="copy-report">${icon('copy')}Copy report</button></div><p>If your manager blocks downloads or clipboard access, select and copy the report above.</p>`);
  const update=()=>$('#report-preview').value=report($('#include-logs').checked);update();$('#include-logs').onchange=update;
  $('#download-report').onclick=()=>{
    const url=URL.createObjectURL(new Blob([$('#report-preview').value],{type:'application/json'}));
    const a=document.createElement('a');a.href=url;a.download=`zygisk-${live?'device':'sample'}-report-${new Date().toISOString().slice(0,10)}.json`;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);toast('Download requested. The report is also available to copy.');
  };
  $('#copy-report').onclick=async()=>{try{await navigator.clipboard.writeText($('#report-preview').value);toast('Report copied to clipboard.');}catch{const field=$('#report-preview');field.focus();field.select();toast('Clipboard unavailable. Copy the selected report manually.');}};
}
function render() {
  const requested=location.hash.slice(1); view=['overview','modules','diagnostics','logs'].includes(requested)?requested:'overview';
  all('[data-nav]').forEach(a=>{a.classList.toggle('active',a.dataset.nav===view);if(a.dataset.nav===view)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
  $('#breadcrumb').textContent=view[0].toUpperCase()+view.slice(1);document.title=`${$('#breadcrumb').textContent} · Zygisk Study`;
  $('#mode-banner').innerHTML=live?`${icon('shield')}<span><strong>Device mode.</strong> Read-only collection through your manager.</span><span class="mode-pill">${busy?'COLLECTING':'ON-DEMAND SNAPSHOT'}</span>`:`${icon('info')}<span><strong>Preview mode.</strong> You’re exploring sample data. Open in a compatible root manager to inspect your device.</span><span class="mode-pill">DEMO WORKSPACE</span>`;
  if(!snapshot){$('#content').innerHTML=`<div class="loading">${icon('activity')}<h2>${busy?'Reading your device…':'Device data unavailable'}</h2><p>${busy?'Checking the environment, modules, and diagnostic signals.':'Check the error above and confirm your manager grants the WebUI root access.'}</p>${!busy?'<button class="button primary" data-action="refresh">Retry diagnostics</button>':''}</div>`;return;}
  $('#nav-modules').textContent=snapshot.modules.length;$('#nav-issues').textContent=attention();$('#sidebar-version').textContent=snapshot.meta.version||'Unknown version';
  $('#content').innerHTML=({overview,modules:modulesPage,diagnostics:diagnosticPage,logs:logsPage}[view])();
  if(view==='modules')updateModuleResults();if(view==='diagnostics')updateChecks();if(view==='logs')updateLogs();
}
async function refresh(initial=false) {
  if(busy)return;busy=true;$('#error-banner').hidden=true;render();
  try{snapshot=live?await collectDevice():demoSnapshot();if(!initial)toast(live?'Device snapshot updated.':'Sample diagnostics refreshed. No device is connected.');}
  catch(error){$('#error-banner').textContent=`${snapshot?'Refresh failed — showing the previous snapshot. ':'Collection failed. '}${error.message}`;$('#error-banner').hidden=false;}
  finally{busy=false;render();}
}
function init() {
  all('[data-icon]').forEach(el=>el.innerHTML=icon(el.dataset.icon));
  document.addEventListener('click',event=>{
    const action=event.target.closest('[data-action]');if(action){if(action.dataset.action==='refresh')refresh();if(action.dataset.action==='export'&&snapshot)exportDialog();}
    const module=event.target.closest('[data-module]');if(module)showModule(Number(module.dataset.module));
    const tab=event.target.closest('[data-tab]');if(tab){checkTab=tab.dataset.tab;render();$(`[data-tab="${checkTab}"]`).focus();}
    const check=event.target.closest('[data-check]');if(check){const c=snapshot.checks.find(c=>c.id===check.dataset.check);if(c)showDialog(`<h2>${escapeHtml(c.title)}</h2>${badge(c.status)}<p>${escapeHtml(c.detail)}</p><div class="check-detail"><strong>WHAT TO DO NEXT</strong>${escapeHtml(c.fix)}</div>`);}
  });
  document.addEventListener('input',event=>{if(event.target.id==='module-search'){moduleQuery=event.target.value;updateModuleResults();}if(event.target.id==='log-search'){logQuery=event.target.value;updateLogs();}});
  document.addEventListener('change',event=>{if(event.target.id==='module-filter'){moduleFilter=event.target.value;updateModuleResults();}if(event.target.id==='log-filter'){logFilter=event.target.value;updateLogs();}});
  $('#close-dialog').onclick=closeDialog;
  $('#detail-dialog').addEventListener('click',event=>{if(event.target===$('#detail-dialog')){const r=event.target.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)closeDialog();}});
  $('#about').onclick=()=>showDialog(`<h2>Understand your Zygisk.</h2><p>Zygisk Study is an original-source, educational reimplementation of the loader pattern. It is not ZygiskNext or an upstream Magisk implementation.</p><div class="notice">${icon('alert')}<span>This project is experimental and can crash zygote or boot-loop a device. A passing dashboard does not certify that it is safe to flash.</span></div><p><strong>Opening on a device</strong><br>Use the module WebUI in KernelSU, or a compatible APatch / Magisk WebUI host exposing the KernelSU-style <code>ksu.exec</code> bridge. Standard Magisk Manager has no built-in WebUI. Ordinary browsers display sample data only.</p><p><strong>Scope</strong><br>No background polling, cloud requests, root-state changes, or active injection tests. Native functions need a Debug build or dedicated test module for verification. The interface and collector work offline.</p><a class="button" href="https://github.com/VenusIsJaded/Zygisk" target="_blank" rel="noopener noreferrer">${icon('github')}View project source ${icon('arrow-up-right')}</a>`);
  window.addEventListener('hashchange',()=>{if(location.hash==='#main')return;render();window.scrollTo(0,0);});refresh(true);
}
if(typeof document!=='undefined')document.addEventListener('DOMContentLoaded',init);
if(typeof module!=='undefined'&&module.exports)module.exports={parseSnapshot,moduleState,escapeHtml,demoSnapshot,RUNTIME,logLevel};
