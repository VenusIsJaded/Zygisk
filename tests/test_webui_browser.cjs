// SPDX-License-Identifier: Apache-2.0
// Run with NODE_PATH pointing at an installation of Playwright and Chromium installed.
// This suite is run separately; build.yml gates the dependency-free WebUI tests.
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {pathToFileURL}=require('node:url');
const {chromium}=require('playwright');
const app=require('../webroot/app.js');
const repo=path.resolve(__dirname,'..');
const url=pathToFileURL(path.join(repo,'webroot/index.html')).href;
const row=(kind,...fields)=>[kind,...fields.map(v=>Buffer.from(String(v)).toString('base64'))].join('\t');
const hostile='<img src=x onerror="window.injected=1"> $(reboot) 日本語';
const sample=app.demoSnapshot();
const snapshot=[row('meta','protocol','1'),row('meta','model','Browser fixture'),row('meta','version','fixture'),
  ...sample.checks.filter(c=>c.group==='startup').map(c=>row('check',c.id,c.status,c.title,c.detail,c.fix)),
  row('module','hostile',hostile,'1','Fixture','Untrusted module metadata','arm64-v8a','study','enabled','yes'),
  row('log',`09-07 12:00:00.000 1 1 W ZygiskStudy: ${hostile}`),row('meta','complete','1')].join('\n');
(async()=>{
  const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
  let assertions=0;
  const check=(condition,message)=>{assert.ok(condition,message);assertions++;};
  const errors=[],network=[];
  function monitor(page) {
    page.on('pageerror',error=>errors.push(error.message));
    page.on('request',request=>{if(/^https?:/.test(request.url()))network.push(request.url());});
  }
  try {
    const context=await browser.newContext({viewport:{width:1440,height:1100},acceptDownloads:true});
    const page=await context.newPage();monitor(page);
    await page.goto(url);await page.waitForSelector('.stats-grid');
    check((await page.locator('#mode-banner').innerText()).includes('Preview mode'),'ordinary browser explicitly labels sample mode');
    await page.locator('[data-nav="modules"]').click();
    await page.locator('#module-search').fill('JNI');
    check(await page.locator('#module-results tbody tr').count()===1,'module search filters rows');
    await page.locator('#module-search').fill('no matches');
    check((await page.locator('#module-results').innerText()).includes('No matching'),'empty search is explained');
    await page.locator('#module-search').fill('');await page.locator('#module-filter').selectOption('review');
    check(await page.locator('#module-results tbody tr').count()===2,'review filter includes layout and marker warnings');
    await page.locator('.module-name').first().click();await page.waitForSelector('dialog[open]');
    check((await page.locator('#dialog-content').innerText()).includes('not enumerate'),'module details explain layout mismatch');
    await page.locator('#close-dialog').click();
    await page.locator('[data-nav="diagnostics"]').click();await page.locator('[data-tab="runtime"]').click();
    check(await page.locator('#check-results details').count()===15,'all native functions are listed');
    check(await page.locator('#check-results .badge.unknown').count()===15,'no native function is reported passed');
    await page.locator('#check-results summary').first().click();
    check(await page.locator('#check-results details[open]').count()===1,'check troubleshooting expands');
    await page.locator('[data-nav="logs"]').click();await page.locator('#log-filter').selectOption('warning');
    check(await page.locator('.log-line').count()===1,'log level filtering works');
    await page.locator('#log-search').fill('does not exist');
    check((await page.locator('#log-results').innerText()).includes('No messages match'),'empty log filter is explained');
    await page.locator('[data-action="export"]').click();
    let report=JSON.parse(await page.locator('#report-preview').inputValue());
    check(report.mode==='sample-preview'&&report.logs.length===0&&!report.logsIncluded,'preview export omits logs');
    await page.locator('#include-logs').check();report=JSON.parse(await page.locator('#report-preview').inputValue());
    check(report.logs.length===4&&report.logsIncluded,'logs require explicit export opt-in');
    const downloadEvent=page.waitForEvent('download');await page.locator('#download-report').click();
    const download=await downloadEvent;
    check(download.suggestedFilename().startsWith('zygisk-sample-report-'),'download is labeled sample');
    await page.locator('#close-dialog').click();await page.locator('[data-nav="overview"]').click();
    fs.mkdirSync(path.join(repo,'build'),{recursive:true});
    await page.screenshot({path:path.join(repo,'build/webui-desktop.png'),fullPage:true});
    await page.setViewportSize({width:375,height:812});
    for(const view of ['overview','modules','diagnostics','logs']) {
      await page.locator(`[data-nav="${view}"]`).click();
      check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${view} has no mobile page overflow`);
    }
    await page.locator('[data-nav="overview"]').click();
    await page.screenshot({path:path.join(repo,'build/webui-mobile.png'),fullPage:true});
    await context.close();

    const device=await browser.newContext({viewport:{width:1280,height:900}});
    await device.addInitScript(({snapshot})=>{
      window.__mode='success';window.__calls=[];
      window.ksu={exec(command,options,callback){
        window.__calls.push(command);
        if(window.__mode==='timeout')return;
        queueMicrotask(()=>window[callback](window.__mode==='error'?1:0,
          window.__mode==='invalid'?'malformed':snapshot,window.__mode==='error'?'Root permission denied':''));
      }};
    },{snapshot});
    const live=await device.newPage();monitor(live);await live.goto(url);await live.waitForSelector('.stats-grid');
    check((await live.locator('#mode-banner').innerText()).includes('Device mode'),'bridge selects live collection');
    check((await live.locator('#content').innerText()).includes('Browser fixture'),'device data replaces samples');
    await live.locator('[data-nav="modules"]').click();
    check(await live.locator('.module-name').innerText()===hostile,'hostile metadata is displayed literally');
    check(await live.locator('#content img').count()===0&&!await live.evaluate(()=>window.injected),'metadata does not inject HTML');
    await live.locator('.module-name').click();check(await live.locator('#dialog-content img').count()===0,'dialog metadata is escaped');
    await live.locator('#close-dialog').click();
    await live.locator('[data-nav="logs"]').click();
    check((await live.locator('.log-message').innerText()).includes(hostile)&&await live.locator('#log-results img').count()===0,'logs remain inert');
    await live.evaluate(()=>{window.__mode='error';});await live.locator('[data-action="refresh"]').first().click();
    await live.waitForSelector('#error-banner:not([hidden])');
    check((await live.locator('#error-banner').innerText()).includes('previous snapshot'),'refresh failure marks stale data');
    check(await live.locator('.log-message').count()===1,'previous device snapshot remains visible');
    await live.evaluate(()=>{window.__mode='success';});await live.locator('[data-action="refresh"]').first().click();
    // The error banner is hidden at refresh start. Wait for collection to finish
    // as well, so a failed retry cannot masquerade as a successful recovery.
    await live.waitForSelector('.heading-actions [data-action="refresh"]:not([disabled])');
    await live.locator('#error-banner').waitFor({state:'hidden'});
    check(await live.locator('.log-message').count()===1,'successful retry restores the device snapshot');
    check(await live.evaluate(()=>window.__calls.every(c=>c==='sh /data/adb/modules/zygisk_study/webroot/diagnostics.sh')),'all root commands are constant');
    await device.close();

    for(const mode of ['error','invalid','timeout']) {
      const ctx=await browser.newContext();
      await ctx.addInitScript(mode=>{
        window.ksu={exec(c,o,n){if(mode==='timeout')return;queueMicrotask(()=>window[n](mode==='error'?1:0,'malformed','Denied'));}};
      },mode);
      const p=await ctx.newPage();monitor(p);
      if(mode==='timeout')await p.clock.install();
      await p.goto(url);
      if(mode==='timeout')await p.clock.fastForward(31000);
      await p.waitForSelector('#error-banner:not([hidden])');
      check((await p.locator('#content').innerText()).includes('Device data unavailable'),`${mode} is not replaced with sample success`);
      check(await p.locator('.stats-grid').count()===0,`${mode} has no misleading health metrics`);
      await ctx.close();
    }
    const legacy=await browser.newContext();
    await legacy.addInitScript(()=>{Object.hasOwn=undefined;HTMLDialogElement.prototype.showModal=undefined;HTMLDialogElement.prototype.close=undefined;});
    const old=await legacy.newPage();monitor(old);await old.goto(url);await old.waitForSelector('.stats-grid');
    await old.locator('#about').click();check(await old.locator('dialog[open]').count()===1,'dialog fallback opens');
    await old.locator('#close-dialog').click();check(await old.locator('dialog[open]').count()===0,'dialog fallback closes');
    await legacy.close();
    assert.deepEqual(errors,[],'no browser JavaScript errors');
    assert.deepEqual(network,[],'offline dashboard makes no network requests');
    console.log(`Browser checks: ${assertions} passed; no JavaScript errors or network requests.`);
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
