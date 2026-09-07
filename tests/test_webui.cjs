// SPDX-License-Identifier: Apache-2.0
// No npm dependencies. Every filesystem fixture stays under the checkout.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const net = require('node:net');
const {spawnSync} = require('node:child_process');
const app = require('../webroot/app.js');
const repo = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(repo, 'webroot/app.js'), 'utf8');
const build = path.join(repo, 'build');
fs.mkdirSync(build, {recursive:true});
const row = (kind, ...fields) => [kind, ...fields.map(v => Buffer.from(String(v)).toString('base64'))].join('\t');
const end = row('meta', 'complete', '1');
function wire(extra=[]) {
  return [row('meta','protocol','1'), ...app.demoSnapshot().checks.filter(c=>c.group==='startup')
    .map(c=>row('check', c.id,c.status,c.title,c.detail,c.fix)), ...extra, end].join('\n')+'\n';
}
const moduleRow = (...overrides) => row('module', ...Object.assign(
  ['example','Example','1','Author','Description','arm64-v8a','study','enabled','yes'], ...overrides));

test('complete snapshot adds only unverified native checks', () => {
  const parsed=app.parseSnapshot(wire());
  assert.equal(parsed.checks.length,26);
  assert.equal(parsed.checks.filter(c=>c.group==='runtime').length,15);
  assert.ok(parsed.checks.filter(c=>c.group==='runtime').every(c=>c.status==='unknown'));
  assert.equal(app.parseSnapshot(wire().replaceAll('\n','\r\n')).checks.length,26);
});
test('metadata is data, including unicode, HTML, tabs and shell expressions', () => {
  const value='<img src=x onerror=alert(1)> $(touch nope) 日本語\tline\nnext';
  const parsed=app.parseSnapshot(wire([moduleRow({1:value}),row('log',value)]));
  assert.equal(parsed.modules[0].name,value);
  assert.equal(parsed.logs[0],value);
  assert.ok(!app.escapeHtml(value).includes('<img'));
  assert.equal(app.escapeHtml('&<>"\''),'&amp;&lt;&gt;&quot;&#39;');
});
test('truncated UTF-8 metadata is displayed safely, not a total snapshot failure', () => {
  const entry=moduleRow().split('\t');
  entry[2]=Buffer.from([0xe6,0x97]).toString('base64');
  assert.equal(app.parseSnapshot(wire([entry.join('\t')])).modules[0].name,'\ufffd');
});
test('malformed, partial and oversized responses fail closed', () => {
  const invalid=[null,'','x'.repeat(5000001),wire().replace(end,''),row('meta','complete','1'),
    wire().replace(row('meta','protocol','1'),row('meta','protocol','2')),
    wire().replace(/^check[^\n]+\n/m,''),wire([row('unknown','x')]),
    wire([row('meta','__proto__','polluted')]),wire([row('meta','protocol','1')]),
    wire([row('log','x')+'\textra']),wire(['log\t!!!']),
    wire()+row('log','after completion')];
  for(const value of invalid) assert.throws(()=>app.parseSnapshot(value));
  assert.equal({}.polluted,undefined);
});
test('duplicate checks, callback spoofing and invalid states are rejected', () => {
  for(const [id,status] of [['root','pass'],['onLoad','pass'],['other','pass'],['inventory_limit','green']]) {
    assert.throws(()=>app.parseSnapshot(wire([row('check',id,status,'Title','Detail','Fix')])));
  }
});
test('module records are unique, bounded and have known enums', () => {
  assert.throws(()=>app.parseSnapshot(wire([moduleRow(),moduleRow()])));
  for(const changes of [{0:''},{6:'other'},{7:'active'},{8:'maybe'}]) {
    assert.throws(()=>app.parseSnapshot(wire([moduleRow(changes)])));
  }
  assert.throws(()=>app.parseSnapshot(wire(Array.from({length:257},(_,i)=>moduleRow({0:String(i)})))));
});
test('module status never equates discovery or disable markers with runtime state', () => {
  const modules=app.demoSnapshot().modules;
  assert.equal(app.moduleState(modules[0]).status,'unknown');
  assert.equal(app.moduleState(modules[3]).label,'Layout mismatch');
  assert.equal(app.moduleState(modules[4]).label,'Disabled marker');
  assert.equal(app.moduleState({...modules[0],flags:'removing'}).label,'Pending removal');
  assert.equal(app.moduleState({...modules[0],layout:'none'}).label,'ABI unavailable');
});
test('sample snapshots are independent and log filtering recognizes Android levels', () => {
  const first=app.demoSnapshot();first.checks.at(-1).status='pass';
  assert.equal(app.demoSnapshot().checks.at(-1).status,'unknown');
  for(const [level,want] of [['E','error'],['F','error'],['W','warning'],['I','info']]) {
    assert.equal(app.logLevel(`09-07 12:00:00.000 1 1 ${level} ZygiskStudy: message`),want);
  }
});
function bridge(exec) {
  const window={ksu:{exec}};
  let timeout,cleared=false;
  const context=vm.createContext({window,atob,TextDecoder,Uint8Array,
    setTimeout:fn=>{timeout=fn;return 1;},clearTimeout:()=>{cleared=true;}});
  vm.runInContext(source,context);
  return {window,context,collect:()=>vm.runInContext('collectDevice()',context),
    expire:()=>timeout(),cleared:()=>cleared};
}
test('manager bridge executes only the constant command and removes callbacks',async()=>{
  let calls=0;
  const b=bridge((command,options,name)=>{
    calls++;assert.equal(command,'sh /data/adb/modules/zygisk_study/webroot/diagnostics.sh');
    assert.equal(options,'{}');b.window[name](0,wire([moduleRow({1:'$(reboot)'})]),'');
  });
  assert.equal((await b.collect()).modules[0].name,'$(reboot)');
  assert.equal(calls,1);assert.ok(b.cleared());
  assert.deepEqual(Object.keys(b.window),['ksu']);
});
test('bridge permission errors, malformed output, exceptions and timeouts reject',async()=>{
  for(const response of [[1,'','Root denied'],[0,'not a snapshot','']]) {
    const b=bridge((c,o,n)=>b.window[n](...response));
    await assert.rejects(b.collect());assert.ok(b.cleared());
    assert.deepEqual(Object.keys(b.window),['ksu']);
  }
  const broken=bridge(()=>{throw new Error('Unavailable');});
  await assert.rejects(broken.collect(),/Unavailable/);
  const slow=bridge(()=>{}),promise=slow.collect();slow.expire();
  await assert.rejects(promise,/timed out/);assert.ok(slow.cleared());
  assert.deepEqual(Object.keys(slow.window),['ksu']);
});
test('export excludes logs unless opted in and labels preview vs device',()=>{
  const b=bridge(()=>{});
  vm.runInContext('snapshot=demoSnapshot()',b.context);
  const safe=JSON.parse(vm.runInContext('report()',b.context));
  assert.equal(safe.mode,'device');assert.equal(safe.logsIncluded,false);assert.deepEqual(safe.logs,[]);
  assert.equal(JSON.parse(vm.runInContext('report(true)',b.context)).logs.length,4);
  const preview=vm.createContext({});vm.runInContext(source,preview);
  vm.runInContext('snapshot=demoSnapshot()',preview);
  assert.equal(JSON.parse(vm.runInContext('report()',preview)).mode,'sample-preview');
});
function fixture(t) {
  const root=fs.mkdtempSync(path.join(build,'webui-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const write=(name,body='',mode=0o644)=>{
    const file=path.join(root,name);fs.mkdirSync(path.dirname(file),{recursive:true});
    fs.writeFileSync(file,body,{mode});return file;
  };
  write('bin/id','#!/bin/sh\nprintf "%s\\n" "${FAKE_UID:-0}"\n',0o755);
  write('bin/getprop',`#!/bin/sh
case "$1" in
ro.product.model) echo 'Test device';;
ro.build.version.release) echo 15;;
ro.product.cpu.abi) echo "\${FAKE_ABI:-arm64-v8a}";;
ro.dalvik.vm.native.bridge) echo "\${FAKE_BRIDGE:-libtest.so}";;
sys.boot_completed) echo 1;;
*) exit 1;;
esac
`,0o755);
  write('bin/getenforce','#!/bin/sh\necho Enforcing\n',0o755);
  write('bin/logcat',`#!/bin/sh
[ "\${DENY_LOGS:-0}" != 1 ] || exit 1
[ "$*" = "-d -t 150 -v threadtime -s ZygiskStudy:* *:S" ] || exit 2
printf '%s\\n' '09-07 12:00:00.000 1 1 W ZygiskStudy: fixture'
`,0o755);
  write('data/adb/modules/zygisk_study/module.prop','id=zygisk_study\nversion=test\n');
  write('data/adb/modules/zygisk_study/.loader_names','bridge=libtest.so\n');
  write('system/lib64/libtest.so');
  write('data/system/zygisk_study/denylist','# comment\ncom.example.app\n');
  const run=(env={})=>spawnSync('sh',[path.join(repo,'webroot/diagnostics.sh')],{
    encoding:'utf8',timeout:30000,maxBuffer:6000000,
    env:{...process.env,PATH:path.join(root,'bin')+':'+process.env.PATH,ZS_DIAG_ROOT:root,...env}
  });
  const collect=env=>{const result=run(env);assert.equal(result.status,0,result.stderr);return app.parseSnapshot(result.stdout);};
  return {root,write,run,collect};
}
const status=(snapshot,id)=>snapshot.checks.find(c=>c.id===id).status;
test('real shell collector discovers study, standard, disabled and wrong-ABI modules',t=>{
  const f=fixture(t);
  for(const [id,layout] of [['study','arm64-v8a/libzygisk-module.so'],['standard','arm64-v8a.so'],['other','x86.so']]) {
    f.write(`data/adb/modules/${id}/zygisk/${layout}`);
    f.write(`data/adb/modules/${id}/module.prop`,`name=${id}\nversion=1\nauthor=fixture\n`);
  }
  f.write('data/adb/modules/study/disable');
  const snapshot=f.collect();
  assert.equal(snapshot.modules.length,3);
  assert.equal(snapshot.modules.find(m=>m.id==='study').flags,'disabled');
  assert.equal(snapshot.modules.find(m=>m.id==='study').eligible,'yes');
  assert.equal(snapshot.modules.find(m=>m.id==='standard').layout,'standard');
  assert.equal(snapshot.modules.find(m=>m.id==='other').layout,'none');
  for(const id of ['root','enabled','boot','bridge','mount','pending','denylist','inventory']) assert.equal(status(snapshot,id),'pass');
  assert.equal(status(snapshot,'daemon'),'unknown');assert.equal(status(snapshot,'socket'),'fail');
  assert.equal(snapshot.logs.length,1);
});
test('collector never evaluates module metadata and bounds display fields',t=>{
  const f=fixture(t),sentinel=path.join(f.root,'must-not-exist');
  f.write('data/adb/modules/hostile/zygisk/arm64-v8a.so');
  f.write('data/adb/modules/hostile/module.prop',`name=$(touch ${sentinel}) <script>alert(1)</script> 日本語\nauthor=${'A'.repeat(4000)}\n`);
  const snapshot=f.collect();
  assert.match(snapshot.modules[0].name,/\$\(touch/);assert.ok(!fs.existsSync(sentinel));
  assert.equal(snapshot.modules[0].author.length,1024);
});
test('collector rejects non-root and reports unavailable inventory rather than empty success',t=>{
  const f=fixture(t);const denied=f.run({FAKE_UID:'2000'});
  assert.notEqual(denied.status,0);assert.match(denied.stderr,/Root access/);
  fs.rmSync(path.join(f.root,'data/adb/modules'),{recursive:true});
  assert.equal(status(f.collect(),'inventory'),'unknown');
});
test('collector reports changed properties, removal, pending mounts and denied logs',t=>{
  const f=fixture(t);f.write('data/adb/modules/zygisk_study/remove');
  f.write('data/system/zygisk_study/.mount_pending');
  const snapshot=f.collect({FAKE_BRIDGE:'libforeign.so',DENY_LOGS:'1',FAKE_ABI:'unknown'});
  assert.equal(status(snapshot,'enabled'),'fail');assert.equal(status(snapshot,'bridge'),'fail');
  assert.equal(status(snapshot,'mount'),'unknown');assert.equal(status(snapshot,'pending'),'warn');
  assert.equal(snapshot.meta.logStatus,'denied');assert.equal(snapshot.logs.length,0);
});
test('daemon and socket evidence is constrained to installed paths',async t=>{
  const f=fixture(t);f.write('data/system/zygisk_study/zygiskd.pid','42\n');
  fs.mkdirSync(path.join(f.root,'proc/42'),{recursive:true});
  fs.symlinkSync(path.join(f.root,'data/adb/modules/zygisk_study/libs/arm64-v8a/zygiskd'),path.join(f.root,'proc/42/exe'));
  const endpoint=path.join(f.root,'data/system/zygisk_study/sock');
  const server=net.createServer();await new Promise(resolve=>server.listen(endpoint,resolve));
  try {
    f.write('data/adb/modules/zygisk_study/session.sock','/data/system/zygisk_study/sock\n');
    let snapshot=f.collect();assert.equal(status(snapshot,'daemon'),'pass');assert.equal(status(snapshot,'socket'),'pass');
    assert.ok(!JSON.stringify(snapshot).includes(endpoint));
    f.write('data/adb/modules/zygisk_study/session.sock','/data/system/zygisk_study/../zygisk_study/sock');
    snapshot=f.collect();assert.equal(status(snapshot,'socket'),'fail');
  } finally {await new Promise(resolve=>server.close(resolve));}
});
test('inventory cap is explicit and a maximal snapshot remains parseable',t=>{
  const f=fixture(t);
  for(let i=0;i<257;i++) {
    f.write(`data/adb/modules/m${i}/zygisk/arm64-v8a.so`);
    f.write(`data/adb/modules/m${i}/module.prop`,['name','author','description','version'].map(k=>`${k}=${'x'.repeat(1100)}`).join('\n'));
  }
  const snapshot=f.collect();assert.equal(snapshot.modules.length,256);
  assert.equal(status(snapshot,'inventory_limit'),'warn');
});

test('release assembly ships only four WebUI assets and verifier rejects missing/empty/broken assets',t=>{
  const f=fixture(t);
  const result=spawnSync('python3',['-c',String.raw`
import os, pathlib, shutil, subprocess, sys, zipfile
repo, root = map(pathlib.Path, sys.argv[1:])
source = (repo / 'scripts/build_module.sh').read_text()
assembly = 'assemble_module() {' + source.split('assemble_module() {',1)[1].split('\n}\n',1)[0] + '\n}\n'
verify = source[source.index('verify_zip() {'):source.index('# Drive the build')]
staging = root / 'staging'
env = {**os.environ, 'REPO_ROOT':str(repo), 'MODULE_DIR':str(staging), 'SCRIPT_DIR':str(repo/'scripts'),
       'VERSION_NAME':'test', 'VERSION_CODE':'1', 'TOOLCHAIN':str(root), 'TMPDIR':str(root)}
proc = subprocess.run(['bash','-c','set -euo pipefail; ABI_LIST=(); '+assembly+'\nassemble_module'],env=env,capture_output=True,text=True)
assert proc.returncode == 0, proc.stdout+proc.stderr
assets = ['index.html','app.js','styles.css','diagnostics.sh']
assert sorted(p.name for p in (staging/'webroot').iterdir()) == sorted(assets)
for name in assets:
    assert (staging/'webroot'/name).read_bytes() == (repo/'webroot'/name).read_bytes()
# ELF checks are covered by the existing archive suite; isolate the WebUI contract here.
verifier = root/'verifier'; verifier.mkdir(); (verifier/'verify.sh').write_text('#!/bin/sh\nexit 0\n')
env['REPO_ROOT']=str(verifier)
entries = {p.relative_to(staging).as_posix():p.read_bytes() for p in staging.rglob('*') if p.is_file()}
def check(contents, good, reason=''):
    archive=root/'fixture.zip'
    with zipfile.ZipFile(archive,'w') as z:
        for name,data in contents.items(): z.writestr(name,data)
    p=subprocess.run(['bash','-c','set -euo pipefail; ABI_LIST=(); '+verify+'\nverify_zip "$1"','verify',str(archive)],env=env,capture_output=True,text=True)
    assert (p.returncode == 0) == good, p.stdout+p.stderr
    if reason: assert reason in p.stdout+p.stderr, p.stdout+p.stderr
check(entries,True)
for name in assets:
    key='webroot/'+name
    missing=dict(entries);del missing[key];check(missing,False,key)
    empty=dict(entries);empty[key]=b'';check(empty,False,key)
broken=dict(entries);broken['webroot/diagnostics.sh']=b'if then\n';check(broken,False,'shell syntax error')
print('WebUI assembly and archive mutations passed')
`,repo,f.root],{encoding:'utf8',timeout:30000});
  assert.equal(result.status,0,result.stdout+result.stderr);
});
