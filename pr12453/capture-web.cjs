// Drives the checked-out Web UI against a real, normally paired local daemon.
// The only interception delays one outgoing PUT; no response is mocked.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs');
const assert=require('node:assert/strict');
const out=process.env.CAPTURE_DIR || __dirname;
fs.mkdirSync(out,{recursive:true});
const token=fs.readFileSync(process.env.BROWSER_TOKEN_FILE,'utf8').trim();
const base=process.env.WEB_ORIGIN || 'http://127.0.0.1:5178';
const observations=[];
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.BROWSER_EXECUTABLE,headless:true});
 try {
 for(const [name,width,height] of [['desktop',1440,1000],['mobile',390,844]]){
  if(process.env.CAPTURE_VIEWPORT && name!==process.env.CAPTURE_VIEWPORT)continue;
  const ctx=await browser.newContext({viewport:{width,height},locale:'en-US'});
  await ctx.addInitScript(t=>localStorage.setItem('zeroclaw_token',t),token);
  const page=await ctx.newPage();
  const errors=[]; page.on('pageerror',e=>errors.push(e.message));
  const headers={Authorization:`Bearer ${token}`};
  async function registry(){const r=await ctx.request.get(base+'/api/config/provider-registry',{headers});assert.equal(r.status(),200);return r.json()}
  async function put(expected,document){const r=await ctx.request.put(base+'/api/config/provider-registry',{headers,data:{expected,registry:document}});assert.equal(r.status(),200,await r.text())}
  const seed=await registry(), document=structuredClone(seed);
  document.models['chat.demo.gateway'].model='gpt-synthetic-before';
  document.models['chat.backup.prod']={capability:'chat',provider:'gateway.prod',model:'gpt-synthetic-backup'};
  await put(seed,document);
  await page.goto(base+'/config/providers.registry?model=chat.demo.gateway');
  const editor=page.getByRole('textbox',{name:'Models',exact:true});
  await editor.waitFor();assert.match(await editor.inputValue(),/chat\.demo\.gateway/);
  await page.screenshot({path:`${out}/${name}-registry-open.png`,fullPage:true});
  await page.getByRole('tab',{name:'Connections',exact:true}).click();
  const connections=await page.getByRole('textbox',{name:'Connections',exact:true}).inputValue();
  assert.match(connections,/\*{3,}/);assert(!connections.includes('synthetic-evidence-not-a-real-credential'));
  await page.screenshot({path:`${out}/${name}-connections-masked.png`,fullPage:true});
  await page.getByRole('tab',{name:'Models',exact:true}).click();
  let models=JSON.parse(await editor.inputValue());models['chat.demo.gateway'].model=`gpt-synthetic-saved-${name}`;
  await editor.fill(JSON.stringify(models,null,2));
  let release,seen; const hold=new Promise(r=>release=r), entered=new Promise(r=>seen=r);
  await page.route('**/api/config/provider-registry',async route=>{
   if(route.request().method()==='PUT'){seen();await hold;}await route.continue();
  });
  const response=page.waitForResponse(r=>r.url().endsWith('/api/config/provider-registry')&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Save registry',exact:true}).click();await entered;
  assert(await editor.isDisabled());assert(await page.getByRole('button',{name:'Save registry',exact:true}).isDisabled());
  assert(await page.getByRole('button',{name:'Reload registry',exact:true}).isDisabled());
  await page.screenshot({path:`${out}/${name}-save-pending.png`,fullPage:true});
  release();assert.equal((await response).status(),200);
  await page.waitForFunction(()=>!document.querySelector('textarea[aria-label="Models"]').disabled);
  await page.unroute('**/api/config/provider-registry');
  assert.equal((await registry()).models['chat.demo.gateway'].model,`gpt-synthetic-saved-${name}`);
  await page.screenshot({path:`${out}/${name}-save-persisted.png`,fullPage:true});
  const old=await registry(),concurrent=structuredClone(old);concurrent.models['chat.backup.prod'].model=`gpt-synthetic-concurrent-${name}`;
  await put(old,concurrent);
  models=JSON.parse(await editor.inputValue());models['chat.demo.gateway'].model=`gpt-synthetic-unsaved-${name}`;
  await editor.fill(JSON.stringify(models,null,2));
  const conflict=page.waitForResponse(r=>r.url().endsWith('/api/config/provider-registry')&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Save registry',exact:true}).click();assert.equal((await conflict).status(),400);
  await page.getByRole('alert').waitFor();const conflictText=await page.getByRole('alert').innerText();
  assert.match(conflictText,/conflict|changed|reload/i);assert.equal(JSON.parse(await editor.inputValue())['chat.demo.gateway'].model,`gpt-synthetic-unsaved-${name}`);
  assert.equal((await registry()).models['chat.demo.gateway'].model,`gpt-synthetic-saved-${name}`);
  await page.getByRole('button',{name:'Save registry',exact:true}).scrollIntoViewIfNeeded();
  await page.screenshot({path:`${out}/${name}-concurrent-conflict.png`,fullPage:true});
  page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Reload registry',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('textarea[aria-label="Models"]')?.value.includes('gpt-synthetic-saved'));
  await page.goto(base+'/quickstart');
  await page.locator('select:has(option[value="chat.demo.gateway"])').selectOption('chat.demo.gateway',{timeout:60000});
  assert.match(await page.locator('body').innerText(),/chat\.demo\.gateway/);
  await page.getByRole('heading',{name:'Model',exact:true}).scrollIntoViewIfNeeded();
  await page.screenshot({path:`${out}/${name}-quickstart-existing.png`,fullPage:true});
  await page.getByRole('button',{name:/^Balanced/}).filter({hasText:'Trusted daily driver'}).click();
  await page.getByRole('button',{name:'none',exact:true}).click();
  const agent=`evidence_web_${name}`;await page.getByRole('textbox',{name:'Name',exact:true}).fill(agent);
  const create=page.getByRole('button',{name:'Create',exact:true});assert(await create.isEnabled());
  await page.screenshot({path:`${out}/${name}-quickstart-ready.png`,fullPage:true});
  const applied=page.waitForResponse(r=>r.url().endsWith('/api/quickstart/apply')&&r.request().method()==='POST');
  await create.click();const appliedResponse=await applied;assert.equal(appliedResponse.status(),200,await appliedResponse.text());
  const result=await appliedResponse.json();assert.notEqual(result.kind,'errors',JSON.stringify(result));
  await page.goto(base+'/agent/'+agent);await page.getByRole('button',{name:'chat.demo.gateway',exact:true}).waitFor({timeout:60000});
  await page.getByRole('button',{name:'chat.demo.gateway',exact:true}).click();
  await page.screenshot({path:`${out}/${name}-agent-picker.png`,fullPage:true});
  const choice=page.getByRole('button',{name:'chat.backup.prod',exact:true});
  if(await choice.count())await choice.click();else await page.getByRole('option',{name:/chat\.backup\.prod/}).click();
  await page.getByRole('button',{name:'chat.backup.prod',exact:true}).waitFor();
  await page.screenshot({path:`${out}/${name}-agent-switched.png`,fullPage:true});
  assert.deepEqual(errors,[]);
  observations.push({browser:browser.version(),viewport:{name,width,height},openedExactKey:'chat.demo.gateway',credentialsMasked:true,pendingPut:{responseMocked:false,editorDisabled:true,saveDisabled:true,reloadDisabled:true},savedModel:`gpt-synthetic-saved-${name}`,conflict:{status:400,draftRetained:true,persistedModelPreserved:true,message:conflictText},quickstart:{selection:'chat.demo.gateway',status:200,result},agentSwitch:'chat.backup.prod',pageErrors:errors});
  fs.writeFileSync(out+'/observations.json',JSON.stringify(observations,null,2)+'\n');
  await ctx.close();console.log(name,'completed');
 }
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
