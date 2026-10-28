'use strict';
/* MIB Gold alert server: runs the SAME MIB engine as the dashboard (extracted from index.html) on real PAXG/USDT candles,
   and sends Web Push notifications for NEW CONFIRMED signals. No private keys ever reach the browser. */
const http=require('http'),https=require('https'),fs=require('fs'),path=require('path'),vm=require('vm'),crypto=require('crypto');
const b64u=b=>Buffer.from(b).toString('base64url');
const SEC={'1m':60,'5m':300,'15m':900,'30m':1800};

/* ---------------- engine: loaded from the dashboard file so strategy lives in ONE place ---------------- */
function loadEngine(htmlPath){
  const html=fs.readFileSync(htmlPath,'utf8');
  const a=html.indexOf('// ==ENGINE=='),b=html.indexOf('// ==/ENGINE==');
  if(a<0||b<0) throw new Error('ENGINE markers not found in '+htmlPath);
  const ctx=vm.createContext({candles:[],tf:'5m',console});
  return vm.runInContext(html.slice(a,b)+'\n;({scanSignals,calcMACD,findSwings,findStructure})',ctx,{timeout:5000});
}

/* ---------------- Web Push (RFC 8291 aes128gcm + RFC 8292 VAPID), built on node:crypto ---------------- */
function vapidFromSeed(seed){
  const priv=crypto.createHash('sha256').update(seed).digest();
  const e=crypto.createECDH('prime256v1'); e.setPrivateKey(priv);
  return {priv:b64u(priv),pub:b64u(e.getPublicKey())};
}
function vapidJWT(aud,subject,v){
  const pub=Buffer.from(v.pub,'base64url'),key=crypto.createPrivateKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:b64u(pub.subarray(1,33)),y:b64u(pub.subarray(33,65)),d:v.priv}});
  const h=b64u(JSON.stringify({typ:'JWT',alg:'ES256'})),c=b64u(JSON.stringify({aud,exp:Math.floor(Date.now()/1000)+12*3600,sub:subject}));
  const sig=crypto.sign('sha256',Buffer.from(h+'.'+c),{key,dsaEncoding:'ieee-p1363'});
  return h+'.'+c+'.'+b64u(sig);
}
const hmac=(k,d)=>crypto.createHmac('sha256',k).update(d).digest();
function encryptPayload(sub,plain){
  const ua=Buffer.from(sub.keys.p256dh,'base64url'),auth=Buffer.from(sub.keys.auth,'base64url'),salt=crypto.randomBytes(16);
  const as=crypto.createECDH('prime256v1'); as.generateKeys(); const asPub=as.getPublicKey(),secret=as.computeSecret(ua);
  const ikm=hmac(hmac(auth,secret),Buffer.concat([Buffer.from('WebPush: info\0'),ua,asPub,Buffer.from([1])]));
  const prk=hmac(salt,ikm),cek=hmac(prk,Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'),Buffer.from([1])])).subarray(0,16),nonce=hmac(prk,Buffer.concat([Buffer.from('Content-Encoding: nonce\0'),Buffer.from([1])])).subarray(0,12);
  const ci=crypto.createCipheriv('aes-128-gcm',cek,nonce),ct=Buffer.concat([ci.update(Buffer.concat([Buffer.from(plain),Buffer.from([2])])),ci.final(),ci.getAuthTag()]);
  const rs=Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt,rs,Buffer.from([65]),asPub,ct]);
}
function nativeSend(sub,payload,o){
  return new Promise(resolve=>{
    let u; try{ u=new URL(sub.endpoint); }catch(e){ return resolve({status:0,err:'bad endpoint'}); }
    const body=encryptPayload(sub,payload);
    const req=https.request({method:'POST',hostname:u.hostname,port:u.port||443,path:u.pathname+u.search,rejectUnauthorized:process.env.PUSH_INSECURE_TEST!=='1',timeout:12000,headers:{
      'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream','Content-Length':body.length,TTL:String(o.ttl||600),Urgency:o.urgency||'high',
      Authorization:'vapid t='+vapidJWT(u.origin,o.subject,o.vapid)+', k='+o.vapid.pub}},res=>{ res.resume(); res.on('end',()=>resolve({status:res.statusCode})); });
    req.on('timeout',()=>{ req.destroy(new Error('timeout')); }); req.on('error',e=>resolve({status:0,err:e.message}));
    req.end(body);
  });
}
let lib=null; try{ if(process.env.PUSH_IMPL!=='native') lib=require('web-push'); }catch(e){}
async function sendPush(sub,payload,o){
  if(lib){   // audited library when installed (Render runs npm install); node:crypto implementation is the fallback
    try{ lib.setVapidDetails(o.subject,o.vapid.pub,o.vapid.priv); const r=await lib.sendNotification(sub,payload,{TTL:o.ttl||600,urgency:o.urgency||'high'}); return {status:r.statusCode}; }
    catch(e){ return {status:e.statusCode||0,err:e.message}; }
  }
  return nativeSend(sub,payload,o);
}

/* ---------------- storage: file (ephemeral on free hosts) + optional Upstash Redis for persistence ---------------- */
function makeStore(dir,env){
  const file=path.join(dir,'state.json'),U=env.UPSTASH_REDIS_REST_URL,T=env.UPSTASH_REDIS_REST_TOKEN;
  let st={subs:{},sent:[]},t=0;
  async function up(cmd){ try{ const r=await fetch(U,{method:'POST',headers:{Authorization:'Bearer '+T},body:JSON.stringify(cmd)}); return (await r.json()).result; }catch(e){ return null; } }
  return {
    get state(){ return st; },
    async load(){
      try{ if(U){ const v=await up(['GET','mib_state']); if(v) st=JSON.parse(v); } else st=JSON.parse(fs.readFileSync(file,'utf8')); }catch(e){}
      st.subs=st.subs||{}; st.sent=Array.isArray(st.sent)?st.sent:[];
    },
    save(){ clearTimeout(t); t=setTimeout(async()=>{ st.sent=st.sent.slice(-500); const s=JSON.stringify(st); try{ if(U) await up(['SET','mib_state',s]); else { fs.mkdirSync(dir,{recursive:true}); fs.writeFileSync(file,s); } }catch(e){ console.error('save failed',e.message); } },300); }
  };
}

/* ---------------- market feed (Binance PAXG/USDT klines, same source as the dashboard) ---------------- */
function makeFeed(env){
  const hosts=(env.DATA_HOSTS||'https://data-api.binance.vision,https://api.binance.com').split(','),pair=env.PAIR||'PAXGUSDT';
  return async function fetchKlines(tf){
    let err='';
    for(const h of hosts){
      try{
        const c=new AbortController(),t=setTimeout(()=>c.abort(),8000),r=await fetch(`${h}/api/v3/klines?symbol=${pair}&interval=${tf}&limit=500`,{signal:c.signal}); clearTimeout(t);
        if(!r.ok){ err=h+' HTTP '+r.status; continue; }
        const j=await r.json(); if(!Array.isArray(j)||j.length<100){ err=h+' too few candles'; continue; }
        return j.map(k=>({t:Math.floor(k[0]/1000),open:+k[1],high:+k[2],low:+k[3],close:+k[4],v:+k[5],tb:+k[9]}));
      }catch(e){ err=h+' '+e.message; }
    }
    throw new Error(err||'no data');
  };
}
function validateCandles(c){
  if(!Array.isArray(c)||c.length<100) return 'too few candles';
  for(const x of c){ if(![x.t,x.open,x.high,x.low,x.close].every(Number.isFinite)||x.high<x.low||x.close<=0) return 'invalid candle'; }
  for(let i=1;i<c.length;i++) if(c[i].t<=c[i-1].t) return 'candles out of order';
  return '';
}
function feedHealth(c,tf,now){          // LIVE / STALE with a reason; STALE blocks signal generation
  const sec=SEC[tf],n=c.length,last=c[n-1];
  if((now/1000)-(last.t+sec)>Math.max(90,sec*0.25)) return {state:'STALE',why:'newest candle is old'};
  for(let i=Math.max(1,n-31);i<n;i++) if(c[i].t-c[i-1].t!==sec) return {state:'STALE',why:'missing candles'};
  return {state:'LIVE',why:''};
}

/* ---------------- the app ---------------- */
function createApp(o){
  const env=o.env||process.env,engine=o.engine,fetchKlines=o.fetchKlines,send=o.send||sendPush,now=o.now||(()=>Date.now());
  const seed=env.VAPID_SEED; let vapid,ephemeral=false;
  if(seed) vapid=vapidFromSeed(seed); else { const e=crypto.createECDH('prime256v1'); e.generateKeys(); vapid={priv:b64u(e.getPrivateKey()),pub:b64u(e.getPublicKey())}; ephemeral=true; console.warn('WARNING: VAPID_SEED not set: using temporary keys; phones must re-register after every restart.'); }
  const subject=env.VAPID_SUBJECT||'mailto:admin@example.com',store=o.store||makeStore(env.DATA_DIR||path.join(__dirname,'data'),env);
  const tfs=(env.TFS||'1m,5m,15m,30m').split(',').filter(x=>SEC[x]),feed={},signals=[],log=[];
  tfs.forEach(tf=>feed[tf]={state:'CONNECTING',why:'',lastOk:0,lastScanKey:0,err:''});
  const say=m=>{ log.push(new Date(now()).toISOString()+' '+m); if(log.length>80) log.shift(); if(!o.quiet) console.log(m); };
  const hostOK=u=>{ try{ const x=new URL(u); return x.protocol==='https:'&&(env.ALLOW_ANY_PUSH_HOST==='1'||/(^|\.)(fcm\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$/.test(x.hostname)); }catch(e){ return false; } };
  const validSub=s=>s&&typeof s.endpoint==='string'&&s.endpoint.length<600&&hostOK(s.endpoint)&&s.keys&&typeof s.keys.p256dh==='string'&&typeof s.keys.auth==='string'&&Buffer.from(s.keys.p256dh,'base64url').length===65&&Buffer.from(s.keys.auth,'base64url').length===16;
  const sid=ep=>crypto.createHash('sha256').update(ep).digest('hex').slice(0,24);
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));

  /* ---- Telegram bot (optional): set TELEGRAM_BOT_TOKEN. Alerts go to every chat that sent /start (or is listed in TELEGRAM_CHAT_ID) ---- */
  const token=env.TELEGRAM_BOT_TOKEN||'';
  const tg=o.tg||(token?{call:async(method,params,timeout)=>{ const c=new AbortController(),t=setTimeout(()=>c.abort(),timeout||15000);
      try{ const r=await fetch('https://api.telegram.org/bot'+token+'/'+method,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(params||{}),signal:c.signal}); clearTimeout(t); const j=await r.json().catch(()=>({})); return {ok:r.ok&&j.ok!==false,status:r.status,json:j}; }
      catch(e){ clearTimeout(t); return {ok:false,status:0,err:e.message}; } }}:null);
  const envChats=(env.TELEGRAM_CHAT_ID||'').split(',').map(x=>x.trim()).filter(Boolean);
  const chatDefaults=()=>({tfs:(env.TELEGRAM_TFS||'5m').split(',').filter(x=>SEC[x]),buy:true,sell:true,offset:0,tz:0});
  const tgState=()=>{ const st=store.state; st.tg=st.tg||{chats:{}}; st.tg.chats=st.tg.chats||{}; envChats.forEach(id=>{ if(!st.tg.chats[id]) st.tg.chats[id]=chatDefaults(); }); return st.tg; };
  const lastClose={};
  const pad=n=>String(n).padStart(2,'0');
  function tgTime(ms,tz){ const d=new Date(ms+tz*3600000); return d.getUTCDate()+' '+['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()]+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+' (UTC'+(tz>=0?'+':'')+tz+')'; }
  function tgText(sg,c){
    const off=Number.isFinite(c.offset)?c.offset:0,f=v=>(v+off).toFixed(2),B=sg.dir>0?'BUY':'SELL';
    return (sg.dir>0?'🟢 ':'🔴 ')+B+' CONFIRMED — XAUUSD '+sg.tf.toUpperCase().replace(/^(\d+)M$/,'M$1')+'\nEntry: '+f(sg.entry)+'\nStop-loss: '+f(sg.sl)+'\nTake-profit: '+(sg.tp!=null?f(sg.tp)+' (live MSS exit)':'live — exits at the first opposite MSS (none set yet)')+'\nSignal time: '+tgTime(sg.t,c.tz||0);
  }
  async function tgSend(chatId,text){
    const delays=o.retryDelays||[1500,5000];
    for(let a=0;a<=delays.length;a++){
      const r=await tg.call('sendMessage',{chat_id:chatId,text,disable_web_page_preview:true});
      if(r.ok) return 'ok';
      if(r.status===403||r.status===400&&/chat not found|blocked/i.test(JSON.stringify(r.json||''))){ delete tgState().chats[chatId]; store.save(); say('telegram chat removed'); return 'removed'; }
      if(a<delays.length) await sleep(r.status===429?Math.min(10000,((r.json&&r.json.parameters&&r.json.parameters.retry_after)||2)*1000):delays[a]); else say('telegram send failed '+(r.status||r.err));
    }
    return 'failed';
  }
  async function tgBroadcast(sg){
    if(!tg) return 0; let n=0;
    if(!(Number.isFinite(sg.entry)&&Number.isFinite(sg.sl)&&(sg.dir>0?sg.sl<sg.entry:sg.sl>sg.entry))) return 0;
    for(const [id,c] of Object.entries(tgState().chats)){
      if(!(sg.dir>0?c.buy:c.sell)||!(c.tfs||[]).includes(sg.tf)) continue;
      if(await tgSend(id,tgText(sg,c))==='ok') n++;
    }
    return n;
  }
  /* ---- ntfy (optional, no account): set NTFY_TOPIC to a long secret word; install the free ntfy app and subscribe to the same topic ---- */
  const topic=(env.NTFY_TOPIC||'').trim(),ntfyBase=(env.NTFY_SERVER||'https://ntfy.sh').replace(/\/+$/,'');
  const ntfyOK=/^[A-Za-z0-9_-]{8,64}$/.test(topic),ntfyPost=o.ntfyPost||(async body=>{ const c=new AbortController(),t=setTimeout(()=>c.abort(),12000);
    try{ const r=await fetch(ntfyBase,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:c.signal}); clearTimeout(t); return {ok:r.ok,status:r.status}; }catch(e){ clearTimeout(t); return {ok:false,status:0,err:e.message}; } });
  const ntfyState=()=>{ const st=store.state; st.ntfy=st.ntfy||{offset:0}; return st.ntfy; };
  const ntfyCfg=()=>({offset:ntfyState().offset||0,tz:Number.isFinite(+env.NTFY_TZ)?+env.NTFY_TZ:0});
  async function ntfySend(title,message){
    const delays=o.retryDelays||[1500,5000];
    for(let a=0;a<=delays.length;a++){
      const r=await ntfyPost({topic,title,message,priority:4,tags:['chart_with_upwards_trend']});
      if(r.ok) return 'ok'; if(r.status===400||r.status===401||r.status===403){ say('ntfy rejected '+r.status); return 'rejected'; }
      if(a<delays.length) await sleep(delays[a]); else say('ntfy send failed '+(r.status||r.err));
    }
    return 'failed';
  }
  async function ntfyBroadcast(sg){
    if(!ntfyOK) return 0;
    if(!(Number.isFinite(sg.entry)&&Number.isFinite(sg.sl)&&(sg.dir>0?sg.sl<sg.entry:sg.sl>sg.entry))) return 0;
    const tfs=(env.NTFY_TFS||'5m').split(',');
    if(!tfs.includes(sg.tf)||(sg.dir>0&&env.NTFY_BUY==='off')||(sg.dir<0&&env.NTFY_SELL==='off')) return 0;
    const lines=tgText(sg,ntfyCfg()).split('\n');
    return (await ntfySend(lines[0],lines.slice(1).join('\n')))==='ok'?1:0;
  }
  const HELP='MIB Gold alerts\n/tf 5m 15m — timeframes (1m 5m 15m 30m)\n/buy on|off · /sell on|off\n/sync 4036.5 — type your MT5 price so alerts match MT5\n/tz 1 — your time zone offset (Lagos = 1)\n/status · /test · /stop';
  async function tgCommand(msg){
    const id=String(msg.chat.id),text=(msg.text||'').trim(),[cmd0,...args]=text.split(/\s+/),cmd=(cmd0||'').split('@')[0].toLowerCase();
    const reply=t=>tg.call('sendMessage',{chat_id:id,text:t});
    if(cmd==='/id') return reply('Your chat id: '+id+(envChats.length&&!envChats.includes(id)?'\n(not authorised on this server)':''));
    if(envChats.length&&!envChats.includes(id)) return;                      // private server: only listed chats may use it
    const st=tgState(),c=st.chats[id];
    if(cmd==='/start'){ if(!c){ st.chats[id]=chatDefaults(); store.save(); } return reply('✅ Alerts on. You will get NEW CONFIRMED XAUUSD signals only (never developing ones).\nChat id: '+id+'\n\n'+HELP+'\n\nTip: set TELEGRAM_CHAT_ID='+id+' on the server so this survives restarts.'); }
    if(!c) return reply('Send /start first.');
    if(cmd==='/stop'){ delete st.chats[id]; store.save(); return reply('Alerts stopped. Send /start to turn them on again.'); }
    if(cmd==='/tf'){ const t=args.map(x=>x.toLowerCase()).filter(x=>SEC[x]); if(!t.length) return reply('Use: /tf 5m 15m (choices: 1m 5m 15m 30m)'); c.tfs=[...new Set(t)]; store.save(); return reply('Timeframes: '+c.tfs.join(', ')); }
    if(cmd==='/buy'||cmd==='/sell'){ const v=(args[0]||'').toLowerCase(); if(v!=='on'&&v!=='off') return reply('Use: '+cmd+' on  or  '+cmd+' off'); c[cmd.slice(1)]=v==='on'; store.save(); return reply(cmd.slice(1).toUpperCase()+' alerts '+v.toUpperCase()); }
    if(cmd==='/tz'){ const z=parseFloat(args[0]); if(!Number.isFinite(z)||Math.abs(z)>14) return reply('Use: /tz 1  (hours from UTC)'); c.tz=z; store.save(); return reply('Time zone UTC'+(z>=0?'+':'')+z); }
    if(cmd==='/sync'){
      const px=parseFloat(args[0]),tfk=Object.keys(lastClose).find(k=>feed[k]&&feed[k].state==='LIVE');
      if(args[0]&&['reset','0'].includes(args[0].toLowerCase())){ c.offset=0; store.save(); return reply('Price sync cleared.'); }
      if(!Number.isFinite(px)||px<=0) return reply('Use: /sync 4036.50  (the gold price you see in MT5 right now)');
      if(!tfk) return reply('Market data is not live right now, try again in a minute.');
      c.offset=px-lastClose[tfk]; store.save(); return reply('Synced. Alerts will now use your MT5 price scale (offset '+(c.offset>=0?'+':'')+c.offset.toFixed(2)+').');
    }
    if(cmd==='/status') return reply('Feed: '+tfs.map(t=>t+' '+feed[t].state).join(' · ')+'\nTimeframes: '+c.tfs.join(', ')+'\nBUY '+(c.buy?'on':'off')+' · SELL '+(c.sell?'on':'off')+'\nOffset: '+(c.offset||0).toFixed(2)+' · UTC'+((c.tz||0)>=0?'+':'')+(c.tz||0));
    if(cmd==='/test') return reply('🧪 TEST ONLY — not a trading signal. Telegram alerts are working. No entry, stop-loss or take-profit here.');
    return reply(HELP);
  }
  let tgOff=0,tgRun=false;
  async function tgPoll(){
    if(!tg||tgRun) return; tgRun=true;
    await tg.call('deleteWebhook',{});
    while(tgRun){
      const r=await tg.call('getUpdates',{offset:tgOff,timeout:25,allowed_updates:['message']},35000);
      if(!r.ok){ await sleep(o.tgErrorDelay||5000); continue; }
      for(const u of (r.json&&r.json.result)||[]){ tgOff=u.update_id+1; try{ if(u.message&&u.message.chat&&u.message.text) await tgCommand(u.message); }catch(e){ say('telegram command error '+e.message); } }
      if(o.tgOnce) break;
    }
    tgRun=false;
  }

  async function deliver(id,payload){          // retries transient failures, drops dead subscriptions
    const s=store.state.subs[id]; if(!s) return 'gone';
    const delays=o.retryDelays||[1500,5000];
    for(let a=0;a<=delays.length;a++){
      const r=await send(s.sub,JSON.stringify(payload),{vapid,subject,ttl:payload.test?120:600,urgency:'high'});
      if(r.status>=200&&r.status<300){ s.lastOk=now(); s.fails=0; store.save(); return 'ok'; }
      if(r.status===404||r.status===410){ delete store.state.subs[id]; store.save(); say('subscription expired, removed'); return 'expired'; }
      if(r.status===400||r.status===401||r.status===403){ say('push rejected '+r.status+' '+(r.err||'')); s.fails=(s.fails||0)+1; return 'rejected'; }
      if(a<delays.length) await sleep(delays[a]); else { s.fails=(s.fails||0)+1; say('push failed after retries: '+(r.status||r.err)); }
    }
    return 'failed';
  }
  async function broadcast(sg){
    let sent=0;
    for(const [id,s] of Object.entries(store.state.subs)){
      const p=s.prefs||{}; if(!(sg.dir>0?p.buy:p.sell)||!(p.tfs||[]).includes(sg.tf)) continue;
      const off=Number.isFinite(s.offset)?s.offset:0;
      const pl={id:sg.id,sym:'XAUUSD',tf:sg.tf,dir:sg.dir,entry:sg.entry+off,sl:sg.sl+off,tp:sg.tp!=null?sg.tp+off:null,t:sg.t,dec:2,silent:p.sound===false,test:false};
      if(!(Number.isFinite(pl.entry)&&Number.isFinite(pl.sl)&&(pl.dir>0?pl.sl<pl.entry:pl.sl>pl.entry))){ say('invalid signal values, not sent'); continue; }
      if(await deliver(id,pl)==='ok') sent++;
    }
    sent+=await tgBroadcast(sg); sent+=await ntfyBroadcast(sg);
    sg.sent=sent; return sent;
  }
  async function processTf(tf){
    const f=feed[tf],sec=SEC[tf];
    let c; try{ c=await fetchKlines(tf); const bad=validateCandles(c); if(bad) throw new Error(bad); }
    catch(e){ f.err=e.message; f.state=(now()-f.lastOk>Math.max(120000,sec*2000))?'OFFLINE':'STALE'; f.why='data fetch failed: '+e.message; return; }
    f.err=''; lastClose[tf]=c[c.length-1].close; const h=feedHealth(c,tf,now()); f.state=h.state; f.why=h.why; f.lastOk=now(); f.lastT=c[c.length-1].t;
    if(h.state!=='LIVE') return;                                   // never generate signals from stale or incomplete data
    const n=c.length,key=c[n-2].t; if(f.lastScanKey===key) return; f.lastScanKey=key;
    const sigs=engine.scanSignals(c);                              // same code as the chart; each bar only uses data up to itself
    for(const s of sigs){
      if(s.i<n-3) continue;                                        // only the latest closed candles can be new
      const ct=c[s.i].t,id='XAUUSD|'+tf+'|'+ct+'|'+(s.dir>0?'BUY':'SELL');
      if(store.state.sent.includes(id)) continue;
      store.state.sent.push(id); store.save();                     // at-most-once per signal id, even across restarts
      const closeMs=(ct+sec)*1000,sg={id,tf,dir:s.dir,entry:s.entry,sl:s.sl,tp:s.tp,t:closeMs,detected:now(),sent:0};
      signals.unshift(sg); signals.length=Math.min(signals.length,50);
      if(now()-closeMs>2*sec*1000+10000){ sg.late=true; say('signal '+id+' detected too late, not sent'); continue; }
      say('NEW '+id+' entry '+s.entry+' sl '+s.sl); await broadcast(sg);
    }
  }
  let timers=[];
  function start(){ tgPoll(); tfs.forEach((tf,i)=>{ let run=false; const go=async()=>{ if(run) return; run=true; try{ await processTf(tf); }catch(e){ say('loop error '+e.message); } run=false; }; timers.push(setTimeout(()=>{ go(); timers.push(setInterval(go,+(env.POLL_MS||10000))); },i*1500)); }); }
  function stop(){ tgRun=false; timers.forEach(t=>{clearTimeout(t);clearInterval(t);}); timers=[]; }
  const headline=()=>feed[feed['5m']?'5m':tfs[0]];

  /* ---- HTTP ---- */
  const STATIC={'/':'index.html','/index.html':'index.html','/sw.js':'sw.js','/manifest.webmanifest':'manifest.webmanifest','/icon-192.png':'icon-192.png','/icon-512.png':'icon-512.png'};
  const MIME={html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',webmanifest:'application/manifest+json',png:'image/png'};
  const hits=new Map();
  const limited=ip=>{ const t=Math.floor(now()/60000),h=hits.get(ip); if(!h||h.t!==t){ hits.set(ip,{t,n:1}); if(hits.size>5000) hits.clear(); return false; } return ++h.n>90; };
  const J=(res,code,obj)=>{ const b=JSON.stringify(obj); res.writeHead(code,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Cache-Control':'no-store'}); res.end(b); };
  const readBody=req=>new Promise((ok,no)=>{ let b='',n=0; req.on('data',d=>{ n+=d.length; if(n>16384){ no(new Error('too large')); req.destroy(); } else b+=d; }); req.on('end',()=>{ try{ ok(JSON.parse(b||'{}')); }catch(e){ no(new Error('bad json')); } }); req.on('error',no); });
  const lastTest=new Map();
  const handler=async(req,res)=>{
    const u=new URL(req.url,'http://x'),p=u.pathname;
    if(req.method==='OPTIONS'){ res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'600'}); return res.end(); }
    const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
    if(p.startsWith('/api/')&&p!=='/api/health'&&limited(ip)) return J(res,429,{error:'slow down'});
    try{
      if(STATIC[p]&&req.method==='GET'){ const f=STATIC[p],buf=fs.readFileSync(path.join(__dirname,f)); res.writeHead(200,{'Content-Type':MIME[f.split('.').pop()]||'application/octet-stream','Cache-Control':f==='sw.js'||f==='index.html'?'no-cache':'public, max-age=3600'}); return res.end(buf); }
      if(p==='/api/health') return J(res,200,{ok:true,uptime:Math.round(process.uptime()),subs:Object.keys(store.state.subs).length,feed:Object.fromEntries(tfs.map(t=>[t,{state:feed[t].state,why:feed[t].why,lastCandle:feed[t].lastT||null}])),ephemeralKeys:ephemeral,telegram:!!tg,telegramChats:tg?Object.keys(tgState().chats).length:0,ntfy:ntfyOK});
      if(p==='/api/vapid') return J(res,200,{key:vapid.pub,feed:{state:headline().state,why:headline().why}});
      if(p==='/api/signals') return J(res,200,{signals:signals.map(s=>({id:s.id,tf:s.tf,dir:s.dir,t:s.t,sent:s.sent,late:!!s.late})),log:log.slice(-20)});
      if(p==='/api/ntfy-test'||p==='/api/sync'){      // the secret topic acts as the password
        if(!ntfyOK||u.searchParams.get('topic')!==topic) return J(res,403,{error:'wrong topic'});
        if(p==='/api/ntfy-test'){ const r=await ntfySend('🧪 TEST ONLY — not a trading signal','ntfy alerts are working. No entry, stop-loss or take-profit here.'); return J(res,r==='ok'?200:502,{ok:r==='ok'}); }
        const px=parseFloat(u.searchParams.get('price')),k=Object.keys(lastClose).find(t=>feed[t]&&feed[t].state==='LIVE');
        if(u.searchParams.get('price')==='reset'){ ntfyState().offset=0; store.save(); return J(res,200,{ok:true,offset:0}); }
        if(!Number.isFinite(px)||px<=0) return J(res,400,{error:'use price=4036.5'});
        if(!k) return J(res,503,{error:'market data not live right now'});
        ntfyState().offset=px-lastClose[k]; store.save(); return J(res,200,{ok:true,offset:+ntfyState().offset.toFixed(2)});
      }
      if(p==='/api/subscribe'&&req.method==='POST'){
        const b=await readBody(req); if(!validSub(b.subscription)) return J(res,400,{error:'invalid subscription'});
        const id=sid(b.subscription.endpoint),cur=store.state.subs[id];
        if(!cur&&Object.keys(store.state.subs).length>=+(env.MAX_SUBS||100)) return J(res,503,{error:'subscription limit reached'});
        const pr=b.prefs||{};
        store.state.subs[id]={sub:{endpoint:b.subscription.endpoint,keys:{p256dh:b.subscription.keys.p256dh,auth:b.subscription.keys.auth}},prefs:{buy:pr.buy!==false,sell:pr.sell!==false,sound:pr.sound!==false,tfs:(Array.isArray(pr.tfs)?pr.tfs:['5m']).filter(x=>SEC[x])},offset:Number.isFinite(+b.offset)&&Math.abs(+b.offset)<2000?+b.offset:0,created:cur?cur.created:now(),lastOk:cur?cur.lastOk:0,fails:0};
        store.save(); return J(res,200,{ok:true,id});
      }
      if(p==='/api/unsubscribe'&&req.method==='POST'){ const b=await readBody(req); delete store.state.subs[sid(String(b.endpoint||''))]; store.save(); return J(res,200,{ok:true}); }
      if(p==='/api/test'&&req.method==='POST'){
        const b=await readBody(req),id=sid(String(b.endpoint||'')); if(!store.state.subs[id]) return J(res,404,{error:'not subscribed'});
        if(now()-(lastTest.get(id)||0)<5000) return J(res,429,{error:'wait a few seconds'}); lastTest.set(id,now());
        const r=await deliver(id,{test:true,silent:store.state.subs[id]?.prefs?.sound===false});
        return J(res,r==='ok'?200:502,{ok:r==='ok',result:r});
      }
      J(res,404,{error:'not found'});
    }catch(e){ J(res,400,{error:e.message}); }
  };
  return {handler,start,stop,feed,signals,store,vapid,processTf,deliver,broadcast,log,tgCommand,tgPoll,tgText};
}

module.exports={createApp,loadEngine,makeStore,makeFeed,vapidFromSeed,vapidJWT,encryptPayload,validateCandles,feedHealth,SEC};

if(require.main===module){
  (async()=>{
    const engine=loadEngine(path.join(__dirname,'index.html')),store=makeStore(process.env.DATA_DIR||path.join(__dirname,'data'),process.env);
    await store.load();
    const app=createApp({engine,fetchKlines:makeFeed(process.env),store});
    const port=+process.env.PORT||8080;
    http.createServer(app.handler).listen(port,()=>console.log('MIB Gold server on :'+port+' ('+(lib?'web-push library':'built-in push')+')'));
    app.start();
    if(process.env.RENDER_EXTERNAL_URL) setInterval(()=>{ fetch(process.env.RENDER_EXTERNAL_URL+'/api/health').catch(()=>{}); },10*60*1000);
  })();
}
