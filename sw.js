/* MIB Gold service worker: shows push notifications (even when the app is closed) + offline app shell */
const VER='mib-v1',SHELL=['./','index.html','manifest.webmanifest','icon-192.png'];
self.addEventListener('install',e=>{ e.waitUntil(caches.open(VER).then(c=>c.addAll(SHELL)).catch(()=>{}).then(()=>self.skipWaiting())); });
self.addEventListener('activate',e=>{ e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==VER).map(k=>caches.delete(k)))).then(()=>self.clients.claim())); });
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/')) return;
  e.respondWith(fetch(e.request).then(r=>{ const c=r.clone(); caches.open(VER).then(x=>x.put(e.request,c)).catch(()=>{}); return r; }).catch(()=>caches.match(e.request).then(r=>r||caches.match('./'))));
});
function idb(){ return new Promise((res,rej)=>{ const r=indexedDB.open('mib',1); r.onupgradeneeded=()=>r.result.createObjectStore('hist',{keyPath:'k'}); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function histAdd(o){ try{ const db=await idb(); o.k=String(o.at).padStart(14,'0')+'|'+(o.id||''); await new Promise((res,rej)=>{ const tx=db.transaction('hist','readwrite'),st=tx.objectStore('hist'); st.put(o); const kq=st.getAllKeys(); kq.onsuccess=()=>{ const ks=kq.result.sort(); while(ks.length>100) st.delete(ks.shift()); }; tx.oncomplete=res; tx.onerror=()=>rej(tx.error); }); }catch(e){} }
function note(d){
  if(d.test) return {title:'TEST ONLY — MIB GOLD (not a trading signal)',opts:{body:'Notification setup works. This is a test: it contains no real entry, stop-loss or take-profit.',tag:'mib-test',renotify:true,silent:!!d.silent,vibrate:[120,60,120],icon:'icon-192.png',badge:'icon-192.png',data:{url:'./'}}};
  const dec=d.dec!=null?d.dec:2,f=v=>Number(v).toFixed(dec),T='M'+String(d.tf).replace('m',''),B=d.dir>0?'BUY':'SELL';
  const when=new Date(d.t).toLocaleString([], {day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
  const tp=d.tp!=null?f(d.tp)+' (live MSS exit)':'live — exits at the first opposite MSS (none set yet)';
  return {title:'MIB GOLD ALERT · '+d.sym+' '+T+' — '+B+' CONFIRMED',opts:{body:'Entry: '+f(d.entry)+'\nStop-loss: '+f(d.sl)+'\nTake-profit: '+tp+'\nSignal time: '+when,tag:d.id,renotify:false,requireInteraction:true,silent:!!d.silent,vibrate:[200,100,200,100,200],icon:'icon-192.png',badge:'icon-192.png',timestamp:d.t,data:{url:'./',id:d.id}}};
}
function valid(d){ return d&&(d.test||((d.dir===1||d.dir===-1)&&[d.entry,d.sl,d.t].every(Number.isFinite)&&d.entry>0&&d.sl>0&&(d.dir>0?d.sl<d.entry:d.sl>d.entry)&&(d.tp==null||Number.isFinite(d.tp))&&typeof d.id==='string'&&d.sym)); }
self.addEventListener('push',e=>{
  let d=null; try{ d=e.data?e.data.json():null; }catch(x){}
  e.waitUntil((async()=>{
    if(!valid(d)){   // never show invented numbers; Chrome still requires a visible notification
      await self.registration.showNotification('MIB GOLD: alert data incomplete',{body:'A signal arrived with missing or invalid values, so no prices are shown. Open the dashboard to check the chart.',tag:'mib-invalid',icon:'icon-192.png',badge:'icon-192.png',data:{url:'./'}});
      return;
    }
    const n=note(d);
    await self.registration.showNotification(n.title,n.opts);
    await histAdd(d.test?{at:Date.now(),test:true,id:'test',src:'push'}:{at:Date.now(),id:d.id,sym:d.sym,tf:d.tf,dir:d.dir,entry:d.entry,sl:d.sl,tp:d.tp,t:d.t,dec:d.dec,src:'push'});
    (await self.clients.matchAll({includeUncontrolled:true})).forEach(c=>c.postMessage({type:'hist'}));
  })());
});
self.addEventListener('notificationclick',e=>{
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{ for(const c of cs){ if('focus' in c) return c.focus(); } return self.clients.openWindow('./'); }));
});
