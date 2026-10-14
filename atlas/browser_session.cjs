/* Isolated native browsing worker. stdout is private parent IPC, never an application log. */
'use strict';
const readline=require('node:readline');
const input=readline.createInterface({input:process.stdin});
let browser=null,context=null,settings=null,started=false,stopping=false;
async function stop(){stopping=true;if(browser){await browser.close();process.exit(0);}}
function allowed(url,config){
  try{
    const u=new URL(url);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)return false;
    let path=u.pathname;for(let i=0;i<4;i++){const next=decodeURIComponent(path);if(next===path)break;path=next;}
    if(path.includes('\\')||path.includes('%')||path.includes('//')||path.split('/').some(p=>p==='.'||p==='..'))return false;
    const inside=p=>p==='/'||path===p.replace(/\/$/,'')||path.startsWith(p.replace(/\/$/,'')+'/');
    return Object.hasOwn(config.origins,u.origin)&&inside(config.origins[u.origin])&&!config.excluded.some(inside);
  }catch{return false;}
}
input.on('line',async line=>{
  try{
    const config=JSON.parse(line);
    if(started){
      if(config.action==='stop')await stop();
      if(config.action==='cookies'&&context){
        const cookies=[];const available=await context.cookies();
        for(const origin of Object.keys(settings.origins)){
          const u=new URL(origin);for(const cookie of available){
            const domain=cookie.domain.replace(/^\./,'');
            if(u.hostname!==domain&&!u.hostname.endsWith('.'+domain))continue;
            if(cookie.partitionKey)continue;
            const prefix=settings.origins[origin].replace(/\/$/,'')||'/';const path=cookie.path.replace(/\/$/,'')||'/';
            if(prefix!=='/'&&path!=='/'&&prefix!==path&&!prefix.startsWith(path+'/')&&!path.startsWith(prefix+'/'))continue;
            cookies.push({origin,name:cookie.name,value:cookie.value,path:cookie.path,secure:cookie.secure,expires:cookie.expires});
          }
        }
        console.log(JSON.stringify({state:'cookies',id:config.id,cookies:cookies.length<=100?cookies:[],limit_exceeded:cookies.length>100}));
      }
      return;
    }
    started=true;
    settings=config;
    const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
    browser=await chromium.launch({channel:'msedge',headless:config.headless,args:['--proxy-bypass-list=<-loopback>','--ignore-certificate-errors-spki-list='+config.ca_spki,'--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],proxy:{server:'http://127.0.0.1:'+config.port,username:'atlas',password:config.password}});
    if(stopping){await stop();return;}
    context=await browser.newContext({serviceWorkers:'block',acceptDownloads:false});
    let blocked=0;
    await context.route('**/*',route=>{if(allowed(route.request().url(),config))return route.continue();console.log(JSON.stringify({state:'blocked',count:++blocked}));return route.abort('blockedbyclient');});
    if(context.routeWebSocket)await context.routeWebSocket('**/*',ws=>{const url=ws.url().replace(/^wss:/,'https:').replace(/^ws:/,'http:');if(allowed(url,config))ws.connectToServer();else{console.log(JSON.stringify({state:'blocked',count:++blocked}));ws.close();}});
    const page=await context.newPage();
    await page.goto(config.url,{waitUntil:'domcontentloaded',timeout:30000});
    console.log(JSON.stringify({state:'ready'}));
    browser.on('disconnected',()=>process.exit(0));
  }catch{
    console.log(JSON.stringify({state:'failed',reason:'Browser module/channel/navigation failed; check Node, Playwright, Edge, scope and the retained run evidence.'}));
    await browser?.close();process.exit(1);
  }
});
input.on('close',stop);
