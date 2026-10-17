import { ctr } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
const KEY='youtube.watch.single.keys.v1', REFRESH='youtube.watch.single.config.v1';
const decoder={decode(b){const parts=[];for(let i=0;i<b.length;i+=8192)parts.push(String.fromCharCode(...b.subarray(i,i+8192)));return parts.join('');}};
const eq=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const unhex=s=>Uint8Array.from(s.match(/../g)||[],x=>parseInt(x,16));
function join(xs){const b=new Uint8Array(xs.reduce((n,x)=>n+x.length,0));let p=0;for(const x of xs){b.set(x,p);p+=x.length;}return b;}
function vint(b,p){let n=0,m=1;for(let i=0;i<10;i++){if(p>=b.length)throw Error('varint');const c=b[p++];n+=(c&127)*m;if(c<128)return[n,p];m*=128;}throw Error('varint size');}
function enc(n){const a=[];do{const x=n%128;n=Math.floor(n/128);a.push(x|(n?128:0));}while(n);return Uint8Array.from(a);}
function field(n,b){return join([enc(n*8+2),enc(b.length),b]);}
export function fields(b){let p=0;const out=[];while(p<b.length){const start=p;let tag;[tag,p]=vint(b,p);if(!Number.isSafeInteger(tag))throw Error('tag');const n=Math.floor(tag/8),w=tag%8;if(n<1||n>=2**29)throw Error('field');let s=p;if(w===2){let z;[z,p]=vint(b,p);if(!Number.isSafeInteger(z))throw Error('length');s=p;p+=z;}else if(w===0)[,p]=vint(b,p);else if(w===1||w===5)p+=w===1?8:4;else throw Error('wire');if(p>b.length)throw Error('truncated');out.push({n,w,body:b.subarray(s,p),raw:b.subarray(start,p)});}return out;}
function at(b,path){let xs=[b];for(const n of path)xs=xs.flatMap(x=>fields(x).filter(f=>f.n===n&&f.w===2).map(f=>f.body));return xs;}
function one(b,p){const x=at(b,p);if(x.length!==1)throw Error('single field');return x[0];}
function rewrite(b,path,fn){if(!path.length)return fn(b);let changed=false;const out=fields(b).map(f=>{if(f.n!==path[0]||f.w!==2)return f.raw;const x=rewrite(f.body,path.slice(1),fn);if(eq(x,f.body))return f.raw;changed=true;return field(f.n,x);});return changed?join(out):b;}
const layout=x=>decoder.decode(one(x,[172660663,2,183314536,1]));
const base=[7,51779735,1,49399797,1], sections=[...base,50195462];
export function filterNext(input){
 const all=at(input,[...sections,1,153515154]);
 const template=all.find(x=>layout(x).startsWith('spacing_cell.eml-fe|'));
 const stats={renderers_replaced:0,videos_kept:0,community_posts_replaced:0,pagination_removed:0};
 if(!template)return{output:input,stats};
 function spacer(x){let core=one(template,[172660663]);const id=one(x,[172660663,2,183314536,6]);core=rewrite(core,[2,183314536,6],()=>id);stats.renderers_replaced++;return join([field(172660663,core),...fields(x).filter(f=>f.n===5).map(f=>f.raw)]);}
 let output=rewrite(input,sections,sec=>{
  if(!at(sec,[7]).some(x=>decoder.decode(x)==='related-items'))return sec;
  return rewrite(sec,[1,153515154],x=>{
   const name=layout(x);
   if(stats.videos_kept<1&&name.startsWith('video_lockup_with_attachment.eml-fe|')&&!decoder.decode(x).includes('pagead')){stats.videos_kept++;return x;}
   if(name.startsWith('cell_divider.eml-fe|')||name.startsWith('spacing_cell.eml-fe|'))return x;
   if(stats.renderers_replaced>=150)throw Error('card limit');
   return spacer(x);
  });
 });
 function post(x){if(!['images_post_root_slim.eml-fe|','options_post_root.eml-fe|','post_root.eml-fe|'].some(p=>layout(x).startsWith(p)))return x;stats.community_posts_replaced++;return spacer(x);}
 for(const p of [[...sections,1,153515154],[...base,51845067,5,57988071,1,153515154]])output=rewrite(output,p,post);
 output=rewrite(output,[7,51779735,1,49399797],b=>join(fields(b).filter(f=>{if(f.n===2&&f.w===2&&at(f.body,[52047593,1]).length){stats.pagination_removed++;return false;}return true;}).map(f=>f.raw)));
 return{output,stats};
}
function umpRead(b,p){if(p>=b.length)throw Error('UMP');const first=b[p++];let lead=0;while(lead<4&&(first&(128>>lead)))lead++;const size=lead+1;let shift=size===5?0:8-size,n=size===5?0:first&((1<<shift)-1);for(let i=1;i<size;i++){if(p>=b.length)throw Error('UMP integer');n+=b[p++]*2**shift;shift+=8;}return[n,p];}
function umpEnc(n){for(let size=1;size<=4;size++){if(n<2**(7*size)){const shift=8-size,prefix=size>1?((1<<(size-1))-1)<<(9-size):0;const a=[prefix|(n%2**shift)];n=Math.floor(n/2**shift);for(let i=1;i<size;i++){a.push(n%256);n=Math.floor(n/256);}return Uint8Array.from(a);}}return Uint8Array.from([240,n%256,Math.floor(n/256)%256,Math.floor(n/65536)%256,Math.floor(n/16777216)%256]);}
function umpParts(b){let p=0;const xs=[];while(p<b.length){const start=p;let type,size;[type,p]=umpRead(b,p);[size,p]=umpRead(b,p);if(p+size>b.length)throw Error('incomplete UMP');xs.push({type,body:b.subarray(p,p+size),start,end:p+size});p+=size;}return xs;}
function replace(b,changes){return join(fields(b).map(f=>changes.has(f.n)?field(f.n,changes.get(f.n)):f.raw));}
function decode(payload,keys){const encrypted=one(payload,[1]),sig=one(payload,[2]),iv=one(payload,[3]);const compression=fields(payload).find(f=>f.n===4&&f.w===0);if(!compression||vint(compression.body,0)[0]!==1||iv.length!==16)return null;for(const key of keys){if(key.length!==32)continue;if(!eq(hmac(sha256,key.subarray(16),join([encrypted,iv])),sig))continue;return{compressed:ctr(key.subarray(0,16),iv).decrypt(encrypted),key,iv};}return null;}
export async function transformUMP(input,keys,compress){
 const parts=umpParts(input),output=[];let header=null;
 const stats={next_parts:0,repacked_parts:0,renderers_replaced:0,videos_kept:0,community_posts_replaced:0,pagination_removed:0};
 for(const p of parts){let raw=input.subarray(p.start,p.end);
  if(p.type===10){const t=fields(p.body).find(f=>f.n===1&&f.w===0);header=t?vint(t.body,0)[0]:null;}
  else if(p.type===11){const prior=header;header=null;if(prior===25){const d=decode(p.body,keys);if(d){const clear=await compress.gunzip(d.compressed);if(!clear)throw Error('gunzip');if(at(clear,[4,3]).length){stats.next_parts++;let edited=clear;if(!stats.renderers_replaced)edited=rewrite(clear,[4,3],next=>{if(stats.renderers_replaced)return next;const r=filterNext(next);for(const k of Object.keys(r.stats))stats[k]+=r.stats[k];return r.output;});
    const zipped=await compress.gzip(edited);if(!zipped)throw Error('gzip');const encrypted=ctr(d.key.subarray(0,16),d.iv).encrypt(zipped),sig=hmac(sha256,d.key.subarray(16),join([encrypted,d.iv]));const body=replace(p.body,new Map([[1,encrypted],[2,sig]]));raw=join([umpEnc(p.type),umpEnc(body.length),body]);stats.repacked_parts++;
  }}}}
  output.push(raw);
 }
 return{output:join(output),stats};
}
function keys(ctx){return(ctx.storage.getJSON(KEY)||[]).map(unhex);}
function saveConfig(ctx,b){let saved=false;for(const c of at(b,[1,16,7,138536474,146311580])){for(const key of at(c,[1])){if(key.length!==32)continue;const ring=ctx.storage.getJSON(KEY)||[],s=hex(key);if(!ring.includes(s))ring.push(s);ctx.storage.setJSON(KEY,ring.slice(-8));ctx.storage.set(REFRESH,'yes');saved=true;}}return saved;}
const BUILD='watch-one-v1';
async function report(ctx,stage,data={}){
 const url=ctx.env?.DEBUG_URL;if(!url)return;
 try{
  const throttle='youtube.watch.diag.'+BUILD+'.'+stage+'.'+(data.endpoint||'');
  if(Date.now()-Number(ctx.storage.get(throttle)||0)<3000)return;
  ctx.storage.set(throttle,String(Date.now()));
  await ctx.http.post(url,{body:{build:BUILD,stage,...data},timeout:1200,policy:'DIRECT',credentials:'omit'});
 }catch{}
}
export default async function(ctx){
 const match=/^https:\/\/([^/:?#]+)(?::\d+)?(\/[^?#]*)/.exec(ctx.request.url);if(!match)return;const u={hostname:match[1].toLowerCase()},path=match[2];
 await report(ctx,ctx.response?'response-entry':'request-entry',{endpoint:path,status:ctx.response?.status,compression_api:!!ctx.compress});
 const config=u.hostname==='youtubei.googleapis.com'&&['/youtubei/v1/log_event','/youtubei/v1/config'].includes(path);
 if(!ctx.response){if(config&&path.endsWith('/log_event')&&!ctx.storage.get(REFRESH)){ctx.request.headers.delete('x-youtube-hot-hash-data');await report(ctx,'config-refresh-requested');return{headers:ctx.request.headers};}return;}
 const init=u.hostname.endsWith('.googlevideo.com')&&path==='/initplayback';
 const direct=u.hostname==='youtubei.googleapis.com'&&path==='/youtubei/v1/next';
 if(!config&&!init&&!direct)return;
 let original;
 try{original=new Uint8Array(await ctx.response.arrayBuffer());if(config){let saved=false;try{saved=saveConfig(ctx,original);}catch{}if(!saved){const enc=ctx.response.headers.get('content-encoding');let plain;if(enc==='br')plain=await ctx.compress.unbrotli(original);else if(enc==='gzip')plain=await ctx.compress.gunzip(original);if(plain)saved=saveConfig(ctx,plain);}if(saved){console.log('YT Watch: config key saved locally');await report(ctx,'config-saved',{key_count:keys(ctx).length});}else await report(ctx,'config-without-key',{bytes:original.length,encoding:ctx.response.headers.get('content-encoding')});return{body:original};}
  if(ctx.response.status!==200)return{body:original};
  if(direct){
   const r=filterNext(original);console.log('YT Watch direct '+JSON.stringify(r.stats));await report(ctx,'direct-next-result',{bytes:original.length,...r.stats});
   if(eq(r.output,original))return{body:original};
   const headers=ctx.response.headers;headers.delete('etag');headers.delete('content-md5');headers.delete('transfer-encoding');headers.set('content-length',String(r.output.length));return{headers,body:r.output};
  }
  const ring=keys(ctx);if(!ring.length){console.log('YT Watch: waiting for config key');await report(ctx,'waiting-config',{bytes:original.length});return{body:original};}
  const r=await transformUMP(original,ring,ctx.compress);console.log('YT Watch '+JSON.stringify(r.stats));await report(ctx,'filter-result',{bytes:original.length,key_count:ring.length,...r.stats});if(!r.stats.repacked_parts)return{body:original};
  const headers=ctx.response.headers;headers.delete('etag');headers.delete('content-md5');headers.delete('transfer-encoding');headers.set('content-length',String(r.output.length));return{headers,body:r.output};
 }catch(e){console.log('YT Watch: pass through ('+String(e)+')');await report(ctx,'pass-through-error',{error:String(e).slice(0,180)});if(original)return{body:original};}
}
