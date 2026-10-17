import fs from 'node:fs';import assert from 'node:assert/strict';import {gzipSync,gunzipSync}from'node:zlib';import{createHmac,createDecipheriv}from'node:crypto';
import script,{filterNext,transformUMP,fields}from'../egern/youtube_watch.js';
const root=new URL('file://'+process.env.PORT_GOLD_DIR.replace(/\/$/,'')+'/'),rows=JSON.parse(fs.readFileSync(new URL('manifest.json',root)));
const keys=JSON.parse(fs.readFileSync(process.env.YT_STATE_DIR+'/onesie-keyring.json')).map(x=>new Uint8Array(Buffer.from(x,'hex')));
const compress={gzip:async b=>new Uint8Array(gzipSync(b,{level:6})),gunzip:async b=>new Uint8Array(gunzipSync(b))};
const get=(b,n)=>fields(b).find(f=>f.n===n&&f.w===2)?.body;
function uint(b,p){const first=b[p++];let lead=0;while(lead<4&&(first&(128>>lead)))lead++;const size=lead+1;let shift=size===5?0:8-size,n=size===5?0:first&((1<<shift)-1);for(let i=1;i<size;i++){n+=b[p++]*2**shift;shift+=8;}return[n,p];}
function parts(b){let p=0;const out=[];while(p<b.length){let t,z;[t,p]=uint(b,p);[z,p]=uint(b,p);assert(p+z<=b.length);out.push([t,b.subarray(p,p+z)]);p+=z;}return out;}
function plaintext(b){const enc=get(b,1),sig=get(b,2),iv=get(b,3);for(const k of keys){if(!createHmac('sha256',k.subarray(16)).update(Buffer.concat([enc,iv])).digest().equals(Buffer.from(sig)))continue;const d=createDecipheriv('aes-128-ctr',k.subarray(0,16),iv);return gunzipSync(Buffer.concat([d.update(enc),d.final()]));}throw Error('No authenticated key');}
let direct=0,streams=0,changed=0;
for(const row of rows){const input=new Uint8Array(fs.readFileSync(new URL(`${row.index}.input`,root))),expected=new Uint8Array(fs.readFileSync(new URL(`${row.index}.expected`,root)));
 if(row.kind==='next'){const r=filterNext(input);assert.deepEqual(Buffer.from(r.output),Buffer.from(expected));assert.deepEqual(r.stats,row.stats);direct++;}
 else{const r=await transformUMP(input,keys,compress);for(const k of Object.keys(r.stats))assert.equal(r.stats[k],row.stats[k],k);const a=parts(r.output),b=parts(expected);assert.equal(a.length,b.length);for(let i=0;i<a.length;i++){assert.equal(a[i][0],b[i][0]);if(Buffer.from(a[i][1]).equals(Buffer.from(b[i][1])))continue;assert.equal(a[i][0],11);assert.deepEqual(plaintext(a[i][1]),plaintext(b[i][1]));changed++;}streams++;}
}
// Full Egern-shaped invocation: no Node globals in the script's API surface.
const memory=new Map([['youtube.watch.single.keys.v1',keys.map(k=>Buffer.from(k).toString('hex'))]]);
const storage={get:k=>memory.get(k),getJSON:k=>memory.get(k),set:(k,v)=>memory.set(k,v),setJSON:(k,v)=>memory.set(k,v)};
const row=rows.find(r=>r.kind==='ump'&&r.stats.renderers_replaced>0),input=new Uint8Array(fs.readFileSync(new URL(`${row.index}.input`,root)));
const result=await script({request:{url:'https://test.googlevideo.com/initplayback'},response:{status:200,headers:new Headers(),arrayBuffer:async()=>input.buffer},storage,compress});assert(result.body.length>0);
assert.equal(Number(result.headers.get('content-length')),result.body.length);
console.log(JSON.stringify({pass:true,directPages:direct,encryptedStreams:streams,independentlyVerifiedCiphertextParts:changed,deviceRuntimeExercisedByThisTest:false}));
const diagnostics=[];
await script({request:{url:'https://test.googlevideo.com/initplayback'},response:{status:200,headers:new Headers(),arrayBuffer:async()=>input.buffer},storage,compress,env:{DEBUG_URL:'http://diagnostic.invalid/egern-log'},http:{post:async(url,options)=>{diagnostics.push(options.body);return{status:200};}}});
assert(diagnostics.some(x=>x.stage==='response-entry'));
assert(diagnostics.some(x=>x.stage==='filter-result'&&x.videos_kept===1));
for(const key of keys)assert(!JSON.stringify(diagnostics).includes(Buffer.from(key).toString('hex')));
console.log('PASS: diagnostic stages reported without key material');
const directRow=rows.find(r=>r.kind==='next'&&r.stats.videos_kept===1);
const directBody=new Uint8Array(fs.readFileSync(new URL(`${directRow.index}.input`,root)));
const directResult=await script({request:{url:'https://youtubei.googleapis.com/youtubei/v1/next?alt=proto'},response:{status:200,headers:new Headers(),arrayBuffer:async()=>directBody.buffer},storage:{get:()=>null,getJSON:()=>null,set:()=>{},setJSON:()=>{}},compress});
assert.deepEqual(Buffer.from(directResult.body),Buffer.from(filterNext(directBody).output));
console.log('PASS: plain /next wrapper filters without any configuration key');
