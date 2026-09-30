const DISPOSABLE_URL="https://disposable.github.io/disposable-email-domains/domains.txt";
const FALLBACK_DISPOSABLE=new Set(["10minutemail.com","10minutemail.net","armyspy.com","dispostable.com","fakeinbox.com","guerrillamail.com","guerrillamail.net","guerrillamail.org","mailcatch.com","maildrop.cc","mailinator.com","mailnesia.com","mintemail.com","mohmal.com","moose-mail.com","sharklasers.com","snail-mail.net","spambog.com","temp-mail.org","tempail.com","tempmail.com","throwawaymail.com","yopmail.com"]);
const ROLE_NAMES=new Set(["abuse","accounts","accounting","admin","administrator","billing","bookings","careers","compliance","contact","customerservice","enquiries","events","hello","help","hr","info","inquiries","jobs","legal","mail","marketing","office","orders","privacy","reception","returns","sales","security","service","support","team","web","webmaster"]);
const NO_REPLY_NAMES=new Set(["noreply","no-reply","do-not-reply","donotreply","no_reply","mailer-daemon"]);
const PLACEHOLDER_LOCALS=new Set(["test","testing","example","email","none","null","unknown","asdf","qwerty","user","username","fake","sample","dummy"]);
const PLACEHOLDER_DOMAINS=new Set(["example.com","example.org","example.net","test.com","invalid.com","none.com","email.com"]);
const KNOWN_DEAD_DOMAINS=new Set(["mailblocks.com","lycos.co.uk","myrealbox.com","rocketmail.co.uk","walla.com"]);
const KNOWN_CATCH_ALL_DOMAINS=new Set(["coach.com","xmailg.com"]);
const COMMON_DOMAINS=["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","icloud.com","live.com","msn.com","comcast.net","att.net","verizon.net","me.com","proton.me","protonmail.com","gmx.com","mail.com"];
const PROVIDER_MX_HINTS=[["google","Google"],["outlook","Microsoft"],["protection.outlook","Microsoft"],["yahoodns","Yahoo"],["icloud","Apple"],["zoho","Zoho"],["protonmail","Proton"],["mimecast","Mimecast"],["pphosted","Proofpoint"]];
let sourceRows=[],emailCol=-1,results=[],disposableDomains=new Set(FALLBACK_DISPOSABLE);
const el=id=>document.getElementById(id);
const drop=el("drop"),fileInput=el("file"),run=el("run");

function parseCSV(text){
 const out=[];let row=[],cell="",q=false;
 for(let i=0;i<text.length;i++){const c=text[i],n=text[i+1];
  if(q){if(c=='"'&&n=='"'){cell+='"';i++;}else if(c=='"')q=false;else cell+=c;}
  else if(c=='"')q=true;
  else if(c==','){row.push(cell);cell="";}
  else if(c=='\n'){row.push(cell.replace(/\r$/,""));out.push(row);row=[];cell="";}
  else cell+=c;
 }
 if(cell.length||row.length){row.push(cell.replace(/\r$/,""));out.push(row);}
 return out.filter(r=>r.some(v=>v.trim()!==""));
}
function detectEmailColumn(rows){
 if(!rows.length)return -1;const hdr=rows[0].map(x=>x.trim().toLowerCase());
 let i=hdr.findIndex(x=>["email","email address","e-mail","email_address"].includes(x));if(i>=0)return i;
 const sample=rows.slice(0,Math.min(rows.length,30));let best=-1,bestN=0;
 for(let c=0;c<Math.max(...sample.map(r=>r.length));c++){let n=0;sample.forEach(r=>{if(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((r[c]||"").trim()))n++});if(n>bestN){bestN=n;best=c}}
 return best;
}
function normalizeDomain(domain){
 domain=(domain||"").trim().toLowerCase().replace(/\.$/,"");
 try{return new URL("http://"+domain).hostname.toLowerCase()}catch{return domain}
}
function validSyntax(email){
 if(email.length>254||/\s/.test(email))return false;
 const parts=email.split("@");if(parts.length!==2)return false;
 const local=parts[0],domain=normalizeDomain(parts[1]);if(!local||local.length>64||!domain||domain.length>253)return false;
 if(local.startsWith(".")||local.endsWith(".")||local.includes(".."))return false;
 if(!/^[A-Z0-9.!#$%&'*+/=?^_\x60{|}~-]+$/i.test(local))return false;
 if(!/^[a-z0-9.-]+$/i.test(domain)||domain.startsWith(".")||domain.endsWith(".")||domain.includes("..")||!domain.includes("."))return false;
 return domain.split(".").every(x=>x&&x.length<=63&&!x.startsWith("-")&&!x.endsWith("-"));
}
function editDistance(a,b){
 const m=a.length,n=b.length,dp=Array(n+1);for(let j=0;j<=n;j++)dp[j]=j;
 for(let i=1;i<=m;i++){let prev=dp[0];dp[0]=i;for(let j=1;j<=n;j++){const old=dp[j];dp[j]=Math.min(dp[j]+1,dp[j-1]+1,prev+(a[i-1]===b[j-1]?0:1));prev=old}}
 return dp[n];
}
function domainTypo(domain){
 let best=null,bestD=99;
 for(const good of COMMON_DOMAINS){const d=editDistance(domain,good);if(d<bestD){bestD=d;best=good}}
 return bestD===1&&domain!==best?best:null;
}
function suspiciousLocal(local){
 const l=local.toLowerCase();
 if(PLACEHOLDER_LOCALS.has(l))return true;
 if(/^(.)\1{4,}$/.test(l))return true;
 if(/^(asdf|qwerty|test|fake|dummy|sample|unknown)[0-9._-]*$/i.test(l))return true;
 if(/^[0-9]{12,}$/.test(l))return true;
 return false;
}
async function dnsQuery(name,type){
 const url="https://dns.google/resolve?name="+encodeURIComponent(name)+"&type="+encodeURIComponent(type);
 try{const r=await fetch(url,{cache:"no-store"});if(!r.ok)return {state:"error",answers:[]};const d=await r.json();
  if(d.Status===3)return {state:"nxdomain",answers:[]};
  if(d.Status!==0)return {state:"error",answers:[]};
  return {state:"ok",answers:Array.isArray(d.Answer)?d.Answer:[]};
 }catch{return {state:"error",answers:[]}}
}
function parseMxAnswers(answers){return answers.filter(a=>a.type===15).map(a=>String(a.data||"").trim()).filter(Boolean)}
function providerFromMx(mx){
 const x=mx.join(" ").toLowerCase();
 for(const pair of PROVIDER_MX_HINTS)if(x.includes(pair[0]))return pair[1];
 return "";
}
async function domainStatus(domain){
 const mxr=await dnsQuery(domain,"MX");
 if(mxr.state==="nxdomain")return {state:"nxdomain",mx:[],fallback:false,provider:""};
 if(mxr.state==="error")return {state:"tempfail",mx:[],fallback:false,provider:""};
 const mx=parseMxAnswers(mxr.answers);
 if(mx.some(x=>/^\s*0\s+\.\s*$/.test(x)))return {state:"nullmx",mx,fallback:false,provider:""};
 if(mx.length)return {state:"mx",mx,fallback:false,provider:providerFromMx(mx)};
 const ar=await dnsQuery(domain,"A"),aaaar=await dnsQuery(domain,"AAAA");
 if(ar.state==="nxdomain"&&aaaar.state==="nxdomain")return {state:"nxdomain",mx:[],fallback:false,provider:""};
 if(ar.state==="error"&&aaaar.state==="error")return {state:"tempfail",mx:[],fallback:false,provider:""};
 const hasHost=(ar.answers||[]).some(a=>a.type===1)||(aaaar.answers||[]).some(a=>a.type===28);
 return hasHost?{state:"fallback",mx:[],fallback:true,provider:""}:{state:"nomail",mx:[],fallback:false,provider:""};
}
async function loadDisposableList(){
 try{
  const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),5000);
  const r=await fetch(DISPOSABLE_URL,{signal:ctrl.signal,cache:"force-cache"});clearTimeout(timer);
  if(!r.ok)throw new Error("list");
  const text=await r.text(),rows=text.split(/\r?\n/).map(x=>x.trim().toLowerCase()).filter(x=>x&&!x.startsWith("#"));
  if(rows.length<1000)throw new Error("short");
  disposableDomains=new Set(rows);FALLBACK_DISPOSABLE.forEach(x=>disposableDomains.add(x));return rows.length;
 }catch{return disposableDomains.size}
}
function addSignal(obj,level,code,text){
 obj.signals.push({level,code,text});
 if(level==="reject")obj.cls="Reject";else if(level==="questionable"&&obj.cls!=="Reject")obj.cls="Questionable";
}
function finalizeReason(obj){return obj.signals.length?obj.signals.map(s=>s.text).join("; "):"Passed cheap checks"}
async function scrub(){
 run.disabled=true;results=[];el("status").textContent="Loading disposable-domain data…";
 const disposableCount=await loadDisposableList(),seen=new Set(),data=sourceRows.slice(1),prelim=[];
 for(const row of data){
  const raw=(row[emailCol]||"").trim(),email=raw.toLowerCase(),obj={row,email:raw||email,normalized:email,domain:"",local:"",cls:"Send",signals:[],reason:"",provider:""};
  if(!email){addSignal(obj,"reject","blank","Blank email");prelim.push(obj);continue}
  if(seen.has(email)){addSignal(obj,"reject","duplicate","Duplicate");prelim.push(obj);continue}
  seen.add(email);
  if(!validSyntax(email)){addSignal(obj,"reject","syntax","Invalid syntax");prelim.push(obj);continue}
  const parts=email.split("@");obj.local=parts[0].toLowerCase();obj.domain=normalizeDomain(parts[1]);
  if(disposableDomains.has(obj.domain))addSignal(obj,"reject","disposable","Disposable domain");
  if(KNOWN_DEAD_DOMAINS.has(obj.domain))addSignal(obj,"reject","dead_provider","Known dead/retired mail domain");
  if(PLACEHOLDER_DOMAINS.has(obj.domain)||suspiciousLocal(obj.local))addSignal(obj,"questionable","placeholder","Placeholder/suspicious address pattern");
  if(NO_REPLY_NAMES.has(obj.local))addSignal(obj,"reject","no_reply","No-reply mailbox");else if(ROLE_NAMES.has(obj.local))addSignal(obj,"questionable","role","Role account");
  const typo=domainTypo(obj.domain);if(typo)addSignal(obj,"questionable","domain_typo","Possible domain typo → "+typo);
  if(KNOWN_CATCH_ALL_DOMAINS.has(obj.domain))addSignal(obj,"questionable","catch_all_known","Known catch-all domain");
  obj.reason=finalizeReason(obj);prelim.push(obj);
 }
 const domains=[...new Set(prelim.filter(x=>x.cls!=="Reject"&&x.domain).map(x=>x.domain))],cache=new Map();let done=0,next=0;
 const worker=async()=>{while(true){const i=next++;if(i>=domains.length)return;const domain=domains[i];cache.set(domain,await domainStatus(domain));done++;el("status").textContent="DNS/mail routing "+done+"/"+domains.length+" · disposable list "+disposableCount.toLocaleString()+" domains"}};
 const workerCount=Math.min(20,domains.length||1);
 await Promise.all(Array.from({length:workerCount},()=>worker()));
 results=prelim.map(obj=>{
  if(obj.cls==="Reject"||!obj.domain){obj.reason=finalizeReason(obj);return obj}
  const ds=cache.get(obj.domain);if(!ds){addSignal(obj,"questionable","dns_unknown","DNS lookup inconclusive");obj.reason=finalizeReason(obj);return obj}
  obj.provider=ds.provider||"";
  if(ds.state==="nxdomain")addSignal(obj,"reject","nxdomain","Domain does not exist (NXDOMAIN)");
  else if(ds.state==="nullmx")addSignal(obj,"reject","null_mx","Domain explicitly does not accept email (Null MX)");
  else if(ds.state==="nomail")addSignal(obj,"reject","no_mail_route","No MX or usable A/AAAA mail route");
  else if(ds.state==="fallback")addSignal(obj,"questionable","a_fallback","No MX; domain has A/AAAA fallback only");
  else if(ds.state==="tempfail")addSignal(obj,"questionable","dns_tempfail","Temporary/inconclusive DNS failure");
  obj.reason=finalizeReason(obj);return obj;
 });
 render(disposableCount);
}
function render(disposableCount){
 const count=c=>results.filter(x=>x.cls===c).length;
 el("nTotal").textContent=results.length;el("nSend").textContent=count("Send");el("nQ").textContent=count("Questionable");el("nReject").textContent=count("Reject");
 el("stats").hidden=false;el("tableWrap").hidden=false;
 el("rows").innerHTML=results.slice(0,500).map(x=>'<tr><td>'+escapeHTML(x.email)+'</td><td><span class="badge '+x.cls.toLowerCase()+'">'+x.cls+'</span></td><td>'+escapeHTML(x.reason)+'</td></tr>').join("");
 el("status").textContent="Done. "+results.length+" rows classified · "+disposableCount.toLocaleString()+" disposable domains loaded"+(results.length>500?"; showing first 500 below":"")+".";
 el("download").disabled=false;el("audit").disabled=false;run.disabled=false;
}
function escapeHTML(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function csvCell(v){v=String(v==null?"":v);const needsQuotes=v.includes(",")||v.includes(String.fromCharCode(10))||v.includes(String.fromCharCode(13))||v.includes('"');return needsQuotes?'"'+v.replace(/"/g,'""')+'"':v}
function download(name,rows){const lineBreak=String.fromCharCode(13)+String.fromCharCode(10),csv=rows.map(r=>r.map(csvCell).join(",")).join(lineBreak),blob=new Blob([csv],{type:"text/csv;charset=utf-8"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function loadFile(f){
 if(!f)return;const reader=new FileReader();reader.onload=()=>{sourceRows=parseCSV(reader.result);emailCol=detectEmailColumn(sourceRows);results=[];el("stats").hidden=true;el("tableWrap").hidden=true;el("download").disabled=true;el("audit").disabled=true;if(emailCol<0){el("status").textContent="Could not identify an email column.";run.disabled=true;return}el("status").textContent=f.name+": "+Math.max(0,sourceRows.length-1)+" data rows. Ready.";run.disabled=false};reader.readAsText(f);
}
fileInput.addEventListener("change",()=>loadFile(fileInput.files[0]));
drop.addEventListener("dragover",e=>{e.preventDefault();e.stopPropagation();drop.classList.add("drag")});
drop.addEventListener("dragenter",e=>{e.preventDefault();e.stopPropagation();drop.classList.add("drag")});
drop.addEventListener("dragleave",e=>{e.preventDefault();e.stopPropagation();drop.classList.remove("drag")});
drop.addEventListener("drop",e=>{e.preventDefault();e.stopPropagation();drop.classList.remove("drag");const f=e.dataTransfer&&e.dataTransfer.files?e.dataTransfer.files[0]:null;if(f)loadFile(f)});
document.addEventListener("dragover",e=>e.preventDefault());
document.addEventListener("drop",e=>e.preventDefault());
run.addEventListener("click",scrub);
el("download").addEventListener("click",()=>{const hdr=sourceRows[0]||["email"],kept=results.filter(x=>x.cls!=="Reject").map(x=>x.row);download("docklight-cleaned.csv",[hdr,...kept])});
el("audit").addEventListener("click",()=>{download("docklight-audit.csv",[["email","classification","reason","provider","signals"],...results.map(x=>[x.email,x.cls,x.reason,x.provider,x.signals.map(s=>s.code).join("|")])])});