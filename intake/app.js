(()=>{
  const API="https://sunburned.supply/wp-json/docklight-intake/v1";
  const qs=new URLSearchParams(location.search);
  const projectToken=qs.get("p")||"";
  const key=projectToken?"dll-intake:"+projectToken:"";
  let sessionToken=key?sessionStorage.getItem(key):null;
  let pollTimer=null;

  const el=id=>document.getElementById(id);
  const views=["loading","error","login","project"];
  const cards=["questionCard","answerForm","waitingCard","reviewCard","approvedCard"];

  function show(id){views.forEach(v=>el(v).classList.toggle("hidden",v!==id))}
  function showCard(id){cards.forEach(v=>el(v).classList.toggle("hidden",v!==id))}
  function fail(message){
    if(pollTimer){clearTimeout(pollTimer);pollTimer=null}
    el("errorText").textContent=message||"Check the link you were sent by Docklight Labs.";
    show("error");
  }
  async function request(path,opts={}){
    const headers=Object.assign({"Accept":"application/json"},opts.headers||{});
    if(opts.json!==undefined){headers["Content-Type"]="application/json";opts.body=JSON.stringify(opts.json);delete opts.json}
    if(sessionToken)headers["Authorization"]="Bearer "+sessionToken;
    const res=await fetch(API+path,Object.assign({},opts,{headers}));
    let body={};try{body=await res.json()}catch(_){}
    if(!res.ok){
      const err=new Error(body.error||("Request failed ("+res.status+")"));
      err.status=res.status;throw err;
    }
    return body;
  }
  async function loadInvite(){
    if(!projectToken||projectToken.length<20){fail("This invitation link is incomplete.");return}
    try{
      const info=await request("/project/"+encodeURIComponent(projectToken));
      el("loginTitle").textContent=info.title||"Project interview";
      el("loginClient").textContent=info.client_name?("For "+info.client_name):"";
      if(sessionToken){
        try{await loadState();return}catch(e){
          if(e.status===401){sessionStorage.removeItem(key);sessionToken=null}
          else throw e;
        }
      }
      show("login");
      setTimeout(()=>el("pin").focus(),50);
    }catch(e){fail(e.status===404?"This invitation is no longer available.":e.message)}
  }
  async function login(pin){
    const data=await request("/project/"+encodeURIComponent(projectToken)+"/login",{method:"POST",json:{pin}});
    sessionToken=data.session_token;
    sessionStorage.setItem(key,sessionToken);
    renderState(data.state);
  }
  async function loadState(){
    const state=await request("/session/state");
    renderState(state);
  }
  function renderState(state){
    show("project");
    el("projectClient").textContent=state.client_name||"Private project";
    el("projectTitle").textContent=state.title||"Project interview";
    const pct=Math.max(0,Math.min(100,Math.round((Number(state.progress)||0)*100)));
    el("progressBar").style.width=pct+"%";
    el("progressLabel").textContent=pct+"% complete";
    if(state.status==="approved"){showCard("approvedCard");return}
    if(state.status==="review"){showCard("reviewCard");return}
    if(state.status==="waiting"||!state.question){
      showCard("waitingCard");
      schedulePoll();
      return;
    }
    if(pollTimer){clearTimeout(pollTimer);pollTimer=null}
    el("questionText").textContent=state.question;
    el("answer").value="";
    showCard("questionCard");
    el("answerForm").classList.remove("hidden");
  }
  function schedulePoll(){
    if(pollTimer)clearTimeout(pollTimer);
    pollTimer=setTimeout(async()=>{
      try{await loadState()}catch(e){
        if(e.status===401){sessionStorage.removeItem(key);sessionToken=null;show("login")}
        else schedulePoll();
      }
    },5000);
  }

  el("loginForm").addEventListener("submit",async e=>{
    e.preventDefault();
    const pin=el("pin").value.trim();
    const button=e.submitter;button.disabled=true;button.textContent="Opening…";
    try{await login(pin)}
    catch(err){
      if(err.status===429)fail("Too many incorrect PIN attempts. Wait 15 minutes and try again.");
      else{el("pin").setCustomValidity("That PIN was not accepted.");el("pin").reportValidity();el("pin").setCustomValidity("")}
    }finally{button.disabled=false;button.textContent="Open project"}
  });

  el("answerForm").addEventListener("submit",async e=>{
    e.preventDefault();
    const text=el("answer").value.trim();
    if(!text)return;
    const button=e.submitter;button.disabled=true;button.textContent="Sending…";
    try{
      await request("/session/answer",{method:"POST",json:{answer:text,source:"typed"}});
      showCard("waitingCard");
      schedulePoll();
    }catch(err){
      if(err.status===409){await loadState()}
      else{button.disabled=false;button.textContent="Send answer";alert("Your answer was not sent. "+err.message)}
    }
  });

  el("logoutBtn").addEventListener("click",()=>{
    if(key)sessionStorage.removeItem(key);
    sessionToken=null;
    location.reload();
  });

  loadInvite();
})();