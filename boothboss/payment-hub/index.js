(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.DockLightPaymentHub=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';

  const STATUSES=Object.freeze(['pending','succeeded','failed','canceled','manual_confirmed']);
  const PAID_STATUSES=new Set(['succeeded','manual_confirmed']);
  const SAFE_PROTOCOLS=new Set(['https:','paypal:','venmo:','cashapp:']);

  function assertSafeConfig(value,path='config'){
    if(!value||typeof value!=='object')return value;
    for(const [key,child] of Object.entries(value)){
      const compact=key.toLowerCase().replace(/[^a-z0-9]/g,'');
      if(['secret','privatekey','password','passwd','token','accesstoken','refreshtoken','apikey','clientsecret','cvv','cvc','cardnumber','bankaccount','bankcredential','routingnumber'].some(term=>compact===term||compact.endsWith(term)))throw new Error(`Unsafe secret-bearing payment configuration: ${path}.${key}`);
      assertSafeConfig(child,`${path}.${key}`);
    }
    return value;
  }

  function normalizeUrl(value){
    const raw=String(value||'').trim();
    if(!raw)return '';
    let parsed;
    try{parsed=new URL(raw);}catch{throw new Error('Payment URLs must be complete, such as https://…');}
    if(!SAFE_PROTOCOLS.has(parsed.protocol))throw new Error('Payment URLs must use HTTPS or a supported payment-app link.');
    return parsed.href;
  }

  function externalAdapter(definition){
    return Object.freeze({
      ...definition,
      begin({method}){
        return {status:'pending',providerReference:null,handoff:{url:method.url||'',instructions:method.instructions||method.cashtag||'',qr:method.qr||''}};
      }
    });
  }

  const BUILTIN_PROVIDERS=Object.freeze([
    externalAdapter({id:'cash',label:'Cash',capabilities:{verified:true,manual:false,requiresInternet:false,supportsLink:false,supportsQr:false,supportsDeepLink:false}}),
    externalAdapter({id:'stripe',label:'Card / wallet',capabilities:{verified:false,manual:true,requiresInternet:true,supportsLink:true,supportsQr:false,supportsDeepLink:false},isConfigured:method=>Boolean(method.url)}),
    externalAdapter({id:'paypal',label:'PayPal / Venmo',capabilities:{verified:false,manual:true,requiresInternet:false,supportsLink:true,supportsQr:false,supportsDeepLink:true}}),
    externalAdapter({id:'cash_app',label:'Cash App',capabilities:{verified:false,manual:true,requiresInternet:false,supportsLink:true,supportsQr:true,supportsDeepLink:true}}),
    externalAdapter({id:'zelle',label:'Zelle',capabilities:{verified:false,manual:true,requiresInternet:false,supportsLink:false,supportsQr:true,supportsDeepLink:false}}),
    externalAdapter({id:'other',label:'Other',capabilities:{verified:false,manual:true,requiresInternet:false,supportsLink:true,supportsQr:true,supportsDeepLink:true}})
  ]);

  const DEFAULT_METHODS=Object.freeze([
    {id:'cash',provider:'cash',label:'Cash',enabled:true},
    {id:'stripe',provider:'stripe',label:'Card / wallet',enabled:false,url:''},
    {id:'venmo',provider:'paypal',label:'Venmo',enabled:false,url:''},
    {id:'paypal',provider:'paypal',label:'PayPal',enabled:false,url:''},
    {id:'cash_app',provider:'cash_app',label:'Cash App',enabled:false,url:'',cashtag:'',instructions:'',qr:''},
    {id:'zelle',provider:'zelle',label:'Zelle',enabled:false,instructions:'',qr:''},
    {id:'other',provider:'other',label:'Other',enabled:false,url:'',instructions:'',qr:''}
  ]);

  function normalizeProviderResult(result={}){
    const aliases={cancelled:'canceled',success:'succeeded',successful:'succeeded',error:'failed'};
    const status=aliases[result.status]||result.status||'pending';
    if(!STATUSES.includes(status))throw new Error(`Unsupported payment status: ${status}`);
    return {status,providerReference:result.providerReference??result.provider_reference??null,error:result.error||null,handoff:result.handoff||null};
  }

  function createPaymentHub(options={}){
    const providers=new Map(),attempts=new Map();
    const clock=options.now||(()=>new Date().toISOString());
    function registerProvider(adapter){
      if(!adapter||typeof adapter.id!=='string'||typeof adapter.begin!=='function'||!adapter.capabilities)throw new Error('Provider adapter requires id, capabilities, and begin().');
      if(providers.has(adapter.id))throw new Error(`Provider already registered: ${adapter.id}`);
      if(adapter.capabilities.manual&&adapter.capabilities.verified)throw new Error('Manual providers cannot be represented as verified.');
      providers.set(adapter.id,Object.freeze(adapter));return adapter;
    }
    function configuredMethods(config=[]){
      assertSafeConfig(config);
      const supplied=Array.isArray(config)?config:[];
      return DEFAULT_METHODS.map(base=>({...base,...(supplied.find(item=>item.id===base.id)||{})})).sort((a,b)=>{
        const ai=supplied.findIndex(item=>item.id===a.id),bi=supplied.findIndex(item=>item.id===b.id);
        return (ai<0?99:ai)-(bi<0?99:bi);
      }).map(method=>({...method,url:normalizeUrl(method.url)}));
    }
    function listMethods(config=[],connectivity={online:true}){
      return configuredMethods(config).map(method=>{
        const adapter=providers.get(method.provider);
        if(!adapter)throw new Error(`Unknown payment provider: ${method.provider}`);
        const usesNetwork=adapter.capabilities.requiresInternet||Boolean(method.url);
        const configured=adapter.isConfigured?adapter.isConfigured(method):true;
        const unavailableReason=!configured?'not_configured':(!connectivity.online&&usesNetwork?'offline':null);
        return {...method,capabilities:{...adapter.capabilities,requiresInternet:usesNetwork},available:Boolean(method.enabled&&!unavailableReason),unavailableReason};
      });
    }
    function loadPaymentRecord(record){
      if(!record?.id)throw new Error('Payment record requires an id.');
      const result=normalizeProviderResult(record),normalized={...record,...result,methodLabel:record.methodLabel||record.method_label,providerReference:record.providerReference??record.provider_reference??null,externalConfirmationRequired:record.externalConfirmationRequired??record.external_confirmation_required??false,externalConfirmation:record.externalConfirmation??record.external_confirmation??false,handoff:record.handoff||result.handoff||{url:record.handoff_url||'',instructions:record.instructions||'',qr:record.qr||''},createdAt:record.createdAt||record.created_at||record.timestamp,updatedAt:record.updatedAt||record.updated_at||record.timestamp};
      attempts.set(record.id,normalized);return normalized;
    }
    function beginPayment({attemptId,amount,currency='USD',method,context={}}){
      if(!attemptId)throw new Error('attemptId is required.');
      if(attempts.has(attemptId))return attempts.get(attemptId);
      if(!method?.enabled)throw new Error('This payment method is disabled.');
      assertSafeConfig(method,'method');assertSafeConfig(context,'context');
      if(!Number.isFinite(Number(amount))||Number(amount)<0)throw new Error('Payment amount must be a non-negative number.');
      method={...method,url:normalizeUrl(method.url)};
      const adapter=providers.get(method.provider);
      if(!adapter)throw new Error(`Unknown payment provider: ${method.provider}`);
      const timestamp=clock(),providerResult=normalizeProviderResult(adapter.begin({attemptId,amount,currency,method,context}));
      const attempt={id:attemptId,amount:Number(amount),currency,method:method.id,methodLabel:method.label,provider:method.provider,status:providerResult.status,providerReference:providerResult.providerReference,externalConfirmationRequired:Boolean(adapter.capabilities.manual),externalConfirmation:false,handoff:providerResult.handoff||null,context:{...context},createdAt:timestamp,updatedAt:timestamp};
      attempts.set(attemptId,attempt);return attempt;
    }
    function transition(attemptId,status){
      const attempt=attempts.get(attemptId);if(!attempt)throw new Error(`Unknown payment attempt: ${attemptId}`);
      if(attempt.status!=='pending')return attempt;
      const next={...attempt,status,externalConfirmation:status==='manual_confirmed',updatedAt:clock()};attempts.set(attemptId,next);return next;
    }
    function cancelPayment(attemptId){return transition(attemptId,'canceled');}
    function confirmExternalPayment(attemptId){const attempt=attempts.get(attemptId);if(!attempt)throw new Error(`Unknown payment attempt: ${attemptId}`);return transition(attemptId,attempt.externalConfirmationRequired?'manual_confirmed':'succeeded');}
    function applyProviderResult(attemptId,result){const normalized=normalizeProviderResult(result),next=transition(attemptId,normalized.status);if(normalized.providerReference&&next.providerReference!==normalized.providerReference){const updated={...next,providerReference:normalized.providerReference,updatedAt:clock()};attempts.set(attemptId,updated);return updated;}return next;}
    function serializePaymentRecord(attempt){
      const value=attempt||{};
      return {id:value.id,amount:value.amount,currency:value.currency,method:value.method,method_label:value.methodLabel,provider:value.provider,status:value.status,provider_reference:value.providerReference||null,external_confirmation_required:Boolean(value.externalConfirmationRequired),external_confirmation:Boolean(value.externalConfirmation),handoff_url:value.handoff?.url||'',instructions:value.handoff?.instructions||'',qr:value.handoff?.qr||'',timestamp:value.createdAt,created_at:value.createdAt,updated_at:value.updatedAt};
    }
    if(options.registerBuiltins!==false)for(const adapter of BUILTIN_PROVIDERS)registerProvider(adapter);
    return {registerProvider,listMethods,beginPayment,cancelPayment,confirmExternalPayment,applyProviderResult,normalizeProviderResult,serializePaymentRecord,loadPaymentRecord,isPaid:attempt=>PAID_STATUSES.has(attempt?.status),getAttempt:id=>attempts.get(id)};
  }

  return {createPaymentHub,DEFAULT_METHODS,BUILTIN_PROVIDERS,STATUSES,assertSafeConfig,normalizeUrl,normalizeProviderResult};
});
