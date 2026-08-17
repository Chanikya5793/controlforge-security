import assert from 'node:assert/strict';

// Executable UI logic contracts, not browser/passkey or real-network evidence.
let activeNetwork='',deviceFilter=null,networkSupport=true;
const me={tenant_id:'alpha',role:'admin'};
const location={search:'?network=alpha&device=shared-mac'};
const storage=new Map([['controlforge-network','beta']]);
const sessionStorage={getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value)};
const nodes=new Map();
const $=selector=>{
  if(!nodes.has(selector))nodes.set(selector,{
    textContent:'',hidden:false,href:'',attributes:{},children:[],nextElementSibling:{textContent:''},
    replaceChildren(...children){this.children=children},
    setAttribute(name,value){this.attributes[name]=value},
  });
  return nodes.get(selector);
};
const text=(_tag,value)=>({value});
const empty=(root,title,detail)=>root.replaceChildren({value:title},{value:detail});
const toast=()=>{};
let selectedCase=null,evidenceRows=[],evidenceMeta={},requestedCaseId=null,caseRequest=0;
let rendered=[];
const renderCaseQueue=()=>{};
const renderCase=async detail=>{rendered.push(detail.case_id)};
let api=async(path,options)=>{
  assert.equal(path,'/v1/networks');
  assert.equal(options.headers['x-network-id'],'');
  return {networks:[{tenant_id:'alpha',display_name:'Alpha',status:'active'}]};
};
__HELPERS__
__LOAD_CASE__
__REQUEST_API__
let csrf='synthetic-token-not-used';
const loadWorkspace=async()=>{throw new Error('Invalid scope must not load the workspace')};
__SHOW_OPERATIONS__

await configureInvestigationScope();
assert.equal(activeNetwork,'alpha');
assert.equal(deviceFilter,'shared-mac');
storage.set('controlforge-network','beta');
assert.equal(activeNetwork,'alpha','scope must not drift with another selection');
globalThis.fetch=async(path,options)=>{
  assert.equal(path,'/v1/dashboard/cases');
  assert.equal(options.headers['x-network-id'],'alpha');
  return {ok:true,json:async()=>({cases:[]})};
};
assert.deepEqual(await requestApi('/v1/dashboard/cases'),{cases:[]});
assert.equal(new URL(investigationUrl('x&network=beta#'), 'https://admin.test').searchParams.get('device'),'x&network=beta#');
assert.equal(new URL(investigationUrl('x&network=beta#'), 'https://admin.test').searchParams.get('network'),'alpha');
for(const search of ['?network=beta','?network=','?network=alpha&network=beta','?network=alpha&device=','?network=alpha&device=a&device=b','?network=alpha&device=%00','?network=alpha&device='+'x'.repeat(129)]){
  location.search=search;
  await assert.rejects(configureInvestigationScope());
  assert.equal($('#network-console-link').hidden,false);
  assert.equal($('#network-console-link').href,'/console');
}
location.search='?network=alpha';
await configureInvestigationScope();
assert.equal(deviceFilter,null);
location.search='?network=beta';
await showOperations();
assert.equal($('#operations').hidden,true);
assert.equal($('#workspace-nav').hidden,true);
assert.equal($('#auth-panel .grid').hidden,true);
assert.equal($('#main').attributes['aria-busy'],'false');
assert.equal($('#connection-chip').textContent,'Network unavailable');
networkSupport=false;
location.search='?network=beta';
await assert.rejects(configureInvestigationScope());

const pending=new Map();
api=path=>new Promise((resolve,reject)=>pending.set(path,{resolve,reject}));
const settle=id=>{
  pending.get('/v1/cases/'+id).resolve({case_id:id});
  pending.get('/v1/cases/'+id+'/evidence').resolve({evidence:[{alert_id:id}],total:1,truncated:false});
};
const first=loadCase('first');
const second=loadCase('second');
assert.equal(selectedCase,null);
settle('second');await second;
settle('first');await first;
assert.equal(selectedCase.case_id,'second');
assert.deepEqual(rendered,['second']);
assert.equal(evidenceRows[0].alert_id,'second');
const failed=loadCase('failed');
pending.get('/v1/cases/failed').reject(new Error('Synthetic failure'));
await failed;
assert.equal(selectedCase,null);
assert.deepEqual(evidenceRows,[]);
assert.equal($('#case-workbench').children[0].value,'Case evidence unavailable');
assert.equal($('#case-workbench').attributes['aria-busy'],'false');
const stale=loadCase('stale');
clearCaseSelection();settle('stale');await stale;
assert.equal(selectedCase,null);
assert.deepEqual(rendered,['second']);
console.log('investigation contracts passed');
