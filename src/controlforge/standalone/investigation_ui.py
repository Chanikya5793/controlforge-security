# ruff: noqa: E501, RUF001
"""Same-origin investigation navigation and evidence-first display helpers."""

INVESTIGATION_SCRIPT = r"""
const investigationUrl=(deviceId=null)=>{
  const query=new URLSearchParams({investigate:'1',network:activeNetwork});
  if(deviceId!==null)query.set('device',deviceId);
  return '/admin?'+query.toString()+'#cases-workspace';
};
const deviceLink=(deviceId,label)=>{
  const link=text('a',label,'device-link');link.href=investigationUrl(deviceId);return link;
};
const configureInvestigationScope=async()=>{
  const back=$('#network-console-link');back.hidden=!networkSupport;back.href='/console';
  const params=new URLSearchParams(location.search);
  for(const key of ['network','device'])if(params.getAll(key).length>1)throw new Error('This investigation link is ambiguous. Return to the network console and reopen it.');
  const requested=params.get('network');
  activeNetwork=requested??sessionStorage.getItem('controlforge-network')??me.tenant_id;
  if(networkSupport){
    const listing=await api('/v1/networks',{headers:{'x-network-id':''}});
    const network=listing.networks.find(n=>n.tenant_id===activeNetwork&&n.status==='active');
    if(!network)throw new Error('This network is unavailable to your account. Return to the network console and select an available network.');
    $('#overview-title').textContent=network.display_name+' · Investigations';
    $('#identity-detail').textContent=network.display_name+' · '+me.role;
  }else if(activeNetwork!==me.tenant_id){
    throw new Error('This investigation link does not belong to your network.');
  }
  // A link selects an authorized view; it never changes account permissions.
  sessionStorage.setItem('controlforge-network',activeNetwork);
  deviceFilter=params.get('device');
  if(deviceFilter!==null&&(!deviceFilter.length||deviceFilter.length>128||/[\x00-\x1f\x7f]/.test(deviceFilter)))throw new Error('This device link is invalid. Return to the network console and reopen the device.');
  back.href='/console?'+new URLSearchParams({network:activeNetwork});
};
const renderDeviceContext=async()=>{
  const root=$('#device-context');root.hidden=deviceFilter===null;
  if(deviceFilter===null)return;
  root.replaceChildren(text('p','Loading this device’s connection evidence…'));
  try{
    const {device}=await api('/v1/dashboard/devices/'+encodeURIComponent(deviceFilter));
    const facts=text('dl','','provenance');
    for(const [label,value] of [['Device ID',device.device_id],['Recorded state',device.status],['Checked by server',absolute(device.observed_at)],['Last authenticated check-in',absolute(device.last_seen_at)],['Last activity received',absolute(device.last_telemetry_at)]])facts.append(definition(label,value));
    const steps=text('ul','');for(const step of device.guidance.steps)steps.append(text('li',step));
    const connection=text('details','','review-guidance');
    connection.append(text('summary','Connection evidence & next steps'),text('p',device.guidance.detail,'muted'),facts,steps,text('p',device.guidance.limits,'muted small'));
    root.replaceChildren(text('div','Case filter · Exact linked device','eyebrow'),text('h3',device.display_name),text('p',device.guidance.title),connection,text('p','Only the case queue is filtered. Other panels remain network-wide. A case may include evidence from other devices.','muted small'),deviceLink(null,'Show all network cases'));
  }catch(error){
    root.replaceChildren(text('h3','Device connection details unavailable'),text('p',error.message,'error'),text('p','The exact device filter remains active. No device was inferred from an actor name. Retry Refresh or return to all network cases.','muted'),deviceLink(null,'Show all network cases'));
  }
};
const renderFindingGuide=(card,item)=>{
  const guide=item.guidance;
  card.append(text('h4','What was recorded'),text('p',guide.summary));
  const source=text('div','','cluster small');
  source.append(text('span','Reported actor: '+item.actor));
  if(item.device)source.append(deviceLink(item.device.device_id,'View device: '+item.device.display_name));
  else source.append(text('span',item.event.device_id?'Linked device record unavailable':'No linked device'));
  card.append(source,text('p','Event reported at '+absolute(item.event.occurred_at)+' · Received by server '+absolute(item.event.received_at),'muted small'),text('h4','Why review it?'),text('p',guide.context,'muted'));
  if(item.rule.description)card.append(text('p','Saved rule’s purpose: '+item.rule.description,'muted small'));
  const review=text('details','','review-guidance'),steps=text('ol','');
  review.append(text('summary','What to review next'));
  for(const [index,step] of guide.steps.entries())steps.append(text('li',index===guide.steps.length-1&&!canInvestigate()?'Ask an analyst to record the review and choose an evidence-based disposition. Your role is read-only.':step));
  review.append(steps,text('p',guide.limits,'notice small'));card.append(review);
};
const clearCaseSelection=()=>{
  caseRequest++;requestedCaseId=null;selectedCase=null;evidenceRows=[];
  $('#case-workbench').setAttribute('aria-busy','false');
  empty($('#case-workbench'),'Select a case','Choose a finding from this network’s filtered queue.');
};
"""
