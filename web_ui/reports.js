/* Full-run report library. Artifact text is data, never executable application code. */
'use strict';
window.TraceReports=(()=>{
 const make=(tag,text,className)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;};
 const dialog=make('dialog',undefined,'report-library');dialog.setAttribute('aria-labelledby','report-library-title');
 const bar=make('header',undefined,'report-library-bar'),heading=make('div');
 const title=make('h2','Reports & logs');title.id='report-library-title';const provenance=make('p');heading.append(title,provenance);
 const actions=make('div',undefined,'report-library-actions'),refresh=make('button','Refresh files','outline'),downloadAll=make('button','Download all (.zip)','outline'),close=make('button','×','report-close');close.setAttribute('aria-label','Close reports');actions.append(refresh,downloadAll,close);bar.append(heading,actions);
 const message=make('p',undefined,'report-library-message');message.setAttribute('role','status');message.hidden=true;
 const picker=make('select',undefined,'report-mobile-picker');picker.setAttribute('aria-label','Choose report or log');
 const layout=make('div',undefined,'report-library-layout'),nav=make('nav',undefined,'report-files');nav.setAttribute('aria-label','Run artifacts');const reader=make('section',undefined,'report-reader');reader.setAttribute('aria-label','Selected report or log');layout.append(nav,reader);dialog.append(bar,message,picker,layout);document.body.append(dialog);
 let context=null,bundle=null,selected=null,view='report',requestSerial=0;
 function status(text){message.hidden=!text;message.textContent=text;}
 function save(content,name,type='text/plain'){const url=URL.createObjectURL(content instanceof Blob?content:new Blob([content],{type})),a=make('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);}
 function selectedFile(){return bundle?.files.find(f=>f.id===selected);}
 async function load(){
  const serial=++requestSerial;refresh.disabled=true;status('Loading retained artifacts…');
  try{const response=await fetch(context.endpoint);if(!response.ok)throw Error('Reports are not available for this run yet.');const value=await response.json();if(serial!==requestSerial)return;if(!Array.isArray(value.files))throw Error('The report inventory could not be read.');bundle=value;
   if(!selectedFile())selected=bundle.files.find(f=>f.id==='c3-html')?.id||bundle.files.find(f=>f.id==='c2-result')?.id||bundle.files[0]?.id;
   status(bundle.files.length?`${bundle.files.length} files · credentials redacted in views and downloads.`:'No artifacts yet. Files appear as the run writes them.');renderNav();renderReader();downloadAll.disabled=!bundle.files.length;
  }catch(error){if(serial===requestSerial){status(error.message);downloadAll.disabled=true;reader.replaceChildren(make('p','Refresh after the investigation produces its reports.','report-empty'));}}
  finally{if(serial===requestSerial)refresh.disabled=false;}
 }
 function renderNav(){nav.replaceChildren();picker.replaceChildren();for(const group of ['C2','C3','Logs']){const optgroup=make('optgroup');optgroup.label=group;for(const file of bundle.files.filter(f=>f.group===group)){const option=make('option',file.title);option.value=file.id;option.selected=file.id===selected;optgroup.append(option);}picker.append(optgroup);}for(const group of ['C2','C3','Logs']){const section=make('section'),h=make('h3',group==='C2'?'C2 · Investigation':group==='C3'?'C3 · Verification':'Run logs');section.append(h);
  for(const file of bundle.files.filter(f=>f.group===group)){const button=make('button',undefined,'report-file');button.append(make('span',file.title),make('small',`${file.kind.toUpperCase()} · ${(file.bytes/1024).toFixed(1)} KB`));if(file.id===selected)button.setAttribute('aria-current','true');button.addEventListener('click',()=>{selected=file.id;view='report';renderNav();renderReader();});section.append(button);}
  for(const missing of (bundle.missing||[]).filter(f=>f.group===group)){const p=make('p',`${missing.title} · not produced`,'report-unavailable');section.append(p);}nav.append(section);
 }}
 function section(title,content,open=false){const d=make('details');d.open=open;d.append(make('summary',title),make('pre',typeof content==='string'?content:JSON.stringify(content,null,2)));return d;}
 function jsonReport(content){let data;try{data=JSON.parse(content);}catch{reader.append(make('pre',content));return;}
  if(!data||typeof data!=='object'){reader.append(make('pre',content));return;}
  const verdict=data.verdict||data.decision;if(verdict&&typeof verdict==='object'){const stamp=make('div',undefined,'report-verdict');stamp.append(make('strong',verdict.label||verdict.verdict||'Review'),make('span',verdict.confidence?`${verdict.confidence} confidence`:'Independent verification'));reader.append(stamp);}
  if(data.hypothesis)reader.append(make('p',data.hypothesis,'report-hypothesis'));
  const labels={claims:'Claims',techniques:'Techniques',findings:'Verification findings',verification:'Verification results',queries:'Queries',agent:'Agent findings',skeptic:'Skeptic review',actions:'Response drafts',limitations:'Limitations',notes:'Notes',flags:'Report annotations',manifest:'Run manifest',evidence:'Evidence',step_results:'Step results',dynamic_steps:'Agent steps',audit:'Audit',trace:'Tool trace'};
  for(const [key,value]of Object.entries(data)){if(key==='hypothesis')continue;const count=Array.isArray(value)?` (${value.length})`:'';reader.append(section((labels[key]||key.replaceAll('_',' '))+count,value,['verification','flags','limitations'].includes(key)));}
 }
 function logReport(file){const lines=file.content.split('\n').filter(line=>line.trim());const entries=lines.map((line,index)=>{let value;try{value=JSON.parse(line);}catch{value={unparsed_line:line};}return {line:index+1,value,search:line.toLowerCase()};});
  const tools=make('div',undefined,'report-log-tools'),search=make('input');search.type='search';search.placeholder='Search roles, tools, IDs or log content';search.setAttribute('aria-label','Search log entries');const count=make('span');tools.append(search,count);const list=make('div',undefined,'report-log-entries'),pager=make('div',undefined,'report-log-pages'),prev=make('button','Previous','outline'),next=make('button','Next','outline'),pageLabel=make('span');pager.append(prev,pageLabel,next);reader.append(tools,list,pager);let page=0;const size=50;
  function paint(){const matches=entries.filter(e=>e.search.includes(search.value.toLowerCase()));const pages=Math.max(1,Math.ceil(matches.length/size));page=Math.min(page,pages-1);count.textContent=`${matches.length} / ${entries.length} entries`;list.replaceChildren();for(const entry of matches.slice(page*size,(page+1)*size)){const v=entry.value;const name=v?.role||[v?.server,v?.tool].filter(Boolean).join('.')||v?.method||'Audit entry';const ms=typeof v?.ms==='number'?` · ${(v.ms/1000).toFixed(2)}s audit`:'';list.append(section(`Line ${entry.line} · ${name}${ms}`,v));}if(!matches.length)list.append(make('p','No matching log entries.','report-empty'));prev.disabled=page===0;next.disabled=page+1>=pages;pageLabel.textContent=`Page ${page+1} of ${pages}`;}
  search.addEventListener('input',()=>{page=0;paint();});prev.addEventListener('click',()=>{page--;paint();});next.addEventListener('click',()=>{page++;paint();});paint();
 }
 function renderReader(){const file=selectedFile();reader.replaceChildren();if(!file){reader.append(make('p','No retained files yet.','report-empty'));return;}
  const top=make('div',undefined,'report-reader-top'),info=make('div');info.append(make('h3',file.title),make('p',file.path,'report-path'));const download=make('button','Download file','outline');download.addEventListener('click',()=>save(file.content,file.path.split('/').at(-1),file.kind==='html'?'text/html':'text/plain'));top.append(info,download);reader.append(top);
  const controls=make('div',undefined,'report-view-toggle');controls.setAttribute('role','group');controls.setAttribute('aria-label','Report view');for(const name of ['report','source']){const b=make('button',name==='report'?'Read':'Source');b.setAttribute('aria-pressed',String(view===name));b.addEventListener('click',()=>{view=name;renderReader();});controls.append(b);}reader.append(controls);
  if(view==='source'){reader.append(make('pre',file.content,'report-source'));return;}
  if(file.kind==='html'){const frame=make('iframe');frame.title='Full C3 report';frame.className='report-html';frame.setAttribute('sandbox','');frame.referrerPolicy='no-referrer';frame.src=context.endpoint+'/'+file.id+'/view';reader.append(frame);}
  else if(file.kind==='jsonl')logReport(file);
  else if(file.kind==='json')jsonReport(file.content);
  else reader.append(make('pre',file.content,'report-source'));
 }
 picker.addEventListener('change',()=>{selected=picker.value;view='report';renderNav();renderReader();});
 refresh.addEventListener('click',load);close.addEventListener('click',()=>dialog.close());dialog.addEventListener('close',()=>{requestSerial++;});
 downloadAll.addEventListener('click',async()=>{downloadAll.disabled=true;const endpoint=context.endpoint,runId=bundle.run_id;try{const response=await fetch(endpoint+'.zip');if(!response.ok)throw Error('The archive could not be downloaded.');save(await response.blob(),`trace-${runId}-reports.zip`);}catch(error){status(error.message);}finally{downloadAll.disabled=!bundle?.files.length;}});
 async function open(options){context={...options};bundle=null;selected=null;view='report';provenance.textContent=`${options.mode==='recorded'?'Recorded evidence':'Live run'} · ${options.runId} · ${options.commit||'current execution'}`;nav.replaceChildren();reader.replaceChildren();downloadAll.disabled=true;if(!dialog.open)dialog.showModal();await load();}
 return {open};
})();
