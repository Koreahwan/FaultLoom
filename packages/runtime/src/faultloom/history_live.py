"""Editor form markup and same-origin client; no external dependencies."""

STYLE = """
.live-actions{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}.live-status{flex:1;min-width:170px;font-size:12px;color:var(--muted);line-height:1.7}.live-status.error{color:#973b30}
.case-actions{display:flex;gap:8px;margin:17px 0}.event .correct{margin-top:10px;padding:5px 10px;font-size:11px}.editor-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.editor-grid .wide{grid-column:1/-1}
.editor-grid label{font-weight:600}.editor-grid select{max-width:none;width:100%}.editor-grid fieldset{border:1px solid var(--line);border-radius:8px;padding:12px}.editor-grid legend{font-size:12px;color:var(--muted)}
.domain-options{display:flex;flex-wrap:wrap;gap:12px}.domain-options label{display:flex;gap:5px;align-items:center;font-weight:400}.domain-options input{width:auto;accent-color:var(--green)}
.editor-grid textarea{height:170px;margin:0;font-family:inherit}.editor-error{color:#973b30;font-size:12px;line-height:1.8;white-space:pre-wrap;margin-top:12px}.editor-buttons{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}
.editor-target{font-size:12px;line-height:1.7;background:var(--paper);padding:10px;border-radius:8px;overflow-wrap:anywhere}.editor-help{font-size:11px;color:var(--muted);margin-top:5px}
.event-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.source-status{font-size:11px;margin-top:9px;color:var(--muted)}.case-actions{flex-wrap:wrap}
@media(max-width:650px){.editor-grid{grid-template-columns:1fr}dialog{padding:18px}header{gap:10px}header>span.local{display:none}.brand{flex-shrink:0}header>a.local{white-space:nowrap}}
"""

ACTIONS = '''<section class="live-actions" aria-label="기록 관리">
<span id="live-status" class="live-status" role="status">기록을 불러오고 있습니다.</span>
<button id="refresh-history" class="secondary" type="button">새로 불러오기</button>
<button id="create-case" class="primary" type="button" disabled>작업 등록</button>
</section>'''

FORMS = '''
<dialog id="case-editor" aria-labelledby="case-editor-heading">
<form id="case-form"><div class="dialoghead"><h2 id="case-editor-heading">작업 등록</h2><button type="button" id="close-case" aria-label="작업 창 닫기">닫기</button></div>
<div class="editor-grid">
<div class="wide"><label for="case-title">작업 제목</label><input id="case-title" maxlength="240" required></div>
<div><label for="case-track">업무 유형</label><select id="case-track"></select></div>
<div><label for="case-state">작업 상태</label><select id="case-state"></select></div>
<div class="wide"><label for="case-subject">대상·고객 이름</label><input id="case-subject" maxlength="240"><p class="editor-help">개인 기록에 사용할 이름을 입력하세요.</p></div>
<fieldset class="wide"><legend>분야</legend><div class="domain-options" id="case-domains"></div></fieldset>
<div id="case-date-field"><label for="case-date">시작 날짜 (선택)</label><input id="case-date" type="date"></div>
</div><p id="case-error" class="editor-error" role="alert"></p>
<div class="editor-buttons"><button type="button" id="cancel-case" class="secondary">취소</button><button type="submit" id="save-case" class="primary">작업 저장</button></div></form>
</dialog>
<dialog id="note-editor" aria-labelledby="note-editor-heading">
<form id="note-form"><div class="dialoghead"><h2 id="note-editor-heading">기록 추가</h2><button type="button" id="close-note" aria-label="기록 창 닫기">닫기</button></div>
<p id="note-target" class="editor-target"></p><div class="editor-grid">
<div><label for="note-kind">기록 종류</label><select id="note-kind"></select></div>
<div><label for="note-date">발생 날짜 (선택)</label><input id="note-date" type="date"></div>
<div class="wide"><label for="note-summary">기록 제목</label><input id="note-summary" maxlength="240" required></div>
<div class="wide"><label for="note-detail">내용</label><textarea id="note-detail" maxlength="12000"></textarea></div>
</div><p id="note-error" class="editor-error" role="alert"></p>
<div class="editor-buttons"><button type="button" id="cancel-note" class="secondary">취소</button><button type="submit" id="save-note" class="primary">기록 저장</button></div></form>
</dialog>
<dialog id="file-editor" aria-labelledby="file-editor-heading">
<form id="file-form"><div class="dialoghead"><h2 id="file-editor-heading">자료 연결</h2><button type="button" id="close-file" aria-label="자료 창 닫기">닫기</button></div>
<p id="file-target" class="editor-target"></p><div class="editor-grid">
<div><label for="file-origin">자료 위치</label><select id="file-origin" required></select></div>
<div><label for="file-label">자료 이름</label><input id="file-label" maxlength="240" required></div>
<div class="wide"><label for="file-path">위치 안의 파일 경로</label><input id="file-path" maxlength="700" placeholder="예: reports/result.pdf" required><p class="editor-help">선택한 위치를 기준으로 입력하세요. 연결 후 사본을 보관할 수 있습니다. 파일당 최대 16 MiB입니다.</p></div>
</div><p id="file-error" class="editor-error" role="alert"></p>
<div class="editor-buttons"><button type="button" id="cancel-file" class="secondary">취소</button><button type="submit" id="save-file" class="primary">자료 연결 저장</button></div></form>
</dialog>
'''

SCRIPT = r"""
let editingCase=null,notingCase=null,correctingEvent=null,pendingOperation=null;
function status(text,error=false){el('live-status').textContent=text;el('live-status').className='live-status'+(error?' error':'');}
function clearFilters(){query=track=origin=state='';for(const id of ['query','track-filter','origin-filter','state-filter'])el(id).value='';}
function setBusy(busy){data.busy=busy;for(const id of ['save-case','save-note','close-case','cancel-case','close-note','cancel-note','save-file','close-file','cancel-file','refresh-history'])el(id).disabled=busy;render();}
async function request(path,options={}){
 const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options});
 let value={};try{value=await response.json();}catch{}
 if(!response.ok){const err=new Error(value.message||value.error||'request_failed');err.status=response.status;throw err;}
 return value;
}
async function reloadHistory(selectCase=null){
 const snapshot=await request('/api/history');data.snapshot=snapshot;cases.splice(0,cases.length,...snapshot.cases);data.ready=true;
 if(selectCase){clearFilters();active=selectCase;}updateMetrics();render();
}
function populate(id,values){for(const [value,label] of Object.entries(values)){const option=node('option','',label);option.value=value;el(id).append(option);}}
populate('case-track',data.tracks);populate('case-state',data.states);populate('note-kind',data.notes);
for(const [value,label] of Object.entries(data.domains)){const wrap=node('label'),check=node('input');check.type='checkbox';check.value=value;check.name='domain';wrap.append(check,document.createTextNode(label));el('case-domains').append(wrap);
 check.addEventListener('change',()=>{if(check.checked){for(const other of el('case-domains').querySelectorAll('input'))if(value==='unknown'?other!==check:other.value==='unknown')other.checked=false;}});}
function openCase(caseId=null){
 if(!data.ready||data.busy)return;editingCase=caseId;pendingOperation=null;el('case-form').reset();el('case-error').textContent='';
 const c=cases.find(c=>c.id===caseId);el('case-editor-heading').textContent=c?'작업 정보 수정':'작업 등록';
 el('case-title').value=c?.title||'';el('case-track').value=c?.track||'research';el('case-state').value=c?.state||'active';el('case-subject').value=c?.subject||'';
 for(const checkbox of el('case-domains').querySelectorAll('input'))checkbox.checked=(c?.domains||['unknown']).includes(checkbox.value);
 el('case-date-field').hidden=!!c;el('case-editor').showModal();el('case-title').focus();
}
function openNote(caseId,eventId=null){
 if(!data.ready||data.busy)return;notingCase=caseId;correctingEvent=eventId;pendingOperation=null;el('note-form').reset();el('note-error').textContent='';
 const c=cases.find(c=>c.id===caseId),event=c?.events.find(e=>e.id===eventId);if(!c)return;
 el('note-editor-heading').textContent=event?'기록 정정':'기록 추가';
 el('note-target').textContent=event?'정정할 기록: '+(event.data.summary||event.data.title||event.data.label||data.kinds[event.kind]):c.title;
 el('note-kind').value=event?'correction':'note';el('note-kind').disabled=!!event;
 for(const option of el('note-kind').options)if(option.value==='correction')option.disabled=!event;
 el('note-editor').showModal();el('note-summary').focus();
}
async function saveOperation(operation,dialog,errorId){
 const signature=JSON.stringify(operation);
 if(!pendingOperation||pendingOperation.signature!==signature)pendingOperation={signature,body:{...operation,operation_id:crypto.randomUUID().replaceAll('-',''),expected_head:data.snapshot.head}};
 setBusy(true);el(errorId).textContent='';status('기록을 저장하고 있습니다.');
 try{const result=await request('/api/mutate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pendingOperation.body)});
   await reloadHistory(result.case_id);pendingOperation=null;dialog.close();status(result.appended?'저장했습니다.':'이미 저장된 기록을 확인했습니다.');
 }catch(error){
   if(error.status===409){pendingOperation=null;try{await reloadHistory();}catch{}el(errorId).textContent='다른 기록이 먼저 저장됐습니다. 최신 목록을 불러왔으니 입력 내용을 확인한 뒤 다시 저장하세요.';}
   else if(error.status===401){data.ready=false;el(errorId).textContent='접속이 만료됐습니다. 실행할 때 만든 새 접속 링크로 다시 열어주세요.';}
   else if(error.status===400){el(errorId).textContent='입력 내용을 확인해 주세요. '+error.message;pendingOperation=null;}
   else{el(errorId).textContent='저장 결과를 확인하지 못했습니다. 연결을 확인하고 같은 내용으로 다시 저장해 주세요. 중복 요청은 한 번만 기록됩니다.';}
   status('저장을 확인하지 못했습니다.',true);
 }finally{setBusy(false);}
}
el('case-form').addEventListener('submit',async event=>{event.preventDefault();if(data.busy)return;
 const domains=Array.from(el('case-domains').querySelectorAll('input:checked'),input=>input.value);if(!domains.length){el('case-error').textContent='분야를 하나 이상 선택하세요.';return;}
 const operation={operation:editingCase?'update':'create',data:{title:el('case-title').value.trim(),track:el('case-track').value,state:el('case-state').value,subject:el('case-subject').value.trim(),domains}};
 if(editingCase)operation.case_id=editingCase;else operation.occurred_at=el('case-date').value||null;
 await saveOperation(operation,el('case-editor'),'case-error');
});
el('note-form').addEventListener('submit',async event=>{event.preventDefault();if(data.busy)return;
 const value={kind:el('note-kind').value,summary:el('note-summary').value.trim(),detail:el('note-detail').value};if(correctingEvent)value.corrects=correctingEvent;
 await saveOperation({operation:'record',case_id:notingCase,occurred_at:el('note-date').value||null,data:value},el('note-editor'),'note-error');
});
for(const [button,dialog] of [['close-case','case-editor'],['cancel-case','case-editor'],['close-note','note-editor'],['cancel-note','note-editor'],['close-file','file-editor'],['cancel-file','file-editor']])el(button).addEventListener('click',()=>{if(!data.busy)el(dialog).close();});
for(const id of ['case-editor','note-editor','file-editor'])el(id).addEventListener('cancel',event=>{if(data.busy)event.preventDefault();});
el('create-case').addEventListener('click',()=>openCase());
el('refresh-history').addEventListener('click',async()=>{if(data.busy)return;setBusy(true);try{await reloadHistory();status('최신 기록을 불러왔습니다.');}catch{status('기록을 불러오지 못했습니다. 실행 중인 서버와 접속 상태를 확인하세요.',true);}finally{setBusy(false);}});
async function startEditor(){
 const token=new URLSearchParams(location.hash.slice(1)).get('access');history.replaceState(null,'',location.pathname);
 try{if(token)await request('/api/session',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:'{}'});
 await reloadHistory();status('이 PC의 개인 기록에 연결됐습니다.');
 }catch{status('접속 링크가 필요하거나 만료됐습니다. 서버를 실행할 때 만든 접속 링크로 열어주세요.',true);}
}
startEditor();
"""

SCRIPT += r"""
let linkingCase=null;const pendingCommands=new Map();
function openFile(caseId){
 if(!data.ready||data.busy)return;linkingCase=caseId;pendingOperation=null;el('file-form').reset();el('file-error').textContent='';
 el('file-origin').replaceChildren();for(const value of data.snapshot.source_origins||[]){const option=node('option','',value);option.value=value;el('file-origin').append(option);}
 el('file-target').textContent=cases.find(c=>c.id===caseId)?.title||'';el('file-editor').showModal();el('file-label').focus();
}
el('file-form').addEventListener('submit',async event=>{event.preventDefault();if(data.busy)return;
 await saveOperation({operation:'link_file',case_id:linkingCase,data:{origin:el('file-origin').value,path:el('file-path').value.trim(),label:el('file-label').value.trim()}},el('file-editor'),'file-error');
});
async function sourceCommand(operation,caseId,referenceId=null){
 if(!data.ready||data.busy)return;const value={operation,case_id:caseId,data:referenceId?{reference_event_id:referenceId}:{}};
 const signature=JSON.stringify(value);if(!pendingCommands.has(signature))pendingCommands.set(signature,{...value,operation_id:crypto.randomUUID().replaceAll('-',''),expected_head:data.snapshot.head});
 setBusy(true);status(operation==='check_sources'?'원본 파일을 다시 확인하고 있습니다.':'원본 사본을 보관하고 있습니다.');
 try{const result=await request('/api/mutate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(pendingCommands.get(signature))});
   await reloadHistory(caseId);pendingCommands.delete(signature);status(operation==='check_sources'?'원본 확인 결과를 기록했습니다.':'사본을 보관했습니다. 내려받아 당시 파일을 확인할 수 있습니다.');
 }catch(error){if(error.status===409){pendingCommands.delete(signature);try{await reloadHistory();}catch{}status('다른 기록이 먼저 저장됐습니다. 최신 상태를 확인하고 다시 실행하세요.',true);}
   else if(error.status===401){data.ready=false;status('접속이 만료됐습니다. 실행할 때 만든 새 접속 링크로 다시 열어주세요.',true);}
   else if(error.status===400){pendingCommands.delete(signature);status('자료를 확인해 주세요. '+error.message,true);}
   else status('결과를 확인하지 못했습니다. 연결을 확인하고 같은 작업을 다시 실행하세요.',true);
 }finally{setBusy(false);}
}
async function downloadAttachment(caseId,event){
 if(data.busy)return;setBusy(true);status('보관한 사본의 무결성을 확인하고 있습니다.');
 try{const response=await fetch('/api/attachment/'+caseId+'/'+event.id,{credentials:'same-origin',cache:'no-store'});if(!response.ok)throw new Error('download failed');
   const blob=await response.blob(),bytes=await blob.arrayBuffer();
   const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),value=>value.toString(16).padStart(2,'0')).join('');
   if(hash!==event.data.sha256||bytes.byteLength!==event.data.bytes)throw new Error('digest mismatch');
   const url=URL.createObjectURL(blob),link=node('a');link.href=url;link.download=event.data.name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
   status('사본의 해시가 일치합니다. 브라우저에 저장을 요청했습니다.');
 }catch{status('사본을 확인하거나 내려받지 못했습니다. 원본 이력과 백업을 확인하세요.',true);}finally{setBusy(false);}
}
"""
