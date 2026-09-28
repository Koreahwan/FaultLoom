"""Self-contained human reference UI. No source bodies, remote assets, or live actions."""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re

from .knowledge import CHECK_SCHEMA, KINDS, REVIEWS, CatalogError, validate_catalog

_STYLE = """
:root{color-scheme:light;--ink:#172735;--muted:#5c6d77;--line:#dce4e6;--paper:#f4f7f6;--green:#167768;--pale:#e5f2ed}
*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;background:var(--paper);color:var(--ink);font-family:'Segoe UI','Malgun Gothic',sans-serif;font-size:14px}
button,input,select,textarea{font:inherit}button{cursor:pointer}button:disabled{cursor:not-allowed;opacity:.5}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #3b9e90;outline-offset:3px}
header{background:#152d39;color:#fff;padding:24px 36px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.brand{display:flex;gap:12px;align-items:center}.mark{background:#bce0cd;color:#163e31;border-radius:10px;width:38px;height:38px;display:grid;place-items:center;font-weight:800;font-size:23px}
.wordmark{font-size:19px;font-weight:750;letter-spacing:.5px}.brand small{display:block;color:#bdd0d4;font-size:12px;margin-top:3px}
.local{color:#d2e8dd;border:1px solid #4f716f;border-radius:30px;padding:7px 12px;font-size:12px;text-decoration:none}
main{max-width:1500px;margin:0 auto;padding:28px 30px 38px}.intro{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin-bottom:22px}
h1{font-size:28px;letter-spacing:-1px;margin:0 0 8px}p{line-height:1.65;margin:0;color:var(--muted)}.date{font-size:12px;text-align:right;line-height:1.7;color:var(--muted)}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}.metric{background:#fff;border:1px solid var(--line);border-radius:12px;padding:17px 20px}
.metric strong{display:block;font-size:28px;line-height:1.2;margin-bottom:5px;letter-spacing:-1px}.metric span{font-size:12px;color:var(--muted)}
.workspace{display:grid;grid-template-columns:190px minmax(350px,1fr) 320px;gap:18px;align-items:start}.panel{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden}
.panelhead{padding:19px 18px 14px;font-weight:700;font-size:14px}.filters{padding:0 9px 12px}.filter{border:0;background:none;width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px;border-radius:8px;color:var(--muted);text-align:left}
.filter[aria-pressed=true]{background:var(--pale);color:#155e50;font-weight:700}.count{font-size:11px;background:#edf1f2;padding:3px 7px;border-radius:12px}
.side-note{padding:16px 17px;border-top:1px solid var(--line);font-size:12px;line-height:1.7;color:var(--muted)}
.toolbar{padding:16px;display:flex;gap:9px;border-bottom:1px solid var(--line);flex-wrap:wrap}.search{flex:1;min-width:160px}
input,select{width:100%;border:1px solid #ced9dc;border-radius:8px;padding:10px 12px;background:#fff;color:var(--ink)}select{width:auto;max-width:160px;font-size:12px}
.resultbar{display:flex;justify-content:space-between;gap:12px;padding:12px 17px;font-size:12px;color:var(--muted);border-bottom:1px solid #edf0f1}
.rows{max-height:590px;overflow:auto}.row{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid #edf0f1}.row.active{background:#f0f7f4;box-shadow:inset 3px 0 #167768}
.row input{width:16px;height:16px;flex:0 0 16px;accent-color:var(--green);margin:0}.row-main{border:0;background:transparent;color:inherit;text-align:left;min-width:0;flex:1;padding:0}
.row-title{display:block;font-weight:650;font-size:13px;line-height:1.55;overflow-wrap:anywhere}.row-path{display:block;font-size:11px;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}
.row-meta{display:flex;align-items:center;gap:6px;margin-top:7px;flex-wrap:wrap}.chip{display:inline-block;font-size:10px;padding:3px 7px;border-radius:5px;background:#edf1f3;color:#50636e}
.chip.good{background:#e6f3ec;color:#286748}.chip.warn{background:#fff0d5;color:#795619}.empty{padding:50px 20px;text-align:center;color:var(--muted);line-height:1.8}
.more{margin:12px auto;display:block;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px 20px;color:var(--muted)}
.detail{padding:0 19px 20px}.detail h2{font-size:17px;line-height:1.6;overflow-wrap:anywhere;margin:0 0 10px}.detail .description{font-size:12px;line-height:1.7;margin:14px 0 20px;padding:12px;background:#f6f8f7;border-radius:8px}
.field{margin:17px 0}.field label{display:block;font-size:11px;font-weight:700;color:var(--muted);margin-bottom:6px}.field .value{font-size:12px;line-height:1.65;overflow-wrap:anywhere}.mono{font-family:Consolas,monospace;font-size:11px!important}
.actionbar{margin-top:18px;padding:14px 17px;border:1px solid #b9d8ca;border-radius:12px;background:#eff7f2;display:flex;gap:15px;align-items:center;justify-content:space-between}.actionbar p{font-size:12px}
.primary{background:var(--green);border:0;color:#fff;border-radius:8px;padding:11px 17px;font-weight:650;white-space:nowrap}.secondary{border:1px solid var(--line);background:#fff;border-radius:8px;padding:10px 14px;color:var(--ink)}
footer{padding-top:20px;font-size:11px;color:var(--muted);line-height:1.8}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
dialog{border:0;border-radius:16px;box-shadow:0 22px 90px #162c3940;width:min(760px,92vw);padding:24px}dialog::backdrop{background:#0b22275c}dialog h2{margin:0 0 8px;font-size:21px}
.dialoghead{display:flex;justify-content:space-between;gap:15px;margin-bottom:16px}.dialoghead button{border:0;background:#f1f4f3;border-radius:7px;padding:6px 11px;color:var(--ink)}
dialog label{display:block;font-size:12px;margin-bottom:6px}textarea{width:100%;height:300px;resize:vertical;border:1px solid var(--line);border-radius:8px;padding:12px;margin:14px 0;font-family:Consolas,'Malgun Gothic',monospace;font-size:12px;line-height:1.7}
.dialogactions{display:flex;justify-content:flex-end;gap:8px;align-items:center;flex-wrap:wrap}.notice{font-size:11px;color:var(--muted);margin-right:auto;line-height:1.6}
@media(max-width:1100px){.workspace{grid-template-columns:165px minmax(300px,1fr)}.detailpanel{grid-column:1/-1}.detail{display:grid;grid-template-columns:1fr 1fr;gap:0 25px}.detail h2,.detail .description{grid-column:1/-1}.rows{max-height:540px}}
@media(max-width:650px){header{padding:18px}main{padding:20px 14px}.intro{display:block}.date{text-align:left;margin-top:10px}.metrics{grid-template-columns:1fr 1fr;gap:8px}.metric{padding:13px}.workspace{grid-template-columns:1fr}.filters{display:flex;overflow:auto}.filter{width:auto;flex-shrink:0}.side-note{display:none}.panelhead{padding:14px 16px}.detail{display:block}.actionbar{align-items:stretch;flex-direction:column}.local{font-size:10px}h1{font-size:25px}}
"""

_SCRIPT = r"""
'use strict';
const data = JSON.parse(document.getElementById('reference-data').textContent);
const catalog = data.catalog, entries = catalog.entries, labels = data.kinds, reviews = data.reviews;
const checks = new Map(data.check.entries.map(row => [row.id, row]));
const selected = new Set();
let currentKind = '', currentReview = '', query = '', visibleLimit = 100, activeId = entries[0]?.id;
const byId = new Map(entries.map(entry => [entry.id, entry]));
const el = id => document.getElementById(id);
const node = (tag, cls, text) => {const item = document.createElement(tag); if(cls) item.className = cls; if(text !== undefined) item.textContent = text; return item;};
const available = entry => checks.get(entry.id)?.status === 'unchanged' && entry.review !== 'retired';
const sourceLabel = entry => ({unchanged:'해시 일치',changed:'원본 변경',missing:'원본 없음',unsafe_or_unavailable:'원본 확인 필요'})[checks.get(entry.id)?.status] || '미확인';
el('origin').textContent = catalog.origin.label;
el('checked-at').textContent = new Date(data.check.checked_at).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})+' KST';
el('total').textContent = entries.length.toLocaleString();
el('kind-total').textContent = new Set(entries.map(e=>e.kind)).size;
el('matched').textContent = entries.filter(e=>checks.get(e.id)?.status==='unchanged').length.toLocaleString();
el('reviewed').textContent = entries.filter(e=>e.review==='operator_reviewed').length.toLocaleString();
function updateSelection(){
  el('selected-count').textContent = selected.size + '개 자료 선택';
  el('prepare').disabled = !selected.size;
}
function renderFilters(){
  el('filters').replaceChildren();
  for(const [kind,label] of [['','전체 자료'],...Object.entries(labels)]){
    const count=entries.filter(e=>!kind||e.kind===kind).length;
    const button=node('button','filter'); button.type='button'; button.setAttribute('aria-pressed',String(currentKind===kind));
    button.append(node('span','',label),node('span','count',String(count)));
    button.addEventListener('click',()=>{currentKind=kind;visibleLimit=100;renderFilters();renderRows();});
    el('filters').append(button);
  }
}
function field(label,value,mono=false){
  const wrap=node('div','field');wrap.append(node('label','',label),node('div','value'+(mono?' mono':''),value));return wrap;
}
function renderDetail(){
  const entry=byId.get(activeId);el('detail').replaceChildren();
  if(!entry){el('detail').append(node('p','','자료를 선택해 출처를 확인하세요.'));return;}
  el('detail').append(node('h2','',entry.title));
  el('detail').append(node('span','chip',labels[entry.kind]));
  el('detail').append(node('p','description','원본 본문과 이전 작업 지시는 실행하지 않습니다. 이 화면은 자료의 위치와 목록 생성 시점의 파일 상태를 보여줍니다.'));
  el('detail').append(field('출처',catalog.origin.label),field('원본 경로',entry.path,true),field('내용 검토 상태',reviews[entry.review]),field('원본 파일 상태',sourceLabel(entry)));
  el('detail').append(field('참조 ID',entry.id,true),field('SHA-256',entry.sha256,true),field('파일 크기',entry.bytes.toLocaleString()+' bytes'));
  if(entry.tags.length)el('detail').append(field('태그',entry.tags.join(' · ')));
}
function renderRows(){
  const words=query.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
  const filtered=entries.filter(entry=>{
    const text=[entry.title,entry.path,entry.kind,labels[entry.kind],...entry.tags].join(' ').toLocaleLowerCase();
    return (!currentKind||entry.kind===currentKind)&&(!currentReview||entry.review===currentReview)&&words.every(word=>text.includes(word));
  });
  if(!filtered.some(entry=>entry.id===activeId)){activeId=filtered[0]?.id;renderDetail();}
  el('rows').replaceChildren();
  el('result-count').textContent=filtered.length.toLocaleString()+'개 자료';
  if(!filtered.length)el('rows').append(node('div','empty','검색 결과가 없습니다. 다른 단어나 자료 종류를 선택해 보세요.'));
  for(const entry of filtered.slice(0,visibleLimit)){
    const row=node('div','row'+(activeId===entry.id?' active':''));
    const checkbox=node('input');checkbox.type='checkbox';checkbox.checked=selected.has(entry.id);checkbox.disabled=!available(entry);
    checkbox.setAttribute('aria-label',entry.title+' 선택');
    checkbox.addEventListener('change',()=>{if(checkbox.checked)selected.add(entry.id);else selected.delete(entry.id);updateSelection();});
    const button=node('button','row-main');button.type='button';button.append(node('span','row-title',entry.title),node('span','row-path',entry.path));
    const meta=node('span','row-meta');meta.append(node('span','chip',labels[entry.kind]),node('span','chip',reviews[entry.review]));
    meta.append(node('span','chip '+(checks.get(entry.id)?.status==='unchanged'?'good':'warn'),sourceLabel(entry)));button.append(meta);
    button.addEventListener('click',()=>{activeId=entry.id;renderDetail();renderRows();});row.append(checkbox,button);el('rows').append(row);
  }
  el('more').hidden=filtered.length<=visibleLimit;
}
const md = text => String(text).replace(/[\r\n]/g,' ').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/([\\`*_{}\[\]()#!|])/g,'\\$1');
function packetText(){
  const purpose=el('purpose').value.trim()||'참고자료 검토';
  const lines=['# 참고자료 검토 목록','','검토 목적: '+md(purpose),'','출처 묶음: '+md(catalog.origin.label),'목록 SHA-256: '+catalog.digest,'화면의 원본 해시 확인 시점: '+data.check.checked_at,'',
    '이 목록은 화면에 저장된 스냅샷에서 생성됐습니다. 원본의 현재 상태와 내용의 적합성은 별도 확인이 필요합니다.','이전 역할·스킬·작업 지시는 참고자료로만 다룹니다.',''];
  for(const id of selected){const entry=byId.get(id);lines.push('## '+md(entry.title),'','- 참조 ID: '+entry.id,'- 경로: '+md(entry.path),'- 종류: '+labels[entry.kind],'- 내용 상태: '+reviews[entry.review],'- SHA-256: '+entry.sha256,'- [ ] 현재 검토에 필요한 근거인지 확인','');}
  return lines.join('\n')+'\n';
}
el('query').addEventListener('input',event=>{query=event.target.value;visibleLimit=100;renderRows();});
el('review-filter').addEventListener('change',event=>{currentReview=event.target.value;visibleLimit=100;renderRows();});
el('more').addEventListener('click',()=>{visibleLimit+=100;renderRows();});
el('clear-selection').addEventListener('click',()=>{selected.clear();updateSelection();renderRows();});
el('prepare').addEventListener('click',()=>{el('packet').value=packetText();el('packet-dialog').showModal();});
el('close-dialog').addEventListener('click',()=>el('packet-dialog').close());
el('purpose').addEventListener('input',()=>el('packet').value=packetText());
el('download').addEventListener('click',()=>{
  const blob=new Blob([packetText()],{type:'text/markdown;charset=utf-8'});const url=URL.createObjectURL(blob);
  const link=node('a');link.href=url;link.download='faultloom-review-list.md';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  el('download-status').textContent='브라우저에 저장을 요청했습니다.';
});
renderFilters();renderRows();renderDetail();updateSelection();
"""


def _hash(content: str) -> str:
    return base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode("ascii")


def local_page_link(filename: str | None, label: str) -> str:
    if filename is None:
        return ""
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,70}\.html", filename):
        raise CatalogError("navigation must name a local HTML file in the same directory")
    return f'<a class="local" href="{filename}">{html.escape(label)}</a>'


def render_overview(catalog: dict, checks: dict, *, history_page: str | None = None) -> str:
    validate_catalog(catalog)
    if checks.get("schema") != CHECK_SCHEMA or checks.get("catalog_digest") != catalog["digest"]:
        raise CatalogError("source checks do not match this catalogue")
    check_ids = [entry["id"] for entry in checks.get("entries", [])]
    if len(check_ids) != len(set(check_ids)) or set(check_ids) != {entry["id"] for entry in catalog["entries"]}:
        raise CatalogError("source checks must cover exactly the catalogue entries")
    document = {"catalog": catalog, "check": checks, "kinds": KINDS, "reviews": REVIEWS}
    encoded = json.dumps(document, ensure_ascii=False, indent=2)
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    encoded = encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    policy = f"default-src 'none'; connect-src 'none'; img-src 'none'; style-src 'sha256-{_hash(_STYLE)}'; script-src 'sha256-{_hash(_SCRIPT)}'; base-uri 'none'; form-action 'none'"
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{html.escape(policy, quote=True)}">
<title>FaultLoom · 연구 자료실</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
  <div class="brand"><div class="mark" aria-hidden="true">F</div><div><div class="wordmark">FaultLoom</div><small>RESEARCH REFERENCES</small></div></div>
  {local_page_link(history_page, '작업 이력')}<span class="local">개인 자료실 · 원본 읽기 전용</span>
</header>
<main>
  <section class="intro"><div><h1>연구 자료실</h1><p>참고자료를 찾고, 출처를 확인하고, 검토할 자료를 모으세요.</p></div>
  <div class="date"><strong id="origin"></strong><br>원본 확인 시점 <span id="checked-at"></span></div></section>
  <section class="metrics" aria-label="자료 현황">
    <div class="metric"><strong id="total">0</strong><span>보관된 자료</span></div>
    <div class="metric"><strong id="kind-total">0</strong><span>자료 종류</span></div>
    <div class="metric"><strong id="matched">0</strong><span>목록과 해시가 같은 원본</span></div>
    <div class="metric"><strong id="reviewed">0</strong><span>사용자 검토 표시</span></div>
  </section>
  <section class="workspace" aria-label="자료 탐색">
    <aside class="panel"><div class="panelhead">자료 종류</div><nav class="filters" id="filters" aria-label="자료 종류 필터"></nav>
    <p class="side-note">과거 사례와 외부 참고자료를 함께 찾되, 개인의 발견·제출 실적으로 계산하지 않습니다.</p></aside>
    <section class="panel" aria-label="자료 목록">
      <div class="toolbar"><label class="search"><span class="sr-only">자료 검색</span><input id="query" type="search" placeholder="제목, 경로, 태그로 검색" maxlength="240"></label>
      <label><span class="sr-only">내용 검토 상태</span><select id="review-filter"><option value="">모든 검토 상태</option><option value="unreviewed">내용 검토 전</option><option value="operator_reviewed">사용자 검토 표시</option><option value="retired">참고 중단</option></select></label></div>
      <div class="resultbar"><span id="result-count" aria-live="polite"></span><span>본문은 원본에 보관</span></div>
      <div class="rows" id="rows"></div><button class="more" id="more" type="button">자료 더 보기</button>
    </section>
    <aside class="panel detailpanel" aria-label="자료 상세"><div class="panelhead">출처와 상태</div><div class="detail" id="detail"></div></aside>
  </section>
  <section class="actionbar" aria-label="선택한 자료"><div><strong id="selected-count" aria-live="polite">0개 자료 선택</strong><p>목적과 출처를 묶은 검토 목록으로 저장할 수 있습니다.</p></div>
  <div><button class="secondary" id="clear-selection" type="button">선택 해제</button> <button class="primary" id="prepare" type="button" disabled>검토 목록 만들기</button></div></section>
  <footer>이 화면은 생성 시점의 자료 목록입니다. 해시 일치와 내용의 정확성·최신성은 별개입니다.<br>프롬프트와 스킬도 실행 권한이 없는 참고자료로 표시됩니다.</footer>
</main>
<dialog id="packet-dialog" aria-labelledby="packet-heading">
  <div class="dialoghead"><div><h2 id="packet-heading">참고자료 검토 목록</h2><p>선택한 자료의 출처와 확인할 내용을 남깁니다.</p></div><button id="close-dialog" type="button" aria-label="검토 목록 닫기">닫기</button></div>
  <label for="purpose">검토 목적</label><input id="purpose" maxlength="240" placeholder="예: 고객 보고서에 필요한 작성 기준 확인">
  <label for="packet" class="sr-only">검토 목록 미리보기</label><textarea id="packet" readonly spellcheck="false"></textarea>
  <div class="dialogactions"><span class="notice" id="download-status" aria-live="polite">화면의 스냅샷을 저장합니다. 현재 원본 상태는 별도 확인하세요.</span><button class="primary" id="download" type="button">Markdown 저장</button></div>
</dialog>
<script id="reference-data" type="application/json">
{encoded}
</script>
<script>{_SCRIPT}</script>
</body>
</html>
"""
