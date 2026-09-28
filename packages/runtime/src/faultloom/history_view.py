"""Private, offline work-history exports. Rendering never changes a record."""
from __future__ import annotations

import html
import json

from .knowledge import markdown_text
from .knowledge_view import _STYLE, _hash, local_page_link
from .work_history import DOMAINS, KINDS, NOTES, STATES, TRACKS

_CSS = _STYLE + """
.history-workspace{display:grid;grid-template-columns:minmax(300px,400px) minmax(0,1fr);gap:20px;align-items:start}
.history-toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}.history-toolbar input{flex:1;min-width:190px}
.history-toolbar select{max-width:200px}.cases{max-height:740px;overflow:auto}.case-button{display:block;width:100%;text-align:left;background:#fff;border:0;border-bottom:1px solid var(--line);padding:17px;color:var(--ink)}
.case-button[aria-pressed=true]{background:var(--pale);box-shadow:inset 3px 0 var(--green)}.case-button h2{font-size:14px;line-height:1.65;margin:0 0 7px;overflow-wrap:anywhere}.case-button p{font-size:12px}
.case-meta{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.case-detail{padding:23px}.case-detail h2{font-size:23px;line-height:1.6;margin:0 0 10px;overflow-wrap:anywhere}
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:18px 0}.summary-grid div{background:#f4f7f6;border-radius:8px;padding:12px;font-size:12px;overflow-wrap:anywhere}
.summary-grid strong{display:block;color:var(--muted);font-size:11px;margin-bottom:5px}.timeline{margin-top:25px}.timeline h3{font-size:16px;margin-bottom:16px}
.event{border-left:2px solid #c5dcd2;padding:0 0 22px 17px;margin-left:4px}.event h4{font-size:14px;line-height:1.6;margin:7px 0;overflow-wrap:anywhere}.event p{font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}.event time{font-size:11px;color:var(--muted)}
.event .event-id{font-family:Consolas,monospace;font-size:10px;color:#7b888c;overflow-wrap:anywhere;margin-top:9px}.intro .badge{font-size:12px;color:#226653;background:var(--pale);padding:6px 10px;border-radius:20px;white-space:nowrap}
.info{background:#f4f7f6;padding:12px 14px;border-radius:8px;font-size:12px;line-height:1.8;margin-top:12px}.resultbar{background:#fff}.source-path{font-family:Consolas,monospace;font-size:11px}
@media(max-width:800px){.history-workspace{grid-template-columns:1fr}.cases{max-height:360px}.case-detail{padding:18px}.case-detail h2{font-size:20px}}
@media(max-width:500px){.summary-grid{grid-template-columns:1fr}.history-toolbar select{max-width:100%;flex:1}.intro .badge{display:inline-block;margin-top:12px}}
"""

_JS = r"""
'use strict';
const data=JSON.parse(document.getElementById('history-data').textContent),cases=data.snapshot.cases;
const el=id=>document.getElementById(id),node=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
let active=cases[0]?.id,query='',track='',origin='',state='';
const date=value=>!value?'시점 미기록':value.length===10?value:new Date(value).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})+' KST';
const sourceStatuses={unchanged:'원본 일치',changed:'원본 변경',missing:'원본 없음',unmapped:'원본 위치 미설정',unsafe_or_unavailable:'확인 불가',budget_exhausted:'확인 용량 초과'};
function updateMetrics(){el('case-count').textContent=cases.length;el('record-count').textContent=cases.reduce((sum,c)=>sum+c.events.length,0);
el('legacy-count').textContent=cases.filter(c=>c.origin==='terminator').length;el('new-count').textContent=cases.filter(c=>c.origin==='faultloom').length;
el('generated').textContent=date(data.snapshot.generated_at);}updateMetrics();
for(const [id,options] of [['track-filter',data.tracks],['state-filter',data.states]])for(const [value,label] of Object.entries(options)){const option=node('option','',label);option.value=value;el(id).append(option);}
function field(title,text){const n=node('div');n.append(node('strong','',title),document.createTextNode(text));return n;}
function eventText(event){const d=event.data;
 if(event.kind==='legacy_snapshot')return ['당시 상태: '+d.status,'당시 심각도 표기: '+(d.severity||'없음'),'당시 보상 표기: '+(d.bounty_text||'없음'),'제출일 기록: '+date(d.submitted),'당시 확인일: '+date(d.checked),'당시 종료일: '+date(d.resolved),'출처: '+d.source.path+':'+d.line,'원본 SHA-256: '+d.source.sha256].join('\n');
 if(event.kind==='reference'||event.kind==='file_reference')return ['출처: '+d.origin,'경로: '+d.path,'SHA-256: '+d.sha256].join('\n');
 if(event.kind==='attachment')return ['보관 파일: '+d.name,'크기: '+d.bytes.toLocaleString()+' bytes','SHA-256: '+d.sha256,'원본: '+d.source.origin+' / '+d.source.path].join('\n');
 if(event.kind==='reference_check')return ['확인 시점: '+date(d.checked_at),...d.results.map(r=>sourceStatuses[r.status]+' · '+r.source.path)].join('\n');
 if(event.kind==='case_created'||event.kind==='case_updated')return [data.tracks[d.track],d.domains.map(v=>data.domains[v]).join(' · '),data.states[d.state],d.subject].filter(Boolean).join(' · ');
 return d.detail+(d.corrects?'\n정정 대상: '+d.corrects:'');
}
function renderDetail(){const c=cases.find(c=>c.id===active);el('detail').replaceChildren();
 if(!c){el('detail').append(node('p','empty','검색 결과가 없습니다. 조건을 바꿔 보세요.'));return;}
 el('detail').append(node('h2','',c.title),node('p','',c.subject||'대상·고객 미기록'));
 const grid=node('div','summary-grid');grid.append(field('업무 유형',data.tracks[c.track]),field('분야',c.domains.map(v=>data.domains[v]).join(' · ')),field('작업 상태',data.states[c.state]),field('기록 출처',c.origin==='terminator'?'Terminator 과거 기록':'FaultLoom'));
 el('detail').append(grid);
 if(data.live){const actions=node('div','case-actions');for(const [label,callback] of [['기록 추가',()=>openNote(c.id)],['작업 수정',()=>openCase(c.id)],['자료 연결',()=>openFile(c.id)],['원본 다시 확인',()=>sourceCommand('check_sources',c.id)]]){const button=node('button','secondary',label);button.type='button';button.disabled=!data.ready||data.busy||(label==='자료 연결'&&!data.snapshot.source_origins?.length);button.addEventListener('click',callback);actions.append(button);}el('detail').append(actions);}
 if(c.origin==='terminator')el('detail').append(node('p','info','보존된 제출표의 당시 기록입니다. 아래 상태와 보상 표기는 원문에서 가져온 것으로, 현재 상태나 수령 금액을 확인한 값은 아닙니다.'));
 const timeline=node('section','timeline');timeline.setAttribute('aria-label','작업 타임라인');timeline.append(node('h3','','작업 기록 · '+c.events.length));
 const corrected=new Set(c.events.filter(e=>e.kind==='correction').map(e=>e.data.corrects));
 const latestChecks=new Map();for(const e of c.events)if(e.kind==='reference_check')for(const r of e.data.results)latestChecks.set(r.event_id,{...r,checked_at:e.data.checked_at});
 for(const event of c.events){const item=node('article','event');item.append(node('span','chip',data.kinds[event.kind]+(corrected.has(event.id)?' · 후속 정정 있음':'')));
   const title=event.data.summary||event.data.label||(event.kind==='legacy_snapshot'?event.data.platform+' · '+event.data.status:event.kind==='reference_check'?'원본 참조 '+event.data.results.length+'건 확인':event.data.title);
   item.append(node('h4','',title),node('time','','발생 '+date(event.occurred_at)+' / 기록 '+date(event.recorded_at)),node('p','',eventText(event)),node('div','event-id',event.id));
   const check=latestChecks.get(event.id);if(check)item.append(node('p','source-status',sourceStatuses[check.status]+' · '+date(check.checked_at)));
   if(data.live){const controls=node('div','event-actions');const button=node('button','secondary correct','이 기록 정정');button.type='button';button.disabled=!data.ready||data.busy;button.addEventListener('click',()=>openNote(c.id,event.id));controls.append(button);
     if(['reference','file_reference','legacy_snapshot'].includes(event.kind)){const source=event.kind==='legacy_snapshot'?event.data.source:event.data;
       const archived=c.events.some(e=>e.kind==='attachment'&&e.data.source.origin===source.origin&&e.data.source.path===source.path&&e.data.sha256===source.sha256&&e.data.bytes===source.bytes);
       const archive=node('button','secondary correct',archived?'사본 보관됨':'사본 보관');archive.type='button';archive.disabled=!data.ready||data.busy||archived;archive.addEventListener('click',()=>sourceCommand('archive_reference',c.id,event.id));controls.append(archive);}
     if(event.kind==='attachment'){const download=node('button','secondary correct','사본 내려받기');download.type='button';download.disabled=!data.ready||data.busy;download.addEventListener('click',()=>downloadAttachment(c.id,event));controls.append(download);}item.append(controls);}timeline.append(item);}
 el('detail').append(timeline,node('p','event-id',c.id));
}
function render(){const words=query.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
 const filtered=cases.filter(c=>{const text=[c.title,c.subject,c.origin,data.tracks[c.track],...c.domains.map(v=>data.domains[v]),...c.events.flatMap(e=>[e.data.summary||'',e.data.title||'',eventText(e)])].join(' ').toLocaleLowerCase();
 return (!track||c.track===track)&&(!origin||c.origin===origin)&&(!state||c.state===state)&&words.every(w=>text.includes(w));});
 if(!filtered.some(c=>c.id===active))active=filtered[0]?.id;el('cases').replaceChildren();el('result-count').textContent=filtered.length+'개 작업';
 if(!filtered.length)el('cases').append(node('p','empty','조건에 맞는 작업이 없습니다.'));
 for(const c of filtered){const button=node('button','case-button');button.type='button';button.setAttribute('aria-pressed',String(c.id===active));button.append(node('h2','',c.title),node('p','',c.subject));
 const meta=node('div','case-meta');meta.append(node('span','chip',data.tracks[c.track]),node('span','chip',data.states[c.state]),node('span','chip',c.origin==='terminator'?'Terminator':'FaultLoom'));button.append(meta);
 button.addEventListener('click',()=>{active=c.id;render();});el('cases').append(button);}
 renderDetail();if(data.live)el('create-case').disabled=!data.ready||data.busy;
}
el('query').addEventListener('input',e=>{query=e.target.value;render();});
el('track-filter').addEventListener('change',e=>{track=e.target.value;render();});
el('origin-filter').addEventListener('change',e=>{origin=e.target.value;render();});
el('state-filter').addEventListener('change',e=>{state=e.target.value;render();});
el('clear-filters').addEventListener('click',()=>{query=track=origin=state='';for(const id of ['query','track-filter','origin-filter','state-filter'])el(id).value='';render();});
render();
"""


def render_history(snapshot: dict, *, reference_page: str | None = None, live: bool = False) -> str:
    from . import history_live
    document = {"snapshot": snapshot, "tracks": TRACKS, "domains": DOMAINS, "states": STATES, "kinds": KINDS,
                "notes": NOTES, "live": live, "ready": False, "busy": False}
    stylesheet = _CSS + (history_live.STYLE if live else "")
    script = _JS + (history_live.SCRIPT if live else "")
    actions = history_live.ACTIONS if live else ""
    forms = history_live.FORMS if live else ""
    badge = "개인 작업 공간" if live else "개인용 조회본"
    footer = "저장한 기록은 이 PC의 개인 이력에 남습니다." if live else "개인 기록을 내보낸 파일입니다. 새로운 기록은 원본 이력에 저장한 뒤 조회본을 갱신하세요."
    encoded = json.dumps(document, ensure_ascii=False, indent=2).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    encoded = encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    connection_policy = "'self'" if live else "'none'"
    policy = f"default-src 'none'; connect-src {connection_policy}; style-src 'sha256-{_hash(stylesheet)}'; script-src 'sha256-{_hash(script)}'; base-uri 'none'; form-action 'none'"
    return f'''<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{html.escape(policy, quote=True)}"><title>FaultLoom · 작업 이력</title>
<style>{stylesheet}</style></head><body>
<header><div class="brand"><div class="mark">F</div><div><div class="wordmark">FaultLoom</div><small>WORK HISTORY</small></div></div>{local_page_link(reference_page, '연구 자료실')}<span class="local">개인 작업 이력</span></header>
<main><section class="intro"><div><h1>연구와 업무 기록</h1><p>판단, 실패, 보고서와 후속 결과를 작업별로 살펴보세요.</p></div><span class="badge">{badge}</span></section>
{actions}
<section class="metrics" aria-label="이력 현황"><div class="metric"><strong id="case-count"></strong><span>전체 작업</span></div><div class="metric"><strong id="record-count"></strong><span>시간순 기록</span></div><div class="metric"><strong id="new-count"></strong><span>FaultLoom 작업</span></div><div class="metric"><strong id="legacy-count"></strong><span>Terminator 과거 작업</span></div></section>
<section class="history-toolbar" aria-label="이력 검색"><input id="query" type="search" aria-label="작업 검색" placeholder="제목, 기록 내용, 출처 검색" maxlength="240">
<select id="track-filter" aria-label="업무 유형"><option value="">모든 업무</option></select>
<select id="origin-filter" aria-label="기록 출처"><option value="">모든 출처</option><option value="faultloom">FaultLoom</option><option value="terminator">Terminator</option></select>
<select id="state-filter" aria-label="작업 상태"><option value="">모든 상태</option></select><button id="clear-filters" class="secondary" type="button">필터 초기화</button></section>
<section class="history-workspace"><section class="panel" aria-label="작업 목록"><div class="resultbar"><span id="result-count" aria-live="polite"></span><span>기록한 경험</span></div><div class="cases" id="cases"></div></section>
<section class="panel case-detail" aria-label="작업 상세" id="detail"></section></section>
<footer>불러온 기록 시점: <span id="generated"></span><br>{footer}</footer></main>
{forms}
<script id="history-data" type="application/json">\n{encoded}\n</script><script>{script}</script></body></html>
'''


def render_markdown(snapshot: dict) -> str:
    md = markdown_text
    lines = ["# FaultLoom 개인 작업 이력", "", f"내보낸 시점: {snapshot['generated_at']}",
             "기록자의 메모와 과거 자료를 정리한 개인용 문서입니다.", ""]
    for case in snapshot["cases"]:
        lines.extend([f"## {md(case['title'])}", "", f"- 작업 ID: `{case['id']}`",
                      f"- 유형: {TRACKS[case['track']]}", f"- 상태: {STATES[case['state']]}",
                      f"- 출처: {case['origin']}", f"- 대상·고객: {md(case['subject'])}", ""])
        for event in case["events"]:
            lines.extend([f"### {KINDS[event['kind']]}", "", f"발생: {event['occurred_at'] or '미기록'} / 기록: {event['recorded_at']}", ""])
            for key, value in event["data"].items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False, sort_keys=True)
                lines.append(f"- {md(key)}: {md(str(value))}")
            lines.extend(["", f"기록 ID: `{event['id']}`", ""])
    return "\n".join(lines)
