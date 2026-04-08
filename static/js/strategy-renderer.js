/* strategy-renderer.js — deterministic Big4 HTML renderer from structured JSON. */
(function(global){

  function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function inlineHtml(s){
    s=esc(s);
    s=s.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
    s=s.replace(/\*(.+?)\*/g,'<em>$1</em>');
    s=s.replace(/`(.+?)`/g,'<code>$1</code>');
    s=s.replace(/\n/g,'<br>');
    return s;
  }
  function isNum(v){ return /^\d+(\.\d+)?$/.test((v||'').trim()); }
  function isHashHeader(v){ return /^(#|no\.?|م)$/i.test((v||'').trim()); }

  function normalizeRows(headers,rows){
    var expected=headers.length;
    var hasHash=headers.length&&isHashHeader(headers[0]);
    var seq=1;
    return (rows||[]).map(function(r){
      var row=(r||[]).map(function(c){return(c||'').trim();});
      if(hasHash){
        if(row.length===expected-1){ row.unshift(String(seq)); }
        else if(row.length===expected&&!isNum(row[0])){ row=[String(seq)].concat(row.slice(0,expected-1)); }
        if(!row.length||!isNum(row[0])) row[0]=String(seq);
        seq++;
      }
      if(row.length>expected){ row=row.slice(0,expected-1).concat([row.slice(expected-1).join(' ')]); }
      while(row.length<expected) row.push('—');
      row=row.slice(0,expected).map(function(c){return c||'—';});
      var body=hasHash?row.slice(1):row;
      return body.some(function(c){return c!=='—';})?row:null;
    }).filter(Boolean);
  }

  function shouldNarrowFirstCol(headers,rows){
    if(!headers.length||!isHashHeader(headers[0])) return false;
    var sample=rows.slice(0,5);
    return sample.length>0&&sample.every(function(r){return isNum(r[0]);});
  }

  var PRIORITY_MAP={
    'critical':'<span class="priority-critical">Critical</span>',
    'حرج':'<span class="priority-critical">حرج</span>',
    'high':'<span class="priority-high">High</span>',
    'عالي':'<span class="priority-high">عالي</span>',
    'عالية':'<span class="priority-high">عالية</span>',
    'medium':'<span class="priority-medium">Medium</span>',
    'متوسط':'<span class="priority-medium">متوسط</span>',
    'low':'<span class="priority-low">Low</span>',
    'منخفض':'<span class="priority-low">منخفض</span>'
  };

  function cellHtml(text,isPriorityCol){
    var s=(text||'').trim();
    if(!s||s==='—') return '<td class="cell-missing">—</td>';
    if(isPriorityCol){ var lc=s.toLowerCase(); if(PRIORITY_MAP[lc]) return '<td>'+PRIORITY_MAP[lc]+'</td>'; }
    return '<td>'+inlineHtml(s)+'</td>';
  }

  function renderCallout(block,isRtl){
    var dir=isRtl?' dir="rtl"':'';
    var html='<div class="callout-label"'+dir+'>'+inlineHtml(block.label||'')+'</div>';
    if(block.text) html+='<p'+dir+' style="'+(isRtl?'padding-right':'padding-left')+':1rem;color:#374151;margin-top:.2rem;">'+inlineHtml(block.text)+'</p>';
    return html;
  }
  function renderParagraph(block,isRtl){ return '<p'+(isRtl?' dir="rtl"':'')+'>'+inlineHtml(block.text||'')+'</p>'; }
  function renderBulletList(block,isRtl){
    return '<ul'+(isRtl?' dir="rtl"':'')+'>'+(block.items||[]).map(function(it){return '<li>'+inlineHtml(it)+'</li>';}).join('')+'</ul>';
  }
  function renderNumberedList(block,isRtl){
    return '<ol'+(isRtl?' dir="rtl"':'')+'>'+(block.items||[]).map(function(it){return '<li>'+inlineHtml(it)+'</li>';}).join('')+'</ol>';
  }
  function renderTable(block,isRtl){
    var headers=block.headers||[];
    var rows=normalizeRows(headers,block.rows||[]);
    if(!headers.length) return '';
    var align=isRtl?'right':'left';
    var dir=isRtl?' dir="rtl"':'';
    var tableClass=shouldNarrowFirstCol(headers,rows)?' class="narrow-first-col"':'';
    var priorityCols=[];
    headers.forEach(function(h,i){
      if(/^(priority|الأولوية|likelihood|الاحتمالية|impact|التأثير|status|الحالة)$/i.test((h||'').trim())) priorityCols.push(i);
    });
    var thCells=headers.map(function(h){return '<th style="text-align:'+align+'">'+inlineHtml(h)+'</th>';}).join('');
    var trs=rows.map(function(row){
      return '<tr>'+headers.map(function(_,ci){return cellHtml(row[ci],priorityCols.indexOf(ci)!==-1);}).join('')+'</tr>';
    }).join('');
    return '<div class="table-wrapper"'+dir+'><table'+tableClass+'><thead><tr>'+thCells+'</tr></thead><tbody>'+trs+'</tbody></table></div>';
  }
  function renderEvidence(block,isRtl){
    var dir=isRtl?' dir="rtl"':'';
    var checks=(block.items||[]).map(function(it){
      return '<label style="display:flex;gap:.5rem;align-items:flex-start;margin:.3rem 0;"><input type="checkbox" disabled style="margin-top:.2rem;"> <span>'+inlineHtml(it)+'</span></label>';
    }).join('');
    return '<div class="evidence-gate"'+dir+'>'+(block.label?'<strong>'+inlineHtml(block.label)+'</strong>':'')+checks+'</div>';
  }
  function renderSubheading(block,isRtl){ return '<h3'+(isRtl?' dir="rtl"':'')+'>'+inlineHtml(block.text||'')+'</h3>'; }

  function renderBlock(block,isRtl){
    var t=(block.type||'').toLowerCase();
    if(t==='callout')       return renderCallout(block,isRtl);
    if(t==='paragraph')     return renderParagraph(block,isRtl);
    if(t==='bullet_list')   return renderBulletList(block,isRtl);
    if(t==='numbered_list') return renderNumberedList(block,isRtl);
    if(t==='table')         return renderTable(block,isRtl);
    if(t==='evidence')      return renderEvidence(block,isRtl);
    if(t==='subheading')    return renderSubheading(block,isRtl);
    if(t==='hr')            return '<hr>';
    if(block.text)          return renderParagraph(block,isRtl);
    return '';
  }

  function renderStrategyFromJSON(json,isRtl){
    if(!json||!json.sections) return '';
    isRtl=!!isRtl;
    var html='';
    json.sections.forEach(function(section){
      var title=section.number?section.number+'. '+(section.title||''):(section.title||'');
      if(title) html+='<div class="section-banner">'+inlineHtml(title)+'</div>';
      (section.blocks||[]).forEach(function(block){html+=renderBlock(block,isRtl);});
    });
    return html;
  }

  var SECTION_KEY_MAP={
    'vision':'1','pillars':'2','environment':'3','business':'3',
    'gaps':'4','gap':'4','roadmap':'5','implementation':'5',
    'kpis':'6','kpi':'6','performance':'6','confidence':'7','risks':'7'
  };

  function renderSectionFromJSON(json,sectionKey,isRtl){
    if(!json||!json.sections) return null;
    isRtl=!!isRtl;
    var targetNum=SECTION_KEY_MAP[sectionKey]||sectionKey;
    var section=null;
    json.sections.forEach(function(s){
      if(s.number===targetNum) section=s;
      if(!section&&s.key===sectionKey) section=s;
    });
    if(!section) return null;
    var title=section.number?section.number+'. '+(section.title||''):(section.title||'');
    var html=title?'<div class="section-banner">'+inlineHtml(title)+'</div>':'';
    (section.blocks||[]).forEach(function(block){html+=renderBlock(block,isRtl);});
    return html;
  }

  function validateSectionJSON(json,sectionKey){
    if(!json||!json.sections) return false;
    var map={vision:'1',pillars:'2',environment:'3',business:'3',gaps:'4',roadmap:'5',implementation:'5',kpis:'6',performance:'6',confidence:'7',risks:'7'};
    var targetNum=map[sectionKey]||sectionKey;
    var section=null;
    json.sections.forEach(function(s){ if(s.number===targetNum||s.key===sectionKey) section=s; });
    if(!section) return false;
    return (section.blocks||[]).every(function(b){
      if((b.type||'').toLowerCase()!=='table') return true;
      if(!b.headers||!b.headers.length) return false;
      var rows=normalizeRows(b.headers,b.rows||[]);
      return rows.every(function(r){return r.length===b.headers.length;});
    });
  }

  global.renderStrategyFromJSON=renderStrategyFromJSON;
  global.renderSectionFromJSON=renderSectionFromJSON;
  global.validateSectionJSON=validateSectionJSON;

})(typeof window!=='undefined'?window:this);
