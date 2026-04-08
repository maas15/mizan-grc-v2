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

  // Detect timeframe values like "6 months", "12 months", "Within 18 months"
  function isTimeframe(v){
    return /^(\d+\s*(?:months?|years?|weeks?|days?|أشهر|شهر|سنوات|سنة)|within\s+\d+)/i.test((v||'').trim());
  }

  function normalizeRows(headers,rows){
    var expected=headers.length;
    var hasHash=headers.length&&isHashHeader(headers[0]);
    var seq=1;
    return (rows||[]).map(function(r){
      var row=(r||[]).map(function(c){return(c||'').trim();});
      if(hasHash){
        if(row.length===expected-1){ row.unshift(String(seq)); }
        else if(row.length===expected&&!isNum(row[0])){
          if(row[0]==='') row[0]=String(seq);  // empty #-cell: fill in number
          else{ row=[String(seq)].concat(row.slice(0,expected-1)); }  // text: shift
        }
        if(!row.length||!isNum(row[0])) row[0]=String(seq);
        // Pattern 4: col0=digit, col1=real text, col2=timeframe (leaked into Target Metric)
        // e.g. | 2 | Implement governance | 9 months | Establish data classification | 15 months |
        if(row.length===expected&&isNum(row[0])&&row[1]&&!isTimeframe(row[1])&&isTimeframe(row[2])){
          var tf=row[2];
          var metric=row[4]&&!isTimeframe(row[4])?row[4]:'—';
          var justif=row[3]&&!isTimeframe(row[3])?row[3]:'—';
          row=[row[0],row[1],metric,justif,tf];
        }
        // Pattern 4b: col3=timeframe (leaked into Justification)
        // e.g. | 2 | Implement gov | Approved doc | 9 months | 15 months |
        if(row.length===expected&&isNum(row[0])&&!isTimeframe(row[1])&&!isTimeframe(row[2])&&expected===5&&isTimeframe(row[3])){
          row=[row[0],row[1],row[2],'—',row[3]];
        }
        // Pattern 3: col0=digit, col1=timeframe (leaked into Objective)
        if(row.length===expected&&isNum(row[0])&&isTimeframe(row[1])){
          var obj=null;
          for(var pi=2;pi<row.length;pi++){if(row[pi]&&!isTimeframe(row[pi])){obj=row[pi];break;}}
          var tf2=null;
          for(var pi2=row.length-1;pi2>0;pi2--){if(row[pi2]&&isTimeframe(row[pi2])){tf2=row[pi2];break;}}
          row=[row[0],obj||'—','—','—',tf2||row[1]];
        }
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
    var label=inlineHtml(block.label||'');
    var body=block.text||'';
    // Long body text (sub-section narratives like "Regulatory Landscape...") —
    // render as a bolded lead sentence inside the body paragraph so the full
    // text reads at normal size, not squeezed into a tiny labelled box.
    if(body.length>80){
      return '<p'+dir+' class="section-subparagraph"><strong>'+label+'</strong> '+inlineHtml(body)+'</p>';
    }
    var html='<div class="callout-label"'+dir+'>'+label+'</div>';
    if(body) html+='<p'+dir+' style="'+(isRtl?'padding-right':'padding-left')+':1rem;color:#1e293b;margin-top:.2rem;font-size:1rem;">'+inlineHtml(body)+'</p>';
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

  // ── Fragment-merging helpers (coalescePreviewTables) ────────────────────
  function normHeaderText(t){
    return (t||'').trim().toLowerCase().replace(/\s+/g,' ');
  }

  function headerLikeCell(t){
    return [
      '#','no','no.',
      'objective','target metric','justification','timeframe',
      'initiative','description','expected deliverable',
      'gap','priority','status',
      'activity','owner','timeline','deliverable',
      'factor','importance',
      'risk','likelihood','impact','mitigation plan',
      'kpi','calculation formula',
      'الهدف','المؤشر المستهدف','المبرر','الإطار الزمني',
      'المبادرة','الوصف','المخرج المتوقع',
      'الفجوة','الأولوية','الحالة',
      'النشاط','المالك','المدة','المخرج',
      'العامل','الأهمية',
      'المخاطر','الاحتمالية','التأثير','خطة المعالجة'
    ].indexOf(normHeaderText(t)) !== -1;
  }

  function isHeaderLikeCells(cells){
    if(!cells||!cells.length) return false;
    var hits=cells.filter(headerLikeCell).length;
    return hits>=Math.max(2,Math.ceil(cells.length/2));
  }

  // Merge consecutive fragmented table blocks into one.
  // AI generates each gap/CSF/initiative row as a separate mini-table whose header
  // becomes a dark <thead>. This coalesces them before any HTML is rendered.
  function coalescePreviewTables(blocks){
    var out=[];
    (blocks||[]).forEach(function(block){
      if((block.type||'').toLowerCase()!=='table'){ out.push(block); return; }
      var prev=out.length?out[out.length-1]:null;
      var currHeaders=(block.headers||[]).slice();
      var currRows=(block.rows||[]).slice();
      if(prev&&(prev.type||'').toLowerCase()==='table'){
        var prevCols=(prev.headers||[]).length;
        var currCols=currHeaders.length;
        var prevHasRows=(prev.rows||[]).length>0;
        var currHasRows=currRows.length>0;
        var prevHeaderLike=isHeaderLikeCells(prev.headers||[]);
        var currHeaderLike=isHeaderLikeCells(currHeaders);
        if(prevCols&&prevCols===currCols){
          // Fragment case: current block is a data row stored in headers, no rows
          if(!currHasRows&&!currHeaderLike&&(prevHasRows||prevHeaderLike)){
            prev.rows=(prev.rows||[]);
            prev.rows.push(currHeaders);
            return;
          }
          // Same-schema continuation: merge rows
          if(currHasRows&&prevHasRows){
            var sameSchema=JSON.stringify((prev.headers||[]).map(normHeaderText))===
                           JSON.stringify(currHeaders.map(normHeaderText));
            if(sameSchema){ prev.rows=(prev.rows||[]).concat(currRows); return; }
          }
        }
      }
      out.push({type:'table',headers:currHeaders,rows:currRows});
    });
    return out;
  }


  function renderStrategyFromJSON(json,isRtl){
    if(!json||!json.sections) return '';
    isRtl=!!isRtl;
    var html='';
    json.sections.forEach(function(section){
      var title=section.number?section.number+'. '+(section.title||''):(section.title||'');
      if(title) html+='<div class="section-banner">'+inlineHtml(title)+'</div>';
      coalescePreviewTables(section.blocks||[]).forEach(function(block){html+=renderBlock(block,isRtl);});
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
    coalescePreviewTables(section.blocks||[]).forEach(function(block){html+=renderBlock(block,isRtl);});
    return html;
  }

  function validateSectionJSON(json,sectionKey){
    if(!json||!json.sections) return false;
    var map={vision:'1',pillars:'2',environment:'3',business:'3',gaps:'4',roadmap:'5',implementation:'5',kpis:'6',performance:'6',confidence:'7',risks:'7'};
    var targetNum=map[sectionKey]||sectionKey;
    var section=null;
    json.sections.forEach(function(s){ if(s.number===targetNum||s.key===sectionKey) section=s; });
    if(!section) return false;
    var _blocks3=coalescePreviewTables(section.blocks||[]);
    return _blocks3.every(function(b){
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
