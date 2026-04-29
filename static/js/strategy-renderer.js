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

  // True if two strings are the same after normalising whitespace and case
  function sameish(a, b){
    a = (a||'').trim().toLowerCase().replace(/\s+/g,' ');
    b = (b||'').trim().toLowerCase().replace(/\s+/g,' ');
    return !!a && a === b;
  }

  // Identify a table's semantic schema from its header row
  function tableSchemaName(headers){
    var norm=(headers||[]).map(function(h){
      return (h||'').trim().toLowerCase().replace(/\s+/g,' ');
    });
    var j=JSON.stringify(norm);
    if(j===JSON.stringify(['#','objective','target metric','justification','timeframe'])) return 'strategic-objectives';
    if(j===JSON.stringify(['#','kpi description','target value','calculation formula','justification','timeframe'])) return 'kpi-summary';
    if(j===JSON.stringify(['#','metric','type kpi/kri','target value','calculation formula','data source','owner','frequency','timeframe'])) return 'kpi-summary';
    if(j===JSON.stringify(['#','gap','description','priority','status'])) return 'gap-analysis';
    if(j===JSON.stringify(['#','initiative','description','expected deliverable'])) return 'pillar-initiatives';
    if(j===JSON.stringify(['#','risk','likelihood','impact','mitigation plan'])) return 'key-risks';
    if(j===JSON.stringify(['#','factor','description','importance'])) return 'csf-table';
    // Procedure-specific schemas
    if(norm.some(function(h){return /^activity$|^النشاط$/.test(h);}) &&
       norm.some(function(h){return /^responsible|^المسؤول/.test(h);}) &&
       norm.some(function(h){return /^informed|^المُبلَّغ/.test(h);})) return 'procedure-raci';
    if(norm.some(function(h){return /^decision.?point|^نقطة.?القرار/.test(h);}) &&
       norm.some(function(h){return /^condition|^الشرط/.test(h);})) return 'procedure-decision';
    if(norm.some(function(h){return /^evidence.?type|^نوع.?الدليل/.test(h);}) &&
       norm.some(function(h){return /^retention|^مدة.?الاحتفاظ/.test(h);})) return 'procedure-evidence';
    if((norm.some(function(h){return /^item$|^control.?id|^رقم.?الضابط/.test(h);}) ||
        norm.some(function(h){return /^field$|^الحقل$/.test(h);})) &&
       norm.some(function(h){return /^description$|^control.?desc|^وصف|^value$|^القيمة$/.test(h);})) return 'procedure-purpose-scope';
    // Arabic variants
    if(j===JSON.stringify(['#','الهدف','المؤشر المستهدف','المبرر','الإطار الزمني'])) return 'strategic-objectives';
    if(j===JSON.stringify(['#','وصف مؤشر الأداء','القيمة المستهدفة','صيغة الحساب','المبرر','الإطار الزمني'])) return 'kpi-summary';
    if(j===JSON.stringify(['#','المؤشر','النوع kpi/kri','القيمة المستهدفة','صيغة الاحتساب','مصدر البيانات','المالك','التكرار','الإطار الزمني'])) return 'kpi-summary';
    if(j===JSON.stringify(['#','الفجوة','الوصف','الأولوية','الحالة'])) return 'gap-analysis';
    if(j===JSON.stringify(['#','المخاطر','الاحتمالية','التأثير','خطة المعالجة'])) return 'key-risks';
    return 'generic';
  }

  // Compact values that should never wrap or word-split (Likelihood, Impact, Priority)
  var COMPACT_VALUES=/^(critical|high|medium|low|حرج|عالي|عالية|متوسط|منخفض|open|confirmed|open\s*[-–]\s*confirmed)$/i;

  // Return true if a normalised row looks semantically broken for its schema.
  // When any row is suspicious, validateSectionJSON returns false and the
  // preview falls back to the (cleaner) markdown path instead of broken JSON.
  function rowSuspiciousForSchema(headers, row){
    var schema=tableSchemaName(headers);
    if(schema==='strategic-objectives' && row.length===5){
      // Last column must be a timeframe
      if(row[4]==='—'||!isTimeframe(row[4])) return true;
      // Justification must NOT be a timeframe
      if(isTimeframe(row[3])) return true;
      // Target Metric must NOT duplicate Objective
      if(row[1]&&row[2]&&sameish(row[1],row[2])) return true;
    }
    if(schema==='kpi-summary' && row.length===6){
      // Last column must be a timeframe
      if(row[5]==='—'||!isTimeframe(row[5])) return true;
      // Justification must NOT be a timeframe
      if(isTimeframe(row[4])) return true;
      // Target Value must NOT be a timeframe
      if(isTimeframe(row[2])) return true;
      // Both Target Value AND Calculation Formula blank → flag for regeneration
      if(row[2]==='—' && row[3]==='—' && isTimeframe(row[5])) return true;
    }
    if(schema==='key-risks' && row.length===5){
      // Row number leaked into Risk column: #=N, Risk=N (same numeric)
      if(isNum(row[1]) && row[1]===row[0]) return true;
      // Likelihood column contains long narrative (>4 words) — real risk name shifted right
      if(row[2]&&row[2]!=='—'&&row[2].trim().split(/\s+/).length>4) return true;
    }
    return false;
  }

  function normalizeRows(headers,rows){
    var expected=headers.length;
    var hasHash=headers.length&&isHashHeader(headers[0]);
    var schema=tableSchemaName(headers);
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

        // ── Key Risks repair: row number leaked into Risk column ──
        // Happens when AI omits the row # and produces 4-cell row:
        // [2, "Departmental Resistance...", "Medium", "High"] (4 cells)
        // normalizeRows unshifts seq giving: [2, "2", "Departmental...", "Medium", "High"]
        // Detection: row[1] is a pure number equal to row[0] → shift content right
        if(schema==='key-risks' && expected===5 && isNum(row[0]) && isNum(row[1]) && row[1]===row[0]){
          row=[row[0], row[2]||'—', row[3]||'—', row[4]||'—', '—'];
        }

        // ── Strong objective/KPI table repair (mirrors app.py _normalize_json_table) ──

        // ── 5-column tables: #, Objective, Target Metric, Justification, Timeframe ──
        // (Skip for key-risks which is also 5-col but uses different semantics)
        if(expected===5 && hasHash && isNum(row[0]) && schema!=='key-risks'){
          var c1=row[1], c2=row[2], c3=row[3], c4=row[4];

          // Case D: timeframe leaked into Objective (col1)
          // e.g. [3, "21 months", "Real objective text", "24 months", "—"]
          if(isTimeframe(c1)){
            var dObj=null;
            for(var di=2;di<row.length;di++){ if(row[di]&&row[di]!=='—'&&!isTimeframe(row[di])){dObj=row[di];break;} }
            var dTf=null;
            for(var dj=row.length-1;dj>0;dj--){ if(row[dj]&&row[dj]!=='—'&&isTimeframe(row[dj])){dTf=row[dj];break;} }
            row=[row[0], dObj||'—', '—', '—', dTf||c1];
            c1=row[1]; c2=row[2]; c3=row[3]; c4=row[4];
          }

          // Case A: duplicated objective + two timeframes
          // e.g. [2, "Establish PIA...", "Establish PIA...", "8 months", "12 months"]
          if(!isTimeframe(c1) && sameish(c1,c2) && isTimeframe(c3) && isTimeframe(c4)){
            row=[row[0],c1,'—','—',c4];
          }
          // Case A-partial: duplicated objective + one timeframe, real content in last col
          // e.g. [2, "Establish...", "Establish...", "8 months", "Some justification"]
          else if(!isTimeframe(c1) && sameish(c1,c2) && isTimeframe(c3) && !isTimeframe(c4)){
            row=[row[0],c1,'—',c4==='—'?'—':c4,c3];
          }
          // Case B: valid objective + valid metric + timeframe leaked into justification
          // e.g. [2, "Establish PIA...", "Approved doc", "8 months", "12 months"]
          else if(!isTimeframe(c1) && !isTimeframe(c2) && isTimeframe(c3) && isTimeframe(c4)){
            row=[row[0],c1,c2,'—',c4];
          }
          // Case E: TF in justification col, real non-TF content in timeframe col
          // e.g. [1, "Establish Ethics Board", "Approved structure", "6 months", "Deploy AI risk framework"]
          else if(!isTimeframe(c1) && !isTimeframe(c2) && isTimeframe(c3) && !isTimeframe(c4) && c4!=='—'){
            row=[row[0],c1,c2,c4,c3];
          }
          // Case B3: TF in justification, timeframe col is blank
          // e.g. [2, obj, metric, "8 months", "—"]
          else if(!isTimeframe(c1) && !isTimeframe(c2) && isTimeframe(c3) && c4==='—'){
            row=[row[0],c1,c2,'—',c3];
          }
          // Case C: timeframe leaked into target metric (col2)
          // e.g. [2, "Establish PIA...", "6 months", "Some justification", "12 months"]
          else if(!isTimeframe(c1) && isTimeframe(c2)){
            var nonTime=row.slice(2).filter(function(c){return c!=='—'&&!isTimeframe(c);});
            var tfVals =row.slice(1).filter(function(c){return c!=='—'&& isTimeframe(c);});
            row[1]=c1;
            row[2]=nonTime[0]||'—';
            row[3]=nonTime[1]||'—';
            row[4]=tfVals.length?tfVals[tfVals.length-1]:row[4];
          }
        }

        // ── 6-column KPI tables: #, KPI Desc, Target Value, Calc Formula, Justification, Timeframe ──
        // Last column header must contain "timeframe" / "الإطار الزمني"
        if(expected===6 && hasHash && isNum(row[0])){
          var lastHdr=(headers[5]||'').trim().toLowerCase();
          var isTimefameTable=/timeframe|الإطار الزمني|الزمني/.test(lastHdr);
          if(isTimefameTable){
            var k1=row[1],k2=row[2],k3=row[3],k4=row[4],k5=row[5];
            // KPI Case 1: TF in Justification (col5), non-TF in Timeframe (col6) → swap
            if(isTimeframe(k4) && !isTimeframe(k5) && k5!=='—'){
              row=[row[0],k1,k2,k3,k5,k4];
            }
            // KPI Case 2: Target (col2) duplicates KPI Desc (col1) AND Formula (col3) is TF
            // e.g. [2, "AI Data Gov Rate", "AI Data Gov Rate", "18 months", "AI Explain Rate", "15 months"]
            else if(sameish(k1,k2) && isTimeframe(k3)){
              row=[row[0],k1,'—','—',k4==='—'?'—':k4,k5];
            }
            // KPI Case 3: TF leaked into Target Value (col2), Timeframe (col6) is blank
            // e.g. [3, "AI Incident...", "24 months", "—", "—", "—"]
            else if(isTimeframe(k2) && k5==='—'){
              row=[row[0],k1,'—',k3,k4,k2];
            }
            // KPI Case 4: TF in Target (col2), real TF already in Timeframe (col6)
            // e.g. [2, "AI Gov Rate", "15 months", "formula", "justif", "18 months"]
            else if(isTimeframe(k2) && isTimeframe(k5)){
              row=[row[0],k1,'—',k3,k4,k5];
            }
          }
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
    var schema=tableSchemaName(headers);
    var narrowClass=shouldNarrowFirstCol(headers,rows)?'narrow-first-col':'';
    var cls=[narrowClass,'schema-'+schema].filter(Boolean).join(' ');    var tableClass=cls?' class="'+cls+'"':'';
    var priorityCols=[];
    headers.forEach(function(h,i){
      if(/^(priority|الأولوية|likelihood|الاحتمالية|impact|التأثير|status|الحالة)$/i.test((h||'').trim())) priorityCols.push(i);
    });
    var thCells=headers.map(function(h){return '<th style="text-align:'+align+'">'+inlineHtml(h)+'</th>';}).join('');
    var trs=rows.map(function(row){
      return '<tr>'+headers.map(function(_,ci){return cellHtml(row[ci],priorityCols.indexOf(ci)!==-1);}).join('')+'</tr>';
    }).join('');
    return '<div class="table-wrapper" data-schema="'+schema+'"'+dir+'>'
      +'<table'+tableClass+'><thead><tr>'+thCells+'</tr></thead><tbody>'+trs+'</tbody></table></div>';
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
  // Merge consecutive fragmented table blocks into one.
  // AI generates each gap/CSF/initiative row as a separate mini-table whose header
  // becomes a dark <thead>. This coalesces them before any HTML is rendered.
  function coalescePreviewTables(blocks){
    // PREVIEW/EXPORT PARITY (remediation prompt clause G):
    // Frontend must render, not repair. Fragmented-table coalescing has
    // been moved to the backend (ensure_markdown_formatting). Returning
    // blocks unchanged keeps preview visually identical to the exported
    // PDF/DOCX. Left as a named function (not deleted) so the existing
    // call sites continue to work.
    return (blocks || []).slice();
  }
  function _coalescePreviewTables_disabled(blocks){
    var out=[];
    (blocks||[]).forEach(function(block){
      if((block.type||'').toLowerCase()!=='table'){ out.push(block); return; }
      var currHeaders=(block.headers||[]).slice();
      var currRows=(block.rows||[]).slice();
      var prev=out.length?out[out.length-1]:null;
      if(prev&&(prev.type||'').toLowerCase()==='table'){
        var prevHeaders=prev.headers||[];
        var prevRows=prev.rows||[];
        var sameColCount=prevHeaders.length&&prevHeaders.length===currHeaders.length;
        var sameSchema=sameColCount&&(
          JSON.stringify(prevHeaders.map(normHeaderText))===
          JSON.stringify(currHeaders.map(normHeaderText))
        );
        if(sameColCount){
          // Current block is a data row disguised as headers (no rows, not header-like)
          if(currRows.length===0&&!isHeaderLikeCells(currHeaders)){
            prev.rows=prevRows.concat([currHeaders]);
            return;
          }
          // Previous block was a disguised row, current is real table — absorb prev row into current
          if(prevRows.length===0&&!isHeaderLikeCells(prevHeaders)&&currRows.length>0){
            block.rows=[prevHeaders].concat(currRows);
            out[out.length-1]=block;
            return;
          }
          // Same-schema continuation — merge rows
          if(currRows.length>0&&prevRows.length>0&&sameSchema){
            prev.rows=prevRows.concat(currRows);
            return;
          }
        }
        // N-1 col fragment: AI omitted the # column but the prev table has a hash header.
        // e.g. prev ["#","GAP","DESCRIPTION","PRIORITY","STATUS"] (5 cols)
        //      curr ["NO DEDICATED DATA MGMT OFFICE","NO CDO...","CRITICAL","OPEN"] (4 cols)
        if(prevHeaders.length&&currHeaders.length===prevHeaders.length-1
            &&isHashHeader(prevHeaders[0])){
          if(currRows.length===0&&!isHeaderLikeCells(currHeaders)){
            prev.rows=prevRows.concat([[''].concat(currHeaders)]);
            return;
          }
          if(currRows.length>0&&prevRows.length>0){
            prev.rows=prevRows.concat(currRows.map(function(r){return[''].concat(r);}));
            return;
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
    var _blocks=coalescePreviewTables(section.blocks||[]);
    return _blocks.every(function(b){
      if((b.type||'').toLowerCase()!=='table') return true;
      if(!b.headers||!b.headers.length) return false;
      var rows=normalizeRows(b.headers,b.rows||[]);
      // Length check
      if(!rows.every(function(r){return r.length===b.headers.length;})) return false;
      // Schema-aware suspicious-row check: if any row is semantically broken,
      // fail validation so the preview falls back to the markdown path.
      if(rows.some(function(r){return rowSuspiciousForSchema(b.headers,r);})) return false;
      return true;
    });
  }

/* ══════════════════════════════════════════════════════════════════════════
   strategy-renderer.js — Phase 3 additions:
   Quality annotation, traceability indicators, placeholder detection,
   semantic integrity flags, publishability awareness
   ══════════════════════════════════════════════════════════════════════════ */

  // ── Quality annotation: scan blocks for placeholders ─────────────────────
  var PLACEHOLDER_RE = /^\[(?:insert|placeholder|TBD|TODO|add here|أضف هنا|إضافة)[^\]]*\]$/i;
  var PLACEHOLDER_DASH_RE = /^—+$|^\-+$|^\.{3,}$/;

  function isPlaceholderCell(text) {
    var t = (text || '').trim();
    return !t || PLACEHOLDER_RE.test(t) || PLACEHOLDER_DASH_RE.test(t);
  }

  function isPlaceholderRow(row) {
    // A row is placeholder-only if all substantive cells are blank/dash/bracket
    var substance = row.filter(function(c, i) { return i > 0; }); // skip # col
    return substance.every(function(c) { return isPlaceholderCell(c); });
  }

  function countPlaceholderRows(rows) {
    return rows.filter(isPlaceholderRow).length;
  }

  // ── Semantic integrity: detect shifted values ─────────────────────────────
  function detectSemanticIssues(headers, rows, schema) {
    var issues = [];
    if (schema === 'strategic-objectives') {
      rows.forEach(function(row) {
        if (row.length < 5) return;
        // Timeframe leaked into justification
        if (isTimeframe(row[3]) && !isTimeframe(row[4])) {
          issues.push('Timeframe value detected in Justification column');
        }
        // Objective duplicated in metric column
        if (row[1] && row[2] && sameish(row[1], row[2])) {
          issues.push('Objective text duplicated in Target Metric column');
        }
      });
    }
    if (schema === 'kpi-summary') {
      rows.forEach(function(row) {
        if (row.length < 6) return;
        if (isTimeframe(row[2])) issues.push('Timeframe value in Target Value column');
        if (isTimeframe(row[4])) issues.push('Timeframe value in Justification column');
      });
    }
    if (schema === 'key-risks') {
      rows.forEach(function(row) {
        if (row.length < 5) return;
        if (isNum(row[1]) && row[1] === row[0]) issues.push('Row number leaked into Risk column');
        if (row[2] && row[2] !== '—' && row[2].trim().split(/\s+/).length > 4) {
          issues.push('Long narrative in Likelihood column (possible column shift)');
        }
      });
    }
    return issues;
  }

  // ── Quality annotation banner rendered above tables with issues ───────────
  function renderQualityBanner(issues, isRtl) {
    if (!issues || !issues.length) return '';
    var dir = isRtl ? ' dir="rtl"' : '';
    var items = issues.slice(0, 3).map(function(iss) {
      return '<li style="margin:.15rem 0;">' + esc(iss) + '</li>';
    }).join('');
    return (
      '<div class="quality-issue-banner"' + dir + '>' +
        '<span class="quality-issue-icon">⚠️</span>' +
        '<div><strong>' + (isRtl ? 'تحذير جودة:' : 'Quality Notice:') + '</strong>' +
        '<ul style="margin:.25rem 0 0;padding-inline-start:1.2rem;">' + items + '</ul>' +
        '</div>' +
      '</div>'
    );
  }

  // ── Traceability indicator appended to section banners ────────────────────
  function renderTraceabilityIndicator(sectionKey, evidenceLevel, isRtl) {
    var levelConfig = {
      high:   { color: '#10b981', icon: '🔗', label: isRtl ? 'قابل للتتبع' : 'Traceable' },
      medium: { color: '#3b82f6', icon: '🔍', label: isRtl ? 'قابل للتتبع جزئياً' : 'Partially Traced' },
      low:    { color: '#f59e0b', icon: '❓', label: isRtl ? 'يحتاج تتبعاً' : 'Needs Tracing' },
    };
    var cfg = levelConfig[evidenceLevel] || levelConfig.low;
    return (
      '<span class="traceability-indicator" style="color:' + cfg.color + ';" ' +
        'title="' + cfg.label + '">' + cfg.icon + '</span>'
    );
  }

  // ── Override renderTable to include quality annotations ───────────────────
  var _origRenderTable = global.renderTable;

  function renderTableWithQuality(block, isRtl) {
    var headers = block.headers || [];
    var rows = normalizeRows(headers, block.rows || []);
    var schema = tableSchemaName(headers);
    var qualityIssues = [];

    // Check for placeholder rows
    var placeholderCount = countPlaceholderRows(rows);
    if (placeholderCount > 0) {
      qualityIssues.push((isRtl ? 'صفوف نائبة: ' : 'Placeholder rows: ') + placeholderCount);
    }

    // Check for semantic issues
    var semanticIssues = detectSemanticIssues(headers, rows, schema);
    qualityIssues = qualityIssues.concat(semanticIssues);

    // Check for insufficient row count (< 2 real rows for major tables)
    var realRows = rows.filter(function(r) { return !isPlaceholderRow(r); });
    // Pillar initiative tables legitimately contain one initiative per pillar —
    // exclude them from the "only 1 substantive row" warning so individual
    // pillar blocks don't trigger false quality alerts.
    if (headers.length >= 4 && realRows.length < 2 && rows.length > 0 &&
        schema !== 'pillar-initiatives') {
      qualityIssues.push(isRtl ? 'الجدول يحتوي على صف واحد فقط' : 'Table has only 1 substantive row');
    }

    var banner = renderQualityBanner(qualityIssues, isRtl);
    var tableHtml = renderTable(block, isRtl);
    return banner + tableHtml;
  }

  // ── Override renderSectionFromJSON to add traceability + quality pass ──────
  var _origRenderSectionFromJSON = global.renderSectionFromJSON;

  global.renderSectionFromJSON = function(json, sectionKey, isRtl, traceabilityRecord) {
    if (!json || !json.sections) return null;
    isRtl = !!isRtl;
    var targetNum = SECTION_KEY_MAP[sectionKey] || sectionKey;
    var section = null;
    json.sections.forEach(function(s) {
      if (s.number === targetNum) section = s;
      if (!section && s.key === sectionKey) section = s;
    });
    if (!section) return null;

    // Traceability indicator intentionally NOT injected into normal
    // preview section banners (remediation prompt clause F). The icon
    // defaulted to ❓ when no traceability record was passed, leaking
    // into every strategy preview. If traceability is needed, show it
    // in the dedicated traceability panel (see /api/traceability).
    var title = section.number ? section.number + '. ' + (section.title || '') : (section.title || '');
    var html = title ? '<div class="section-banner">' + inlineHtml(title) + '</div>' : '';

    coalescePreviewTables(section.blocks || []).forEach(function(block) {
      if ((block.type || '').toLowerCase() === 'table') {
        html += renderTableWithQuality(block, isRtl);
      } else {
        html += renderBlock(block, isRtl);
      }
    });
    return html;
  };

  // ── Full document render with quality pass ─────────────────────────────────
  var _origRenderStrategyFromJSON = global.renderStrategyFromJSON;

  global.renderStrategyFromJSON = function(json, isRtl, traceabilityRecords) {
    if (!json || !json.sections) return '';
    isRtl = !!isRtl;
    var html = '';
    json.sections.forEach(function(section) {
      // Traceability indicator intentionally NOT injected in preview mode
      // (remediation prompt clause F). traceabilityRecords is still
      // accepted as a parameter for backwards compat, but no ❓/🔍/🔗
      // icon is appended to section banners in the normal document view.
      var title = section.number ? section.number + '. ' + (section.title || '') : (section.title || '');
      if (title) html += '<div class="section-banner">' + inlineHtml(title) + '</div>';
      coalescePreviewTables(section.blocks || []).forEach(function(block) {
        if ((block.type || '').toLowerCase() === 'table') {
          html += renderTableWithQuality(block, isRtl);
        } else {
          html += renderBlock(block, isRtl);
        }
      });
    });
    return html;
  };

  // ── Publishability summary for strategy JSON ──────────────────────────────
  global.computeJsonPublishability = function(json) {
    if (!json || !json.sections) return { score: 0, issues: ['No sections found'] };
    var issues = [];
    var totalTables = 0, cleanTables = 0;

    json.sections.forEach(function(section) {
      var sectionHasContent = false;
      coalescePreviewTables(section.blocks || []).forEach(function(block) {
        var t = (block.type || '').toLowerCase();
        if (t === 'paragraph' || t === 'callout') {
          if ((block.text || '').trim().length > 30) sectionHasContent = true;
        }
        if (t === 'table') {
          sectionHasContent = true;
          totalTables++;
          var hdrs = block.headers || [];
          var rows = normalizeRows(hdrs, block.rows || []);
          var schema = tableSchemaName(hdrs);
          var placeholders = countPlaceholderRows(rows);
          var semantic = detectSemanticIssues(hdrs, rows, schema);
          var suspicious = rows.some(function(r) { return rowSuspiciousForSchema(hdrs, r); });
          if (placeholders === 0 && semantic.length === 0 && !suspicious) cleanTables++;
          if (placeholders > 0) issues.push('Table "' + hdrs.slice(1, 3).join('/') + '": ' + placeholders + ' placeholder row(s)');
          if (semantic.length) issues.push.apply(issues, semantic.slice(0, 2));
          if (suspicious) issues.push('Table "' + hdrs.slice(1, 3).join('/') + '": suspicious row structure');
        }
      });
      if (!sectionHasContent) {
        issues.push('Section "' + (section.title || section.number || '?') + '" has no substantive content');
      }
    });

    var tableScore = totalTables > 0 ? Math.round((cleanTables / totalTables) * 100) : 100;
    var sectionPenalty = Math.min(issues.filter(function(i) { return i.indexOf('no substantive') > -1; }).length * 15, 40);
    var score = Math.max(0, tableScore - sectionPenalty);
    return { score: score, issues: issues, totalTables: totalTables, cleanTables: cleanTables };
  };


  // Original exports preserved — overridden above by Phase 3 wrappers
  global.validateSectionJSON=validateSectionJSON;

})(typeof window!=='undefined'?window:this);
