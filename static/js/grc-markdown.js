/* grc-markdown.js — shared Markdown→HTML renderer used by domain.html and dashboard.html
   Extracted from domain.html to avoid duplication.
   Include this before any page that calls grcMarkdownToHTML().
*/
function grcMarkdownToHTML(md){
  if(!md)return '';

  // ── Step 0: strip trace comment tags ─────────────────────────────────────
  // Trace tags (<!-- trace:section=...|src=... -->) must never appear in
  // preview HTML. They also contain | characters that break pipe-table
  // cell-splitting if left in place. Strip them unconditionally before
  // any other processing.
  md = md.replace(/<!--\s*trace:[^>]*-->/gi, '');

  // ── Step 1: cleanup helpers (same as server-side) ────────────────────────
  // PRE-PIPE-FENCE: ensure every pipe-table block is preceded by a blank line.
  // Without this, a paragraph ending immediately before a | row (zero blank lines)
  // gets consumed as a phantom table header, merging prose into table cells.
  md = md.replace(/([^\n])\n(\|)/g, '$1\n\n$2');
  // PRE-TABLE-BRIDGE: merge pipe-table blocks separated only by **BOLD** labels.
  // AI generates each gap/initiative as: bold-label line + single pipe row + separator.
  // These become separate mini-tables where every data row is a dark <thead>.
  // Fix: strip **BOLD ALL-CAPS** lines that appear between two pipe-table rows
  // so the rows are collected as one continuous table.
  md = (function(text){
    var ls = text.split('\n'), out = [], i = 0;
    while(i < ls.length){
      var prev = i > 0 ? ls[i-1].trim() : '';
      var curr = ls[i].trim();
      // Look ahead past blank lines to find the next non-blank content
      // (the pipe-fence step may have inserted a blank before the next | row)
      var peekNext = i + 1;
      while(peekNext < ls.length && !ls[peekNext].trim()) peekNext++;
      var nextContent = peekNext < ls.length ? ls[peekNext].trim() : '';
      var prevIsPipe = prev.startsWith('|');
      var nextIsPipe = nextContent.startsWith('|');
      var isBoldBridge = /^\*\*[A-Z\u0600-\u06FF][^*]{0,120}\*\*\s*$/.test(curr);
      if(prevIsPipe && nextIsPipe && isBoldBridge){
        // Skip the bold label AND any blank lines between it and the next pipe row
        i = peekNext;
        continue;
      }
      out.push(ls[i]); i++;
    }
    return out.join('\n');
  })(md);
  // G0: JOIN orphan counter "| N" with the next pipe row — do NOT strip.
  // AI generates step numbers on their own line followed by data on the next line:
  //   | 1          ← orphan counter (was being stripped, losing the step number)
  //   | Action | Owner | Deliverable |
  // Join → "| 1 | Action | Owner | Deliverable |" (restores Step column)
  md = md.replace(/^\|\s*(\d+)\s*\n(\|[^\n]+)$/gm, '| $1 $2');
  // G1: strip dangling " | N" at end of rows
  md = md.replace(/(\|[^\n]*\|)\s*\|\s*\d+\s*$/gm, '$1');
  // PRE-0f: split separator+data merged lines  "|---|---| 3 | content |"
  // GUARD: if rest contains only separator chars (- : | space) the whole line IS a
  // valid multi-cell separator like "|---|---|" partially captured — keep it intact.
  md = md.replace(/^(\|(?:\s*[-:]+\s*\|)+)([^\n]+)$/gm, function(m, sep, rest){
    rest = rest.trim();
    if(!/[A-Za-z\u0600-\u06FF0-9]/.test(rest) && /^[-:\s|]+$/.test(rest))
      return m;
    if(/[A-Za-z\u0600-\u06FF0-9]/.test(rest))
      return sep + '\n' + (rest.startsWith('|') ? rest : '| '+rest);
    return sep;
  });
  // PRE-0c: split packed data rows  "| 1 | x | | 2 | y |"  (no newline crossing)
  md = md.replace(/(\|)([^\S\n]*\|[^\S\n]*\d+[^\S\n]*\|)/g, '$1\n$2');
  // PRE-0d: split "Label text | col | col |" into label paragraph + table header row.
  // Covers both colon variant ("Immediate Actions : | Step |")
  // and no-colon variant ("Implementation Rate | Step | Action |").
  // Condition: line doesn't start with | or #, ends with a pipe table (3+ pipes).
  md = md.replace(/^([^|\n#][^\n]{5,}?)\s+(\|(?:[^|\n]+\|){2,}[^\n]*)$/gm, function(m, label, tbl){
    // Only split if the pipe part looks like table columns (has real words between pipes)
    var pipeParts = tbl.split('|').filter(function(p){ return p.trim().length > 0; });
    if(pipeParts.length >= 2) return label.trim() + '\n\n' + tbl.trim();
    return m;
  });
  // PRE-META: fix metadata tables where first row is empty "| | |"
  // AI generates: "| | |\n|---|---|\n| **Key** | Value |" — empty row becomes header
  // Fix: remove any pure-empty pipe rows (all cells whitespace only)
  md = md.replace(/^\|(?:\s*\|)+\s*$/gm, function(m){
    var cells = m.split('|').slice(1,-1);
    var allEmpty = cells.every(function(c){ return !c.trim(); });
    return allEmpty ? '' : m;
  });
  // PRE-PHANTOM: strip injected default-header rows that got promoted to data rows.
  // These appear as: | 1 | # | Item | Detail 1 | Detail 2 | Detail 3 | Status |
  // or without the leading row-counter: | # | Item | Detail 1 | Detail 2 | Detail 3 | Status |
  // They are an artifact of _inject_table_headers() firing on already-headed RACI tables.
  md = md.replace(
    /^\|?\s*\d*\s*\|?\s*#\s*\|\s*Item\s*\|\s*Detail\s*1\s*\|\s*Detail\s*2\s*\|\s*Detail\s*3\s*\|\s*Status\s*\|\s*$/gm,
    ''
  );
  // PRE-DBLHASH: collapse consecutive # header cells: "| # | # | Obj |" → "| # | Obj |"
  // AI frequently generates double-# columns which cramp every other column to ~20pt.
  // CRITICAL: also trim the separator row to match the new column count, because
  // renderTable uses the separator to determine headerCols — if separator still has
  // N cols after header is collapsed to N-1, the table renders as N cols.
  md = (function(src){
    var ls = src.split('\n'), out = [];
    for(var li = 0; li < ls.length; li++){
      var ln = ls[li].trim();
      var nextIdx = li + 1;
      var nextLn = (nextIdx < ls.length) ? ls[nextIdx].trim() : '';
      var isSep = /^\|[\s\-:|]+\|$/.test(nextLn) || /^[-|\s:]+$/.test(nextLn);
      if(ln.startsWith('|') && isSep){
        // Collapse consecutive # cells in the header
        var parts = ln.split('|');
        var inner = parts.slice(1, parts.length - 1);
        var collapsed = []; var prevHash = false; var dropped = 0;
        inner.forEach(function(cell){
          var s = cell.trim().replace(/\*+/g, '');
          var isHash = (s === '#' || s === 'م' || s === 'no' || s === 'no.');
          if(isHash && prevHash){ dropped++; return; }
          collapsed.push(cell); prevHash = isHash;
        });
        out.push('|' + collapsed.join('|') + '|');
        // If columns were dropped, rewrite the separator to match the new count
        // so renderTable computes the correct headerCols from the separator row.
        if(dropped > 0 && nextIdx < ls.length){
          var newCols = collapsed.length;
          ls[nextIdx] = '|' + Array(newCols).fill('---').join('|') + '|';
        }
      } else {
        out.push(ls[li]);
      }
    }
    return out.join('\n');
  })(md);
  // PRE-TRUNCFIX: repair truncated cell values (AI drops leading chars on token boundaries)
  // e.g. "tiative" → "Initiative", "ablish" → "Establish", "eploy" → "Deploy"
  var _trunc = {
    'tiative':'Initiative','ablish':'Establish','velop':'Develop',
    'tablish':'Establish','stablish':'Establish','mplement':'Implement',
    'eploy':'Deploy','onduct':'Conduct','reate':'Create','uild':'Build',
    'onfigure':'Configure','efine':'Define','ngage':'Engage',
    'xecutive':'Executive','egulatory':'Regulatory',
    'actor':'Factor','isk':'Risk','udget':'Budget',
    'uring':'During','hortage':'Shortage','ption':'Option',
    'dentify':'Identify','ssess':'Assess','valuate':'Evaluate'
  };
  md = md.replace(/^(\|(?:[^|\n]*\|)+)$/gm, function(row){
    if(row.indexOf('---') !== -1) return row; // skip separator rows
    return row.replace(/\|\s*([a-z]\w*(?:\s[^\|]*)?)\s*(?=\|)/g, function(m, cellContent){
      var firstWord = cellContent.trim().split(/\s/)[0];
      if(_trunc[firstWord]){
        return m.replace(firstWord, _trunc[firstWord]);
      }
      return m;
    });
  });
  // Trim leading whitespace before |
  md = md.replace(/^[ \t]+(\|)/gm, '$1');

  // PRE-PILLAR: Convert bold Pillar titles merged with narrative into headings
  // "**Pillar 1: Title** Narrative text" → "### Pillar 1: Title\n\nNarrative text"
  md = md.replace(/^\*\*\s*(Pillar\s+\d+\s*:\s*[^*\n]+?)\s*\*\*\s*([A-Z\u0600-\u06FF])/gm, '### $1\n\n$2');
  md = md.replace(/^\*\*\s*((?:\u0627\u0644\u0631\u0643\u064a\u0632\u0629|\u0631\u0643\u064a\u0632\u0629)\s*\d+\s*:\s*[^*\n]+?)\s*\*\*\s*([\u0600-\u06FF])/gm, '### $1\n\n$2');

  // ── Step 2: collect all table blocks then process line-by-line ───────────
  var lines = md.split('\n');
  var html  = '';
  var i     = 0;

  function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function inlineHtml(s){
    s = esc(s);
    s = s.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
    s = s.replace(/\*(.+?)\*/g,'<em>$1</em>');
    s = s.replace(/`(.+?)`/g,'<code>$1</code>');
    return s;
  }

  while(i < lines.length){
    var line = lines[i];
    var s    = line.trim();

    // ── Blank line ──────────────────────────────────────────────────────────
    if(!s){ i++; continue; }

    // ── Horizontal rule ─────────────────────────────────────────────────────
    if(/^---+$/.test(s)){ html += '<hr>'; i++; continue; }

    // ── Headings ────────────────────────────────────────────────────────────
    var hm = s.match(/^(#{1,4})\s+(.+)$/);
    if(hm){
      var lvl = hm[1].length;
      var tag = 'h'+Math.min(lvl+1, 4);
      var headingText = hm[2];
      // If heading contains an embedded pipe table, split it:
      // "#### Gap #1 ... Immediate Actions : | Step | Action | Owner |"
      var pipeIdx = headingText.indexOf('|');
      if(pipeIdx > 0 && headingText.split('|').length >= 4){
        var hLabel = headingText.substring(0, pipeIdx).trim();
        var hTable = headingText.substring(pipeIdx).trim();
        html += '<'+tag+'>'+inlineHtml(hLabel)+'</'+tag+'>';
        // Inject table line back into the stream for normal table processing
        lines.splice(i+1, 0, hTable);
      } else {
        html += '<'+tag+'>'+inlineHtml(headingText)+'</'+tag+'>';
      }
      i++; continue;
    }

    // ── Pipe table block ────────────────────────────────────────────────────
    if(s.startsWith('|')){

      function renderTable(tableLines, inheritedHeader){
        if(!tableLines.length) return '';

        // Determine expected column count from first separator, or first row
        var headerCols = 0;
        for(var ti=0; ti<tableLines.length; ti++){
          if(/^\|[\s\-:|]+\|$/.test(tableLines[ti])){
            headerCols = tableLines[ti].split('|').length - 2;
            break;
          }
        }
        if(!headerCols && tableLines.length){
          headerCols = tableLines[0].split('|').slice(1,-1).length;
        }

        // Parse every non-separator row into typed row objects
        // ── Pre-detect RACI7 table type using RAW (un-padded) first row ──────
        // CRITICAL: this must happen BEFORE the forEach padding loop, because
        // once cells are padded to headerCols every row has 7 elements and
        // the 6-vs-7 check can never fire.
        var rawFirstRow = null;
        for(var pi=0; pi<tableLines.length; pi++){
          var ptl = tableLines[pi].trim();
          if(/^\|[\s\-:|]+\|$/.test(ptl)) continue; // skip separator
          rawFirstRow = ptl.split('|').slice(1,-1).map(function(c){return c.trim();});
          break;
        }
        var isRaci7Pre = rawFirstRow && rawFirstRow.length === 7 && (function(){
          var h = rawFirstRow.map(function(c){return c.toLowerCase();});
          return h.some(function(c){return /^activity/.test(c);}) &&
                 h.some(function(c){return /^responsible/.test(c);}) &&
                 h.some(function(c){return /^informed/.test(c);});
        })();

        var rows = [];
        var rowIdx2 = 0; // 0 = header row, >0 = data rows
        tableLines.forEach(function(tl){
          if(/^\|[\s\-:|]+\|$/.test(tl)) return; // skip separator
          var cells = tl.split('|').slice(1,-1).map(function(c){return c.trim();});
          if(!cells.length) return;

          // ── RACI7 fix: handle rows with optional leading row-counter ────────
          // Must happen BEFORE padding so cells.length is still the raw count.
          if(isRaci7Pre && rowIdx2 > 0){
            var isDigit0 = /^\d+$/.test(cells[0]);
            // Case A: AI added extra row-counter giving headerCols+1 cells → drop it
            if(isDigit0 && cells.length === headerCols + 1){
              cells = cells.slice(1); // Drop the spurious row number → headerCols cells
            // Case B: Same cell count but "1" landed in Activity slot (prompt said
            // "# column") and actual Activity text shifted into Responsible.
            // Detect: cells[0] is digit, cells[1] is long text and NOT a short role.
            } else if(isDigit0 && cells.length === headerCols && cells.length >= 2){
              var cell1 = cells[1] || '';
              var looksLikeRole = /^(CDO|CEO|CRO|DPO|CISO|IT Team|IT Director|HR|PMO|Executive|Data Steward|Training|Legal|Risk|Compliance|SOC|CSIRT|Procurement|Finance|Business|Management)\b/i.test(cell1);
              if(cell1.length > 15 && !looksLikeRole){
                cells = cells.slice(1); // drop the digit
                cells.push('');         // pad right to keep headerCols count
              }
            // Standard fix: Informed column missing (6-col row in 7-col table) → insert '—' at index 4
            } else if(cells.length === headerCols - 1){
              cells.splice(4, 0, '—');
            }
          }
          rowIdx2++;

          while(cells.length < headerCols) cells.push('');
          rows.push(cells.slice(0, headerCols));
        });

        if(!rows.length) return '';

        // Decide which row is the header:
        // - If inheritedHeader is provided AND the first row looks like a data row
        //   (first cell is a number or empty, i.e. continuation rows), use inheritedHeader.
        // - Otherwise first row is the header.
        var header, dataRows;
        var firstCellIsData = rows.length > 0 &&
          (/^\d+$/.test(rows[0][0]) || rows[0][0] === '');
        if(inheritedHeader && firstCellIsData){
          header   = inheritedHeader;
          dataRows = rows;
        } else {
          header   = rows[0];
          dataRows = rows.slice(1);
        }

        // Safety: collapse any remaining duplicate # cells in the header
        // (catches cases where PRE-DBLHASH didn't fire due to missing separator)
        (function(){
          var collapsed = []; var prevH = false;
          header.forEach(function(cell){
            var s = cell.trim().replace(/\*+/g,'');
            var isH = (s==='#'||s==='م'||s==='no'||s==='no.');
            if(isH && prevH) return;
            collapsed.push(cell); prevH = isH;
          });
          if(collapsed.length !== header.length){
            header = collapsed;
            // Trim data rows to match new column count
            dataRows = dataRows.map(function(r){ return r.slice(0, collapsed.length); });
            headerCols = collapsed.length;
          }
        })();

        var numCols = header.length;

        // ── KPI assessment 5-col fix ────────────────────────────────────────
        // Header: Step|Action|Tool/System|Owner|Output
        // AI often generates 4-cell data rows (omits step number at index 0).
        // Rows are padded to 5 by this point, so we detect by first-cell content:
        // if first cell is non-numeric in a Step-headed table, step was omitted.
        var isKpi5 = (numCols === 5) && (function(){
          var h = header.map(function(c){ return c.toLowerCase().trim(); });
          return (h[0] === 'step' || h[0] === 'الخطوة') &&
                 h.some(function(c){ return /^action$|^الإجراء$/.test(c); }) &&
                 h.some(function(c){ return /^owner$|^المسؤول$/.test(c); });
        })();
        if(isKpi5){
          var kpiCounter = 0;
          dataRows = dataRows.map(function(row){
            var firstCell = (row[0] || '').trim();
            var firstIsNum = /^\d+$/.test(firstCell);
            if(firstIsNum){
              kpiCounter = parseInt(firstCell, 10);
              return row;
            }
            // Step number was omitted: first cell is Action text.
            // Shift right by 1, prepend sequential counter, drop trailing padded empty.
            kpiCounter++;
            return [String(kpiCounter)].concat(row.slice(0, numCols - 1));
          });
        }
        var isHashHeader = /^[#№]$/.test((header[0]||'').trim());
        var isStepNumHeader = /^(step|الخطوة|خطوة|م|no\.?)$/i.test((header[0]||'').trim());

        if(isHashHeader){
          // # header: inject / repair row numbers
          // Handles three cases:
          //   A) Row has too few cells → prepend counter
          //   B) Row has right number but empty first cell → fill it in
          //   C) Row has right number and non-numeric first cell → replace with counter
          var rowCounter = 1;
          dataRows = dataRows.map(function(row){
            var firstCell = (row[0]||'').trim();
            var isNum = /^\d+(\.\d+)?$/.test(firstCell);
            if(isNum){
              // Row already has a valid number — sync counter then return
              rowCounter = parseInt(firstCell, 10) + 1;
              return row;
            }
            if(firstCell === ''){
              // Empty first cell: fill it in, keep rest intact
              var filled = row.slice();
              filled[0] = String(rowCounter++);
              return filled;
            }
            // Non-numeric non-empty first cell: row number was omitted
            if(row.length < numCols){
              return [String(rowCounter++)].concat(row);
            }
            // Row length == numCols but no row number → prepend and trim last
            return [String(rowCounter++)].concat(row).slice(0, numCols);
          });
        } else if(!isStepNumHeader && !isRaci7Pre && numCols > 2){
          // Non-# non-RACI header (Activity, Initiative, Gap...): strip spurious row numbers.
          // RACI7 tables are explicitly excluded because their Activity column is never
          // a row number and the stripping logic would corrupt the first cell.
          dataRows = dataRows.map(function(row){
            var firstCell = (row[0]||'').trim();
            if(/^\d+(\.\d+)?$/.test(firstCell) && row.length === numCols){
              var fixed = row.slice(1);
              while(fixed.length < numCols) fixed.push('');
              return fixed;
            }
            return row;
          });
        }

        // ── Detect document metadata table: 2-col key-value (e.g. document cover table) ──
        // When: exactly 2 columns AND first-col cells are all bold (**key**) OR
        // header cells are both empty/generic (the AI emits | | | as header which gets
        // stripped, making data row 0 the new "header").
        // Render as a clean .doc-meta-table card — NO navy header, no data-table styling.
        var isDocMeta = (numCols === 2) && (function(){
          // All rows (header + data) should have first cell as bold or recognizable doc-property label
          var allRows = [header].concat(dataRows);
          var boldCount = 0;
          allRows.forEach(function(r){ if(/\*\*/.test(r[0]||'')) boldCount++; });
          return boldCount >= Math.floor(allRows.length * 0.6);
        })();

        if(isDocMeta){
          var metaOut = '<div class="doc-meta-table"><table>';
          var allMetaRows = [header].concat(dataRows);
          allMetaRows.forEach(function(row){
            if(!row[0] && !row[1]) return; // skip truly empty rows
            metaOut += '<tr><td class="doc-meta-key">'+inlineHtml(row[0]||'')+'</td><td class="doc-meta-val">'+inlineHtml(row[1]||'')+'</td></tr>';
          });
          metaOut += '</table></div>';
          return metaOut;
        }

        // ── Schema detection — MUST come before schemaClass assignment ──────────
        // WARNING: var declarations here are NOT hoisted with their values. All
        // schema detection that drives schemaClass AND isCriticalEmpty must be
        // evaluated before those consumers. Previously these were declared after
        // schemaClass, causing all schema vars to be undefined (hoisted but un-
        // initialised), so no schema class was ever assigned in the markdown path.

        // ── Detect Strategic Objectives table (5-col: # Objective TargetMetric Justification Timeframe) ──
        var isObjTable = (numCols === 5) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return (h[0] === '#' || h[0] === 'م') &&
                 h.some(function(c){ return /^objective$|^الهدف/.test(c); }) &&
                 h.some(function(c){ return /^target|^المقياس|^المؤشر/.test(c); }) &&
                 h.some(function(c){ return /^timeframe$|^الإطار/.test(c); });
        })();

        // ── Detect Pillar Initiative table (4-col: # Initiative Description ExpectedDeliverable) ──
        var isPillarTable = (numCols === 4) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return (h[0] === '#' || h[0] === 'م') &&
                 h.some(function(c){ return /^initiative$|^المبادرة/.test(c); }) &&
                 h.some(function(c){ return /^description$|^الوصف/.test(c); }) &&
                 h.some(function(c){ return /^expected|^المخرج/.test(c); });
        })();

        // ── Detect KPI main table (6-col: # KPIDescription TargetValue Formula Justification Timeframe) ──
        var isKpiTable = (numCols === 6) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return (h[0] === '#' || h[0] === 'م') &&
                 h.some(function(c){ return /^kpi|^وصف المؤشر/.test(c); }) &&
                 h.some(function(c){ return /^target|^القيمة/.test(c); }) &&
                 h.some(function(c){ return /^formula|^calculation|^صيغة/.test(c); });
        })();

        // ── Detect Key Risks table (5-col: # Risk Likelihood Impact MitigationPlan) ──
        var isRiskTable = (numCols === 5) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return (h[0] === '#' || h[0] === 'م') &&
                 h.some(function(c){ return /^risk$|^الخطر/.test(c); }) &&
                 h.some(function(c){ return /^likelihood$|^الاحتمالية/.test(c); }) &&
                 h.some(function(c){ return /^mitigation|^خطة/.test(c); });
        })();

        // ── Detect Gap Analysis table (5-col: # Gap Description Priority Status) ──
        var isGapTable = (numCols === 5) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return (h[0] === '#' || h[0] === 'م') &&
                 h.some(function(c){ return /^gap$|^الفجوة/.test(c); }) &&
                 h.some(function(c){ return /^priority$|^الأولوية/.test(c); }) &&
                 h.some(function(c){ return /^status$|^الحالة/.test(c); });
        })();

        // ── Detect Procedure RACI table ──
        var isProcRaciTable = (numCols >= 5) && (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return h.some(function(c){ return /^activity$|^النشاط/.test(c); }) &&
                 h.some(function(c){ return /^responsible|^المسؤول/.test(c); }) &&
                 h.some(function(c){ return /^informed|^المُبلَّغ/.test(c); });
        })();

        // ── Detect Procedure Control Mapping table (Item/ControlID, Description, Details/ControlDescription, Notes) ──
        var isProcControlTable = (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return h.some(function(c){ return /^item$|^control.?id|^رقم.?الضابط/.test(c); }) &&
                 h.some(function(c){ return /^description$|^control.?desc|^وصف.?الضابط/.test(c); });
        })();

        // ── Detect Procedure Decision Points table ──
        var isProcDecisionTable = (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return h.some(function(c){ return /^decision|^نقطة.?القرار/.test(c); }) &&
                 h.some(function(c){ return /^condition|^الشرط/.test(c); });
        })();

        // ── Detect Procedure Evidence table ──
        var isProcEvidenceTable = (function(){
          var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
          return h.some(function(c){ return /^evidence.?type|^نوع.?الدليل/.test(c); }) &&
                 h.some(function(c){ return /^retention|^مدة.?الاحتفاظ/.test(c); });
        })();

        // ── KEY RISKS: repair leaked row number in dataRows ─────────────────────
        // When AI omits the # column, normalizer prepends seq, leaking it into Risk:
        // AI:           [2, "Citizen Service...", "Medium", "High", —]       (4-cell)
        // normalizer:   [2, "2", "Citizen Service...", "Medium", "High"]     (5-cell)
        // Detection:    row[0] === row[1] AND row[2] is a narrative (>5 chars)
        if(isRiskTable){
          dataRows = dataRows.map(function(row){
            if(row.length === 5 &&
               /^\d+$/.test(row[0]) &&
               row[0] === row[1] &&
               (row[2]||'').length > 5){
              return [row[0], row[2], row[3]||'—', row[4]||'—', '—'];
            }
            return row;
          });
        }

        // ── PROCEDURE PURPOSE & SCOPE: extract narrative from header row ─────────
        // The AI sometimes generates the Purpose & Scope narrative as the first
        // cell of the control-mapping table header row (rather than as a paragraph
        // before the table). When detected, emit the narrative as a paragraph and
        // promote the first data row (or a default schema) to be the real header.
        var procedureNarrativeParagraph = '';
        if((header[0]||'').length > 60 && /[.،]/.test(header[0])){
          // First header cell is a long narrative sentence — extract it
          procedureNarrativeParagraph = '<p class="proc-purpose-narrative">' + inlineHtml(header[0]) + '</p>';
          // Determine real headers: if first data row looks like column labels, promote it
          function looksLikeHeaderRow(cells){
            if(!cells || !cells.length) return false;
            var knownHeaders = [
              'item','control id','control description','compliance requirement',
              'description','details','notes','requirement','status',
              'activity','responsible','accountable','consulted','informed',
              'decision point','condition','evidence type','retention period',
              'رقم الضابط','وصف الضابط','متطلب الامتثال','النشاط','المسؤول'
            ];
            var hits = cells.filter(function(c){
              return knownHeaders.indexOf((c||'').toLowerCase().trim()) !== -1;
            }).length;
            // A row qualifies as a header row if ≥ half its cells match known header names
            return hits >= Math.max(1, Math.ceil(cells.length / 2));
          }
          if(dataRows.length > 0 && looksLikeHeaderRow(dataRows[0])){
            header = dataRows[0];
            dataRows = dataRows.slice(1);
            numCols = header.length;
            headerCols = numCols;
          } else {
            // Fallback: use the remaining header cells as column names,
            // keeping Control ID, Description, Notes if available
            var remainderHeaders = header.slice(1);
            if(remainderHeaders.length >= 2){
              header = remainderHeaders;
              numCols = header.length;
              headerCols = numCols;
            }
          }
          // Re-run schema detection with updated header
          isProcControlTable = (function(){
            var h = header.map(function(c){ return (c||'').toLowerCase().trim(); });
            return h.some(function(c){ return /^item$|^control.?id|^رقم.?الضابط/.test(c); }) &&
                   h.some(function(c){ return /^description$|^control.?desc|^وصف.?الضابط/.test(c); });
          })();
        }

        // ── Determine schema CSS class for column-width rules ──
        var schemaClass = '';
        if(isObjTable)           schemaClass = 'schema-strategic-objectives';
        else if(isPillarTable)   schemaClass = 'schema-pillar-initiatives';
        else if(isKpiTable)      schemaClass = 'schema-kpi-summary';
        else if(isRiskTable)     schemaClass = 'schema-key-risks';
        else if(isGapTable)      schemaClass = 'schema-gap-analysis';
        else if(isProcRaciTable) schemaClass = 'schema-procedure-raci';
        else if(isProcControlTable) schemaClass = 'schema-procedure-purpose-scope';
        else if(isProcDecisionTable) schemaClass = 'schema-procedure-decision';
        else if(isProcEvidenceTable) schemaClass = 'schema-procedure-evidence';

        var tableClsAttr = schemaClass ? ' class="'+schemaClass+'"' : '';
        var schemaAttr   = schemaClass ? ' data-schema="'+schemaClass.replace('schema-','')+'"' : '';
        var out = '<div class="table-wrapper"'+schemaAttr+'><table'+tableClsAttr+'><thead><tr>';
        header.forEach(function(c){ out += '<th>'+inlineHtml(c)+'</th>'; });
        out += '</tr></thead><tbody>';

        // Helper: wrap priority/status text in coloured span
        function priorityHtml(raw){
          var s = raw.trim().toLowerCase();
          if(s === 'critical' || s === 'حرج' || s === 'حرجي')
            return '<span class="priority-critical">'+esc(raw)+'</span>';
          if(s === 'high' || s === 'عالي' || s === 'عالية')
            return '<span class="priority-high">'+esc(raw)+'</span>';
          if(s === 'medium' || s === 'متوسط' || s === 'متوسطة')
            return '<span class="priority-medium">'+esc(raw)+'</span>';
          if(s === 'low' || s === 'منخفض' || s === 'منخفضة')
            return '<span class="priority-low">'+esc(raw)+'</span>';
          return inlineHtml(raw);
        }

        // Schema detection vars (isObjTable/isPillarTable/isKpiTable/isRiskTable
        // isProcRaciTable/isProcControlTable etc.) are declared ABOVE before schemaClass.
        // This block was the old (duplicate) location — removed to fix JS var hoisting bug.

          var hl = (h||'').toLowerCase().trim();
          if(/^(priority|الأولوية|likelihood|الاحتمالية|impact|التأثير|status|الحالة|importance|الأهمية)$/.test(hl)){
            prioColIdx.push(hi);
          }
        });

        dataRows.forEach(function(row){
          out += '<tr>';
          row.forEach(function(c, ci){
            var cellHtml = (prioColIdx.indexOf(ci) !== -1) ? priorityHtml(c) : inlineHtml(c);
            // Warn on empty cells in critical tables
            var isEmpty = !c || !c.trim() || c.trim() === '—';
            // Only flag empty cells that are structurally required (not optionally blank)
            var isCriticalEmpty = isEmpty && (
              (isObjTable    && (ci === 4)) ||            // Timeframe only
              (isPillarTable && ci >= 2) ||               // Description, Expected Deliverable
              (isKpiTable    && ci === 5) ||              // Timeframe only (Target/Formula may be "—")
              (isRiskTable   && ci >= 2 && ci <= 3)       // Likelihood, Impact (not Mitigation)
            );
            if(isCriticalEmpty){
              out += '<td class="cell-missing">—</td>';
            } else {
              out += '<td>'+cellHtml+'</td>';
            }
          });
          for(var p=row.length;p<numCols;p++) out+='<td class="cell-missing">—</td>';
          out += '</tr>';
        });
        out += '</tbody></table></div>';
        // Prepend any narrative extracted from the header row (procedure Purpose & Scope fix)
        return procedureNarrativeParagraph + out;
      }

      // Collect consecutive pipe lines.
      // Stop at: non-pipe non-blank line (real content break).
      // Allow a single blank line only if NEXT non-blank line is also a pipe line.
      // Also stop if a bold section label appears between blank lines.
      var tableLines = [];
      var lastHeader = null; // track header across sub-sections

      // First collect this table block
      while(i < lines.length){
        var tl = lines[i].trim();
        if(tl.startsWith('|')){
          tableLines.push(tl); i++;
        } else if(!tl){
          // Look ahead past blanks
          var peek = i+1;
          while(peek < lines.length && !lines[peek].trim()) peek++;
          var nextLine = (peek < lines.length) ? lines[peek].trim() : '';
          if(nextLine.startsWith('|')){
            i++; // skip blank, continue table
          } else {
            break; // true table end
          }
        } else {
          break;
        }
      }

      // Render this table block and capture its header for potential inheritance
      var firstHeaderRow = null;
      for(var ti2=0; ti2<tableLines.length; ti2++){
        if(!/^\|[\s\-:|]+\|$/.test(tableLines[ti2])){
          var hCells = tableLines[ti2].split('|').slice(1,-1).map(function(c){return c.trim();});
          // Is it a real header (all text, no digits as first cell)?
          if(hCells.length && !/^\d+$/.test(hCells[0]) && hCells[0] !== ''){
            firstHeaderRow = hCells;
          }
          break;
        }
      }

      // De-duplicate: remove extra separator rows and repeated header rows.
      // AI sometimes emits |---|---| between every data row, splitting one table into
      // N mini-tables each with their own dark header row in the preview.
      (function(){
        if(!tableLines.length) return;
        var realHeader = null;
        for(var _i=0;_i<tableLines.length;_i++){
          if(!/^\|[\s\-:|]+\|$/.test(tableLines[_i])){ realHeader=tableLines[_i]; break; }
        }
        var seenSep = false;
        tableLines = tableLines.filter(function(ln){
          var isSep = /^\|[\s\-:|]+\|$/.test(ln);
          if(isSep){ if(seenSep) return false; seenSep=true; return true; }
          if(realHeader && ln.trim()===realHeader.trim() && seenSep) return false;
          return true;
        });
      })();
      html += renderTable(tableLines, null);
      var inheritedHdr = firstHeaderRow; // carry this across sub-section breaks

      // After the table, consume any section label + continuation table pairs
      while(i < lines.length){
        // Skip blanks
        while(i < lines.length && !lines[i].trim()) i++;
        if(i >= lines.length) break;

        var nextS = lines[i].trim();

        // Check if this is a sub-section label (Goals, Actions, Evidence, etc.)
        var isSectionLabel = /^(\*{1,2}[^*]+\*{1,2}|[^|#\n-][^\n]{0,80})\s*:?\s*$/.test(nextS) &&
          /Short.Term Goals|Medium.Term Goals|Long.Term Goals|Immediate Actions|Evidence Required|الأهداف قصيرة|الأهداف متوسطة|الإجراءات الفورية|المتطلبات/i.test(nextS);

        if(isSectionLabel){
          // Emit label as styled paragraph
          var labelText = nextS.replace(/\*+/g,'').replace(/:$/,'').trim();
          html += '<p class="impl-section-label"><strong>'+inlineHtml(labelText)+'</strong></p>';
          i++;
          // Skip blanks
          while(i < lines.length && !lines[i].trim()) i++;
          // If next line is a pipe, collect that continuation table
          if(i < lines.length && lines[i].trim().startsWith('|')){
            var contLines = [];
            while(i < lines.length){
              var cl = lines[i].trim();
              if(cl.startsWith('|')){
                contLines.push(cl); i++;
              } else if(!cl){
                var pk2 = i+1;
                while(pk2 < lines.length && !lines[pk2].trim()) pk2++;
                var nxt2 = (pk2 < lines.length) ? lines[pk2].trim() : '';
                if(nxt2.startsWith('|')){ i++; }
                else break;
              } else {
                break;
              }
            }
            // Render continuation with inherited header
            html += renderTable(contLines, inheritedHdr);
          }
        } else {
          break; // not a section label, stop consuming
        }
      }
      continue;
    }

    // ── Blockquote ───────────────────────────────────────────────────────────
    if(s.startsWith('> ')){
      html += '<blockquote>';
      while(i < lines.length && lines[i].trim().startsWith('> ')){
        var qLine = lines[i].trim().slice(2); // strip the "> "
        html += '<p>'+inlineHtml(qLine)+'</p>';
        i++;
      }
      html += '</blockquote>';
      continue;
    }

    // ── Bullet list ─────────────────────────────────────────────────────────
    if(/^[-*•]\s+/.test(s)){
      html += '<ul>';
      while(i < lines.length && /^[-*•]\s+/.test(lines[i].trim())){
        html += '<li>'+inlineHtml(lines[i].trim().replace(/^[-*•]\s+/,''))+'</li>';
        i++;
      }
      html += '</ul>'; continue;
    }

    // ── Numbered list ────────────────────────────────────────────────────────
    // Special case: vision/objectives sections like "1. Vision & Objectives **Strategic Mandate** text **Compliance North Star** text..."
    // are output as a single numbered-list item containing multiple bold section labels.
    // Detect this and split into a section heading + callout-label blocks instead of an <ol><li>.
    if(/^\d+\.\s+/.test(s)){
      // Check if this single line contains 2+ bold labels → vision section pattern
      var boldLabels = s.match(/\*\*[^*]{2,50}\*\*/g) || [];
      var isSectionBlock = boldLabels.length >= 2;

      // Only treat as a section-block if it's a SHORT line (< 220 chars).
      // Long lines are vision/strategy paragraphs that happen to have inline bold labels —
      // those should render as normal paragraphs, NOT callout-label blocks.
      if(isSectionBlock && s.length <= 220){
        // Emit as a styled section block: split on **label** boundaries
        var sectionText = s.replace(/^\d+\.\s+/, '');
        var splitParts = sectionText.split(/(\*\*[^*]{2,50}\*\*)/);
        splitParts.forEach(function(part){
          if(/^\*\*[^*]+\*\*$/.test(part)){
            var label = part.slice(2, -2);
            html += '<p class="callout-label"><strong>'+inlineHtml(label)+'</strong></p>';
          } else {
            var trimmed = part.trim();
            if(trimmed) html += '<p>'+inlineHtml(trimmed)+'</p>';
          }
        });
        i++; continue;
      }

      html += '<ol>';
      while(i < lines.length && /^\d+\.\s+/.test(lines[i].trim())){
        html += '<li>'+inlineHtml(lines[i].trim().replace(/^\d+\.\s+/,''))+'</li>';
        i++;
      }
      html += '</ol>'; continue;
    }

    // ── Checkbox line ────────────────────────────────────────────────────────
    if(s.indexOf('☐') !== -1 || s.indexOf('■') !== -1){
      html += '<p>'+s.replace(/☐/g,'<input type="checkbox" disabled> ').replace(/■/g,'<input type="checkbox" checked disabled> ')+'</p>';
      i++; continue;
    }

    // ── Callout label: entire line is **bold** (Strategic Mandate, Vision:, etc.)
    // Render with a styled class so it gets visual separation from surrounding prose.
    if(s.startsWith('**') && s.endsWith('**') && s.length > 4){
      var innerText = s.slice(2, -2);
      // Must not be a table-like pattern (no pipes) and must not be empty
      if(innerText && innerText.indexOf('|') === -1){
        html += '<p class="callout-label"><strong>'+inlineHtml(innerText)+'</strong></p>';
        i++; continue;
      }
    }

    // ── Plain paragraph — also split on inline bold section labels ───────────
    // Handles: "**Strategic Mandate** text... **Compliance North Star** text..."
    // when the AI outputs it as a bare paragraph (no leading "1. ").
    var paraBoldLabels = s.match(/\*\*[^*]{2,50}\*\*/g) || [];
    if(paraBoldLabels.length >= 2){
      var splitParaParts = s.split(/(\*\*[^*]{2,50}\*\*)/);
      splitParaParts.forEach(function(part){
        if(/^\*\*[^*]+\*\*$/.test(part)){
          var label = part.slice(2, -2);
          html += '<p class="callout-label"><strong>'+inlineHtml(label)+'</strong></p>';
        } else {
          var trimmed = part.trim();
          if(trimmed) html += '<p>'+inlineHtml(trimmed)+'</p>';
        }
      });
      i++; continue;
    }

    html += '<p>'+inlineHtml(s)+'</p>';
    i++;
  }

  return html;
}
