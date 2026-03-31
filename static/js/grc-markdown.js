/* grc-markdown.js — shared Markdown→HTML renderer used by domain.html and dashboard.html
   Extracted from domain.html to avoid duplication.
   Include this before any page that calls grcMarkdownToHTML().
*/
function grcMarkdownToHTML(md){
  if(!md)return '';

  // ── Step 1: cleanup helpers (same as server-side) ────────────────────────
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
  // Trim leading whitespace before |
  md = md.replace(/^[ \t]+(\|)/gm, '$1');

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
      var tag = 'h'+(lvl+1);
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
        var rows = [];
        tableLines.forEach(function(tl){
          if(/^\|[\s\-:|]+\|$/.test(tl)) return; // skip separator
          var cells = tl.split('|').slice(1,-1).map(function(c){return c.trim();});
          if(!cells.length) return;
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

        var numCols = header.length;

        // ── Client-side # column repair ─────────────────────────────────────
        // If the first column header is '#' and any data row has non-numeric
        // text in cell[0], the AI omitted the row number. Inject it here so
        // narrow-first-col renders a number instead of a crushed paragraph.
        var isHashHeader = /^[#№]$/.test((header[0]||'').trim());
        if(isHashHeader){
          var rowCounter = 1;
          dataRows = dataRows.map(function(row){
            var firstCell = (row[0]||'').trim();
            var isNum = /^\d+(\.\d+)?$/.test(firstCell) || firstCell === '';
            if(!isNum && row.length < numCols){
              // Missing # — prepend row number, keep all other cells
              return [String(rowCounter++)].concat(row);
            } else if(!isNum && row.length === numCols){
              // Has all cells but cell[0] is text — AI put content in # slot
              // Prepend number and trim to numCols (drop last overflowing cell)
              return [String(rowCounter++)].concat(row).slice(0, numCols);
            }
            if(firstCell !== '') rowCounter = parseInt(firstCell, 10) + 1;
            return row;
          });
        }

        var out = '<div class="table-wrapper"><table><thead><tr>';
        header.forEach(function(c){ out += '<th>'+inlineHtml(c)+'</th>'; });
        out += '</tr></thead><tbody>';
        dataRows.forEach(function(row){
          out += '<tr>';
          row.forEach(function(c){ out += '<td>'+inlineHtml(c)+'</td>'; });
          for(var p=row.length;p<numCols;p++) out+='<td></td>';
          out += '</tr>';
        });
        out += '</tbody></table></div>';
        return out;
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
    if(/^\d+\.\s+/.test(s)){
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

    // ── Plain paragraph ──────────────────────────────────────────────────────
    html += '<p>'+inlineHtml(s)+'</p>';
    i++;
  }

  return html;
}
