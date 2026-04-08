/* strategy-renderer.js
   Deterministic Big4 HTML renderer from structured JSON.
   Replaces grcMarkdownToHTML() for strategy documents when content_json is present.
   All visual decisions are made here — Claude only produces content, never layout.
*/

(function(global){

  // ── Helpers ──────────────────────────────────────────────────────────────
  function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  function inlineHtml(s){
    s = esc(s);
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
    s = s.replace(/`(.+?)`/g, '<code>$1</code>');
    s = s.replace(/\n/g, '<br>');
    return s;
  }

  var PRIORITY_MAP = {
    'critical': '<span class="priority-critical">Critical</span>',
    'حرج':      '<span class="priority-critical">حرج</span>',
    'حرجي':     '<span class="priority-critical">حرجي</span>',
    'high':     '<span class="priority-high">High</span>',
    'عالي':     '<span class="priority-high">عالي</span>',
    'عالية':    '<span class="priority-high">عالية</span>',
    'medium':   '<span class="priority-medium">Medium</span>',
    'متوسط':    '<span class="priority-medium">متوسط</span>',
    'متوسطة':   '<span class="priority-medium">متوسطة</span>',
    'low':      '<span class="priority-low">Low</span>',
    'منخفض':    '<span class="priority-low">منخفض</span>',
    'منخفضة':   '<span class="priority-low">منخفضة</span>'
  };

  function cellHtml(text, isPriorityCol){
    var s = (text||'').trim();
    if(!s || s === '—') return '<td class="cell-missing">—</td>';
    if(isPriorityCol){
      var lc = s.toLowerCase();
      if(PRIORITY_MAP[lc]) return '<td>' + PRIORITY_MAP[lc] + '</td>';
    }
    return '<td>' + inlineHtml(s) + '</td>';
  }

  // ── Block renderers ──────────────────────────────────────────────────────

  function renderCallout(block, isRtl){
    var dir = isRtl ? ' dir="rtl"' : '';
    var html = '<div class="callout-label"' + dir + '>' + inlineHtml(block.label||'') + '</div>';
    if(block.text){
      html += '<p' + dir + ' style="' + (isRtl?'padding-right':'padding-left') + ':1rem;color:#374151;margin-top:.2rem;">'
            + inlineHtml(block.text) + '</p>';
    }
    return html;
  }

  function renderParagraph(block, isRtl){
    var dir = isRtl ? ' dir="rtl"' : '';
    return '<p' + dir + '>' + inlineHtml(block.text||'') + '</p>';
  }

  function renderBulletList(block, isRtl){
    var dir = isRtl ? ' dir="rtl"' : '';
    var items = (block.items||[]).map(function(it){
      return '<li>' + inlineHtml(it) + '</li>';
    }).join('');
    return '<ul' + dir + '>' + items + '</ul>';
  }

  function renderNumberedList(block, isRtl){
    var dir = isRtl ? ' dir="rtl"' : '';
    var items = (block.items||[]).map(function(it){
      return '<li>' + inlineHtml(it) + '</li>';
    }).join('');
    return '<ol' + dir + '>' + items + '</ol>';
  }

  function renderTable(block, isRtl){
    var headers = block.headers || [];
    var rows    = block.rows    || [];
    if(!headers.length) return '';

    var align = isRtl ? 'right' : 'left';
    var dir   = isRtl ? ' dir="rtl"' : '';

    // Detect priority columns by header name
    var priorityCols = [];
    headers.forEach(function(h, i){
      var hl = (h||'').toLowerCase().trim();
      if(/^(priority|الأولوية|likelihood|الاحتمالية|impact|التأثير|status|الحالة)$/.test(hl)){
        priorityCols.push(i);
      }
    });

    // Header row
    var thCells = headers.map(function(h){
      return '<th style="text-align:' + align + '">' + inlineHtml(h) + '</th>';
    }).join('');

    // Data rows
    var trs = rows.map(function(row, ri){
      var tds = headers.map(function(_, ci){
        return cellHtml(row[ci], priorityCols.indexOf(ci) !== -1);
      }).join('');
      return '<tr>' + tds + '</tr>';
    }).join('');

    return '<div class="table-wrapper"' + dir + '>'
      + '<table><thead><tr>' + thCells + '</tr></thead>'
      + '<tbody>' + trs + '</tbody></table></div>';
  }

  function renderEvidence(block, isRtl){
    var items = (block.items||[]);
    var dir = isRtl ? ' dir="rtl"' : '';
    var checks = items.map(function(it){
      return '<label style="display:flex;gap:.5rem;align-items:flex-start;margin:.3rem 0;">'
           + '<input type="checkbox" disabled style="margin-top:.2rem;"> '
           + '<span>' + inlineHtml(it) + '</span></label>';
    }).join('');
    return '<div class="evidence-gate"' + dir + '>'
      + (block.label ? '<strong>' + inlineHtml(block.label) + '</strong>' : '')
      + checks + '</div>';
  }

  function renderSubheading(block, isRtl){
    var dir = isRtl ? ' dir="rtl"' : '';
    return '<h3' + dir + '>' + inlineHtml(block.text||'') + '</h3>';
  }

  function renderBlock(block, isRtl){
    var t = (block.type||'').toLowerCase();
    if(t === 'callout')       return renderCallout(block, isRtl);
    if(t === 'paragraph')     return renderParagraph(block, isRtl);
    if(t === 'bullet_list')   return renderBulletList(block, isRtl);
    if(t === 'numbered_list') return renderNumberedList(block, isRtl);
    if(t === 'table')         return renderTable(block, isRtl);
    if(t === 'evidence')      return renderEvidence(block, isRtl);
    if(t === 'subheading')    return renderSubheading(block, isRtl);
    // Fallback: treat as paragraph
    if(block.text) return renderParagraph(block, isRtl);
    return '';
  }

  // ── Main entry point ─────────────────────────────────────────────────────

  /**
   * renderStrategyFromJSON(json, isRtl)
   * json: the parsed strategy JSON object
   * isRtl: boolean (true for Arabic)
   * returns: HTML string ready for innerHTML
   */
  function renderStrategyFromJSON(json, isRtl){
    if(!json || !json.sections) return '';
    isRtl = !!isRtl;
    var html = '';

    json.sections.forEach(function(section){
      // Section number + title → H2 banner
      var sectionTitle = section.number
        ? section.number + '. ' + (section.title||'')
        : (section.title||'');
      if(sectionTitle){
        html += '<h2>' + inlineHtml(sectionTitle) + '</h2>';
      }

      // Render each block
      (section.blocks||[]).forEach(function(block){
        html += renderBlock(block, isRtl);
      });
    });

    return html;
  }

  /**
   * renderSectionFromJSON(json, sectionKey, isRtl)
   * Renders a single named section (vision, pillars, gaps, etc.)
   * for the existing per-section showSection() architecture.
   * sectionKey maps: vision→"1", pillars→"2", environment→"3",
   *                  gaps→"4", roadmap→"5", kpis→"6", confidence→"7"
   */
  var SECTION_KEY_MAP = {
    'vision': '1', 'pillars': '2', 'environment': '3', 'business': '3',
    'gaps': '4', 'gap': '4', 'roadmap': '5', 'implementation': '5',
    'kpis': '6', 'kpi': '6', 'performance': '6',
    'confidence': '7', 'risks': '7'
  };

  function renderSectionFromJSON(json, sectionKey, isRtl){
    if(!json || !json.sections) return null;
    isRtl = !!isRtl;

    var targetNum = SECTION_KEY_MAP[sectionKey] || sectionKey;
    var section = null;

    // Match by number or by key in title
    json.sections.forEach(function(s){
      if(s.number === targetNum) section = s;
      if(!section && s.key === sectionKey) section = s;
    });

    if(!section) return null;

    var html = '';
    (section.blocks||[]).forEach(function(block){
      html += renderBlock(block, isRtl);
    });
    return html;
  }

  // Expose globally
  global.renderStrategyFromJSON    = renderStrategyFromJSON;
  global.renderSectionFromJSON     = renderSectionFromJSON;

})(typeof window !== 'undefined' ? window : this);
