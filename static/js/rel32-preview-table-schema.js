/* rel32-preview-table-schema.js — REL32 preview table schema-key binding (RTL-safe). */
(function(global){
  'use strict';

  function esc(s){
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function norm(s){
    return String(s || '').trim().toLowerCase().replace(/\s+/g,' ');
  }

  function isNum(v){ return /^\d+(\.\d+)?$/.test(String(v || '').trim()); }

  function colIndexByKeywords(headers, keywords){
    for (var i = 0; i < (headers || []).length; i++) {
      var blob = norm(headers[i]);
      for (var k = 0; k < (keywords || []).length; k++) {
        var kw = norm(keywords[k]);
        if (!kw) continue;
        if (kw === '#' || kw === 'م' || kw === 'no' || kw === 'no.') {
          if (blob === '#' || blob === 'م' || blob === 'no' || blob === 'no.') return i;
          continue;
        }
        if (blob.indexOf(kw) !== -1) return i;
      }
    }
    return -1;
  }

  var REL32_PREVIEW_TABLE_SCHEMAS = {
    kpi_main: {
      table_id: 'kpi_main',
      css_schema: 'kpi-summary',
      columns: [
        { key: 'row_num', label_ar: '#', keywords: ['#', 'م', 'no'] },
        { key: 'indicator', label_ar: 'وصف المؤشر', keywords: ['وصف المؤشر', 'المؤشر', 'indicator', 'kpi', 'metric'] },
        { key: 'type', label_ar: 'النوع', keywords: ['النوع', 'type', 'kpi/kri'] },
        { key: 'target', label_ar: 'القيمة المستهدفة', keywords: ['القيمة المستهدفة', 'مستهدف', 'target', 'القيمة'] },
        { key: 'formula', label_ar: 'صيغة الاحتساب', keywords: ['صيغة الاحتساب', 'صيغة', 'formula', 'احتساب'] },
        { key: 'source', label_ar: 'مصدر', keywords: ['مصدر', 'source', 'البيانات'] },
        { key: 'frequency', label_ar: 'التكرار', keywords: ['التكرار', 'تكرار', 'frequency', 'تواتر', 'دورية'] },
        { key: 'owner', label_ar: 'المالك', keywords: ['المالك', 'owner', 'مسؤول'] }
      ]
    },
    kpi_formula: {
      table_id: 'kpi_formula',
      css_schema: 'kpi-formula',
      columns: [
        { key: 'row_num', label_ar: '#', keywords: ['#', 'م', 'no'] },
        { key: 'indicator', label_ar: 'المؤشر', keywords: ['المؤشر', 'indicator', 'kpi', 'metric'] },
        { key: 'formula', label_ar: 'صيغة الاحتساب', keywords: ['صيغة الاحتساب', 'صيغة', 'formula', 'احتساب'] },
        { key: 'source', label_ar: 'مصدر البيانات', keywords: ['مصدر البيانات', 'مصدر', 'source'] }
      ]
    },
    roadmap: {
      table_id: 'roadmap',
      css_schema: 'roadmap',
      columns: [
        { key: 'phase', label_ar: 'المرحلة', keywords: ['المرحلة', 'مرحلة', 'phase'] },
        { key: 'period', label_ar: 'الفترة', keywords: ['الفترة', 'فترة', 'الإطار الزمني', 'زمن', 'period', 'timeframe'] },
        { key: 'initiative', label_ar: 'المبادرة', keywords: ['المبادرة', 'مبادرة', 'initiative', 'نشاط'] },
        { key: 'owner', label_ar: 'المسؤول', keywords: ['المسؤول', 'مسؤول', 'المالك', 'owner', 'مالك'] },
        { key: 'deliverable', label_ar: 'المخرج المتوقع', keywords: ['المخرج المتوقع', 'المخرج', 'مخرج', 'deliverable', 'output'] },
        { key: 'framework', label_ar: 'الإطار المرتبط', keywords: ['الإطار المرتبط', 'الإطار', 'إطار', 'framework', 'مرتبط'] }
      ]
    },
    gap_action: {
      table_id: 'gap_action',
      css_schema: 'gap-action',
      columns: [
        { key: 'step', label_ar: 'الخطوة', keywords: ['الخطوة', 'خطوة', 'step'] },
        { key: 'action', label_ar: 'الإجراء', keywords: ['الإجراء', 'إجراء', 'action'] },
        { key: 'owner', label_ar: 'المسؤول', keywords: ['المسؤول', 'مسؤول', 'owner', 'مالك'] },
        { key: 'timeframe', label_ar: 'الإطار الزمني', keywords: ['الإطار الزمني', 'زمن', 'timeframe', 'period', 'الإطار'] },
        { key: 'output', label_ar: 'الناتج', keywords: ['الناتج', 'ناتج', 'output', 'مخرج'] }
      ]
    }
  };

  var _FREQ_RE = /^(شهري|ربع|سنو|يوم|أسبو|daily|weekly|monthly|quarter|annual|تواتر|تكرار)/i;
  var _TYPE_RE = /^(kpi|kri|مؤشر|kpi\/kri)$/i;

  function isFreqToken(v){ return _FREQ_RE.test(String(v || '').trim()); }
  function isTypeToken(v){ return _TYPE_RE.test(String(v || '').trim()); }

  function repairKpiRowDict(row){
    var out = Object.assign({}, row);
    if (isTypeToken(out.target) && !isTypeToken(out.type)) {
      var t = out.type; out.type = out.target; out.target = t;
    }
    if (isFreqToken(out.owner) && !isFreqToken(out.frequency)) {
      var f = out.frequency; out.frequency = out.owner; out.owner = f;
    }
    return out;
  }

  function schemaMatchScore(headers, schema){
    var hits = 0;
    (schema.columns || []).forEach(function(col){
      if (colIndexByKeywords(headers, col.keywords || [col.label_ar]) >= 0) hits++;
    });
    return hits;
  }

  function detectRel32PreviewSchema(headers){
    var hdr = headers || [];
    if (!hdr.length) return null;
    var best = null;
    var bestScore = 0;
    Object.keys(REL32_PREVIEW_TABLE_SCHEMAS).forEach(function(id){
      var schema = REL32_PREVIEW_TABLE_SCHEMAS[id];
      var need = Math.max(3, Math.ceil(schema.columns.length * 0.55));
      var score = schemaMatchScore(hdr, schema);
      if (score >= need && score > bestScore) {
        best = id;
        bestScore = score;
      }
    });
    if (best === 'kpi_main' && hdr.length === 4 &&
        schemaMatchScore(hdr, REL32_PREVIEW_TABLE_SCHEMAS.kpi_formula) >= 3) {
      return 'kpi_formula';
    }
    if (best === 'kpi_formula' && hdr.length >= 7 &&
        schemaMatchScore(hdr, REL32_PREVIEW_TABLE_SCHEMAS.kpi_main) >= 6) {
      return 'kpi_main';
    }
    return best;
  }

  function bindRowToSchema(schema, headers, row, rowIndex){
    var out = {};
    (schema.columns || []).forEach(function(col){
      var idx = colIndexByKeywords(headers, col.keywords || [col.label_ar]);
      if (col.key === 'row_num') {
        out[col.key] = (idx >= 0 && isNum(row[idx])) ? String(row[idx]).trim() : String(rowIndex);
        return;
      }
      if (col.key === 'step') {
        out[col.key] = (idx >= 0 && String(row[idx] || '').trim()) ? String(row[idx]).trim() : String(rowIndex);
        return;
      }
      out[col.key] = idx >= 0 ? (String(row[idx] || '').trim() || '—') : '—';
    });
    return out;
  }

  function bindRel32PreviewTable(headers, rows, schemaId){
    var schema = REL32_PREVIEW_TABLE_SCHEMAS[schemaId];
    if (!schema) return null;
    var bound = (rows || []).map(function(r, ri){
      var row = bindRowToSchema(schema, headers, r || [], ri + 1);
      if (schemaId === 'kpi_main') row = repairKpiRowDict(row);
      return row;
    });
    return {
      table_id: schemaId,
      schema: schema,
      schema_labels: schema.columns.map(function(c){ return c.label_ar; }),
      bound_rows: bound
    };
  }

  function renderRel32PreviewTableHtml(headers, rows, options){
    options = options || {};
    var schemaId = options.schemaId || detectRel32PreviewSchema(headers);
    if (!schemaId) return null;
    var bound = bindRel32PreviewTable(headers, rows, schemaId);
    if (!bound) return null;
    var schema = bound.schema;
    var isRtl = !!options.isRtl;
    var dir = isRtl ? ' dir="rtl"' : '';
    var align = isRtl ? 'right' : 'left';
    var html = '<div class="table-wrapper" data-schema="'+schema.css_schema+'" data-table-id="'+schemaId+'"'+dir+'>'
      + '<table class="schema-'+schema.css_schema+'"><thead><tr>';
    schema.columns.forEach(function(col){
      html += '<th style="text-align:'+align+'">'+esc(col.label_ar)+'</th>';
    });
    html += '</tr></thead><tbody>';
    bound.bound_rows.forEach(function(row){
      html += '<tr>';
      schema.columns.forEach(function(col){
        var val = row[col.key];
        if (!val || val === '—') {
          html += '<td class="cell-missing">—</td>';
        } else {
          html += '<td>'+esc(val)+'</td>';
        }
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    return { html: html, bound: bound, schema_id: schemaId };
  }

  function stripTags(s){
    return String(s || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  }

  function extractTableDomBinding(html, tableId){
    var reTable = new RegExp(
      '<div class="table-wrapper"[^>]*data-table-id="'+(tableId || '[^"]+')+'"[^>]*>[\\s\\S]*?</div>\\s*</table>\\s*</div>',
      'i'
    );
    var chunk = html;
    if (tableId) {
      var m = html.match(reTable);
      chunk = m ? m[0] : html;
    }
    var headers = [];
    var headerRe = /<thead>\s*<tr>([\s\S]*?)<\/tr>/i;
    var hm = chunk.match(headerRe);
    if (hm) {
      var thRe = /<th[^>]*>([\s\S]*?)<\/th>/gi;
      var thm;
      while ((thm = thRe.exec(hm[1])) !== null) headers.push(stripTags(thm[1]));
    }
    var firstRow = [];
    var rowRe = /<tbody>\s*<tr>([\s\S]*?)<\/tr>/i;
    var rm = chunk.match(rowRe);
    if (rm) {
      var tdRe = /<td[^>]*>([\s\S]*?)<\/td>/gi;
      var tdm;
      while ((tdm = tdRe.exec(rm[1])) !== null) firstRow.push(stripTags(tdm[1]));
    }
    var byHeader = {};
    headers.forEach(function(h, i){ byHeader[h] = firstRow[i] || ''; });
    return { header_labels_from_dom: headers, first_row_cells_by_header: byHeader, first_row_cells: firstRow };
  }

  function evaluatePreviewDomBinding(html, tableId, schemaId){
    var schema = REL32_PREVIEW_TABLE_SCHEMAS[schemaId || ''];
    var dom = extractTableDomBinding(html, tableId);
    var schemaLabels = schema ? schema.columns.map(function(c){ return c.label_ar; }) : [];
    var mismatched = [];
    var blocking = [];
    if (!schema) {
      blocking.push('unknown_schema:'+String(tableId || schemaId));
    } else if (dom.header_labels_from_dom.join('\u0001') !== schemaLabels.join('\u0001')) {
      mismatched.push('header_order');
      schemaLabels.forEach(function(lbl, i){
        if ((dom.header_labels_from_dom[i] || '') !== lbl) {
          mismatched.push('header:'+lbl+':expected_index_'+i);
        }
      });
    }
    var diag = {
      table_id: tableId || schemaId,
      schema_labels: schemaLabels,
      header_labels_from_dom: dom.header_labels_from_dom,
      first_row_cells_by_header: dom.first_row_cells_by_header,
      mismatched_headers: mismatched,
      preview_dom_binding_passed: mismatched.length === 0 && blocking.length === 0,
      blocking_errors: blocking
    };
    return diag;
  }

  function emitRel32PreviewTableDomBindingCheck(rootOrHtml, options){
    options = options || {};
    var checks = [];
    var html = typeof rootOrHtml === 'string'
      ? rootOrHtml
      : (rootOrHtml && rootOrHtml.innerHTML) ? rootOrHtml.innerHTML : '';
    Object.keys(REL32_PREVIEW_TABLE_SCHEMAS).forEach(function(schemaId){
      if (html.indexOf('data-table-id="'+schemaId+'"') === -1) return;
      checks.push(evaluatePreviewDomBinding(html, schemaId, schemaId));
    });
    var payload = {
      tag: 'REL32-PREVIEW-TABLE-DOM-BINDING-CHECK',
      checks: checks,
      preview_dom_binding_passed: checks.every(function(c){ return c.preview_dom_binding_passed; }),
      mismatched_headers: checks.reduce(function(a,c){ return a.concat(c.mismatched_headers || []); }, []),
      blocking_errors: checks.reduce(function(a,c){ return a.concat(c.blocking_errors || []); }, [])
    };
    if (options.log !== false && typeof console !== 'undefined' && console.debug) {
      console.debug('[REL32-PREVIEW-TABLE-DOM-BINDING-CHECK]', payload);
    }
    return payload;
  }

  var api = {
    REL32_PREVIEW_TABLE_SCHEMAS: REL32_PREVIEW_TABLE_SCHEMAS,
    detectRel32PreviewSchema: detectRel32PreviewSchema,
    bindRel32PreviewTable: bindRel32PreviewTable,
    renderRel32PreviewTableHtml: renderRel32PreviewTableHtml,
    extractTableDomBinding: extractTableDomBinding,
    evaluatePreviewDomBinding: evaluatePreviewDomBinding,
    emitRel32PreviewTableDomBindingCheck: emitRel32PreviewTableDomBindingCheck,
    repairKpiRowDict: repairKpiRowDict
  };

  global.Rel32PreviewTableSchema = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
