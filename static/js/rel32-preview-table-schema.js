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
    if (_pureSourceToken(out.frequency) && !_pureSourceToken(out.source) && _sourceLike(out.source)) {
      var s = out.source; out.source = out.frequency; out.frequency = s;
    }
    if (_pureSourceToken(out.owner) && !_pureSourceToken(out.source) && _sourceLike(out.source)) {
      var o = out.owner; out.owner = out.source; out.source = o;
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

  function headersMatchSchemaLabels(headers, schema){
    var labels = (schema.columns || []).map(function(c){ return norm(c.label_ar); });
    var hdrs = (headers || []).map(norm);
    if (hdrs.length !== labels.length) return false;
    for (var i = 0; i < labels.length; i++) {
      if (hdrs[i] !== labels[i]) return false;
    }
    return true;
  }

  function buildColumnIndexMap(schema, headers){
    var hdrs = headers || [];
    var hdrNorm = hdrs.map(norm);
    var used = {};
    var idxMap = (schema.columns || []).map(function(){ return -1; });

    (schema.columns || []).forEach(function(col, ci){
      var label = norm(col.label_ar);
      for (var i = 0; i < hdrNorm.length; i++) {
        if (used[i]) continue;
        if (hdrNorm[i] === label) { idxMap[ci] = i; used[i] = true; return; }
      }
    });

    (schema.columns || []).forEach(function(col, ci){
      if (idxMap[ci] >= 0) return;
      var keywords = col.keywords || [col.label_ar];
      for (var k = 0; k < keywords.length; k++) {
        var kw = norm(keywords[k]);
        if (!kw) continue;
        for (var i = 0; i < hdrNorm.length; i++) {
          if (used[i]) continue;
          if (kw === '#' || kw === 'م' || kw === 'no' || kw === 'no.') {
            if (hdrNorm[i] === kw || (kw === '#' && hdrNorm[i] === 'م')) {
              idxMap[ci] = i; used[i] = true; break;
            }
            continue;
          }
          if (hdrNorm[i] === kw || hdrNorm[i].indexOf(kw) !== -1) {
            idxMap[ci] = i; used[i] = true; break;
          }
        }
        if (idxMap[ci] >= 0) break;
      }
    });
    return idxMap;
  }

  function bindRowToSchema(schema, headers, row, rowIndex){
    var out = {};
    if (headersMatchSchemaLabels(headers, schema)) {
      (schema.columns || []).forEach(function(col, ci){
        var val = (row || [])[ci];
        if (col.key === 'row_num') {
          out[col.key] = isNum(val) ? String(val).trim() : String(rowIndex);
        } else if (col.key === 'step') {
          out[col.key] = String(val || '').trim() || String(rowIndex);
        } else {
          out[col.key] = String(val || '').trim() || '—';
        }
      });
      return out;
    }
    var idxMap = buildColumnIndexMap(schema, headers);
    (schema.columns || []).forEach(function(col, ci){
      var idx = idxMap[ci];
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

  function cellText(node){
    return stripTags(node ? (node.textContent || node.innerText || '') : '');
  }

  function headersLookLikeKpiMain(headers){
    var h = (headers || []).join('\u0001');
    return h.indexOf('وصف المؤشر') !== -1 || (h.indexOf('التكرار') !== -1 && h.indexOf('المالك') !== -1 && h.indexOf('النوع') !== -1);
  }

  function headersLookLikeKpiFormula(headers){
    var joined = (headers || []).join(' ');
    return joined.indexOf('صيغة الاحتساب') !== -1 &&
      (joined.indexOf('المؤشر') !== -1 || joined.indexOf('مصدر البيانات') !== -1) &&
      joined.indexOf('وصف المؤشر') === -1;
  }

  function headersLookLikeRoadmap(headers){
    var joined = (headers || []).join(' ');
    return (joined.indexOf('المرحلة') !== -1 || joined.indexOf('الفترة') !== -1) &&
      joined.indexOf('المبادرة') !== -1;
  }

  function headersLookLikeGapAction(headers){
    var joined = (headers || []).join(' ');
    return joined.indexOf('الإجراء') !== -1 && joined.indexOf('المسؤول') !== -1 &&
      (joined.indexOf('الناتج') !== -1 || joined.indexOf('الإطار الزمني') !== -1);
  }

  function inferTableSchemaId(headers, tableIdAttr){
    if (tableIdAttr && REL32_PREVIEW_TABLE_SCHEMAS[tableIdAttr]) return tableIdAttr;
    var detected = detectRel32PreviewSchema(headers);
    if (detected) return detected;
    if (headersLookLikeKpiMain(headers)) return 'kpi_main';
    if (headersLookLikeKpiFormula(headers)) return 'kpi_formula';
    if (headersLookLikeRoadmap(headers)) return 'roadmap';
    if (headersLookLikeGapAction(headers)) return 'gap_action';
    return null;
  }

  function extractDomBindingFromTable(table){
    if (!table) return null;
    var headers = Array.from(table.querySelectorAll('thead tr th')).map(cellText);
    if (!headers.length) {
      var firstRowCells = Array.from(table.querySelectorAll('tr:first-child th, tr:first-child td')).map(cellText);
      if (firstRowCells.length >= 3) headers = firstRowCells;
    }
    var firstDataRow = table.querySelector('tbody tr');
    var cells = firstDataRow
      ? Array.from(firstDataRow.querySelectorAll('td')).map(cellText)
      : [];
    var byHeader = {};
    headers.forEach(function(h, i){ byHeader[h] = cells[i] || ''; });
    var wrapper = table.closest('.table-wrapper');
    return {
      table_id: wrapper ? (wrapper.getAttribute('data-table-id') || '') : '',
      header_labels_from_dom: headers,
      first_row_cells: cells,
      first_row_cells_by_header: byHeader,
      schema_binder_applied: !!(wrapper && wrapper.getAttribute('data-table-id'))
    };
  }

  function extractDomBindingsFromRoot(root){
    var rootEl = null;
    if (root && root.querySelectorAll) rootEl = root;
    else if (typeof root === 'string') {
      var tmp = document.createElement('div');
      tmp.innerHTML = root;
      rootEl = tmp;
    }
    if (!rootEl) return [];
    var tables = Array.from(rootEl.querySelectorAll('table'));
    return tables.map(extractDomBindingFromTable).filter(Boolean);
  }

  function _targetLike(v){
    return /^<\s*\d|[\d.]+\s*%|[\d.]+\s*ساع|[\d.]+\s*دقي/i.test(String(v || '').trim());
  }

  function _formulaLike(v){
    return /مجموع|عدد\s*الحوادث|عدد\s*الحوادث|احتساب/i.test(String(v || ''));
  }

  function _sourceLike(v){
    return /siem|soc|log|ticket|survey|report/i.test(String(v || ''));
  }

  function _pureSourceToken(v){
    var s = String(v || '').trim();
    return /^siem\s*\/\s*soc$/i.test(s) || (/^siem/i.test(s) && /soc/i.test(s) && s.length < 40);
  }

  function validateKpiCellForKey(key, cell){
    var errors = [];
    var v = String(cell || '').trim();
    if (!v || v === '—') return errors;
    if (key === 'frequency') {
      if (!isFreqToken(v)) errors.push('التكرار');
      if (_pureSourceToken(v)) errors.push('التكرار');
    }
    if (key === 'source') {
      if (!_sourceLike(v)) errors.push('مصدر');
      if (isFreqToken(v)) errors.push('مصدر');
    }
    if (key === 'owner') {
      if (isFreqToken(v)) errors.push('المالك');
      if (_pureSourceToken(v)) errors.push('المالك');
      if (isTypeToken(v)) errors.push('المالك');
    }
    if (key === 'type') {
      if (!isTypeToken(v) && !/kri/i.test(v)) errors.push('النوع');
    }
    if (key === 'target') {
      if (isTypeToken(v)) errors.push('القيمة المستهدفة');
    }
    if (key === 'formula') {
      if (_targetLike(v) && !_formulaLike(v)) errors.push('صيغة الاحتساب');
    }
    return errors;
  }

  function validateKpiMainByDomIndex(headers, cells){
    var schema = REL32_PREVIEW_TABLE_SCHEMAS.kpi_main;
    var errors = [];
    (schema.columns || []).forEach(function(col, i){
      if ((headers[i] || '') !== col.label_ar) {
        errors.push('rel32_preview_table_header_value_mismatch:kpi_main:' + col.label_ar);
      }
      validateKpiCellForKey(col.key, cells[i] || '').forEach(function(hdr){
        errors.push('rel32_preview_table_header_value_mismatch:kpi_main:' + hdr);
      });
    });
    return errors;
  }

  function validateKpiFormulaByDomIndex(headers, cells){
    var schema = REL32_PREVIEW_TABLE_SCHEMAS.kpi_formula;
    var errors = [];
    (schema.columns || []).forEach(function(col, i){
      if ((headers[i] || '') !== col.label_ar) {
        errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:' + col.label_ar);
      }
      var v = String(cells[i] || '').trim();
      if (col.key === 'indicator' && !v) {
        errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:المؤشر');
      }
      if (col.key === 'indicator' && _targetLike(v)) {
        errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:المؤشر');
      }
      if (col.key === 'formula' && _targetLike(v) && !_formulaLike(v)) {
        errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:صيغة الاحتساب');
      }
      if (col.key === 'source') {
        if (_formulaLike(v) && !_sourceLike(v)) {
          errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:مصدر البيانات');
        }
        if (isFreqToken(v)) {
          errors.push('rel32_preview_table_header_value_mismatch:kpi_formula:مصدر البيانات');
        }
      }
    });
    return errors;
  }

  function validateKpiMainSemantics(byHeader, headers, cells){
    if ((headers || []).length && (cells || []).length) {
      return validateKpiMainByDomIndex(headers, cells);
    }
    return validateKpiMainByDomIndex(
      REL32_PREVIEW_TABLE_SCHEMAS.kpi_main.columns.map(function(c){ return c.label_ar; }),
      REL32_PREVIEW_TABLE_SCHEMAS.kpi_main.columns.map(function(c){ return byHeader[c.label_ar] || ''; })
    );
  }

  function validateKpiFormulaSemantics(byHeader, headers, cells){
    if ((headers || []).length && (cells || []).length) {
      return validateKpiFormulaByDomIndex(headers, cells);
    }
    return validateKpiFormulaByDomIndex(
      headers || [],
      (headers || []).map(function(h){ return byHeader[h] || ''; })
    );
  }

  function evaluatePreviewDomBindingLive(domInfo, schemaId){
    var schema = REL32_PREVIEW_TABLE_SCHEMAS[schemaId || ''];
    var schemaLabels = schema ? schema.columns.map(function(c){ return c.label_ar; }) : [];
    var mismatched = [];
    var blocking = [];
    var headers = domInfo.header_labels_from_dom || [];
    var cells = domInfo.first_row_cells || [];
    var byHeader = domInfo.first_row_cells_by_header || {};

    if (!schema) {
      blocking.push('unknown_schema:' + String(schemaId || domInfo.table_id || 'generic'));
    } else {
      if (headers.join('\u0001') !== schemaLabels.join('\u0001')) {
        mismatched.push('header_order');
        schemaLabels.forEach(function(lbl, i){
          if ((headers[i] || '') !== lbl) {
            mismatched.push('header:' + lbl + ':expected_index_' + i);
          }
        });
      }
      if (!domInfo.schema_binder_applied) {
        blocking.push('rel32_preview_table_schema_binder_not_applied:' + schemaId);
      }
      if (schemaId === 'kpi_main') {
        blocking = blocking.concat(validateKpiMainSemantics(byHeader, headers, cells));
      }
      if (schemaId === 'kpi_formula') {
        blocking = blocking.concat(validateKpiFormulaSemantics(byHeader, headers, cells));
      }
    }

    return {
      table_id: schemaId || domInfo.table_id || 'unknown',
      schema_labels: schemaLabels,
      header_labels_from_dom: headers,
      first_row_cells: cells,
      first_row_cells_by_header: byHeader,
      mismatched_headers: mismatched,
      schema_binder_applied: !!domInfo.schema_binder_applied,
      preview_dom_binding_passed: mismatched.length === 0 && blocking.length === 0,
      blocking_errors: blocking
    };
  }

  function extractTableDomBinding(html, tableId){
    var tmp = document.createElement('div');
    tmp.innerHTML = html || '';
    var selector = tableId
      ? '.table-wrapper[data-table-id="' + tableId + '"] table'
      : 'table';
    var table = tmp.querySelector(selector) || tmp.querySelector('table');
    return extractDomBindingFromTable(table) || {
      header_labels_from_dom: [],
      first_row_cells_by_header: {},
      first_row_cells: []
    };
  }

  function evaluatePreviewDomBinding(html, tableId, schemaId){
    var dom = extractTableDomBinding(html, tableId);
    return evaluatePreviewDomBindingLive(dom, schemaId || tableId);
  }

  function renderPreviewBindingGateBanner(root, payload, isRtl){
    if (!root || !root.querySelector) return;
    var existing = root.querySelector('#rel32-preview-binding-gate');
    if (existing) existing.remove();
    if (payload.preview_dom_binding_passed) return;
    var banner = document.createElement('div');
    banner.id = 'rel32-preview-binding-gate';
    banner.setAttribute('dir', isRtl ? 'rtl' : 'ltr');
    banner.style.cssText = 'background:#fef2f2;border:1px solid #f87171;border-radius:8px;padding:12px 16px;margin:12px 0;color:#991b1b;font-size:.9rem;';
    var title = isRtl ? 'تحذير: عدم تطابق جدول المعاينة مع المخطط' : 'Preview table schema binding failed';
    var detail = (payload.blocking_errors || []).slice(0, 4).join('; ');
    banner.innerHTML = '<strong>' + esc(title) + '</strong><div style="margin-top:.35rem;">' + esc(detail) + '</div>';
    var page = root.querySelector('.document-page') || root;
    page.insertBefore(banner, page.firstChild);
  }

  function emitRel32PreviewTableDomBindingCheck(rootOrHtml, options){
    options = options || {};
    var checks = [];
    var blocking = [];
    var isRtl = !!options.isRtl;

    if (typeof global.Rel32PreviewTableSchema === 'undefined') {
      blocking.push('rel32_preview_schema_binder_not_loaded');
    }

    var domInfos = extractDomBindingsFromRoot(rootOrHtml);
    var seen = {};
    domInfos.forEach(function(domInfo){
      var schemaId = inferTableSchemaId(domInfo.header_labels_from_dom, domInfo.table_id);
      if (!schemaId || seen[schemaId]) return;
      seen[schemaId] = true;
      checks.push(evaluatePreviewDomBindingLive(domInfo, schemaId));
    });

    checks.forEach(function(c){
      blocking = blocking.concat(c.blocking_errors || []);
      if ((c.mismatched_headers || []).length) {
        blocking = blocking.concat(c.mismatched_headers);
      }
    });

    var payload = {
      tag: 'REL32-PREVIEW-TABLE-DOM-BINDING-CHECK',
      rel32_preview_schema_loaded: typeof global.Rel32PreviewTableSchema !== 'undefined',
      static_version: (typeof global._rel32StaticVersion !== 'undefined') ? global._rel32StaticVersion : '',
      checks: checks,
      preview_dom_binding_passed: blocking.length === 0 && checks.length > 0
        ? checks.every(function(c){ return c.preview_dom_binding_passed; })
        : blocking.length === 0,
      mismatched_headers: checks.reduce(function(a,c){ return a.concat(c.mismatched_headers || []); }, []),
      blocking_errors: blocking
    };

    if (!checks.length && domInfos.length && blocking.indexOf('rel32_preview_schema_binder_not_loaded') === -1) {
      var needsSchema = domInfos.some(function(d){
        return !!inferTableSchemaId(d.header_labels_from_dom, d.table_id);
      });
      if (needsSchema) {
        payload.preview_dom_binding_passed = false;
        payload.blocking_errors = payload.blocking_errors.concat(
          ['rel32_preview_schema_tables_present_but_unvalidated']);
      }
    }

    global._rel32PreviewDomBindingPassed = payload.preview_dom_binding_passed;
    global._rel32PreviewDomBindingCheck = payload;

    if (options.block !== false && rootOrHtml && rootOrHtml.querySelector) {
      renderPreviewBindingGateBanner(rootOrHtml, payload, isRtl);
    }

    if (options.log !== false && typeof console !== 'undefined') {
      if (payload.preview_dom_binding_passed) {
        if (console.debug) console.debug('[REL32-PREVIEW-TABLE-DOM-BINDING-CHECK]', payload);
      } else if (console.warn) {
        console.warn('[REL32-PREVIEW-TABLE-DOM-BINDING-CHECK]', payload);
      }
    }
    return payload;
  }

  var api = {
    REL32_PREVIEW_TABLE_SCHEMAS: REL32_PREVIEW_TABLE_SCHEMAS,
    detectRel32PreviewSchema: detectRel32PreviewSchema,
    bindRel32PreviewTable: bindRel32PreviewTable,
    renderRel32PreviewTableHtml: renderRel32PreviewTableHtml,
    extractTableDomBinding: extractTableDomBinding,
    extractDomBindingsFromRoot: extractDomBindingsFromRoot,
    evaluatePreviewDomBinding: evaluatePreviewDomBinding,
    evaluatePreviewDomBindingLive: evaluatePreviewDomBindingLive,
    validateKpiMainSemantics: validateKpiMainSemantics,
    validateKpiFormulaSemantics: validateKpiFormulaSemantics,
    validateKpiMainByDomIndex: validateKpiMainByDomIndex,
    validateKpiFormulaByDomIndex: validateKpiFormulaByDomIndex,
    headersMatchSchemaLabels: headersMatchSchemaLabels,
    emitRel32PreviewTableDomBindingCheck: emitRel32PreviewTableDomBindingCheck,
    repairKpiRowDict: repairKpiRowDict
  };

  global.Rel32PreviewTableSchema = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
