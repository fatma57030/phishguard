(function () {
  "use strict";
  var CFG = window.PHISHGUARD_CONFIG;
  var page = document.body.dataset.page;

  // ---------- helpers (all text goes through textContent: the URL is user-controlled) ----------
  function el(tag, opts, kids) {
    var n = document.createElement(tag);
    opts = opts || {};
    if (opts.cls) n.className = opts.cls;
    if (opts.text != null) n.textContent = opts.text;
    if (opts.attrs) for (var k in opts.attrs) n.setAttribute(k, opts.attrs[k]);
    (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }
  function safeGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function safeSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  // ---------- language ----------
  var lang = safeGet("pg_lang") || ((navigator.language || "").indexOf("ar") === 0 ? "ar" : "en");
  function t(key) { return (window.I18N[lang] && window.I18N[lang][key]) || window.I18N.en[key] || key; }
  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach(function (n) { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll("[data-i18n-ph]").forEach(function (n) { n.placeholder = t(n.dataset.i18nPh); });
  }
  function setLang(l) { lang = l; safeSet("pg_lang", l); applyLang(); if (window.__rerender) window.__rerender(); }

  // ---------- shared sidebar ----------
  function buildChrome() {
    var shield = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>';
    var brand = el("a", { cls: "brand", attrs: { href: "index.html" } });
    brand.innerHTML = shield; // static literal, no user data
    brand.appendChild(el("span", { text: "PhishGuard" }));
    var nav = el("nav", { cls: "side-nav" }, [
      el("a", { attrs: { href: "index.html", "data-i18n": "nav_scanner" } }),
      el("a", { attrs: { href: "about.html", "data-i18n": "nav_about" } }),
      el("button", { cls: "lang-btn", attrs: { type: "button", id: "langBtn", "data-i18n": "lang_btn" } })
    ]);
    nav.children[page === "about" ? 1 : 0].setAttribute("aria-current", "page");
    var sb = document.getElementById("sidebar");
    sb.appendChild(brand); sb.appendChild(nav);
    document.getElementById("langBtn").addEventListener("click", function () { setLang(lang === "ar" ? "en" : "ar"); });
  }

  // ---------- history (per-browser, optional) ----------
  function getHistory() { try { return JSON.parse(safeGet("pg_history") || "[]"); } catch (e) { return []; } }
  function addHistory(url, score, level) {
    var h = getHistory().filter(function (x) { return x.url !== url; });
    h.unshift({ url: url, score: score, level: level });
    safeSet("pg_history", JSON.stringify(h.slice(0, 6)));
  }

  function sevOf(level) { return { Low: "none", Medium: "medium", High: "high" }[level] || "none"; }

  // ---------- API ----------
  function scan(url) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, CFG.REQUEST_TIMEOUT_MS);
    return fetch(CFG.API_BASE_URL.replace(/\/+$/, "") + "/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }), signal: ctrl.signal
    }).then(function (res) {
      return res.json().then(function (d) { return d; }, function () { return { success: false, error: { code: "internal_error", message: "" } }; });
    }).then(function (data) {
      clearTimeout(timer);
      if (!data.success) { var e = new Error((data.error && data.error.message) || ""); e.code = (data.error && data.error.code) || "internal_error"; throw e; }
      return data;
    }, function (err) {
      clearTimeout(timer);
      var e = new Error(""); e.code = err && err.name === "AbortError" ? "timeout" : "network"; throw e;
    });
  }
  function errText(e) {
    var k = "e_" + e.code;
    if (e.code === "timeout") return t("e_timeout");
    var tr = window.I18N.en[k] ? t(k) : null;
    return tr || e.message || t("e_internal_error");
  }

  // ---------- scan form (Home + Results) ----------
  function bindForm(prefill) {
    var form = document.getElementById("scanForm"), input = document.getElementById("urlInput"),
        err = document.getElementById("fieldError");
    if (prefill) input.value = prefill;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var v = input.value.trim();
      if (!v) { err.textContent = t("e_empty"); input.focus(); return; }
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) { err.textContent = t("e_missing_scheme"); input.focus(); return; }
      err.textContent = "";
      location.href = "results.html?url=" + encodeURIComponent(v);
    });
    return err;
  }

  // ---------- HOME ----------
  function initHome() {
    var input = document.getElementById("urlInput"), err = bindForm();
    document.querySelectorAll(".chip").forEach(function (c) {
      c.addEventListener("click", function () { input.value = c.dataset.url; input.focus(); });
    });
    window.__rerender = function () { if (err.textContent) err.textContent = ""; renderHistory(); };
    function renderHistory() {
      var box = document.getElementById("recentBox"), list = document.getElementById("recentList"), h = getHistory();
      list.textContent = ""; box.hidden = !h.length;
      h.forEach(function (x) {
        var a = el("a", { attrs: { href: "results.html?url=" + encodeURIComponent(x.url) } }, [
          el("span", { cls: "u", text: x.url }),
          el("span", { cls: "pill " + sevOf(x.level), text: t("level_" + x.level) + " · " + x.score })
        ]);
        list.appendChild(el("li", {}, [a]));
      });
    }
    document.getElementById("clearHistory").addEventListener("click", function () { safeSet("pg_history", "[]"); renderHistory(); });
    renderHistory();
  }

  // ---------- RESULTS ----------
  function initResults() {
    var root = document.getElementById("resultRoot");
    var url = new URLSearchParams(location.search).get("url");
    bindForm(url);
    var state = { data: null, err: null };
    var wakeTimer;

    function showLoading() {
      root.textContent = "";
      var wake = el("p", { cls: "sub" });
      root.appendChild(el("div", { cls: "state" }, [el("div", { cls: "spinner" }), el("h2", { text: t("loading") }), wake]));
      clearTimeout(wakeTimer);
      wakeTimer = setTimeout(function () { wake.textContent = t("waking"); }, 4000);
    }
    function run() {
      if (!url) { state.err = { code: "empty" }; return render(); }
      showLoading();
      scan(url).then(function (d) { state.data = d; state.err = null; addHistory(url, d.risk_score, d.risk_level); })
        .catch(function (e) { state.err = e; state.data = null; })
        .then(function () { clearTimeout(wakeTimer); render(); });
    }

    function kpi(label, valueNode, cls) {
      return el("div", { cls: "kpi" }, [el("div", { cls: "l", text: label }), el("div", { cls: "v " + (cls || "") }, valueNode)]);
    }
    function panel(title, kids) { return el("div", { cls: "panel" }, [el("h2", { text: title })].concat(kids)); }
    function bullets(arr) { return el("ul", { cls: "bullets" }, (arr || []).map(function (s) { return el("li", { text: s }); })); }

    function row(c, pts) {
      var sev = c.passed ? "none" : c.severity;
      var f = [document.createTextNode(c.message)];
      var finding = el("div", { cls: "f" });
      finding.appendChild(document.createTextNode(c.message));
      if (!c.passed && c.recommendation) finding.appendChild(el("span", { cls: "rec", text: c.recommendation }));
      if (c.limitation) finding.appendChild(el("span", { cls: "lim", text: c.limitation }));
      return el("div", { cls: "tr" }, [
        el("span", { cls: "pill " + sev, text: t("sev_" + sev) }),
        el("div", { cls: "t", text: c.title }),
        finding,
        el("div", { cls: "p", text: c.passed ? "0" : "+" + pts })
      ]);
    }

    function render() {
      root.textContent = "";
      if (state.err) {
        root.appendChild(el("div", { cls: "err-box", attrs: { role: "alert" } }, [el("h2", { text: t("err_title") }), el("p", { text: errText(state.err) }),
          el("div", { cls: "actions" }, [
            state.err.code === "network" || state.err.code === "timeout" ? el("button", { cls: "btn", text: t("retry"), attrs: { type: "button", id: "retryBtn" } }) : null,
            el("a", { cls: "btn ghost", text: t("back_home"), attrs: { href: "index.html" } })])]));
        var rb = document.getElementById("retryBtn"); if (rb) rb.addEventListener("click", run);
        return;
      }
      var d = state.data; if (!d) return;
      var lvl = d.risk_level, lc = "c-" + lvl.toLowerCase();
      var ptsByName = {}; (d.indicators || []).forEach(function (i) { ptsByName[i.name] = i.points; });
      var checks = (d.checks || []).slice().sort(function (a, b) { return (a.passed - b.passed) || ((ptsByName[b.name] || 0) - (ptsByName[a.name] || 0)); });
      var flagged = checks.filter(function (c) { return !c.passed; }).length;
      var p = d.parsed || {};

      // target + summary
      var tgt = [el("div", { cls: "target", text: d.url })];
      if (d.normalized_url && d.normalized_url !== d.url) tgt.push(el("p", { text: t("normalized") + ": " + d.normalized_url }));
      tgt.push(el("p", { text: d.summary }));
      if (lvl === "Low") tgt.push(el("p", { text: t("low_note") }));
      root.appendChild(panel(t("target"), tgt));

      // KPI tiles
      root.appendChild(el("div", { cls: "kpis" }, [
        kpi(t("kpi_score"), [document.createTextNode(String(d.risk_score)), el("small", { text: " " + t("risk_of") })], lc),
        kpi(t("kpi_level"), [document.createTextNode(t("level_" + lvl))], lc),
        kpi(t("kpi_flagged"), [document.createTextNode(String(flagged) + " "), el("small", { text: t("kpi_of") })]),
        kpi(t("kpi_port"), [document.createTextNode(p.port == null ? t("default_port") : String(p.port))], "mono")
      ]));

      // score breakdown bar
      var colors = { high: "var(--high)", medium: "#f0a93a", low: "var(--low)" };
      var bar = el("div", { cls: "bar", attrs: { role: "img", "aria-label": d.risk_score + "/100" } });
      (d.indicators || []).slice().sort(function (a, b) { return b.points - a.points; }).forEach(function (i) {
        var seg = el("i", { attrs: { title: i.title + " +" + i.points } });
        seg.style.flex = String(i.points); seg.style.background = colors[i.severity] || colors.low; bar.appendChild(seg);
      });
      var rest = el("i", { cls: "rest" }); rest.style.flex = String(Math.max(0, 100 - d.risk_score)); bar.appendChild(rest);
      root.appendChild(panel(t("breakdown"), [bar, el("p", { cls: "legend", text: t("legend") })]));

      // checks table
      var table = el("div", { cls: "table" }, [el("div", { cls: "tr th" }, [
        el("span", { text: t("col_status") }), el("span", { text: t("col_check") }), el("span", { text: t("col_finding") }), el("span", { cls: "p", text: t("col_pts") })])]);
      checks.forEach(function (c) { table.appendChild(row(c, ptsByName[c.name] || 0)); });
      root.appendChild(el("h2", { text: t("checks_title") })); root.appendChild(table);

      // recommendations + details
      var rows = [[t("k_scheme"), p.scheme], [t("k_host"), p.hostname], [t("k_ip"), p.is_ip_address ? t("yes") : t("no")],
                  [t("k_port"), p.port == null ? t("default_port") : p.port], [t("k_path"), p.path || "/"]];
      var kv = el("table", { cls: "kv" }, rows.map(function (r) { return el("tr", {}, [el("td", { text: r[0] }), el("td", { text: String(r[1]) })]); }));
      root.appendChild(el("div", { cls: "cols" }, [panel(t("recs_title"), [bullets(d.recommendations)]), panel(t("parsed_title"), [kv])]));
      root.appendChild(el("div", { cls: "notice" }, [el("h2", { text: t("lim_title") }), bullets(d.limitations)]));
      if (lang === "ar") root.appendChild(el("p", { cls: "disclaimer", text: t("backend_en") }));
      // backend text is English: let each block pick its own direction (fixes punctuation in RTL)
      root.querySelectorAll(".f, .rec, .lim, .bullets li, .panel p").forEach(function (n) { n.setAttribute("dir", "auto"); });
    }
    window.__rerender = function () { if (state.data || state.err) render(); };
    run();
  }

  buildChrome();
  applyLang();
  if (page === "home") initHome();
  if (page === "results") initResults();
})();
