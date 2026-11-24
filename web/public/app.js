/* =========================================================
   VulnScan Console — 前端交互
   注意：所有接口数据均通过 textContent 写入 DOM，避免 XSS。
   ========================================================= */

const $ = (selector, root = document) => root.querySelector(selector);

const SEVERITY = {
  critical: { label: "严重", order: 0 },
  high: { label: "高危", order: 1 },
  medium: { label: "中危", order: 2 },
  low: { label: "低危", order: 3 },
  info: { label: "提示", order: 4 },
};

const ACTIONS = {
  scan: { label: "综合扫描", title: "Web 安全扫描报告" },
  sqli: { label: "SQL 注入检测", title: "SQL 注入检测报告" },
  xss: { label: "反射型 XSS 检测", title: "反射型 XSS 检测报告" },
  probe: { label: "HTTP 基线探测", title: "HTTP 基线探测报告" },
};

const state = {
  target: "",
  action: null,
  data: null,
  findings: [],
  busy: false,
};

/* ---------- DOM 辅助 ---------- */

function h(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value; // 仅用于静态图标
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(pathMarkup) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${pathMarkup}</svg>`;
}

const CHEVRON = icon('<path d="M6 9l6 6 6-6"/>');
const DOWNLOAD = icon('<path d="M12 4v11m0 0l-4-4m4 4l4-4M5 20h14"/>');

/* ---------- 通用工具 ---------- */

function toast(message, type = "") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast ${type}`.trim();
  el.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { el.hidden = true; }, 4200);
}

function fmtBytes(size) {
  if (!Number.isFinite(size)) return "—";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(2)} MB`;
}

function fmtTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString("zh-CN", { hour12: false });
}

function hostOf(url) {
  try { return new URL(url).host; } catch { return url || "目标站点"; }
}

function sortedFindings(findings) {
  return [...findings].sort(
    (a, b) => (SEVERITY[a.severity]?.order ?? 9) - (SEVERITY[b.severity]?.order ?? 9),
  );
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`接口返回异常（HTTP ${response.status}）`);
  }
  if (!response.ok || payload.ok === false) {
    throw new Error(payload.error || `请求失败（HTTP ${response.status}）`);
  }
  return payload.ok === true ? payload.data ?? payload : payload;
}

/* ---------- 状态切换 ---------- */

function setBusy(busy) {
  state.busy = busy;
  $("#scanBtn").classList.toggle("loading", busy);
  $("#scanBtn").disabled = busy;
  document.querySelectorAll(".action").forEach((btn) => { btn.disabled = busy; });
  if (busy) {
    $("#emptyState").hidden = true;
    $("#resultView").hidden = true;
    $("#loadingState").hidden = false;
  } else {
    $("#loadingState").hidden = true;
  }
}

function validateTarget(value) {
  const text = value.trim();
  if (!text) throw new Error("请先填写目标地址");
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error("地址格式不正确，需要包含 http:// 或 https://");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("只支持 http/https 目标");
  return url.href;
}

/* ---------- 扫描 ---------- */

async function runAction(action) {
  if (state.busy) return;
  const button = document.querySelector(`.action[data-action="${action}"]`);
  let target;
  try {
    target = validateTarget($("#targetInput").value);
  } catch (error) {
    toast(error.message, "error");
    $("#targetInput").focus();
    return;
  }

  state.target = target;
  localStorage.setItem("vulnscan.target", target);
  setBusy(true);

  const endpoint = { scan: "/api/scan", sqli: "/api/sqli", xss: "/api/xss", probe: "/api/probe" }[action];
  try {
    const data = await api(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: target }),
    });
    renderResult(action, data);
    toast(`${ACTIONS[action].label}完成：${data.summary || "已返回结果"}`, "success");
  } catch (error) {
    toast(error.message, "error");
    if (state.data === null) $("#emptyState").hidden = false;
    else $("#resultView").hidden = false;
  } finally {
    setBusy(false);
    if (action === "scan") button?.blur();
  }
}

/* ---------- 渲染：统计 ---------- */

function stat(label, value, tone = "") {
  return h("div", { class: "stat" }, [
    h("span", { class: "stat-label", text: label }),
    h("span", { class: `stat-value ${tone}`.trim(), text: String(value) }),
  ]);
}

function countSeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of findings) {
    if (counts[item.severity] !== undefined) counts[item.severity] += 1;
    else counts.info += 1;
  }
  return counts;
}

function renderStats(action, data) {
  const row = $("#statsRow");
  row.replaceChildren();
  const findings = data.findings || [];
  const counts = countSeverity(findings);

  if (action === "scan") {
    row.append(
      stat("HTTP 状态", data.status ?? "—", data.status >= 400 ? "bad" : "good"),
      stat("响应长度", fmtBytes(data.length)),
      stat("缺失安全头", (data.missingSecurityHeaders || []).length, "warn"),
      stat("暴露路径", (data.exposedPaths || []).filter((item) => item.status === 200).length, "warn"),
      stat("发现问题", findings.length, findings.length ? "bad" : "good"),
    );
  } else if (action === "probe") {
    row.append(
      stat("HTTP 状态", data.status ?? "—", data.status >= 400 ? "bad" : "good"),
      stat("响应长度", fmtBytes(data.length)),
      stat("响应头数量", Object.keys(data.headers || {}).length),
      stat("页面标题", data.title || "—"),
    );
  } else if (action === "sqli") {
    row.append(
      stat("注入参数", data.param ?? "—", "accent"),
      stat("基线长度", fmtBytes(data.baselineLength)),
      stat(
        "布尔差值",
        `${data.booleanProbe?.difference ?? 0} / 阈值 ${data.booleanProbe?.threshold ?? 0}`,
        data.vulnerable ? "bad" : "",
      ),
      stat("判定", data.vulnerable ? "存在注入" : "未发现", data.vulnerable ? "bad" : "good"),
      stat("问题数", counts.critical + counts.high, "bad"),
    );
  } else if (action === "xss") {
    row.append(
      stat("注入参数", data.param ?? "—", "accent"),
      stat("HTTP 状态", data.status ?? "—"),
      stat("载荷回显", data.reflected ? "已反射" : "未反射", data.reflected ? "bad" : "good"),
      stat("判定", data.reflected ? "存在 XSS" : "未发现", data.reflected ? "bad" : "good"),
    );
  }
  row.hidden = false;
}

/* ---------- 渲染：严重性 ---------- */

function renderSeverity(findings) {
  const counts = countSeverity(findings);
  const total = findings.length;
  const bar = $("#severityBar");
  const legend = $("#severityLegend");
  bar.replaceChildren();
  legend.replaceChildren();

  const order = ["critical", "high", "medium", "low", "info"];
  for (const key of order) {
    if (!counts[key]) continue;
    bar.append(
      h("span", {
        class: key,
        style: `width:${(counts[key] / total) * 100}%`,
        title: `${SEVERITY[key].label} ${counts[key]}`,
      }),
    );
  }
  if (total === 0) bar.append(h("span", { class: "info", style: "width:100%" }));

  for (const key of order) {
    legend.append(
      h("span", { class: "sv-pill" }, [
        h("i", { class: `sev ${key}` }),
        h("span", { text: SEVERITY[key].label }),
        h("b", { text: String(counts[key]) }),
      ]),
    );
  }
  $("#severityTotal").textContent = total ? `共 ${total} 项` : "暂无问题";
}

/* ---------- 渲染：问题清单 ---------- */

function renderFindings(findings) {
  const list = $("#findingsList");
  list.replaceChildren();
  $("#findingCount").textContent = findings.length ? `${findings.length} 项` : "";

  if (findings.length === 0) {
    list.append(h("div", { class: "empty-note", text: "本次探测未发现问题，建议结合人工测试复核。" }));
    return;
  }

  sortedFindings(findings).forEach((item, index) => {
    const severity = SEVERITY[item.severity] ? item.severity : "info";
    const body = h("div", { class: "finding-body" });
    if (item.detail) {
      body.append(h("h5", { text: "详情" }), h("p", { text: item.detail }));
    }
    if (item.evidence) {
      body.append(h("h5", { text: "证据" }), h("pre", { class: "code", text: item.evidence }));
    }
    if (item.suggestion) {
      body.append(h("h5", { text: "修复建议" }), h("p", { text: item.suggestion }));
    }

    const toggle = h("button", {
      class: "finding-toggle",
      type: "button",
      "aria-expanded": index === 0 ? "true" : "false",
    }, [
      h("span", { class: `badge ${severity}`, text: SEVERITY[severity].label }),
      h("span", { class: "finding-title" }, [
        h("strong", { text: item.title }),
        h("small", { text: item.detail || "" }),
      ]),
      h("span", { class: "chevron", html: CHEVRON }),
    ]);

    const card = h("article", { class: `finding${index === 0 ? " open" : ""}`, "data-sev": severity }, [
      toggle,
      body,
    ]);
    toggle.addEventListener("click", () => {
      const open = card.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    list.append(card);
  });
}

/* ---------- 渲染：额外信息 ---------- */

function table(headers, rows) {
  const thead = h("thead", {}, h("tr", {}, headers.map((title) => h("th", { text: title }))));
  const tbody = h("tbody", {}, rows.length
    ? rows.map((cells) => h("tr", {}, cells.map((cell) => (cell instanceof Node ? h("td", {}, cell) : h("td", { text: String(cell ?? "—") })))))
    : [h("tr", {}, h("td", { colspan: String(headers.length), class: "muted", text: "无记录" }))]);
  return h("table", { class: "data-table" }, [thead, tbody]);
}

function renderExtra(action, data) {
  const panel = $("#extraPanel");
  const title = $("#extraTitle");
  const body = $("#extraBody");
  body.replaceChildren();
  let hasContent = false;

  if (action === "probe") {
    title.textContent = "响应头";
    const rows = Object.entries(data.headers || {}).map(([name, value]) => [name, value]);
    body.append(table(["名称", "值"], rows));
    hasContent = rows.length > 0;
  } else if (action === "scan") {
    title.textContent = "详细结果";
    const missing = data.missingSecurityHeaders || [];
    const paths = data.exposedPaths || [];
    const cookies = data.cookieIssues || [];

    if (missing.length) {
      hasContent = true;
      body.append(
        h("h4", { class: "section-title", text: "缺失的安全响应头" }),
        table(["响应头", "说明"], missing.map((item) => [item.header, item.detail])),
      );
    }
    if (paths.length) {
      hasContent = true;
      body.append(
        h("h4", { class: "section-title", text: "敏感路径探测" }),
        table(["路径", "状态", "结论"], paths.map((item) => [
          h("span", { class: "mono", text: item.path }),
          String(item.status),
          item.status === 403
            ? h("span", { class: "pill protected", text: "禁止访问" })
            : item.note
              ? h("span", { class: "pill neutral", text: item.note })
              : h("span", { class: "pill ok", text: "可直接访问" }),
        ])),
      );
    }
    if (cookies.length) {
      hasContent = true;
      body.append(
        h("h4", { class: "section-title", text: "Cookie 属性" }),
        table(["Cookie", "问题"], cookies.map((item) => [item.cookie, item.issues.join("、")])),
      );
    }
  } else if (action === "sqli") {
    title.textContent = "载荷测试明细";
    const rows = (data.results || []).map((item) => [
      item.payload,
      String(item.status),
      String(item.length),
      item.errorSignature || "—",
    ]);
    body.append(
      table(["载荷", "状态码", "响应长度", "报错特征"], rows),
      h("p", { class: "muted", text: `布尔探测：and 1=1 长度 ${data.booleanProbe?.trueLength ?? "—"}，and 1=2 长度 ${data.booleanProbe?.falseLength ?? "—"}，阈值 ${data.booleanProbe?.threshold ?? "—"}` }),
    );
    hasContent = rows.length > 0;
  } else if (action === "xss") {
    title.textContent = "载荷信息";
    body.append(
      table(["项目", "内容"], [
        ["载荷", data.payload],
        ["是否反射", data.reflected ? "是" : "否"],
        ["标记出现", data.markerPresent ? "是" : "否"],
      ]),
    );
    hasContent = true;
  }

  panel.hidden = !hasContent;
}

/* ---------- 渲染：结果总装 ---------- */

function renderResult(action, data) {
  state.action = action;
  state.data = data;
  state.findings = data.findings || [];

  $("#emptyState").hidden = true;
  $("#resultView").hidden = false;

  const probesOnly = action === "probe";
  $("#severityPanel").hidden = probesOnly;
  $(".findings-panel").hidden = probesOnly;

  renderStats(action, data);
  renderSeverity(state.findings);
  renderFindings(state.findings);
  renderExtra(action, data);

  $("#rawJson").textContent = JSON.stringify(data, null, 2);
  $("#rawJson").hidden = true;
  $("#rawToggle").setAttribute("aria-expanded", "false");

  fillReportForm(action, data);

  if (window.innerWidth < 1120) {
    $("#resultView").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function fillReportForm(action, data) {
  const host = hostOf(state.target || data.target || data.url);
  $("#reportTitle").value = `${host} ${ACTIONS[action].title}`;
  const findings = data.findings || [];
  const counts = countSeverity(findings);
  const parts = data.summary ? [data.summary] : [];
  if (findings.length) {
    const detail = Object.entries(counts)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => `${SEVERITY[key].label} ${value} 项`)
      .join("、");
    parts.push(`本次共发现 ${findings.length} 个问题（${detail}），建议按严重性从高到低修复。`);
  }
  $("#reportSummary").value = parts.length ? `${parts.join("。")}。` : "";
}

/* ---------- 报告 ---------- */

async function generateReport() {
  if (!state.data || !state.action) {
    toast("请先执行一次扫描，再生成报告", "error");
    return;
  }
  const title = $("#reportTitle").value.trim();
  if (!title) {
    toast("请填写报告标题", "error");
    return;
  }
  const format = $("#reportFormat").value;
  const button = $("#reportBtn");
  button.classList.add("loading");
  button.disabled = true;

  const findings = state.findings.map((item) => ({
    severity: item.severity,
    name: item.title,
    evidence: [item.detail, item.evidence].filter(Boolean).join(" — "),
    suggestion: item.suggestion,
  }));

  try {
    const result = await api("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title,
        target: state.target,
        summary: $("#reportSummary").value.trim(),
        findings,
        format,
      }),
    });
    const box = $("#reportResult");
    box.replaceChildren();
    box.hidden = false;
    box.append(
      h("div", { text: `已生成：${result.fileName}（${fmtBytes(result.size)}）` }),
      h("a", {
        href: `/api/reports/${encodeURIComponent(result.fileName)}?download=1`,
        text: "下载报告",
      }),
    );
    toast("报告已生成", "success");
    await refreshReports();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.classList.remove("loading");
    button.disabled = false;
  }
}

async function refreshReports() {
  const list = $("#reportList");
  try {
    const data = await api("/api/reports");
    list.replaceChildren();
    if (!data.files?.length) {
      list.append(h("li", { class: "report-empty", text: "暂无报告" }));
      return;
    }
    for (const file of data.files) {
      const preview = h("button", { class: "report-main", type: "button" }, [
        h("span", { class: "report-name", text: file.name }),
        h("span", { class: "report-meta", text: `${fmtBytes(file.size)} · ${fmtTime(file.modified)}` }),
      ]);
      preview.addEventListener("click", () => previewReport(file.name));
      list.append(
        h("li", { class: "report-item" }, [
          preview,
          h("a", {
            class: "dl",
            href: `/api/reports/${encodeURIComponent(file.name)}?download=1`,
            title: "下载",
            html: DOWNLOAD,
          }),
        ]),
      );
    }
  } catch (error) {
    list.replaceChildren(h("li", { class: "report-empty", text: error.message }));
  }
}

async function previewReport(name) {
  const box = $("#reportPreview");
  try {
    const data = await api(`/api/reports/${encodeURIComponent(name)}`);
    $("#previewName").textContent = data.name;
    $("#previewBody").textContent = data.content;
    box.hidden = false;
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    toast(error.message, "error");
  }
}

/* ---------- 复制摘要 ---------- */

async function copySummary() {
  if (!state.data) {
    toast("暂无可复制的扫描结果", "error");
    return;
  }
  const counts = countSeverity(state.findings);
  const lines = [
    `VulnScan 扫描摘要`,
    `目标：${state.target}`,
    `类型：${ACTIONS[state.action].label}`,
    state.data.summary ? `结论：${state.data.summary}` : "",
    `问题：${state.findings.length} 项（${Object.entries(counts).filter(([, v]) => v).map(([k, v]) => `${SEVERITY[k].label} ${v}`).join("、") || "无"}）`,
    "",
    ...sortedFindings(state.findings).map((item, i) => `${i + 1}. [${SEVERITY[item.severity]?.label || "提示"}] ${item.title}${item.detail ? ` — ${item.detail}` : ""}`),
  ].filter((line) => line !== "");

  const text = lines.join("\n");
  try {
    await navigator.clipboard.writeText(text);
    toast("摘要已复制到剪贴板", "success");
  } catch {
    const area = h("textarea", { style: "position:fixed;opacity:0" });
    area.value = text;
    document.body.append(area);
    area.select();
    try { document.execCommand("copy"); toast("摘要已复制", "success"); }
    catch { toast("复制失败，请手动选择文本", "error"); }
    area.remove();
  }
}

/* ---------- 健康检查 ---------- */

async function checkHealth() {
  const pill = $("#healthPill");
  const text = $("#healthText");
  try {
    const data = await api("/api/health");
    pill.classList.add("ok");
    pill.classList.remove("bad");
    text.textContent = "后端在线";
    const version = document.querySelector(".version");
    if (version) version.textContent = `v${data.version}`;
  } catch {
    pill.classList.add("bad");
    pill.classList.remove("ok");
    text.textContent = "后端离线";
  }
}

/* ---------- 事件绑定 ---------- */

function init() {
  const saved = localStorage.getItem("vulnscan.target");
  if (saved) $("#targetInput").value = saved;

  $("#scanForm").addEventListener("submit", (event) => {
    event.preventDefault();
    runAction("scan");
  });

  document.querySelectorAll(".action").forEach((button) => {
    button.addEventListener("click", () => runAction(button.dataset.action));
  });

  $("#reportBtn").addEventListener("click", generateReport);
  $("#refreshReports").addEventListener("click", refreshReports);
  $("#copyBtn").addEventListener("click", copySummary);
  $("#closePreview").addEventListener("click", () => { $("#reportPreview").hidden = true; });

  $("#rawToggle").addEventListener("click", () => {
    const raw = $("#rawJson");
    const open = raw.hidden;
    raw.hidden = !open;
    $("#rawToggle").setAttribute("aria-expanded", String(open));
  });

  checkHealth();
  refreshReports();
}

init();
