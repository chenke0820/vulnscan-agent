#!/usr/bin/env node
/**
 * 扫描核心：只做只读的主动探测。
 *   - 安全响应头 / 服务指纹 / 敏感路径
 *   - SQL 注入（报错特征 + 布尔差异）
 *   - 反射型 XSS
 *
 * 该模块被 MCP 服务与 Web 后端共用，保证两个入口行为一致。
 */

const USER_AGENT = "vulnscan-agent/1.0";
const DEFAULT_TIMEOUT_MS = 10000;

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

/** 为常见问题补充修复建议，报告与前端都会用到。 */
const SUGGESTIONS = {
  服务指纹暴露: "在反向代理或应用配置中移除或改写 Server 响应头，避免暴露中间件与版本号。",
  框架指纹暴露: "关闭 X-Powered-By（如 PHP 的 expose_php=Off），减少攻击面信息。",
  缺少安全响应头: "在网关或应用入口统一补充 HSTS、CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy。",
  "Cookie 安全属性不完整": "为 Cookie 增加 HttpOnly、Secure、SameSite 属性，降低脚本窃取与跨站携带风险。",
  敏感路径可直接访问: "将备份、配置、调试文件移出 Web 根目录，或在服务器层直接返回 403/404。",
  "SQL 注入（报错型）": "使用参数化查询/预编译语句，关闭数据库错误回显，并为数据库账号降权。",
  "SQL 注入（布尔型）": "使用参数化查询/预编译语句，对输入做类型校验，统一错误页面避免布尔差异。",
  "反射型 XSS": "对输出做上下文相关的编码，开启 CSP，优先使用模板引擎的自动转义。",
};

/** 根据标题匹配修复建议。 */
function suggestionFor(title) {
  if (SUGGESTIONS[title]) return SUGGESTIONS[title];
  if (title.includes("安全响应头")) return SUGGESTIONS["缺少安全响应头"];
  for (const [key, value] of Object.entries(SUGGESTIONS)) {
    if (title.includes(key) || key.includes(title)) return value;
  }
  return "结合业务场景修复，并在修复后重新扫描验证。";
}

export function enrichFindings(findings = []) {
  return findings.map((item, index) => ({
    index: index + 1,
    severity: SEVERITY_ORDER.includes(item.severity) ? item.severity : "info",
    title: String(item.title ?? item.name ?? "未命名问题"),
    detail: String(item.detail ?? ""),
    evidence: String(item.evidence ?? ""),
    suggestion: String(item.suggestion ?? suggestionFor(String(item.title ?? item.name ?? ""))),
  }));
}

/** 校验并规范化目标地址，只允许 http/https。 */
export function targetUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`无法解析目标地址: ${input}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`只支持 http/https，收到 ${url.protocol}`);
  }
  return url;
}

/** 发起一次请求，返回状态、头、正文，异常统一转成结构化结果。 */
async function request(url, init = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  try {
    const response = await fetch(url, {
      ...init,
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "User-Agent": USER_AGENT, ...(init.headers ?? {}) },
    });
    const body = await response.text().catch(() => "");
    return {
      ok: true,
      status: response.status,
      headers: response.headers,
      body,
      finalUrl: response.url,
      length: body.length,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      headers: new Headers(),
      body: "",
      finalUrl: url,
      length: 0,
      error: String(error),
    };
  }
}

function titleOf(body) {
  const match = /<title[^>]*>([^<]*)<\/title>/i.exec(body);
  return match ? match[1].trim().slice(0, 120) : null;
}

/** 安全响应头与 Cookie 属性检查。 */
function inspectHeaders(headers, findings) {
  const missing = [];
  const required = [
    ["strict-transport-security", "缺少 HSTS，HTTP 明文可被降级"],
    ["content-security-policy", "缺少 CSP，XSS 缺少第二道防线"],
    ["x-frame-options", "缺少 X-Frame-Options，存在点击劫持风险"],
    ["x-content-type-options", "缺少 X-Content-Type-Options，存在 MIME 嗅探风险"],
    ["referrer-policy", "缺少 Referrer-Policy，可能泄露来源地址"],
  ];
  for (const [name, detail] of required) {
    if (!headers.get(name)) missing.push({ header: name, detail });
  }

  const cookieIssues = [];
  const cookies = headers.getSetCookie?.() ?? [];
  for (const cookie of cookies) {
    const name = cookie.split("=")[0].trim();
    const issues = [];
    if (!/;\s*HttpOnly/i.test(cookie)) issues.push("缺少 HttpOnly");
    if (!/;\s*Secure/i.test(cookie)) issues.push("缺少 Secure");
    if (!/;\s*SameSite/i.test(cookie)) issues.push("缺少 SameSite");
    if (issues.length > 0) cookieIssues.push({ cookie: name, issues });
  }

  const banner = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  if (banner) findings.push({ severity: "low", title: "服务指纹暴露", detail: `Server: ${banner}` });
  if (poweredBy) findings.push({ severity: "low", title: "框架指纹暴露", detail: `X-Powered-By: ${poweredBy}` });
  if (missing.length > 0) {
    findings.push({
      severity: "medium",
      title: `缺少 ${missing.length} 个安全响应头`,
      detail: missing.map((item) => item.header).join(", "),
    });
  }
  for (const item of cookieIssues) {
    findings.push({
      severity: "medium",
      title: "Cookie 安全属性不完整",
      detail: `${item.cookie}: ${item.issues.join("、")}`,
    });
  }
  return { missing, cookieIssues, banner, poweredBy };
}

/**
 * 软 404 判定：有些服务器（含 PHP 内置服务器、phpStudy 默认站点）对任意路径都返回 200，
 * 正文与首页相同或是占位页。这类响应不能算"敏感路径可访问"。
 */
function isSoftNotFound(body, baselineBody) {
  const normalize = (text) => text.replace(/\s+/g, " ").trim();
  if (body.trim() === "") return true;
  if (normalize(body) === normalize(baselineBody)) return true;
  const head = body.slice(0, 3000);
  return /站点创建成功|404 Not Found|Not Found|页面不存在|页面未找到/.test(head) && body.length < 5000;
}

/** 敏感路径的默认风险等级：robots.txt 通常是公开的，只作为信息提示。 */
const PATH_SEVERITY = {
  "/robots.txt": "info",
  "/.git/HEAD": "high",
  "/.env": "high",
  "/phpinfo.php": "high",
  "/admin/": "high",
  "/server-status": "high",
};

/** 敏感路径探测：200 且非软 404 才算暴露，403 记录为存在但受保护。 */
async function probePaths(base, pathList, baselineBody) {
  const results = [];
  for (const path of pathList) {
    const url = new URL(path, base).href;
    const result = await request(url);
    if (result.status === 200 && !isSoftNotFound(result.body, baselineBody)) {
      results.push({ path, status: 200, severity: PATH_SEVERITY[path] ?? "high" });
    } else if (result.status === 403) {
      results.push({ path, status: 403 });
    } else if (result.status === 200) {
      results.push({ path, status: 200, note: "软 404，不计入风险" });
    }
  }
  return results;
}

export const DEFAULT_PATHS = [
  "/robots.txt",
  "/.git/HEAD",
  "/.env",
  "/phpinfo.php",
  "/admin/",
  "/server-status",
];

export async function scanWeb(args = {}) {
  if (!args.url) throw new Error("缺少参数 url");
  const base = targetUrl(args.url).href;
  const findings = [];
  const main = await request(base);
  if (!main.ok) throw new Error(`目标不可达: ${main.error}`);

  const headerInfo = inspectHeaders(main.headers, findings);
  const paths = (Array.isArray(args.paths) && args.paths.length > 0 ? args.paths : DEFAULT_PATHS).slice(0, 12);
  const exposed = await probePaths(base, paths, main.body);

  const highPaths = exposed.filter((item) => item.status === 200 && item.severity === "high").map((item) => item.path);
  if (highPaths.length > 0) {
    findings.push({
      severity: "high",
      title: "敏感路径可直接访问",
      detail: highPaths.join("、"),
    });
  }
  const infoPaths = exposed.filter((item) => item.status === 200 && item.severity === "info").map((item) => item.path);
  if (infoPaths.length > 0) {
    findings.push({
      severity: "info",
      title: "公开信息文件",
      detail: infoPaths.join("、"),
      suggestion: "确认 robots.txt 等公开文件未泄露后台或备份目录；隐藏敏感路径不应只依赖 robots.txt。",
    });
  }

  const title = titleOf(main.body);

  return {
    target: base,
    finalUrl: main.finalUrl,
    status: main.status,
    title,
    server: headerInfo.banner,
    poweredBy: headerInfo.poweredBy,
    length: main.length,
    missingSecurityHeaders: headerInfo.missing,
    cookieIssues: headerInfo.cookieIssues,
    exposedPaths: exposed,
    findings: enrichFindings(findings),
    summary: `HTTP ${main.status}，缺失 ${headerInfo.missing.length} 个安全头，命中 ${
      exposed.filter((p) => p.status === 200).length
    } 个敏感路径`,
  };
}

const SQL_ERROR_SIGNATURES = [
  { pattern: /You have an error in your SQL syntax/i, db: "MySQL" },
  { pattern: /supplied argument is not a valid MySQL/i, db: "MySQL" },
  { pattern: /Warning:\s*mysql_/i, db: "MySQL" },
  { pattern: /XPATH syntax error/i, db: "MySQL (extractvalue)" },
  { pattern: /Duplicate entry .* for key .*group_key/i, db: "MySQL (floor/rand)" },
  { pattern: /SQLSTATE\[/i, db: "PDO" },
  { pattern: /Unclosed quotation mark after the character string/i, db: "MSSQL" },
  { pattern: /ORA-\d{5}/i, db: "Oracle" },
  { pattern: /PostgreSQL.*ERROR/i, db: "PostgreSQL" },
  { pattern: /SQLiteException/i, db: "SQLite" },
];

/** 去掉片段中的 HTML 标签，保留可读文本作为证据。 */
function cleanEvidence(text) {
  return String(text ?? "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
}

/** 从正文中抽取报错特征附近的一小段，作为证据。 */
function errorEvidence(body, pattern) {
  const index = body.search(pattern);
  if (index < 0) return null;
  return cleanEvidence(body.slice(index, index + 200));
}

function setParam(url, param, value) {
  const target = new URL(url.href);
  target.searchParams.set(param, value);
  return target;
}

/** 取 URL 中的最后一个参数作为默认注入点。 */
export function defaultParam(url) {
  const keys = [...url.searchParams.keys()];
  return keys.at(-1) ?? null;
}

/**
 * SQL 注入检测：
 *   1. 单双引号等闭合符触发数据库报错
 *   2. and 1=1 / and 1=2 的响应长度差异（布尔注入）
 */
export async function testSqli(args = {}) {
  if (!args.url) throw new Error("缺少参数 url");
  const url = targetUrl(args.url);
  const param = args.param || defaultParam(url);
  if (!param) throw new Error("URL 中没有可注入的参数，请显式传入 param");
  const originalValue = url.searchParams.get(param) ?? "1";

  const baseline = await request(url.href);
  if (!baseline.ok) throw new Error(`目标不可达: ${baseline.error}`);

  const payloads = ["'", "\"", "')", "') -- ", "' and 1=1 -- ", "' and 1=2 -- "];
  const results = [];
  const findings = [];
  const errorHits = [];

  const trueProbe = await request(setParam(url, param, `${originalValue}' and 1=1 -- `).href);
  const falseProbe = await request(setParam(url, param, `${originalValue}' and 1=2 -- `).href);

  for (const payload of payloads) {
    const target = setParam(url, param, `${originalValue}${payload}`);
    const result = await request(target.href);
    const hit = SQL_ERROR_SIGNATURES.find((sig) => sig.pattern.test(result.body));
    results.push({
      payload,
      url: target.href,
      status: result.status,
      length: result.length,
      errorSignature: hit ? hit.db : null,
    });
    if (hit) {
      errorHits.push({ payload, db: hit.db, evidence: errorEvidence(result.body, hit.pattern) });
    }
  }

  if (errorHits.length > 0) {
    const first = errorHits[0];
    findings.push({
      severity: "critical",
      title: "SQL 注入（报错型）",
      detail: `参数 ${param}，载荷 ${errorHits.map((item) => JSON.stringify(item.payload)).join("、")} 触发 ${first.db} 报错`,
      evidence: first.evidence,
    });
  }

  const baselineLength = baseline.length;
  const trueLength = trueProbe.length;
  const falseLength = falseProbe.length;
  const booleanDiff = Math.abs(trueLength - falseLength);
  const threshold = Math.max(20, Math.round(Math.max(baselineLength, 1) * 0.03));
  if (booleanDiff >= threshold && trueProbe.status === falseProbe.status) {
    findings.push({
      severity: "critical",
      title: "SQL 注入（布尔型）",
      detail: `参数 ${param}: and 1=1 长度 ${trueLength}，and 1=2 长度 ${falseLength}，差值 ${booleanDiff}`,
    });
  }

  return {
    target: baseline.finalUrl,
    param,
    baselineLength,
    booleanProbe: { trueLength, falseLength, difference: booleanDiff, threshold },
    results,
    findings: enrichFindings(findings),
    vulnerable: findings.length > 0,
    summary: findings.length > 0 ? `在参数 ${param} 上确认 SQL 注入` : `参数 ${param} 未发现 SQL 注入`,
  };
}

/** 证据中保留载荷原文，但转义尖括号，避免在 Markdown/HTML 中被当成标签。 */
function escapeEvidence(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** 反射型 XSS：注入唯一标记，检查原样回显。 */
export async function testXss(args = {}) {
  if (!args.url) throw new Error("缺少参数 url");
  const url = targetUrl(args.url);
  const param = args.param || defaultParam(url);
  if (!param) throw new Error("URL 中没有可注入的参数，请显式传入 param");
  const payload = args.payload || "<img src=x onerror=alert(1)>";
  const marker = payload.includes("vulnscan") ? "vulnscan" : "onerror=alert(1)";

  const target = setParam(url, param, payload);
  const result = await request(target.href);
  if (!result.ok) throw new Error(`目标不可达: ${result.error}`);

  const reflected = result.body.includes(payload);
  const findings = reflected
    ? [
        {
          severity: "high",
          title: "反射型 XSS",
          detail: `参数 ${param} 原样回显载荷 ${payload}`,
          evidence: `响应中检测到原样回显：${escapeEvidence(payload)}`,
        },
      ]
    : [];

  return {
    target: result.finalUrl,
    param,
    payload,
    status: result.status,
    reflected,
    markerPresent: result.body.includes(marker),
    findings: enrichFindings(findings),
    summary: reflected ? `参数 ${param} 存在反射型 XSS` : `参数 ${param} 未发现反射型 XSS`,
  };
}

/** 单 URL 探测：建立基线，返回状态、标题、长度与全部响应头。 */
export async function httpProbe(args = {}) {
  if (!args.url) throw new Error("缺少参数 url");
  const result = await request(targetUrl(args.url).href);
  if (!result.ok) throw new Error(`目标不可达: ${result.error}`);
  return {
    url: result.finalUrl,
    status: result.status,
    title: titleOf(result.body),
    length: result.length,
    headers: Object.fromEntries(result.headers.entries()),
  };
}
