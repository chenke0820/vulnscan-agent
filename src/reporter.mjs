#!/usr/bin/env node
/**
 * 报告渲染：把扫描结果生成为 Markdown / 纯文本 / HTML 报告并落盘。
 * 所有文件都被限制在报告目录内，避免任意路径写入。
 */

import { mkdir, readFile, readdir, stat, writeFile, appendFile } from "node:fs/promises";
import path from "node:path";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "./scanner.mjs";

export const SEVERITY_COLOR = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#a16207",
  low: "#0369a1",
  info: "#4b5563",
};

/** 把标题转成安全的文件名片段。 */
export function slugify(title, maxLength = 50) {
  return (
    title
      .replace(/[\\/:*?"<>|\s]+/g, "-")
      .replace(/-{2,}/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, maxLength) || "report"
  );
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

/** 解析相对文件名，并保证结果落在报告目录内。 */
export function resolveReportPath(reportDir, file) {
  const root = path.resolve(reportDir);
  const target = path.resolve(root, file);
  if (!target.startsWith(root + path.sep) && target !== root) {
    throw new Error(`文件必须位于报告目录 ${root} 内`);
  }
  return target;
}

function normalizeSeverity(value) {
  const text = String(value ?? "info").toLowerCase();
  if (value === "严重" || value === "critical") return "critical";
  if (value === "高危" || value === "high") return "high";
  if (value === "中危" || value === "medium") return "medium";
  if (value === "低危" || value === "low") return "low";
  return SEVERITY_ORDER.includes(text) ? text : "info";
}

export function normalizeFindings(findings = []) {
  return findings
    .map((item, index) => ({
      index: index + 1,
      severity: normalizeSeverity(item.severity),
      name: String(item.name ?? item.title ?? "未命名问题"),
      evidence: String(item.evidence ?? item.detail ?? "").trim(),
      suggestion: String(item.suggestion ?? "").trim(),
    }))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .map((item, index) => ({ ...item, index: index + 1 }));
}

export function countBySeverity(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of findings) counts[normalizeSeverity(item.severity)] += 1;
  return counts;
}

/** Markdown 表格单元格转义。 */
function mdCell(text) {
  return String(text ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim() || "-";
}

export function buildMarkdown(meta) {
  const lines = [
    `# ${meta.title}`,
    "",
    `- 检测目标：${meta.target || "未提供"}`,
    `- 生成时间：${meta.generatedAt}`,
    `- 检测工具：vulnscan-agent`,
    "",
    "## 一、概述",
    "",
    meta.summary || "本次检测未提供概述。",
    "",
  ];

  if (meta.findings.length > 0) {
    lines.push(
      "## 二、漏洞清单",
      "",
      "| 序号 | 严重性 | 漏洞名称 | 证据 | 修复建议 |",
      "| --- | --- | --- | --- | --- |",
    );
    for (const item of meta.findings) {
      lines.push(
        `| ${item.index} | ${SEVERITY_LABEL[item.severity]} | ${mdCell(item.name)} | ${mdCell(
          item.evidence,
        )} | ${mdCell(item.suggestion)} |`,
      );
    }
    lines.push("");
  } else {
    lines.push("## 二、漏洞清单", "", "本次检测未发现可利用漏洞。", "");
  }

  const counts = countBySeverity(meta.findings);
  const countText = SEVERITY_ORDER.filter((key) => counts[key]).map((key) => `${SEVERITY_LABEL[key]} ${counts[key]} 项`);
  lines.push("## 三、结论", "");
  lines.push(
    meta.findings.length > 0
      ? `共发现 ${meta.findings.length} 个问题（${countText.join("、")}）。建议按严重性从高到低修复，优先处理可导致数据泄露或权限失控的问题。`
      : "未发现问题，但自动化扫描覆盖有限，建议结合人工测试。",
  );
  lines.push("");

  for (const section of meta.sections) {
    lines.push(`## ${section.heading}`, "", section.body, "");
  }
  return lines.join("\n");
}

/** 纯文本报告：无任何标记符号，记事本直接可读。 */
export function buildText(meta) {
  const rule = "=".repeat(60);
  const thin = "-".repeat(60);
  const lines = [
    rule,
    ` ${meta.title}`,
    rule,
    `检测目标：${meta.target || "未提供"}`,
    `生成时间：${meta.generatedAt}`,
    `检测工具：vulnscan-agent`,
    "",
    "一、概述",
    thin,
    meta.summary || "本次检测未提供概述。",
    "",
    "二、漏洞清单",
    thin,
  ];

  if (meta.findings.length === 0) {
    lines.push("本次检测未发现可利用漏洞。", "");
  } else {
    for (const item of meta.findings) {
      lines.push(`[${item.index}] ${SEVERITY_LABEL[item.severity]} | ${item.name}`);
      if (item.evidence) lines.push(`    证据：${item.evidence}`);
      lines.push(`    修复建议：${item.suggestion || "无"}`);
      lines.push("");
    }
  }

  lines.push("三、结论", thin);
  const counts = countBySeverity(meta.findings);
  const countText = SEVERITY_ORDER.filter((key) => counts[key]).map((key) => `${SEVERITY_LABEL[key]} ${counts[key]} 项`);
  lines.push(
    meta.findings.length > 0
      ? `共发现 ${meta.findings.length} 个问题（${countText.join("、")}），建议按严重性从高到低修复。`
      : "未发现问题，但自动化扫描覆盖有限，建议结合人工测试。",
  );
  lines.push("");

  for (const section of meta.sections) {
    lines.push(section.heading, thin, section.body, "");
  }
  return lines.join("\n");
}

function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function buildHtml(meta) {
  const rows = meta.findings
    .map(
      (item) => `
      <tr>
        <td>${item.index}</td>
        <td><span class="badge" style="background:${SEVERITY_COLOR[item.severity]}">${SEVERITY_LABEL[item.severity]}</span></td>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.evidence) || "-"}</td>
        <td>${escapeHtml(item.suggestion) || "-"}</td>
      </tr>`,
    )
    .join("");

  const extra = meta.sections
    .map((section) => `<section><h2>${escapeHtml(section.heading)}</h2><p>${escapeHtml(section.body)}</p></section>`)
    .join("\n");

  const findingsTable =
    meta.findings.length > 0
      ? `<table><thead><tr><th>序号</th><th>严重性</th><th>漏洞名称</th><th>证据</th><th>修复建议</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<p class="muted">本次检测未发现可利用漏洞。</p>`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(meta.title)}</title>
<style>
  :root { --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --bg:#ffffff; }
  * { box-sizing: border-box; }
  body { margin:0; background:#f3f4f6; color:var(--ink); font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif; line-height:1.7; }
  .page { max-width:960px; margin:32px auto; background:var(--bg); border:1px solid var(--line); border-radius:12px; padding:40px 48px; }
  h1 { font-size:28px; margin:0 0 8px; }
  h2 { font-size:20px; margin:32px 0 12px; padding-bottom:8px; border-bottom:2px solid var(--line); }
  .meta { color:var(--muted); font-size:14px; margin-bottom:24px; }
  .meta span { margin-right:20px; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { background:#f9fafb; font-weight:600; }
  .badge { color:#fff; border-radius:999px; padding:2px 10px; font-size:12px; white-space:nowrap; }
  .muted { color:var(--muted); }
  footer { margin-top:40px; color:var(--muted); font-size:12px; text-align:center; }
</style>
</head>
<body>
<div class="page">
  <h1>${escapeHtml(meta.title)}</h1>
  <div class="meta">
    <span>检测目标：${escapeHtml(meta.target) || "未提供"}</span>
    <span>生成时间：${escapeHtml(meta.generatedAt)}</span>
    <span>工具：vulnscan-agent</span>
  </div>
  <h2>一、概述</h2>
  <p>${escapeHtml(meta.summary) || "本次检测未提供概述。"}</p>
  <h2>二、漏洞清单</h2>
  ${findingsTable}
  <h2>三、结论</h2>
  <p>${meta.findings.length > 0 ? `共发现 ${meta.findings.length} 个问题，建议按严重性从高到低修复。` : "未发现问题，但自动化扫描覆盖有限，建议结合人工测试。"}</p>
  ${extra}
  <footer>由 vulnscan-agent 自动生成</footer>
</div>
</body>
</html>`;
}

async function ensureDir(dir) {
  await mkdir(dir, { recursive: true });
}

/** 生成报告，返回文件信息。 */
export async function createReport(args = {}, reportDir) {
  if (!reportDir) throw new Error("缺少报告目录配置");
  const title = String(args.title ?? "").trim();
  if (!title) throw new Error("缺少参数 title");
  const requested = String(args.format ?? "md").toLowerCase();
  const format = requested === "html" ? "html" : requested === "txt" ? "txt" : "md";
  const generatedAt = new Date().toLocaleString("zh-CN", { hour12: false });

  const meta = {
    title,
    target: String(args.target ?? "").trim(),
    generatedAt,
    summary: String(args.summary ?? "").trim(),
    findings: normalizeFindings(args.findings),
    sections: (args.sections ?? [])
      .filter((section) => section && section.heading)
      .map((section) => ({ heading: String(section.heading), body: String(section.body ?? "").trim() })),
  };

  await ensureDir(reportDir);
  const fileName = args.filename
    ? path.basename(String(args.filename))
    : `${slugify(title)}-${timestamp()}.${format}`;
  const filePath = resolveReportPath(reportDir, fileName);
  const content = format === "html" ? buildHtml(meta) : format === "txt" ? buildText(meta) : buildMarkdown(meta);
  await writeFile(filePath, content, "utf8");

  return {
    path: filePath,
    fileName,
    format,
    title,
    findings: meta.findings.length,
    size: Buffer.byteLength(content, "utf8"),
    message: `报告已生成：${filePath}`,
  };
}

/** 向已有 Markdown 报告追加章节。 */
export async function appendSection(args = {}, reportDir) {
  const file = String(args.file ?? "").trim();
  if (!file) throw new Error("缺少参数 file");
  if (!file.toLowerCase().endsWith(".md")) throw new Error("append_section 只支持 Markdown 文件");
  const heading = String(args.heading ?? "").trim();
  if (!heading) throw new Error("缺少参数 heading");
  const body = String(args.body ?? "").trim();

  const filePath = resolveReportPath(reportDir, file);
  const chunk = `\n## ${heading}\n\n${body}\n`;
  await appendFile(filePath, chunk, "utf8");
  return { path: filePath, appended: chunk.length };
}

/** 列出报告目录中的文件，按修改时间倒序。 */
export async function listReports(reportDir, limit = 30) {
  await ensureDir(reportDir);
  const entries = await readdir(reportDir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const full = path.join(reportDir, entry.name);
    const info = await stat(full);
    files.push({ name: entry.name, size: info.size, modified: info.mtime.toISOString() });
  }
  files.sort((a, b) => b.modified.localeCompare(a.modified));
  return { directory: reportDir, count: files.length, files: files.slice(0, limit) };
}

/** 读取报告内容（最多 20000 字符）。 */
export async function readReport(file, reportDir) {
  const name = String(file ?? "").trim();
  if (!name) throw new Error("缺少参数 file");
  const filePath = resolveReportPath(reportDir, name);
  const content = await readFile(filePath, "utf8");
  return { path: filePath, content: content.slice(0, 20000), truncated: content.length > 20000 };
}
