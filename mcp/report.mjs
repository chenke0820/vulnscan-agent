#!/usr/bin/env node
/**
 * report MCP 服务器（stdio）。
 * 工具：create_report / append_section / list_reports / read_report
 * 报告目录由环境变量 PI_REPORT_DIR 指定，默认仓库根目录下的 reports/。
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { startMcpServer } from "../src/mcp.mjs";
import { createReport, appendSection, listReports, readReport, SEVERITY_COLOR } from "../src/reporter.mjs";

const DEFAULT_DIR = fileURLToPath(new URL("../reports", import.meta.url));
const REPORT_DIR = path.resolve(process.env.PI_REPORT_DIR ?? DEFAULT_DIR);

const TOOLS = [
  {
    name: "create_report",
    description:
      "把检测结果生成可直接阅读的报告文件：默认 Markdown（md），也可选纯文本（txt），另有 HTML 备选。漏洞自动按严重性排序。报告保存到配置的报告目录，返回文件绝对路径。",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "报告标题，例如 sqli-labs 渗透测试报告" },
        target: { type: "string", description: "检测目标地址" },
        summary: { type: "string", description: "概述段落，说明检测范围与方法" },
        findings: {
          type: "array",
          description: "漏洞列表，建议直接使用 vulnscan 返回的 findings",
          items: {
            type: "object",
            properties: {
              severity: { type: "string", description: "critical/high/medium/low/info，也接受 严重/高危/中危/低危" },
              name: { type: "string", description: "漏洞名称" },
              evidence: { type: "string", description: "证据，例如报错信息或响应差异" },
              suggestion: { type: "string", description: "修复建议" },
            },
            required: ["name"],
          },
        },
        sections: {
          type: "array",
          description: "额外章节，例如复现步骤、影响范围",
          items: {
            type: "object",
            properties: { heading: { type: "string" }, body: { type: "string" } },
            required: ["heading"],
          },
        },
        format: { type: "string", description: "输出格式：md（默认）或 txt，两者都是纯文本可直接阅读；也可选 html" },
        filename: { type: "string", description: "自定义文件名，默认由标题和时间生成" },
      },
      required: ["title"],
    },
  },
  {
    name: "append_section",
    description: "向已有 Markdown 报告追加一个章节，适合分批写入长报告。",
    inputSchema: {
      type: "object",
      properties: {
        file: { type: "string", description: "报告文件名或相对路径" },
        heading: { type: "string", description: "章节标题" },
        body: { type: "string", description: "章节正文" },
      },
      required: ["file", "heading", "body"],
    },
  },
  {
    name: "list_reports",
    description: "列出报告目录中的文件，按修改时间倒序，最多返回 20 个。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "read_report",
    description: "读取报告内容（最多 20000 字符），用于检查或修改前确认。",
    inputSchema: {
      type: "object",
      properties: { file: { type: "string", description: "报告文件名或相对路径" } },
      required: ["file"],
    },
  },
];

startMcpServer({
  serverInfo: { name: "report", version: "1.0.0" },
  tools: TOOLS,
  handlers: {
    create_report: (args) => createReport(args, REPORT_DIR),
    append_section: (args) => appendSection(args, REPORT_DIR),
    list_reports: () => listReports(REPORT_DIR, 20),
    read_report: (args) => readReport(args.file, REPORT_DIR),
  },
});

console.error(`[report] 报告目录: ${REPORT_DIR}（严重性配色 ${Object.keys(SEVERITY_COLOR).length} 档）`);
