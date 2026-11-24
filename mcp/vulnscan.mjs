#!/usr/bin/env node
/**
 * vulnscan MCP 服务器（stdio）。
 * 工具：scan_web / http_probe / test_sqli / test_xss
 */

import { startMcpServer } from "../src/mcp.mjs";
import { scanWeb, httpProbe, testSqli, testXss, DEFAULT_PATHS } from "../src/scanner.mjs";

const TOOLS = [
  {
    name: "scan_web",
    description:
      "对一个 Web 目标做基础安全检查：响应状态、服务指纹、缺失的安全响应头、Cookie 属性、常见敏感路径（.git、.env、phpinfo 等）。只做只读探测。",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "目标地址，例如 http://localhost/sqli-labs/" },
        paths: {
          type: "array",
          items: { type: "string" },
          description: `自定义探测路径列表，默认内置：${DEFAULT_PATHS.join(", ")}`,
        },
      },
      required: ["url"],
    },
  },
  {
    name: "http_probe",
    description: "请求单个 URL，返回状态码、标题、响应长度和全部响应头，用于建立基线。",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string", description: "目标地址" } },
      required: ["url"],
    },
  },
  {
    name: "test_sqli",
    description:
      "检测 GET 参数上的 SQL 注入：注入引号类载荷匹配数据库报错特征，并用 and 1=1 / and 1=2 的响应长度差异判断布尔型注入。",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "含参数的完整 URL，例如 http://localhost/sqli-labs/Less-1/?id=1" },
        param: { type: "string", description: "要测试的参数名，默认取 URL 最后一个参数" },
      },
      required: ["url"],
    },
  },
  {
    name: "test_xss",
    description: "检测 GET 参数上的反射型 XSS：注入载荷并检查是否原样回显。",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "含参数的完整 URL" },
        param: { type: "string", description: "要测试的参数名，默认取 URL 最后一个参数" },
        payload: { type: "string", description: "自定义 XSS 载荷，默认 <img src=x onerror=alert(1)>" },
      },
      required: ["url"],
    },
  },
];

startMcpServer({
  serverInfo: { name: "vulnscan", version: "1.0.0" },
  tools: TOOLS,
  handlers: {
    scan_web: scanWeb,
    http_probe: httpProbe,
    test_sqli: testSqli,
    test_xss: testXss,
  },
});
