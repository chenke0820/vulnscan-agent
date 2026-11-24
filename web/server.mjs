#!/usr/bin/env node
/**
 * vulnscan-agent Web 服务
 *  - 零第三方依赖：node:http + 内置 fetch
 *  - 提供扫描 API 与静态前端页面
 *
 * 环境变量：
 *   HOST        监听地址，默认 127.0.0.1（仅本机访问更安全）
 *   PORT        监听端口，默认 7788
 *   REPORTS_DIR 报告目录，默认仓库根目录下的 reports/
 */

import http from "node:http";
import path from "node:path";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { scanWeb, httpProbe, testSqli, testXss } from "../src/scanner.mjs";
import { createReport, listReports, readReport, resolveReportPath } from "../src/reporter.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PUBLIC_DIR = path.join(ROOT, "web", "public");
const REPORT_DIR = path.resolve(process.env.REPORTS_DIR ?? path.join(ROOT, "reports"));
const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number(process.env.PORT ?? 7788);
const VERSION = "1.0.0";
const MAX_BODY = 1024 * 1024;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function json(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function fail(res, status, message) {
  json(res, status, { ok: false, error: message });
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("请求体过大");
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("请求体不是合法 JSON");
  }
}

/** 静态文件响应，带路径穿越防护。 */
async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : decodeURIComponent(pathname).replace(/^\/+/, "");
  const target = path.resolve(PUBLIC_DIR, relative);
  if (!target.startsWith(PUBLIC_DIR + path.sep) && target !== PUBLIC_DIR) {
    return fail(res, 403, "禁止访问");
  }
  try {
    const info = await stat(target);
    if (!info.isFile()) return fail(res, 404, "未找到");
    const data = await readFile(target);
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(target).toLowerCase()] ?? "application/octet-stream",
      "Content-Length": data.length,
      "Cache-Control": "no-cache",
    });
    res.end(data);
  } catch {
    fail(res, 404, "未找到");
  }
}

async function handleReportRead(res, name, download) {
  const filePath = resolveReportPath(REPORT_DIR, name);
  try {
    const data = await readFile(filePath, "utf8");
    if (download) {
      res.writeHead(200, {
        "Content-Type": MIME[path.extname(filePath).toLowerCase()] ?? "application/octet-stream",
        "Content-Disposition": `attachment; filename="${encodeURIComponent(path.basename(filePath))}"`,
        "Content-Length": Buffer.byteLength(data),
      });
      res.end(data);
      return;
    }
    json(res, 200, { ok: true, name: path.basename(filePath), content: data.slice(0, 20000), truncated: data.length > 20000 });
  } catch (error) {
    if (error?.code === "ENOENT") return fail(res, 404, "报告不存在");
    fail(res, 400, error instanceof Error ? error.message : String(error));
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const pathname = url.pathname;

  try {
    if (pathname === "/api/health" && req.method === "GET") {
      const list = await listReports(REPORT_DIR);
      return json(res, 200, {
        ok: true,
        name: "vulnscan-agent",
        version: VERSION,
        tools: ["scan_web", "http_probe", "test_sqli", "test_xss"],
        reportDir: REPORT_DIR,
        reportCount: list.count,
      });
    }

    if (pathname === "/api/scan" && req.method === "POST") {
      const body = await readJson(req);
      return json(res, 200, { ok: true, data: await scanWeb(body) });
    }

    if (pathname === "/api/probe" && req.method === "POST") {
      const body = await readJson(req);
      return json(res, 200, { ok: true, data: await httpProbe(body) });
    }

    if (pathname === "/api/sqli" && req.method === "POST") {
      const body = await readJson(req);
      return json(res, 200, { ok: true, data: await testSqli(body) });
    }

    if (pathname === "/api/xss" && req.method === "POST") {
      const body = await readJson(req);
      return json(res, 200, { ok: true, data: await testXss(body) });
    }

    if (pathname === "/api/report" && req.method === "POST") {
      const body = await readJson(req);
      return json(res, 200, { ok: true, data: await createReport(body, REPORT_DIR) });
    }

    if (pathname === "/api/reports" && req.method === "GET") {
      return json(res, 200, { ok: true, data: await listReports(REPORT_DIR) });
    }

    if (pathname.startsWith("/api/reports/") && req.method === "GET") {
      const name = decodeURIComponent(pathname.slice("/api/reports/".length));
      return handleReportRead(res, name, url.searchParams.get("download") === "1");
    }

    if (pathname.startsWith("/api/")) return fail(res, 404, "接口不存在");

    if (req.method !== "GET" && req.method !== "HEAD") return fail(res, 405, "不支持的方法");
    return serveStatic(res, pathname);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const status = /缺少参数|不支持|无法解析|过大|必须位于/.test(message) ? 400 : 500;
    fail(res, status, message);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`vulnscan-agent web 已启动: http://${HOST}:${PORT}`);
  console.log(`报告目录: ${REPORT_DIR}`);
});
