#!/usr/bin/env node
/**
 * 最小可用的 MCP stdio 传输层。
 * 协议：MCP 2024-11-05 及以上，每条消息一行 JSON-RPC 2.0。
 * 注意：stdout 只能输出协议消息，日志一律写 stderr。
 */

import { createInterface } from "node:readline";

const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

/**
 * 启动一个 stdio MCP 服务。
 * @param {{serverInfo: {name: string, version: string}, tools: Array, handlers: Record<string, Function>}} options
 */
export function startMcpServer({ serverInfo, tools, handlers }) {
  function log(...args) {
    console.error(`[${serverInfo.name}]`, ...args);
  }

  async function handleRequest(message) {
    const { method, params } = message;
    switch (method) {
      case "initialize": {
        const requested = params?.protocolVersion;
        const version = PROTOCOL_VERSIONS.includes(requested) ? requested : PROTOCOL_VERSIONS[0];
        return { protocolVersion: version, capabilities: { tools: {} }, serverInfo };
      }
      case "ping":
        return {};
      case "tools/list":
        return { tools };
      case "tools/call": {
        const name = params?.name;
        const handler = handlers[name];
        if (!handler) throw rpcError(-32602, `未知工具: ${name}`);
        const result = await handler(params?.arguments ?? {});
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
          isError: false,
        };
      }
      default:
        throw rpcError(-32601, `不支持的方法: ${method}`);
    }
  }

  function rpcError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }

  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let pending = 0;
  let stdinClosed = false;

  function maybeExit() {
    if (stdinClosed && pending === 0) process.exit(0);
  }

  input.on("line", (line) => {
    const text = line.trim();
    if (!text) return;
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      log("无法解析的消息:", text.slice(0, 200));
      return;
    }
    // 通知没有 id，不需要回复
    if (message.id === undefined || message.id === null) return;

    pending += 1;
    handleRequest(message)
      .then((result) => send({ jsonrpc: "2.0", id: message.id, result }))
      .catch((error) => {
        const code = error instanceof Error && "code" in error ? error.code : -32603;
        send({
          jsonrpc: "2.0",
          id: message.id,
          error: { code, message: error instanceof Error ? error.message : String(error) },
        });
      })
      .finally(() => {
        pending -= 1;
        maybeExit();
      });
  });

  input.on("close", () => {
    stdinClosed = true;
    maybeExit();
  });

  log(`${serverInfo.name} MCP ${serverInfo.version} 已启动，工具: ${tools.map((tool) => tool.name).join(", ")}`);
}
