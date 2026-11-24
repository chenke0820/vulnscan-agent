#!/usr/bin/env node
/**
 * 仅用于本地测试的故意脆弱靶场（请勿部署到公网）。
 * 覆盖漏洞扫描器的四类探测：安全头缺失、敏感路径、SQL 注入、反射型 XSS。
 *
 * 启动：node demo/vulnerable-target.mjs [port]
 */

import http from "node:http";

const PORT = Number(process.argv[2] ?? process.env.DEMO_PORT ?? 8099);

const page = (title, body) => `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1>${body}<hr><p>VulnScan 本地演示靶场</p></body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const send = (status, body, headers = {}) => {
    res.writeHead(status, {
      "Content-Type": "text/html; charset=utf-8",
      // 故意暴露服务指纹，且不设置任何安全响应头
      Server: "DemoApache/2.4.49 (Win64) PHP/7.4.3",
      "X-Powered-By": "PHP/7.4.3",
      ...headers,
    });
    res.end(body);
  };

  if (url.pathname === "/") {
    // 故意下发不带安全属性的 Cookie
    return send(200, page("VulnScan Demo Shop", `
      <p>演示商城首页，包含两个测试入口：</p>
      <ul>
        <li><a href="/login?name=guest">/login?name=guest</a>（反射型 XSS）</li>
        <li><a href="/item?id=1">/item?id=1</a>（SQL 注入）</li>
      </ul>`), { "Set-Cookie": "SESSIONID=demo123; Path=/" });
  }

  if (url.pathname === "/robots.txt") {
    return send(200, "User-agent: *\nDisallow: /admin/\n", { "Content-Type": "text/plain; charset=utf-8" });
  }

  if (url.pathname === "/.env") {
    return send(200, "APP_ENV=production\nDB_PASSWORD=demo_password\n", { "Content-Type": "text/plain; charset=utf-8" });
  }

  if (url.pathname === "/phpinfo.php") {
    return send(200, page("phpinfo()", "<p>PHP Version 7.4.3（演示）</p>"));
  }

  if (url.pathname === "/admin/" || url.pathname === "/admin") {
    return send(200, page("管理后台", "<p>后台入口可直接访问（演示）。</p>"));
  }

  if (url.pathname === "/login") {
    const name = url.searchParams.get("name") ?? "guest";
    // 故意原样回显，制造反射型 XSS
    return send(200, page("登录", `<p>欢迎回来，${name}</p>`));
  }

  if (url.pathname === "/item") {
    const id = url.searchParams.get("id") ?? "1";
    const rows = [];
    // 布尔型注入：and 1=1 返回三行，and 1=2 返回空列表，造成响应长度差异
    if (/and\s+1\s*=\s*1/i.test(id)) rows.push("商品 A", "商品 B", "商品 C");
    else if (/and\s+1\s*=\s*2/i.test(id)) rows.push();
    // 故意把输入拼进 SQL 并回显报错，制造报错型 SQL 注入
    else if (id.includes("'")) {
      return send(
        500,
        page("SQL Error", `<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${id}' at line 1</pre>`),
      );
    } else rows.push(`商品 #${id}`);
    return send(200, page("商品详情", `<ul>${rows.map((row) => `<li>${row}</li>`).join("")}</ul>`));
  }

  send(404, page("404 Not Found", "<p>页面不存在</p>"));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`演示靶场已启动: http://127.0.0.1:${PORT}`);
  console.log(`XSS 入口: http://127.0.0.1:${PORT}/login?name=guest`);
  console.log(`SQLi 入口: http://127.0.0.1:${PORT}/item?id=1`);
});
