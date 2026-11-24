# 演示靶场 Web 安全扫描报告

- 检测目标：http://127.0.0.1:8099/
- 生成时间：2026/11/24 20:34:09
- 检测工具：vulnscan-agent

## 一、概述

对本地故意脆弱靶场执行综合扫描、SQL 注入与反射型 XSS 检测，覆盖响应头、敏感路径与注入类风险。

## 二、漏洞清单

| 序号 | 严重性 | 漏洞名称 | 证据 | 修复建议 |
| --- | --- | --- | --- | --- |
| 1 | 严重 | SQL 注入（报错型） | 参数 id，载荷 "'"、"')"、"') -- " 触发 MySQL 报错 — You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1'' at line 1 VulnScan 本地演示靶场 | 使用参数化查询/预编译语句，关闭数据库错误回显，并为数据库账号降权。 |
| 2 | 严重 | SQL 注入（布尔型） | 参数 id: and 1=1 长度 197，and 1=2 长度 158，差值 39 | 使用参数化查询/预编译语句，对输入做类型校验，统一错误页面避免布尔差异。 |
| 3 | 高危 | 敏感路径可直接访问 | /.env、/phpinfo.php、/admin/ | 将备份、配置、调试文件移出 Web 根目录，或在服务器层直接返回 403/404。 |
| 4 | 高危 | 反射型 XSS | 参数 name 原样回显载荷 <img src=x onerror=alert(1)> — 响应中检测到原样回显：&lt;img src=x onerror=alert(1)&gt; | 对输出做上下文相关的编码，开启 CSP，优先使用模板引擎的自动转义。 |
| 5 | 中危 | 缺少 5 个安全响应头 | strict-transport-security, content-security-policy, x-frame-options, x-content-type-options, referrer-policy | 在网关或应用入口统一补充 HSTS、CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy。 |
| 6 | 低危 | 服务指纹暴露 | Server: DemoApache/2.4.49 (Win64) PHP/7.4.3 | 在反向代理或应用配置中移除或改写 Server 响应头，避免暴露中间件与版本号。 |
| 7 | 低危 | 框架指纹暴露 | X-Powered-By: PHP/7.4.3 | 关闭 X-Powered-By（如 PHP 的 expose_php=Off），减少攻击面信息。 |
| 8 | 提示 | 公开信息文件 | /robots.txt | 确认 robots.txt 等公开文件未泄露后台或备份目录；隐藏敏感路径不应只依赖 robots.txt。 |

## 三、结论

共发现 8 个问题（严重 2 项、高危 2 项、中危 1 项、低危 2 项、提示 1 项）。建议按严重性从高到低修复，优先处理可导致数据泄露或权限失控的问题。

## 四、复现说明

综合扫描访问首页与内置敏感路径；SQL 注入使用 and 1=1 / and 1=2 及引号闭合载荷；XSS 使用 <img src=x onerror=alert(1)> 并检查回显。
