# Changelog

## v0.1.1

- 新增 `whitelist` 配置项（默认 `[]`），命中用户 ID 或 `UMO` 会话 ID 的事件跳过临时会话阻断和私聊注入拦截。
- 新增 `allow_webchat_by_default`（默认 `true`）：`webchat:` 会话默认放行，避免本地 WebChat 调试被防火墙误拦。
- 新增 `silent_block`（默认 `true`）：消息阶段拦截默认静默，仅阻断并写审计日志，不再主动回复拦截提示。
- 配套测试覆盖：白名单放行、webchat 默认放行关闭、默认静默拦截不回复。
- README 同步补充上述配置项与默认行为说明。

## v0.1.0

- 初始发布 AstrBot Firewall 安全防火墙。
- 支持私聊 prompt injection 拦截、群聊临时会话私聊阻断、白名单与审计日志。
- 新增 `/firewall_status` 状态查看命令。
