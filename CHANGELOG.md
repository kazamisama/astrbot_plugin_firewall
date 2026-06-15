# Changelog

## v0.1.2

- LLM 阶段扫描 `req.prompt` 前默认剥离 `<RAG-Faiss-Memory>...</RAG-Faiss-Memory>` 可信记忆块，降低 LivingMemory/RAG 注入内容触发误判的概率。
- 新增 `strip_trusted_prompt_blocks` 配置项，可关闭可信块剥离。
- 新增审计日志轮转配置：`audit_rotate_bytes` 与 `audit_rotate_keep`。
- 新增回归测试：可信记忆块不误拦、剥离后仍拦截用户注入、审计日志轮转。

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
