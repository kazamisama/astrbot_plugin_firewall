# AstrBot Firewall 安全防火墙



独立安全防护插件，定位为 AstrBot 的轻量入口防火墙。



## 功能



- **私聊 Prompt 注入拦截**：扫描私聊正文和 LLM 请求 prompt，命中忽略规则、角色伪装、泄露系统提示、伪 system/developer 标签等风险片段时阻断。

- **群聊临时会话私聊阻断**：针对 aiocqhttp / OneBot 常见的 `message_type=private` 且 `sub_type=group/group_self/temp` 或携带 `group_id` 的临时会话，默认直接拦截。

- **LLM 请求兜底防护**：即使消息阶段被其他插件绕过，`on_llm_request` 阶段仍会替换高风险 prompt，防止攻击文本进入模型。

- **白名单**：支持用户 ID 或 UMO 会话 ID。

- **审计日志**：拦截记录写入插件数据目录 `audit.jsonl`。



## 默认策略



默认启用：



- `enabled = true`

- `block_group_temporary_private = true`

- `private_prompt_injection_block_enabled = true`

- `allow_webchat_by_default = true`：`webchat:` 会话默认放行，避免本地 WebChat 调试被防火墙误拦。

- `audit_log_enabled = true`



也就是说，插件安装后会立即保护私聊入口；如果某些可信私聊被误拦，可以把用户 ID 或会话 ID 加入 `whitelist`。



## 命令



```text

/firewall_status

```



查看防火墙开关、关键策略和审计记录数量。



## 配置建议



### 1. 严格安全模式（推荐）



保持默认配置：直接阻断临时私聊和高风险私聊注入。



### 2. 静默安全模式



```json

{

  "silent_block": true

}

```



命中后只阻断和写审计日志，不回复提示。



### 3. 观察模式



如果想先观察误判：



```json

{

  "private_prompt_injection_block_enabled": false,

  "private_prompt_injection_tag_enabled": true

}

```



这样 LLM 阶段会把风险片段包裹为 `<INJECTION_RISK>...</INJECTION_RISK>`，但不建议长期用于私聊入口。



## 说明



这个插件与普通 prompt 注入过滤插件的区别是：它把防护边界前移到**私聊入口**，尤其是群聊临时会话私聊，适合用于防止陌生群成员通过临时会话对 Bot 下达越权指令。

