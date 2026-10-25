# Element Skin Union 网关

通过独立网关把 Element Skin 接入 MUA Union 联合认证。Element Skin 继续负责账号认证、权限和进服会话，网关负责 Union 成员协议、角色同步、材质重签名及自己的密钥生效状态。

当前版本为 0.1.0，已提供可运行服务、Docker 部署与离线打包。已实现无冲突角色的联合进服适配，真实 Union 中心与游戏客户端验收需部署后完成。

## 部署

从交付的 Docker 部署包导入镜像并按[部署与运维](doc/部署与运维.md)填写配置、配置主站服务应用和 HTTPS，再运行：

    docker compose run --rm gateway check-config
    docker compose up -d
    docker compose exec gateway /app/union-gateway admin -action status

从本仓库构建镜像可先执行 docker compose build。主站服务应用只需 Client Credentials 与 profile.read.any；成员 key 可以在中心签名的 bootstrap 回调中接收。

进程存活与成员就绪分别使用 /health/live 和 /health/ready。首次登记前 ready=false 是预期状态，公开控制面仍可接收中心回调。

## 首阶段范围

- 启动器通过网关的 `/api/yggdrasil` 使用 Element Skin 账号。
- 游戏服务器通过 `https://skin.mualliance.ltd/api/union/yggdrasil` 验证进服。
- 网关用 Union 共享私钥重签经过 Element Skin 验证的角色材质。
- 成员目录、成员凭证、共享密钥及角色同步在网关形成可恢复的闭环。
- 首次联调使用无名称冲突、无 UUID 冲突、无跨站绑定的测试角色。

Element Skin 不需要先增加密钥版本管理。Union 私钥及其生效版本归网关所有，Element Skin 保留现有密钥。Union OAuth、绑定界面、联合黑名单管理和复杂身份映射列入后续范围。

## 文档入口

| 文档 | 用途 |
| --- | --- |
| [网关实现方案](doc/网关实现方案.md) | 架构、数据模型、配置、API、交互和开发顺序 |
| [部署与运维](doc/部署与运维.md) | Docker 离线包、主站配置、HTTPS、管理诊断与远端验收 |
| [协议证据与待验证项](doc/协议证据与待验证项.md) | 参考源码、公开接口快照、证据等级与联调未知项 |
| [Element Skin 适配清单](doc/ElementSkin适配清单.md) | 当前可复用能力、端点映射、权限及状态边界 |
| [测试与联调计划](doc/测试与联调计划.md) | 离线精确断言、错误路径和真实进服验收 |
| [应用验证记录](reports/应用验证记录-20261025.md) | 本地测试、覆盖率、Linux race 和实际容器结果 |
| [历史实现复盘](doc/历史实现复盘.md) | 已归档 elementskin-union-svc 的可参考部分与已确认缺口 |
| [union-skill 使用说明](doc/union-skill使用说明.md) | 让 AI 为其他架构皮肤站开展适配的方法 |
| [开发约束](AGENTS.md) | 本仓库编码、协议、测试和提交要求 |

## 可复用技能

技能位于 [skills/union-skill/SKILL.md](skills/union-skill/SKILL.md)，附带可独立分发的协议、架构判断和验收参考。它要求 AI 先检查目标皮肤站的真实能力，再选择网关、原生集成或混合适配，不要求目标站改成 Element Skin 的架构。

通用协议记录以 [Union 协议参考](skills/union-skill/references/union-protocol.md) 为单一维护来源；本仓库文档补充 Element Skin 的具体决策。

## 当前验证边界

本文档中的设计不代表 Union 中心已认可该网关。正式登记成员、取得成员凭证、确认中心实际转发行为和真实游戏进服，均需要在获准的测试成员上验证。中心服务端源码不可用，不以模拟服务器测试代替真实互通结论。
