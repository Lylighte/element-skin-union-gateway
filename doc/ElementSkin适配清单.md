# Element Skin 当前能力适配清单

## 适配结论

当前 Element Skin 已具备实现首阶段外置网关所需的账号认证、角色和进服会话能力。网关新增 Union 控制面和出口重签名，不要求先修改主站密钥管理。结论限于无冲突、未绑定角色；真实中心准入和转发仍需联调。

本清单基于[证据记录](协议证据与待验证项.md)所述工作区。实现时重新读取实际源码，不保留 /v1 兼容路径。

## Yggdrasil 路由映射

以下网关路径相对于 /api/yggdrasil；上游路径相对于 elementskin_api_url：

| Method | 网关相对路径 | Element Skin 路径 | 网关责任 |
| --- | --- | --- | --- |
| GET | 空路径 | / | 重建网关 metadata，使用 active Union 公钥与域名 |
| POST | /authserver/authenticate | /authserver/authenticate | 保留登录和角色选择语义，不生成自己的账号 token |
| POST | /authserver/refresh | /authserver/refresh | 保留 clientToken 校验与角色绑定 |
| POST | /authserver/validate | /authserver/validate | 保留成功 204 与协议拒绝 |
| POST | /authserver/invalidate | /authserver/invalidate | 使用主站注销结果 |
| POST | /authserver/signout | /authserver/signout | 使用主站账号认证和撤销 |
| POST | /sessionserver/session/minecraft/join | 同名路径 | 保留 accessToken、selectedProfile 和 serverId |
| GET | /sessionserver/session/minecraft/hasJoined | 同名路径 | 仅重签主站成功返回的本地角色 |
| GET | /sessionserver/session/minecraft/profile/{uuid} | 同名路径 | 保留 unsigned 语义，重签需要签名的 profile |
| GET | /api/users/profiles/minecraft/{name} | 同名路径 | 只允许当前成员本地角色，处理 URL 编码 |
| POST | /api/profiles/minecraft | 同名路径 | 精确批量 body 与结果 |
| GET | /minecraftservices/minecraft/profile/lookup/name/{name} | 同名路径 | 客户端别名映射 |
| POST | /minecraftservices/minecraft/profile/lookup/bulk/byname | 同名路径 | 客户端批量别名映射 |

对尾斜线的行为应由测试固定，不能通过不受控重定向携带密码或 token。上游原始 API location 响应头若指向主站，网关应替换为自身公开认证根，避免启动器绕开网关。

主站 metadata 当前有自有签名公钥以及 fallback 合并公钥。网关不得原样透传这些字段再单独重签。公钥发现端点需覆盖实际目标客户端使用的路径与大小写。

首阶段不声明尚未实现的 OIDC/Yggdrasil Connect 发现能力；如果主站将来输出相关 metadata，不能不加判断复制到网关使启动器改走原生入口。

## 主站认证与进服状态

源码职责：

- internal/service/yggdrasil/auth.go：随机 access token，Redis 保存用户和所选角色。
- internal/service/yggdrasil/refresh.go：检查 clientToken、角色归属和权限，再替换 token。
- internal/service/yggdrasil/session.go：join 校验 token、角色归属与 join 权限；hasJoined 校验会话、角色和当前权限。
- internal/service/yggdrasil/actor.go：通过现有 permission actor 应用进服相关策略。

当前 joinSessionTTL 为 30 秒。hasJoined 从 serverId 找到主站 session，再读取 token 对应角色。网关不得自行延长 session 或仅根据“上次登录成功”构造 hasJoined。

当前 HTTP Join 把 req.RemoteAddr 交给主站 service；当前 HasJoined service 不接收 ip 参数。代理后的 RemoteAddr 可能是网关地址，不能声称保留了原始客户端 IP 校验。若真实中心或目标服务器要求 ip 语义，应单独设计可信转发或网关约束并补测试。

主站 profile 查询 handler 可能包含 fallback 或外部资料解析。实现前逐路由核对，不能因为成功返回 profile 就认定它是当前成员本地账号。全站本地角色索引及权威回查用于约束出口重签。

## 管理读取和事件

| 用途 | 实际入口 | 权限与注意事项 |
| --- | --- | --- |
| 全量本地角色 | GET /v2/admin/profiles?limit=100&cursor=... | 服务应用 profile.read.any；读取 items、has_next、next_cursor |
| 当前用户信息 | GET /v2/users/me | 后续用户委托按实际权限；首阶段无需用户网页授权 |
| 当前用户角色 | GET /v2/users/me/profiles | 后续绑定功能使用 profile.read.owned |
| 角色名回查 | GET /v2/minecraft/profiles/{id} | 当前需 minecraft_profile.read.public；返回角色仍需核对本地归属 |
| Webhook 事件目录 | GET /v2/oauth/webhook-events | 读取实际可订阅权限，不能维护猜测目录 |
| 服务 token | POST /oauth/token | Client Credentials，使用申请且已获准的 app-only 权限 |

当前管理员列表返回 id、name、user_id、owner_email 等字段。同步只向中心提交 UUID 与角色名，不因列表包含邮箱就自动上传所有个人信息。

cursor 是请求参数，next_cursor 是响应字段，不可互换。全部分页读取完成前不执行 /sync。主站列表的分页不是跨请求数据库快照，需靠事件和最终对账修复并发变化。

服务应用订阅 profile.created、profile.updated、profile.deleted；事件数据只含 profile_id、user_id 等基础信息，不含权威 name 快照。Webhook 与 OAuth redirect_uri 互相独立，第一阶段服务应用不需要用户浏览器授权流程。

采用当前主站发放的 signing_secret，不沿用旧 sidecar 文档中“任意配置两边相同 secret 即可”的假设。签名输入、头字段和权限以主站当前契约为准。

## 关键缺口与位置

| 缺口 | 在哪里实现 | 首阶段是否阻塞 |
| --- | --- | --- |
| Union 私钥热更新与版本 | 网关 signing_generations 和 active 快照 | 网关必须实现，不要求改主站 |
| Union 成员路由、验签、目录 | 网关 Union service | 必须 |
| 出口材质重签及公钥 | 网关数据面 | 必须 |
| 全量和增量同步 | 网关 worker 与 service app | 必须 |
| 任意 UUID 重映射 API | 首阶段不调用；未来可用网关映射 | 无冲突角色不阻塞，不能假装支持 remap |
| Union OAuth 用户链路 | 后续独立适配 | 首阶段不包含 |
| 联合黑名单、queryemail | 准入要求待确认 | 若中心强制要求，必须实现后再验收 |

## 不修改主站的边界

网关不更新 keys.private_key、keys.public_key 或 oidc.*，不读取主站 Redis token，不绕过主站 service 权限，不为接入增加临时超级管理员身份。服务应用使用明确的细粒度权限。

如果后续验收发现主站协议错误或需要最小通用接口，另行在主站按其编码规范实施；不能用网关隐藏错误或直接修改底层数据。
