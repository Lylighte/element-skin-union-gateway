# Union 成员协议参考

## 适用范围与证据边界

本参考帮助实现 MUA Union 成员适配。基线为 MUAlliance/yggdrasil-connect 6.1.0-0.3.2 的客户端实现及 2026-10-25 的公开接口观察。中心服务端源码不可用；成员客户端发出的请求和实现的回调是已知事实，中心内部转发、错误码、重试和轮换策略不能据此推定。

使用时重新核对用户提供的源码或当前官方客户端。版本变化时更新证据，不增加未经证实的多格式兼容分支。

主要来源：

- [成员插件源码](https://github.com/MUAlliance/yggdrasil-connect/tree/957a71a84e2d19e2c94069d96f637d17689947c3)
- [联合认证说明](https://docs.mualliance.cn/dev/union/auth)
- [Union OAuth 说明](https://docs.mualliance.cn/dev/union/oauth)

旧文档中仍可能保留 IP 验证的叙述。所读客户端实际使用 RSA 回调签名，应以明确版本源码为准。

## 三类地址

| 地址 | 角色 |
| --- | --- |
| https://skin.mualliance.ltd/api/union | 中心控制 API、成员目录和回调验签公钥 |
| https://skin.mualliance.ltd/api/union/yggdrasil | 游戏服务器使用的联合认证入口 |
| https://skin.mualliance.ltd/api/yggdrasil | MUA 自身成员的 Yggdrasil 入口 |

联合入口还有 /only/{code} 和 /excludes/{code} 模式，多成员 code 以 _ 分隔。不要将 MUA 本站入口当成联合入口，也不要只因联合入口元数据较少就判断它无效。

成员对外有一个登记根地址，参考客户端在其下提供 /api/yggdrasil 和 /api/union/member。根地址可以由反向代理提供；内部上游、端口和进程部署位置可配置。中心是否允许分别登记任意 endpoint 未被证实。

目录里出现带子路径的 bs_root，不能由此推导回调后缀也可任意配置。修改已登记根地址需要考虑中心路由和客户端已保存地址。

## 中心向成员的请求

以下路径相对于登记根地址：

| Method | Path | 请求与行为 |
| --- | --- | --- |
| GET | /api/union/member/ | 公开 hello |
| POST | /api/union/member/updatelist | 验签后用成员凭证向中心拉取 /serverlist |
| POST | /api/union/member/updateprivatekey | 验签后用成员凭证拉取 /privatekey |
| POST | /api/union/member/updatebackendkey | body 的 key 更新成员请求凭证 |
| POST | /api/union/member/sync | 触发成员从本地权威状态发起全量同步 |
| POST | /api/union/member/remapuuid | body.remapped_uuid 为旧 UUID 到新 UUID 的映射 |
| POST | /api/union/member/diagnose | body.nonce 原样回显，timestamp 为 Unix 秒，可带小数 |
| GET | /api/union/member/queryemail?username=... | 按角色名查所有者邮箱；找到返回 200 和 email，没有角色返回 204 |

PHP 插件还提供 updateplugin，但其他架构不得把其远程下载执行能力照搬为通用要求。未实现的请求明确失败，实际准入要求需与中心联调。

hello 字段是 yggdrasilApiVersion、serverListVersion、privateKeyVersion、enabledFeatures。参考 PHP 的版本可表现为数字字符串；成员新实现应选择明确的输出类型，并在中心验收前确认接受情况。

参考插件的 enabledFeatures 包括 unionBlacklist，并按配置增加 emailVerification、invitationCodesForUnion、unionOAuth2。这些名字的完整中心判定语义未知，不应为通过探测无条件声明。也不能把旧项目写的“remapuuid 已弃用”当作中心废弃事实。

## 成员向中心的请求

以下路径相对于中心控制 API 根。带成员鉴权的请求使用 X-Union-Member-Key，不能用目标皮肤站 OAuth token 替代。

| Method | Path | body 或响应形状 |
| --- | --- | --- |
| GET | /serverlist | 响应 servers 数组和 version；成员条目含 code、bs_root |
| GET | /privatekey | 响应 privateKey PEM 和 privateKeyVersion |
| POST | /sync | body.profileList 是 UUID 到角色名的对象 |
| POST | /profile | body.id 为 UUID，body.name 为角色名 |
| PUT | /profile/{uuid} | body.name 为当前角色名 |
| DELETE | /profile/{uuid} | 删除对应角色 |
| POST | /diagnose | 请求中心诊断，返回细节需要实际观察 |
| GET | /profile/unmapped/byname/{name} | 未映射角色查询 |
| GET | /profile/detail/{uuid} | 成员角色、绑定等详细资料 |

精确的全量格式示例：

    {
      "profileList": {
        "11111111111141118111111111111111": "UnionTest"
      }
    }

UUID 是对象键，角色名是值。PHP triggerSync 从 name→uuid 再 flip，最终不是 name→uuid。URL 中角色名或 UUID 必须按路径片段编码，不能通过字符串拼接引入额外路径。

查询响应、重复新增、缺失更新、重复删除的确切错误码必须来自可信样本或真实中心。不要用宽松解析器吞掉错误对象并把它解释为空列表。

## 中心回调验签

请求头：

- X-Message-Signature：RSA 签名的标准 Base64。
- X-Message-Timestamp：Unix 秒的原始字符串。
- X-Message-Nonce：去重随机值。

中心公钥从控制根响应的 union_host_signature_public_key 获取。签名输入是原始请求体字节、原始 timestamp 字符串、原始 nonce 字符串按顺序直接拼接；RSA PKCS#1 v1.5、SHA-256。

参考客户端时间窗口为 now-10 秒到 now+30 秒，nonce 保留 60 秒。实现可严格复现窗口并明确时钟要求；不能把毫秒时间戳误当秒。每个 HTTP 请求读取大小应有上限。

先验签，再用唯一插入或等效原子操作占用 nonce，再执行修改。Cache.has 与随后 put 不能阻止并发重放。nonce 存储失败时不得继续修改。

现有签名没有覆盖 method、path 或 query；GET queryemail 的 query 也不在签名输入中。不可在成员端单方面修改签名公式，应精确匹配已知协议、限制回调路径和权限，并将该限制列入联调记录。中心公钥缓存不等于独立根证书或密钥版本链。

## Yggdrasil 数据面

成员插件提供 /api/yggdrasil 根及下列路径：

- /authserver/authenticate、refresh、validate、invalidate、signout。
- /sessionserver/session/minecraft/join、hasJoined、profile/{uuid}。
- /api/users/profiles/minecraft/{username} 和 POST /api/profiles/minecraft。
- /minecraftservices/minecraft/profile/lookup/name/{username} 和 bulk/byname 别名。

根元数据中的签名字段是 signaturePublickey，注意小写 k。联合入口根响应观察到 signaturePublicKey，注意大写 K；不能因此对所有 endpoint 做字段名归一化。联合入口的根响应不等同于成员完整 metadata。

成员元数据还包括 skinDomains。域名列表来自成员目录及被明确允许的实际材质源；必须是域名而非 root URL 或含路径字符串。使用 CDN 的部署需要额外核实。

公钥发现 endpoint 按目标 authlib-injector 版本和成员路由确认，公开本次数据面使用的签名钥。不要透传底层皮肤站所有公钥而只改 metadata 根的一个字段。

## 材质签名和身份

材质属性签名算法为 RSA PKCS#1 v1.5、SHA-1；签名对象是 properties.value 的 Base64 文本本身，不是解码后的 JSON。signature 使用标准 Base64。

共享私钥的持有者都能产生相同信任域内的材质签名。它不是站点登录密码、cookie JWT secret 或 OAuth token。网关重签前必须确认上游会话成功与角色归属，不能对任意传入 profile 提供签名。

没有字段修改时保留 value 原文；修改 profileId、profileName、材质 URL 后先重编码再签名。保留 SKIN 的模型 metadata、CAPE 等属性。返回签名与元数据、公钥端点的 active 代次一致。

登录、刷新、选择角色、join、hasJoined、profile 查询和材质内部字段必须表达一致身份。映射放在网关时，既要处理向外的本地到 Union 转换，也要处理传向上游的反向转换；仅修改 hasJoined 不足以支持 1.19+。

联合服务器通常先接收客户端对其所属成员的 join，随后中心把服务器的 hasJoined 转发到成员。具体路径、是否转发 ip、绑定映射发生在哪一步均需真实中心确认。

## 密钥与状态隔离

| 名称 | 持有者与用途 |
| --- | --- |
| Union 材质共享私钥 | 成员或网关持有，用于 Yggdrasil 属性签名 |
| union_host_signature_public_key | 成员验证中心回调，不能替代材质公钥 |
| X-Union-Member-Key | 成员调用中心控制 API 的请求凭证 |
| 成员 Union OAuth 私钥 | 成员签署跨站用户信息，不与材质私钥混用 |
| 中心 Union OAuth 公钥 | 成员加密用户信息令牌 |
| 目标站自身 JWT/OIDC/Webhook 密钥 | 按目标站职责独立保留 |

下载版本与实际生效版本分离。私钥解析、派生公钥核对、持久化、运行快照发布完成后才报告成功；丢弃 PEM 仅保存版本不算更新。原子换钥、重启恢复、失败保持当前状态需要由适配实现提供。

现有证据只证明当前版本号及拉取接口，未证明历史密钥、kid、双钥过渡或中心撤销协议。客户端缓存公钥的影响必须单独验证。

## 可选功能

绑定请求位于控制根的 /profile/bind、/unbind、/bindto、/remapuuid。成员必须在服务层验证用户对角色的所有权，不能因为持有全站成员凭证就允许用户指定任意 UUID。

Union OAuth 不是目标站常规 OIDC 的别名。参考成员访问 /oauth2/backend 取得中心 publicKey，生成含 uid、nickname、email、expires_at 的 userInfo；对其 Base64 文本使用成员凭证计算 HMAC-SHA256 的 hex mac，再对 userInfo + "." + mac 用成员独立私钥做 RSA-SHA256 签名。token 对象使用中心公钥分块 RSA PKCS#1 v1.5 加密，跳转 /oauth2/continue。

成员提供 /api/union/member/oauth2/ 公钥和 /grant 入口。跨架构用户 ID 不一定是 PHP 的顺序整数；字段编码、身份命名空间和授权交互须确认，不能把上述流程重命名为标准 OIDC。

联合黑名单涉及按角色查邮箱与进服限制，属于独立授权和个人信息传输范围。第一阶段不主动增加管理 UI；如果中心需要该能力，先明确契约再实现。封禁只落实到目标定义的 join 能力，不任意扩大为全站禁用。
