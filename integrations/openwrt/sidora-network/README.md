# Sidora 软路由控制工具

该目录是主 OpenClash 的受限一次性工具，和 `../runtime-controller.mjs` 管理的 local-socks 分开。保存已部署工具的源码、依赖锁和恢复方法，便于重建；设备位置、凭据及具体部署验收回执保存在私有运维记录中，不随源码公开。

## 当前使用的热加载模式

现网采用 `update_mode=catalog_hot_reload`，复用 `../openclash-refresh.mjs` 的完整目录下载、规则三向合并、核心验证、`PUT /configs?force=false`、选择恢复、路由前后核验和失败恢复。它与原来的定时刷新持有同一组锁；没有第二套订阅下载器或新服务，也不执行旧版 restart 适配。默认自动周期保持原配置，App 手动请求只跳过该轮间隔检查。

手动入口兼容已审阅刷新器的 `catalog` 与 `passthrough` 输出模式，原样交给共享刷新器处理；不增加或恢复节点数量、固定节点存在性等业务门槛。其他输出模式仍拒绝。升级共享刷新器时，应将代码核对及 `config.json.refresh_sha256` 同步更新作为同一项部署步骤；摘要不一致时控制入口拒绝，自动刷新也不能签发新的运行证明。仅更新代码而漏掉该配置，会导致加载正常但 App 节点仍未匹配。

首次没有运行身份凭据时，即使订阅内容未变化也必须完成一次真实加载和读回；不能仅比较磁盘文件就授予节点身份。成功后记录进程 PID、starttime、boot ID 和实际配置摘要。Selector 的 `now` 与 Fallback/URLTest 的显式 `fixed` 都恢复并读回；自动组未固定的临时 `now` 不作为人工偏好保存。

后续自动刷新成功时，共享刷新器在持久化成功交易回执后调用本目录的本地证明函数，继续维护身份凭据。该函数核对同一轮运行时摘要、刷新代码摘要和进程身份，SSH 协议没有“强制认证”入口。配置或进程不一致时保持未核验，不按名称猜测。未变化且未执行加载的普通自动检查不伪造新证明。身份记录失败不会回滚已完成核验的正常网络加载；此时返回 `runtime_attestation=unconfirmed`，旧摘要失配后节点自然显示未核验。

`config.json` 必须填写真实核心路径（仅允许已审查的 `/etc/openclash/clash` 或 `/etc/openclash/core/clash_meta`）以及共享刷新模块的确切 `refresh_sha256`。升级共享模块时同步审阅并更新该摘要，未知版本拒绝控制。群晖运行镜像还必须包含标准 `openssh-client`，并以实际运行 UID 验证私钥和 known_hosts 的 0600 权限；仅准备密钥文件不等于接通。

## 固定边界

只接受 `sidora-network-v1 snapshot`、`fixed-ports`、`start UUID`、`start-hot UUID`、`operation UUID`。`start-hot` 对旧版配置直接拒绝，不降级为 restart。专用 SSH key 的 forced command 验证完整命令，不提供 Shell、端口转发、任意 URL、文件路径或服务名。生产配置固定在 `/etc/sidora-network/config.json`，root 所有且 0600；状态目录 0700，凭据、候选与旧配置从不返回给 Sidora。普通 API 仅返回脱敏状态、节点摘要与操作回执。

以下更新器适配属于保留的 `legacy_restart` 模式，现网热加载模式不调用这些 restart 步骤，也不把它们作为失败回退入口。

受支持更新器是现场读取的 OpenClash 0.47.156：SHA256 `0842b924b1eba9324666c414f42476c7b55f68411bd1f9c06c8644c415dfd01d`。同时要求 init 脚本 SHA256 `315d674bf3e29ea60bf4b15cb313b35c5689fe14596ed9f3e985620223bddff4` 和 `/etc/rc.common` SHA256 `143c915143c351bd96c5e8007d56e191b78975fd75a32709acd42243d68d230d`。版本标签不是校验依据。源码不同立即拒绝更新，不能自动升级 OpenClash、降级校验或直接把新脚本当兼容版本。只读命令不执行更新器。

`adapter-047156.mjs` 在每次操作的私有目录中从已校验原文件生成候选脚本，不覆盖原更新器：

1. 保留原订阅配置读取、请求头、下载、转换参数和关键词过滤函数。
2. 禁止暂存脚本获取、删除原订阅锁；外层 `worker.sh` 在整个下载、应用、核验和恢复过程持有同一文件描述符，并核对 inode。
3. 禁止原任务计数器和自动重启；原计数器已有任务或待重启标记时返回 busy。原脚本的无变化下载也走候选检查，组合动作仍执行一次重启。
4. 原文件替换改为私有候选复制，使用核心退出码和 YAML 结构再次检查；Ruby 异常不再走“只下载但仍替换”的宽松分支。
5. 禁止失败后临时改变 DNS、防火墙和 watchdog 的直连重试；下载失败保留原配置。原 OpenClash 启动流程仍负责正式覆写和分流规则，没有另建配置生成器。
6. 暂存下载的 URL/自定义请求头日志关闭，内部诊断仅进操作目录的私有文件，不复制到共享网页日志或 API。
7. 正常路径只执行一次同版 init 的原生 restart 流程（通过 `/etc/rc.common` 执行私有、带核验点的副本；不替换原 init）。Ruby YAML 校验、关键词过滤及写文件异常均显式传递为失败，不再由后续 rm 或 rescue 掩盖。配置检查失败不重启；新配置启动失败可额外执行一次恢复重启，恢复失败为 unknown。

## 运行与真实结果

请求先写入唯一操作回执，再启动脱离 SSH 会话的一次性子进程。相同 UUID 重试只返回原状态。另一个进行中或 unknown 的操作阻止新更新；不根据超时自动重放。`launch.lock` 是极短的请求串行锁；若进程恰在创建后被 SIGKILL，保留锁并拒绝新操作，人工核验 active 回执及进程后才能清理，不能靠时间自动删除。

阶段为 queued、downloading、validating、restarting、verifying；失败恢复还有 rolling_back。每轮 apply/rollback 都有独立 nonce。私有 init 强制走完整原生生成链，关闭该轮 quick start；源配置复制到 TMP 后校验候选摘要，原覆写链结束且 mv 成功后记录 runtime 摘要，procd 的第一次实际 exec 前记录同一个 shell/核心 PID、starttime、boot ID 和产物摘要。核验必须将这些回执与当前实际 `-f` 进程对应，只有新 PID 或各自两个 hash 不算应用证明。私有 init 加载后仍将 initscript 指向原 `/etc/init.d/openclash`，rc.common 的服务名称与脚本引用保持 openclash。原进程仍响应或 restart 返回 0 均不算完成。操作全过程核验 local-socks 进程身份不变。选择恢复每次写入后重新 GET：Selector 核对 now，Fallback/URLTest 核对 fixed，不要求自动组 now 永远等于固定候选。返回 204 却未保留选择不能写 verified；已从新配置移除的组或候选作为 unavailable 单独记录。选择快照保留原 Selector 和手动固定的自动组；新配置已删除的候选不强制恢复，自动组正常排序不被旧的临时自动选择覆盖。

第一次安装没有 `loaded.json` 时，节点身份显示未匹配。首次受控更新并通过核验后建立“运行进程＋实际配置摘要”回执，后续 snapshot 复用连接指纹映射。外部更改配置或重启导致绑定失效时再次显示未匹配，绝不按名称猜对应。逐组切换不依赖质量映射，仍可使用。名称改动而连接参数不变会得到相同 node_key；转换器修改连接参数时可能无法匹配 IPQuality，需独立核对，不降级为名称匹配。含外部 proxy-providers 的节点不在静态配置中时也安全显示未匹配。

成功回执使用 loaded.json schema 2；旧版没有转换/启动关联证明的 loaded 回执不再授予 identity_verified。第一次 launch 成功记录后删除一次性 pending 标记，后续原生 procd respawn 不依赖旧操作文件、不重做本次应用证明，新进程会显示未匹配直到下次受控更新。完整私有备份包含旧 raw、旧 runtime、选择和阶段证明。

回滚前重新核对当前 raw 仍是本操作候选，runtime 仍是原版本或本次已记录产物；发布恢复文件前再次比较 raw 摘要。发现外部编辑或来源不明变更，保留现场与备份并返回 unknown/rollback_conflict，不覆盖别人的配置。该保护与原订阅锁配合，不声称能阻止不遵守锁的 root 程序在最后一次比较与 rename 之间强行并发写入。

`fixed-ports` 只读 local-socks 已提交的 applied.json、同代 manifest/config、独立核心及实际进程；没有成功证据时 `verified=false`，不返回伪装为已应用的映射。它不触发 poller，不重启 NPM/GOST/local-socks。完整外网通断不由该接口声称。

## 安装和重建准备

- 先记录当前 raw profile、OpenClash 版本与 updater hash、主实例和 local-socks PID/配置/核心摘要、当前订阅锁和 cron。不能用示例路径代替现场值。
- 软路由需要 Node ≥18.20.8、Bash、flock、现有 OpenClash Ruby/curl/uci 依赖；目录 `package-lock.json` 固定 js-yaml 4.1.1。用 `npm ci --omit=dev --ignore-scripts` 在适合该 CPU 的打包环境准备依赖，不引入安装脚本。该工具主要是 JavaScript，js-yaml 无本地扩展。
- 将本目录 cli/toolkit/adapter/worker 和 package 文件、node_modules 安装在 `/etc/sidora-network/`。预先创建 root 所有的 `/etc/sidora-network/state`（0700）；只读命令不会自动创建目录。代码 root 所有，非 root 不可写；`worker.sh` 0755，配置与 controller-token 0600。只读依赖 `/etc/local-socks/convert-any-proxy-to-local-socks-stable.js`，它须仍为仓库已审查版本。
- 依据 `config.example.json` 填真实配置路径和 controller secret 的文件位置。密钥仅存在私有文件，不提交仓库。
- Sidora 群晖容器单独准备 SSH 私钥和严格固定的 known_hosts；私钥与 known_hosts 文件均由容器运行用户所有且 0600。不要使用通用 root 管理 key。
- Dropbear authorized_keys 对专用 key 加 `command="/usr/bin/node /etc/sidora-network/cli.mjs",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty`。先核对当前 Dropbear 支持的限制选项，未验证前不开放调用。建议额外限制来源为 Sidora 宿主地址。
- 群晖到控制器/IPQuality/SSH 走明确内网地址，不经过将重启的代理出口。不开放公网 9090 或新的管理 HTTP 服务。
- 安装前备份 root-private 配置和订阅数据；维护窗口中首次更新核验实际排序、保留的选择、回滚以及 local-socks 未受影响，之后才启用 Sidora 的真实 network 入口。

## 恢复和升级

代码来自仓库，依赖来自 lock。私有备份至少包含 config.json、controller-token、SSH 授权 key 清单及 state/（其中含代理秘密）；按个人秘密备份策略加密保管，不归 Git。已验证回执绑定旧进程，新设备恢复后应重新核验，不复制 loaded.json 冒充当前实例已验证。

更新工具前让现有操作结束并停止新请求。更新 OpenClash 后对照新源码重新审查适配器、增加新 hash 和本地测试，未知版本默认拒绝更新。恢复 unknown 时查看 receipt/replacement/previous.yaml 和真实进程，先恢复配置或核验完成，再维护回执；没有任意“强制成功”远程 API，也不自动删除锁重试。

每次操作的私有备份保留在 state/UUID，当前不自动清理，以免删除唯一恢复依据。个人使用可定期在确认无 active/unknown 操作后，归档保留最近若干已完成目录。长期高频使用前再加明确定义的保留策略。

## 本地验证

`npm ci --ignore-scripts` 后运行 `npm test`。默认校验协议与未知版本拒绝；完整旧版适配测试需要提供从可信设备只读取得且 hash 正确的源码：

```sh
OPENCLASH_TEST_SOURCE=/absolute/private/openclash-update.sh npm test
```

测试在 `/tmp` 编译合成核心、创建隔离服务脚本并运行真实 Bash/Node 子进程，覆盖断开请求后完成、无变化仍只重启一次、失败保留、假成功回滚、恢复失败阻塞新任务。完整测试还要求源码同目录有已校验的 `openclash.init` 和 `rc.common`，并实际运行该 rc.common 副本及私有 init，使用隔离 procd/网络替身验证服务注册和实际 exec 的 PID 关联。测试的 OpenWrt/Ruby 下载边界为合成替身，不能当成现网部署验收；过滤函数与 hash 对应原文保持一致，并独立核对。源脚本本身不复制进仓库。
