# D2 本地实现与部署门禁

本页描述 `0.4.0-dev` 的接口和迁移步骤，不表示已经部署。
普通订阅仍走 `inventory -> node-health -> healthy`；固定端口消费者改为
`NAS 同代私有订阅包（inventory + map）-> 显式转换 -> 本地验证/应用`。
旧顺序转换器不能表达空槽，不要让两个更新入口同时写同一份配置。

## 能力与兼容性

- `/current.json` 仍是 schema 2，仅供普通客户端排序。风险、不可达、未知、重复别名都保留；排序失败原序返回。
- `/local-socks-map.json` 是 schema 1，包含 production purpose、namespace、server_instance_id、端口计划、实例清单和明确空槽。未配置实例 ID 或无法完整映射时返回 503，普通排名仍可发布。
- 探测按连接去重，输出按订阅实例保留；一个连接最多占一个稳定槽。`other` 仍只在 rebuild 重新排序。
- AI 指标为站点/地区探测，未验证登录或对话。ChatGPT 单次站点/支持地区项12分、同服务出口独立地理一致3分，Claude10分。旧 Yes/Native 不授新资格。
- 旧健康加分和晋级资格重新累计；原已满六天且仍在原槽/原连接的节点可获一次迁移宽限，首次迁移提交后七个日历日到期，最多延迟一个有效日，不叠加、不加分、不晋级。
- 同名不同连接可独立探测；有歧义的 dialer 依赖会拒绝。固定消费者目前对 dialer-proxy 或未审阅的复杂配置引用拒绝整批，不静默删除节点。
- 严格 fingerprint 校验同代包内的订阅与映射，改名、新增或连接轮换不会使消费者误取另一份实时订阅。快照中的远端出口仍可能在扫描后失效；最后已应用配置继续运行，可等下一次定时 maintenance 或使用现有手动入口，不新增自动扫描控制回路。

## 本地验收与真实校准

```bash
python -m pytest -q
node --test tests/integration_node_health_operator.test.js
python tools/generate_region_rules.py --check
```

OpenWrt E2E 需要 Linux、`cc`、Node、`flock` 和可用的隔离测试端口。
夹具运行的是临时协议核心，用于进程、SOCKS 握手和崩溃恢复验证，不能代替真实 Mihomo 的现场验收。

镜像发布前还必须通过：

```bash
python tools/check_release_gate.py --file deploy/calibration/site-region.json
```

2026-09-12 已通过现有 ImmortalWrt local-socks 节点采集 ChatGPT 和 Claude 的真实正向 trace：HTTP 200、传输成功、主机匹配、公开出口及支持地区 CA，均由当前探测器判定为 available。脱敏记录位于 `deploy/calibration/site-region.json` 和 `deploy/calibration/claude-site-region.json`，CI 同时回放两份记录。原始出口 IP 已替换，识别性字段已移除；采集未修改路由器配置或重启服务。这只验证站点/地区探测，不代表账号、对话或整套部署验收通过。
负向、挑战、503 和边界用合成 fixtures 与可获得的真实样本，不要求人为制造生产故障。
校准文件要求 `calibration_kind=real`、`reviewed=true`、`original_result_class=available`、环境类别、带时区的捕获时间、探测契约版本1、site，以及 response 中的 transport_code/http_status/host/sanitized_body。
校准中的出口 IP 可替换成测试用的公开地址，但必须先确认原始响应确实满足公开出口及成功契约；不能把原本失败的响应修成成功。
检查器仅验证已审阅资料的格式及正向回放，真实性和环境匹配由发布审阅确认。单元测试替身不构成校准记录。
缺失或不合格时 CI 会阻止发布包含 B 改动的镜像；不得以合成测试全绿代替这个门禁。

## 历史副本预演

只复制本项目 `current.json`、`state.json` 和 current 指向的 state-snapshot 到独立私有目录。
不要在运行目录实例化恢复器，也不要把历史资料放入仓库或镜像。

```bash
python tools/rehearse_migration.py \
  --input-dir /path/to/private-copy/data \
  --output-dir /path/to/new-private-preview \
  --timezone Asia/Shanghai
```

工具拒绝输入/输出目录重叠及覆盖已有输出；选择 current 配对的快照，验证重复迁移、失败重入及布局保持。
输出的 `summary.json` 为脱敏汇总，`state.migrated.json` 是私有副本，不直接覆盖运行状态。
自定义政策用 `--policy-file` 传 JSON PolicyConfig 覆盖项。灾难恢复只有旧备份、无法证明剩余迁移宽限未消费时使用 `--restored-backup`，关闭剩余例外而不重领。
预演中健康项归零不等于首轮发布的净减分；当轮新证据和 AI 子项变化需另作差异表。

## NAS 配置

公开配置模板及 Compose 新增：

```dotenv
NODE_HEALTH_NAMESPACE=node-health-production
NODE_HEALTH_SERVER_INSTANCE_ID=YOUR_REVIEWED_STABLE_ID
```

实例 ID 是一次选定、稳定且唯一的标识，不是每次重启随机产生，也不是认证密钥。
空 ID 允许普通排名工作，但不允许固定端口目标。普通 `/healthz` 保留匿名 HTTP 200 探活，错误详情变成安全码/阶段/诊断 ID。
进度的 percent 为阶段百分比；waiting-retry/rechecking 提供轮次、待复检数和 next_retry_at。
默认地区规则来自 `node_health/region_rules.json`；配置中的自定义 regions 仍可覆盖，消费者采用服务发布的 effective region，不重复猜地区。

### 从 59aec6a 修复同代订阅交付

1. 将 node-health 镜像改为已审阅修复版本的固定 digest。若 `.env` 中已有 `NODE_HEALTH_IMAGE`，只改该值；若 Compose 直接填写 image，改相应服务的 image，不同时新增第二处配置。Container Manager 只重建 node-health 服务，无需因此重建 Mihomo、Sub-Store 或改变网络。
2. 复用现有 `/app/data` 挂载。服务在其中创建 `runtime-bundles` 私有目录（0700，文件0600），不新增容器或挂载，也不写入 `/app/reports`。该目录包含完整订阅凭证，备份必须限制访问。当前和前一已提交代保留，未提交或已回收代不会通过接口提供；清理失败只记录安全日志。
3. 复用现有非空 `http.api_token`。已配置 token、namespace 和 server_instance_id 时，`config.yaml`、Compose 结构和现有环境变量无需额外修改。私有接口即使监听 loopback 也不允许空 token；本次复用的是现有管理 API 权限，不是独立只读权限。
4. 更新后核对 `/version` 的 source_revision 和 `runtime_bundle_schema_version=1`。旧 current/state 没有完整输入，包接口会返回 404，不自动重建排名。默认等下一次定时 maintenance 或明确触发一次，生成配套产物；按已有身份、时效规则复用检测历史，不清空状态、不强制 rebuild，也不重置 M1。不能把新下载订阅填入旧映射，暂不提供猜测式补包工具。
5. 路由器更新同版本 controller，并配置 `RUNTIME_BUNDLE_URL` 和 `RUNTIME_TOKEN_FILE`。token 文件由 root 持有、权限0600，只存现有 NAS token，不把值放入命令行、URL、公开文件或日志。旧 SOURCE_URL/RANKING_URL 可留作历史参考，但新轮询不再读取它们，也不会在失败后退回实时 Sub-Store。
6. 先下载包、离线转换核验实际端口与配置差异，再在已批准维护窗口应用路由。NAS 镜像更新不会安装路由脚本；首次 D2 的 profile、实例、端口及回滚准备仍须完成。

`GET /api/v1/runtime-bundles/latest` 用 `Authorization: Bearer ...` 获取一个 JSON 包；同接口最后一段换成 `bundle_id` 可读取保留的指定代。包 schema=1，含唯一发布 revision、base64 原始订阅字节、字节 SHA-256 和完整 map。mapping_version 不是包 ID，未变的映射可对应不同扫描代。原始订阅在扫描前限制16MiB，包限制32MiB。

私有响应带 `Cache-Control: no-store`；鉴权失败401，缺少或回收代404，损坏/不可读503。使用已有 HTTPS 或受限可信 LAN；HTTP 的 Bearer token 不提供传输加密。下载不跟随重定向，凭据只用于配置的地址。公开 current/map/report 不增加订阅或凭据。运行恢复仍先于下载/退避；下载或转换失败不更改当前代理配置。

## 路由器只读预检

先核对实际服务实现及路径，再决定安装或变更；本页命令不是远端执行授权。

1. 确认 `node --version`、`flock` 的非阻塞文件描述符锁能力、js-yaml，以及 Node 可读取本机 `/proc`。
2. 确认 ubus/procd 可给出此服务的 PID，或提供明确的 SERVICE_PID_FILE。PID须对应固定核心及同一 `-f CONFIG_PATH`，仅 status 退出0不够。
3. 核验实际 core 哈希、配置外壳、DNS、两处IPv6、LAN/mixed监听、权限和代理引用；不默认采用仓内旧 direct 的 fake-IP 模板。
4. 对比当前端口到连接 key 与新目标，尤其 AdsPower 正在使用的端口。首次差异先保留旧运行态，批准具体 mapping_version 后才应用。
5. 核对导出最终目录与配置、核心、脚本、PID、env、Node/js-yaml、输入文件及缓存不重叠；不得把运行依赖放入会被替换的导出目录。

`flock` 是新增部署依赖；缺失时两个入口在修改缓存/配置或启动服务前失败。
锁由内核随进程退出释放，不依赖可能遗留的 PID 目录。不得用删除锁文件的方式处理并发。

## 安装清单与候选生成

固定同一审阅版本的下列文件，不在每次轮询时从 main 拉取脚本：

- `integrations/openwrt/apply-ranking.sh`
- `integrations/openwrt/check-ranking.sh`
- `integrations/openwrt/convert-ranking.mjs`
- `integrations/openwrt/runtime-controller.mjs`
- `integrations/local-socks/convert-any-proxy-to-local-socks-stable.js`
- 按 `node-health.env.example` 建立的私有 env，以及已核验的 runtime-profile.yaml。

复用实际已有 SERVICE_SCRIPT 和独立核心；不要默认替换 procd 服务。使用仓内 service-lib 时，普通启动只使用已配置核心，不再自动从 OpenClash 复制升级。
依赖安装/核心升级另行核验，不能改回执哈希来绕过恢复。

私有 env 必须填写 APPROVED_NAMESPACE、APPROVED_SERVER_INSTANCE_ID、APPROVED_PORT_PLAN_VERSION、RUNTIME_PROFILE_PATH 和 APPROVED_RUNTIME_PROFILE_HASH。
profile 是已审阅的现用配置外壳，不是通用模板；内部存在不可解析的引用时应先处理差异。
profile 哈希可用转换模块导出的 `runtimeProfileHash()` 本地计算，只输出摘要，不输出含认证参数的配置。
独立 `convert-ranking.mjs` 可写候选及无凭据 manifest/TXT，尚不调用服务；所需批准参数与正式入口相同。

正式入口保持为：

```text
apply-ranking.sh INVENTORY_YAML MAP_JSON MAPPING_VERSION
check-ranking.sh
```

同一时刻仅启用一个定时更新入口。新轮询使用 NAS 的 RUNTIME_BUNDLE_URL，不再配置 Sub-Store 实时 SOURCE_URL 作为固定端口输入。
无可信映射/过期/实例或 fingerprint 不符时拒绝新应用；默认新目标最长36小时，旧已应用配置不会因此自动关闭。

## 提交、恢复和可观察性

- 配置/核心语义相同且进程和监听就绪时不重启，纯显示标签只更新manifest/TXT。
- HY2同一 ports 范围复用仍合法的具体端口；真正连接或范围变化仍需应用。其他未支持的 ports 选项拒绝自动物化。
- 首次内部命名改变也可能需要重启；有实际配置变化时会中断 local-socks 的已有连接，回滚可能再次中断。维护窗口必须先明确。
- 首次核验保存 legacy baseline；生成目录中的 baseline.json 标识原始恢复锚点，常规清理保留它。
- config、TXT、manifest和核心快照先落盘，pending记录未完成事务，applied.json是唯一提交选择器；旧applied.version/sha256仅为派生兼容视图。
- 启动/下次检查先恢复pending和本地运行态，再判断上游退避或下载；NAS离线不阻止本地自愈。
- 导出恢复失败不阻止尝试恢复配置与服务。恢复失败保留相关代际资料，停止继续应用新目标。
- 有界错误在 stderr 和 `CACHE_DIR/last-error.json` 中，包含 code/phase/diagnostic_id，不打印解析源片段、URL查询串或子命令stderr。
- NAS报告/TXT仅是目标；路由器本地applied.json及配套TXT表示该设备已验证应用。握手不等于所有代理出网成功，不要删除不可达/风险节点来通过检查。

## 发布和回滚边界

先通过本地验收和真实正向校准，准备实际端口diff、运行配置/核心/导出/状态配对备份、维护窗口及回滚清单，再执行获准部署。
NAS更新期间暂停旧路由器自动顺序更新入口，避免API短暂失联被旧流程当成原序覆盖；不必因此停止现用代理。
固定镜像digest和脚本版本，不能混合旧runner/schema2转换器与新协议。
只回滚到包含新证据验证/迁移规则的兼容镜像，并沿用当前迁移元数据；完全旧程序无法理解新版本字段，不得直接写入新活动目录。
恢复旧备份须再次迁移；无法证明M1未消费时关闭剩余例外。代码回滚不延长首次期限。
撤回端口改造可恢复配对的原运行配置，但不能未经审核重新启用旧的自动顺序覆盖流程。
