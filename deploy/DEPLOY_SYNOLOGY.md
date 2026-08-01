# 群晖 Container Manager 部署与运维

这套部署只增加两个容器：

- `ipquality-node-health`：每天调度、检测、评分、稳定槽位决策、报告和 HTTP 状态接口。
- `ipquality-mihomo-probe`：只负责把每个订阅节点临时暴露成容器内部 SOCKS 监听端口。

Mihomo 控制器和探测端口都不映射到群晖宿主机。群晖只开放 node-health API，默认是 `18887`，以避开已有服务占用的 `8787`。

## 1. 最终数据流

```text
机场订阅
  -> Sub-Store inventory（保留所有真实节点，不做健康过滤）
  -> 群晖 node-health 检测
  -> current.json（排序、拒绝列表、稳定槽位 1-3）
  -> Sub-Store healthy（运行健康排序脚本） -> 手机、电脑、OpenClash 等订阅
  -> OpenWrt 下载 healthy -> 原 rule_conf 转换器 -> local-socks / AdsPower / TXT
```

扫描输入必须是 `inventory`，普通订阅客户端与当前简化部署的 OpenWrt 都使用 `healthy`。不要让 node-health 读取 `healthy`，否则会形成反馈循环，已经被过滤的节点无法重新恢复。本文后半部分保留的 `inventory + current.json` OpenWrt 轮询器只是可选高级方案，本次不部署。

日常排序不需要再通过 `rule_conf` 或其他 Git 仓库反复拉取、覆盖、提交和推送。`current.json` 就是带版本的实时排序源，Sub-Store Script Operator 在服务端读取它；若你习惯用 `rule_conf` 托管脚本，只需一次性托管静态的 `health-ranking-operator.js`，动态排名数据仍直接读取群晖 API。

## 2. 准备目录

将本项目放到群晖的 Container Manager 项目目录。持久化根目录由 `.env` 的 `NODE_HEALTH_STORAGE_ROOT` 指定，建议使用绝对路径，例如 `/volume1/docker/YOUR_PROJECT_DIR`：

```text
/volume1/docker/YOUR_PROJECT_DIR/
├── data/       # current.json、state.json、状态快照和 audit-jobs 任务状态
└── reports/    # 每日、版本归档、临时订阅审计和槽位变更报告
```

可以在 File Station 创建这两个目录，也可以在项目目录通过 SSH 执行：

```bash
mkdir -p /volume1/docker/YOUR_PROJECT_DIR/data
mkdir -p /volume1/docker/YOUR_PROJECT_DIR/reports
```

查询运行 Container Manager 的 DSM 用户 UID/GID：

```bash
id "你的DSM用户名"
```

将持久化目录所有者设为这个用户。下面的 `1026:100` 只是示例，必须与实际 `id` 输出一致：

```bash
chown -R 1026:100 /volume1/docker/YOUR_PROJECT_DIR
chmod -R u+rwX,g+rwX /volume1/docker/YOUR_PROJECT_DIR
```

不方便使用 SSH 时，在 File Station 的“属性 -> 权限”中给该 DSM 用户赋予读写权限，并应用到子目录。

## 3. 配置项目环境变量

复制 `deploy/.env.example` 为项目根目录的 `.env`，或在 Container Manager 创建项目时填写同名环境变量：

```dotenv
PUID=1026
PGID=100
TZ=Asia/Shanghai
NODE_HEALTH_STORAGE_ROOT=/volume1/docker/YOUR_PROJECT_DIR
NODE_HEALTH_BIND_IP=192.0.2.2
NODE_HEALTH_PORT=18887
NODE_HEALTH_API_TOKEN=替换为一段足够长的随机字符串
PYTHON_IMAGE=python:3.12.11-slim-bookworm
MIHOMO_IMAGE=metacubex/mihomo:v1.19.29
SUB_STORE_INVENTORY_URL=http://192.0.2.2:3001/download/collection/inventory?target=ClashMeta&noCache=true
```

需要按实际环境修改：

- `PUID`、`PGID`：上一节查到的 DSM 用户身份。
- `NODE_HEALTH_STORAGE_ROOT`：必填。状态和报告的群晖绝对路径；先创建并授予 `PUID/PGID` 读写权限。
- `NODE_HEALTH_BIND_IP`：群晖的局域网 IP。也可填 `0.0.0.0`，但必须用 DSM 防火墙限制为局域网访问。
- `NODE_HEALTH_API_TOKEN`：保护手动维护/全量重建接口；不要提交到 Git，也不要写进报告。
- `SUB_STORE_INVENTORY_URL`：Sub-Store 完整节点集合的 Clash YAML 下载地址。保留 `target=ClashMeta&noCache=true`，避免 Python 客户端拿到默认 JSON，也避免上游机场资源继续使用 Sub-Store 默认的一小时缓存。
- 容器内的 `127.0.0.1` 指向容器自身，不能用它访问运行在群晖上的 Sub-Store；URL 必须使用群晖局域网 IP 或同一个 Docker 网络中的服务名。

可在群晖 SSH 中生成 API token：

```bash
openssl rand -hex 32
```

Python 基础镜像固定为 `3.12.11-slim-bookworm`，Mihomo 固定为 `v1.19.29`，都不要改成 `latest`。将来升级时先修改对应镜像变量，手动执行一次 `rebuild` 验证，再保留新版本。

默认快速探测并发为 8，完整 IPQuality 并发为 2，位于 `deploy/config/config.example.yaml`。Socket 数量不是主要限制，完整 IPQuality 使用的第三方数据源更容易限流，不建议盲目提高并发。

## 4. 在 Container Manager 创建项目

1. 打开“Container Manager -> 项目 -> 新增”。
2. 项目名称填写 `ipquality-node-health`。
3. 来源选择本项目所在目录，Compose 文件选择根目录的 `compose.yaml`。
4. 确认项目能读取 `.env`，或在项目环境变量区域填写上一节的变量。
5. 构建并启动项目。

项目会在群晖本地构建 `ipquality-node-health:local`，同时拉取固定版本的 `metacubex/mihomo:v1.19.29`。正常状态应看到两个容器均为 healthy。

如果 `mihomo-probe` 的 healthcheck 一直失败，先在日志中确认镜像已经正常启动并监听 `9090`。不要给 `9090` 增加宿主机端口映射，它只允许 node-health 在私有 bridge 网络中访问。

## 5. 启动后检查

在群晖本机或同一局域网执行：

```bash
curl -fsS http://192.0.2.2:18887/healthz
curl -fsS http://192.0.2.2:18887/version
```

再查看 `ipquality-node-health` 日志，确认：

- 配置文件成功加载；
- `inventory` URL 可以下载；
- node-health 可以访问 `http://mihomo-probe:9090`；
- `/app/data`、`/app/reports` 均可写。

探测配置通过 Mihomo 控制器的内存 `payload` 下发，不会把包含节点密码的 YAML 写进群晖持久化目录。出现 `Permission denied` 时不要把容器永久改为 root；修正 `PUID/PGID` 和两个持久化目录权限后重建项目。

## 6. 首次全量检测并建立 1-3 槽位

如果目录中存在早期五槽位原型生成的 `data/current.json`，升级容器后先完成本节的 `rebuild`，确认新文件只含槽位 `1-3`，再更新 Sub-Store Operator 和 OpenWrt 转换器。新组件会主动拒绝仍含槽位 `4/5` 的旧排名，避免不同组件对端口含义理解不一致。

首次部署不要等待日常任务，直接手动发起全量重建：

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer 你的NODE_HEALTH_API_TOKEN" \
  "http://192.0.2.2:18887/api/run?mode=rebuild"
```

`rebuild` 会：

1. 下载完整 `inventory`；
2. 对所有可连接节点做快速检测；
3. 对所有可用节点执行完整 IPQuality；
4. 按地区重新排序，并自动选出每区最优的三个节点作为固定身份槽位 1-3；
5. 生成报告和版本状态快照，最后以原子替换 `current.json` 作为新版本生效点。

深检允许少量第三方接口失败：默认要求全局以及每个有可用节点的地区至少 `80%` 的深检拿到与快速检测一致的出口 IP。除此以外，每个地区还必须有同等比例的有效决策证据，例如至少两个可用风险源、明确的 ChatGPT 状态和地区证据，或明确的质量红线。仅仅拿到一份 `Score` 全为 `null` 的 JSON 不算可发布证据。门槛不满足时整轮失败，旧 `current.json`、稳定槽位和 OpenWrt 配置继续生效。

这里的“原子”是单个可变文件的原子替换，不是把状态和所有报告合成一个跨文件事务。发布顺序是报告 -> `data/state-snapshots/<version>.json` -> `data/state.json` -> `data/current.json`；最后一个 `current.json` 是权威提交点。若在最后一步前中断，重启后仍按旧 `current.json` 选择同版本快照，不会把新槽位状态误配给旧排序。极少数中断可能让磁盘上的报告版本暂时领先于权威 `current.json`，这是因为报告只用于观察、不参与恢复；核对某次报告时应比较其中的 `version` 与当前版本。

运行接口返回 `202 Accepted` 只表示任务已经进入后台。用下面的接口查看 `running`、`running_mode`、`last_success`、`last_error`、`started_at` 和 `progress`：

```bash
curl -fsS http://192.0.2.2:18887/healthz
```

任务运行时，`progress` 会显示当前 `phase`、订阅总节点数、当前阶段已完成/总计/剩余节点数及 `percent`。百分比是当前阶段的节点完成度；`quick-scan` 完成后进入更耗时的 `full-scan`，会从该阶段的 0% 重新计算。任务完成或失败后 `running` 变为 `false`，实时进度清空，结果分别记录在 `last_success` 或 `last_error`。

HTTP 服务仍能响应时 `/healthz` 保持 `200`，避免第三方接口短时故障造成 Container Manager 重启循环；最近一轮检测失败时，JSON 会变为 `status: "degraded"` 并给出 `last_error`。下一轮成功后恢复为 `status: "ok"`。因此容器显示 healthy 只代表服务进程可用，日常监控还应检查 JSON 状态和 `last_success` 日期。

全量检测耗时取决于节点数和第三方接口速度，可能持续较长时间。任务运行中不要重启项目；重复调用运行接口会返回 `409 Conflict`，而不是并发启动第二次扫描。若系统暂时无法创建后台检测线程，接口返回 `503 Service Unavailable`，服务会释放运行锁并在 `/healthz` 记录错误；每日调度会按一小时间隔重试，当天最多三次，不会因单次启动失败永久停止。

查看结果：

```bash
curl -fsS http://192.0.2.2:18887/current.json
```

同时检查持久化目录：

```text
/volume1/docker/YOUR_PROJECT_DIR/data/current.json
/volume1/docker/YOUR_PROJECT_DIR/data/state.json
/volume1/docker/YOUR_PROJECT_DIR/data/state-snapshots/版本号.json
/volume1/docker/YOUR_PROJECT_DIR/reports/YYYY-MM-DD.md
/volume1/docker/YOUR_PROJECT_DIR/reports/YYYY-MM-DD.json
/volume1/docker/YOUR_PROJECT_DIR/reports/alerts/latest-run.md
/volume1/docker/YOUR_PROJECT_DIR/reports/alerts/slot-changes-latest.md
/volume1/docker/YOUR_PROJECT_DIR/reports/alerts/YYYY-MM-DD-版本号.md
```

`data/current.json` 是服务内部的完整当期结果；HTTP `/current.json` 只公开 Sub-Store/OpenWrt 所需的版本、地区稳定槽、动态白名单和拒绝列表，不公开节点名称、出口 IP 或原始检测详情。`state.json` 保存下一轮决策需要的连续通过次数、可信深检和槽位冷却信息；`state-snapshots` 默认只保留最近三个，并通过版本与 `current.json` 配对。

每日 `YYYY-MM-DD.md/.json` 是该日期最后一次写入的完整报告，同一天重复运行会覆盖同名日报。`latest-run.md` 每次发布都会更新，展示当前 degraded/unavailable/absent 槽位；`slot-changes-latest.md` 首次创建后只在真实身份变化时更新，因此不会被下一轮“无变化”覆盖。每日完整报告默认保留 30 天，带日期和版本号的槽位变更历史不随它清理。

如果状态文件不存在或其中没有任何已记录的稳定槽位身份，服务会自动把计划任务或手动 `maintenance` 升级为 `rebuild`。仍在 inventory 中但暂时 unavailable 的槽位在阈值前仍算有效历史；已从 inventory 消失的身份会在当轮释放。损坏且无法解析的状态文件不会被静默忽略，服务会停止发布并要求从备份恢复或由你明确清理后重建。

## 7. 两种运行模式

### 日常稳定维护

配置中的调度器每天 `03:30` 自动执行：

```http
POST /api/run?mode=maintenance
```

它会对全部节点快速检测；完整检测所有稳定槽位、全部新节点和出口 IP 变化节点，并按每个地区的当前动态排名分段抽检约四分之一。每个四节点排名段优先选择最久未深检的成员，因此正常情况下约四天覆盖一轮，不会再在 48 小时时集中触发整批深检。每区当前最高分的动态候补每天额外深检，用于积累连续晋级证据。

稳定槽位 `001-003` 是三个无序的固定身份，不是“001 比 003 更优”的实时排名。`maintenance` 以身份稳定为第一优先级：

| 检测情况 | 稳定槽位处理 | 固定端口结果 |
|---|---|---|
| 新候补仅略高于当前节点 | 不替换 | 继续指向原身份 |
| 高置信候补满足全部自动晋级门槛 | 每区本轮最多替换一个可比较的最弱稳定节点 | 仅被选中的固定端口改变身份 |
| 单次超时或连续第 1-2 次不可用 | 保留原 `node_key`，恢复后计数归零 | 端口可能暂时不可用，但不改指向 |
| 仍在 `inventory` 但连续第 3 次不可用 | 用最高质量合格候补替换该槽位 | 只改变对应固定端口的身份 |
| 节点从 `inventory` 消失 | 当轮释放，并尽量用最高质量合格候补替换 | 只改变对应固定端口；无候补则留空 |
| 明确触发质量红线 | 只用本轮重新深检通过的最高分合格候补替换这个槽位 | 仅该端口变更身份，其他两个槽位不动 |

质量红线必须是明确结论，例如地区不匹配、出口采样不稳定、Tor/DNSBL、多个风险源同时高风险，或 AI 服务明确返回 `Block/WebOnly/APPOnly` 等不可用或受限状态。单次稳定节点出口 IP 变化只会重置置信度并强制绑定新 IP 深检，不会单凭变化换槽。普通超时、第三方风险接口失败以及 AI 检测返回 `Failed/Unknown` 都不是新的红线；此前健康的槽位会保留但标记为 `degraded`，也不能作为新槽位候选。如果同一出口 IP 已有可信红线，模糊结果不能解除它，节点继续被拒绝，直到新的可信 clean 深检通过。

日常允许一个严格受控的自动晋级例外。候补必须同时满足：

- 至少连续 `3` 次完整检测通过，达到高置信度；
- 至少 `2` 个风险评分源返回有效数据，AI 可用性为明确通过；
- 默认 3 次出口采样至少成功 2 次，出口 IP 一致，实际地区与节点地区一致；
- 综合分至少比当前“可比较的最弱稳定节点”高 `20` 分；
- 同一地区本轮最多晋级 `1` 个节点；
- 该地区任一稳定槽位距离上次身份变化，至少已经冷却 `3` 天。

“可比较”只包含当前存在、可用且检测数据足以比较的稳定节点。阈值内的 unavailable 稳定节点不参与“最弱节点”比较，因此自动晋级不能借一次掉线清退它；从 inventory 消失的身份则按缺失规则立即释放。如果该地区尚在冷却期，或没有可比较的稳定节点，本轮不执行性能晋级。

除了当前分差，服务还会核对上一轮可比得分是否同样至少领先 `20` 分，以过滤单日偶然峰值。冷却期只限制“为了更高质量而晋级”，不阻止明确质量红线的安全替换。每次晋级、红线替换或 `rebuild` 后，都会重新计算该地区的 3 天晋级冷却期；同一地区仍然遵守每轮最多晋级一个节点。

稳定槽位之后的动态节点，也就是逻辑上的第 4 名及以后，只有本轮可信深检成功的节点才更新质量分；未轮到的节点保留上一轮可信分数和相对质量依据。动态节点确认不可用或触发红线时仍可直接从 `healthy` 输出移除。

这项策略的明确代价是：某个 AdsPower 固定端口可能在节点恢复前暂时不可用。但它不会因为一次网络波动或普通分数变化悄悄指向另一个身份；只有明确质量红线、满足全部门槛的受控晋级或手动 `rebuild` 才能改变槽位身份。

这些门槛都可以在 `deploy/config/config.example.yaml` 的 `policy` 中调整：

```yaml
promotion_enabled: true
full_audit_daily_fraction: 0.25
promotion_challengers_per_region: 1
promotion_min_full_passes: 3
promotion_score_margin: 20
promotion_max_per_region_per_run: 1
promotion_cooldown_days: 3
min_valid_risk_sources: 2
minimum_candidate_success_rate: 0.6666
```

建议先保持默认值运行。将 `promotion_enabled` 设为 `false` 可完全关闭日常性能晋级，但红线替换和手动 `rebuild` 仍然有效。

需要临时手动运行维护时：

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer 你的NODE_HEALTH_API_TOKEN" \
  "http://192.0.2.2:18887/api/run?mode=maintenance"
```

### 全量重建

以下情况手动运行 `rebuild`：

- 机场订阅发生大规模换线或节点重命名；
- 想允许更优秀节点重新竞争稳定槽位 1-3；
- 恢复了旧备份但不确定槽位历史是否可信；
- 明确希望放弃当前稳定槽位并重新选优。

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer 你的NODE_HEALTH_API_TOKEN" \
  "http://192.0.2.2:18887/api/run?mode=rebuild"
```

`rebuild` 会全量深检所有可用节点，并允许每区所有合格节点重新竞争三个稳定槽位；原来健康的 1-3 也不保留特权。它不使用日常晋级的 `12` 分差、每轮一个和冷却期限制，仍然直接选出当次全量检测中最优的三个节点。

`rebuild` 不会边测边改变线上结果。旧 `current.json` 一直有效，只有全量扫描、评分和文件写入全部成功后才切换到新版本。

### 日报和槽位告警

每日 Markdown/JSON 报告会把稳定槽位与动态排名分开：

- 稳定槽位按 `001-003` 展示固定身份、端口、当前健康状态、最后成功时间和详细检测结果，不把槽位号解释成质量名次。
- 动态节点从第 4 名开始按当日质量顺序展示。
- 阈值内临时不可用的稳定槽位标记为“保留等待恢复”，并显示连续不可用次数；从 inventory 消失或连续达到阈值的节点会记录实际换槽原因。
- 真正发生替换时，记录地区、槽位、旧节点、新节点、触发原因以及运行模式是 `maintenance` 还是 `rebuild`。
- 自动晋级还会记录候补连续完整通过次数、晋级前后分数和实际分差；地区冷却时间保存在 `data/state.json` 的 `slot_changed_at` 中。

`reports/alerts/latest-run.md` 显示本轮保留但 degraded/unavailable/absent 的稳定槽位。`reports/alerts/slot-changes-latest.md` 在首次发布时创建；发生过身份变化后，它保存最近一次真实变化。任何红线替换、自动晋级或 `rebuild` 造成的实际身份替换，都会额外写入 `reports/alerts/YYYY-MM-DD-版本号.md`，不会被下一次检测覆盖。长期监控应关注 `alerts` 目录中新出现的日期版本文件，而不是只轮询一个会变化的文件内容。

每次定时或手动正式扫描还会写入不可变的版本目录：

```text
reports/
├── YYYY-MM-DD.md/json                 # 当天最新一次，兼容现有查看方式
├── scheduled/latest.md/json           # 最近一次正式扫描
├── scheduled/YYYY/MM/DD/<version>/
│   └── report.md/json                 # 每次扫描独立归档
└── alerts/                             # 稳定槽位状态与变化
```

Markdown 报告包含总览、稳定槽、实际端口、当前顺序和每个节点的可用性、出口 IP、国家、州/省、城市、ASN、运营商、延迟、成功率、Google/ChatGPT、评分、置信度、风险原因、可信深检与本轮深检状态。开启 `include_raw_details` 时，每个节点还包含完整格式化的 IPQuality JSON。JSON 报告在 `nodes[].geo` 中提供规范化地理信息，并用 `result_source` 标明结果来自本轮可信深检、缓存深检或快速检测；它不会改变 `current.json`、状态文件或 Sub-Store 排序协议。

### 临时订阅全量审计

临时审计用于检查另一个机场或 Sub-Store 集合，不会修改 `current.json`、正式稳定槽和 OpenWrt 配置。它对全部节点执行快速检测，并对快速检测可用的每个节点执行完整 IPQuality 深检。

默认只允许与 `inventory.url` 相同的协议、主机和端口。若需要读取第二个 Sub-Store，在 `deploy/config/config.example.yaml` 的 `audit.allowed_origins` 中增加精确 origin，例如：

```yaml
audit:
  enabled: true
  allowed_origins:
    - http://192.0.2.2:3001
  max_subscription_bytes: 10485760
  max_nodes: 500
```

提交任务：

```bash
curl -fsS -X POST 'http://192.0.2.2:18887/api/v1/audits' \
  -H 'Authorization: Bearer 你的API令牌' \
  -H 'Content-Type: application/json' \
  --data '{"name":"机场A","subscription_url":"http://192.0.2.2:3001/download/collection/provider-a?target=ClashMeta&noCache=true"}'
```

接口立即返回 `202` 和 `id/status_url`。使用相同 Bearer token 查询状态及下载报告：

```bash
curl -fsS -H 'Authorization: Bearer 你的API令牌' \
  'http://192.0.2.2:18887/api/v1/audits/<id>'
curl -fsS -H 'Authorization: Bearer 你的API令牌' \
  'http://192.0.2.2:18887/api/v1/audits/<id>/report.md'
```

归档位于：

```text
data/audit-jobs/<id>.json
reports/audits/YYYY/MM/DD/<id>/report.md
reports/audits/YYYY/MM/DD/<id>/report.json
```

订阅 URL 可能含访问令牌，因此状态和报告只记录来源 origin 与 URL SHA-256，不保存完整链接。报告也不会写入代理密码、UUID等连接凭据。临时审计和正式扫描共用一个运行锁；已有任务运行时接口返回 `409`，稍后重试即可。

## 8. 配置 Sub-Store

在 Sub-Store 中建立两个集合：

三类消费者不要混用 URL：node-health 的 `SUB_STORE_INVENTORY_URL` 和 OpenWrt 的 `SOURCE_URL` 都读取完整 `inventory?target=ClashMeta&noCache=true`；只有 OpenClash、subconverter、手机和电脑等普通订阅客户端读取经过严格过滤的 `healthy?target=ClashMeta&noCache=true`。node-health 读取 `healthy` 会形成检测反馈循环，OpenWrt 读取 `healthy` 则会失去本地严格校验和全拒绝时生成零监听的能力。

### inventory

- 输入为所有机场订阅。
- 只做公告/套餐节点过滤、名称规范化和必要的协议转换。
- 必须消除重名，并去除“连接参数完全相同但使用不同别名”的重复节点；否则无法生成唯一且跨脚本一致的 `node_key`，检测会安全停止而不是猜测身份。
- 不执行健康排序脚本，不删除未检测节点。
- node-health 的 `SUB_STORE_INVENTORY_URL` 指向它。
- 下载 URL 使用 `http://群晖局域网IP:3001/download/collection/inventory?target=ClashMeta&noCache=true`。

### healthy

- 使用与 `inventory` 相同的真实节点输入和同样的名称规范化规则。
- 最后一步安装并运行 `integrations/sub-store/health-ranking-operator.js` 作为 Script Operator。
- Script Operator 的 `arguments` 填写 `{"rankingUrl":"http://群晖局域网IP:18887/current.json"}`；脚本实际读取 Sub-Store 注入的 `$arguments`，不是普通请求 `$options`。
- OpenClash、subconverter、手机、电脑等所有实际订阅都改为从 `healthy` 派生。
- 下载 URL 使用 `http://群晖局域网IP:3001/download/collection/healthy?target=ClashMeta&noCache=true`。

健康脚本采用两层保护：成功读取有效 `current.json` 时，稳定槽位按固定身份顺序输出，只有第 4 名以后的节点才按 `ranked` 健康排序。动态节点确认不可用、触发红线或不再位于本轮白名单时会删除；稳定槽位在连续不可用阈值内保持身份，达到阈值或从 `inventory` 消失时由 node-health 发布替换后的槽位。

如果 Script Operator 使用远程脚本链接而界面没有单独的 arguments 输入框，把 URL 编码后的 JSON 放到脚本链接 fragment，例如：

```text
https://你的代码地址/health-ranking-operator.js#%7B%22rankingUrl%22%3A%22http%3A%2F%2F192.0.2.2%3A18887%2Fcurrent.json%22%7D
```

脚本会先用 Sub-Store 自身的 `ProxyUtils.produce(..., 'ClashMeta', 'internal')` 规范化 VMess/VLESS/Trojan 等内部对象，再计算与 inventory YAML/OpenWrt 完全一致的 `node_key`。只要状态已成功下载并通过校验，排序白名单就是权威结果：状态中存在允许节点但一个身份都匹配不到时会抛出 identity-drift 错误，不会把未检测节点原样放行。这通常说明 healthy 与 inventory 的处理链不一致，必须先修复再切换客户端；OpenWrt 会因零匹配校验失败而继续使用上一版配置。

有效状态必须至少包含一个地区；每个地区都必须包含对象类型的 `stable_slots`、数组类型的 `ranked` 和对象类型的 `rejected`，并且整份状态至少记录一个节点决策。单个地区可以为空。`regions: {}`、所有地区均为空壳、字段缺失或类型错误则视为不完整状态。

当全局所有节点都被明确拒绝时，排序逻辑本身会得到空数组，但当前 Sub-Store 在 collection processor 后会拒绝生成零节点工件，因此直接请求 `healthy` 通常返回 HTTP 错误，客户端可能继续保留自己的旧缓存。OpenWrt 不依赖该行为：它下载完整 inventory 并在本地生成零监听配置，从而不会继续暴露已确认危险的代理端口。

状态下载、参数或校验失败时，脚本直接抛错，让本次 `healthy` 请求失败，不会把完整输入误标成健康节点。手机和电脑通常继续使用客户端自己的上一份订阅缓存；OpenWrt 则有独立的状态校验和应用回滚，无法验证时继续运行上一版 local-socks 配置。

当前 Sub-Store 的 `/download/collection` 每次请求都会重新执行 `produceArtifact` 和 Script Operator；但机场等上游资源默认仍可能缓存一小时，因此 `inventory`、`healthy` 两个下载 URL 都必须带 `noCache=true`。排序脚本内部再用 `#noCache` 读取 `current.json`，OpenWrt 还会追加 `_node_health_version` 参数并发送 no-cache 请求头，用于把请求与本次排序版本绑定并规避中间缓存。

正式启用前必须针对实际安装的 Sub-Store 版本验收一次：连续请求两次同一个 `healthy?...&noCache=true` URL，在 Sub-Store 日志中确认 Script Operator 两次都运行；然后触发一次确实发生槽位变化的检测，确认返回订阅中该地区稳定节点顺序与新 `current.json` 一致。只有这项验收通过，才能把所有客户端切换到 `healthy`。

如果 `healthy` 后面还经过 subconverter，建议显式设置：

```ini
enable_cache=false
```

或者在每次排序版本发布后清理 subconverter 缓存，否则客户端短时间内可能仍拿到旧顺序。

## 9. 接入 OpenWrt local-socks

OpenWrt 不参与质量检测，只轮询版本并应用已经发布的排序。

### 迁移前备份并停用旧自动刷新

现有 `/etc/local-socks/refresh.sh` 和 `./ctl restart` 会重新下载原始订阅，并按旧远程顺序覆盖 node-health 已生成的稳定槽位配置。因此启用新轮询器前，必须备份旧配置与 cron，并停用所有旧的自动 refresh/restart 任务。

在 OpenWrt 上执行：

```sh
backup_dir="/root/local-socks-health-migration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"

cp -p /etc/crontabs/root "$backup_dir/crontab.root"
cp -p /etc/init.d/local-socks "$backup_dir/init.d.local-socks"
for file in config.yaml refresh.sh convert.mjs ctl source.env service; do
  [ ! -e "/etc/local-socks/$file" ] || cp -p "/etc/local-socks/$file" "$backup_dir/$file"
done
```

备份目录包含订阅凭据时必须保持 `0700`，不得同步到 Git 或公开目录。然后检查 root crontab：

```sh
grep -nE 'local-socks|refresh\.sh|ctl (refresh|restart)' /etc/crontabs/root
```

手动编辑 `/etc/crontabs/root`，只删除或注释调用旧 `refresh.sh`、`ctl refresh`、`ctl restart` 的自动任务，不要改动其他系统任务。完成新 cron 配置后执行：

```sh
/etc/init.d/cron restart
```

旧脚本可以保留作为回滚材料，但不得再由 cron 或日常命令调用。

### 安装健康排序轮询器

复制以下文件：

```text
integrations/openwrt/check-ranking.sh
  -> /etc/local-socks/check-ranking.sh
integrations/openwrt/apply-ranking.sh
  -> /etc/local-socks/apply-ranking.sh
integrations/openwrt/convert-ranking.mjs
  -> /etc/local-socks/convert-ranking.mjs
integrations/openwrt/service-lib.sh
  -> /etc/local-socks/service-lib.sh
integrations/openwrt/local-socks.init
  -> /etc/init.d/local-socks
integrations/openwrt/node-health.env.example
  -> /etc/local-socks/node-health.env
integrations/local-socks/convert-any-proxy-to-local-socks-stable.js
  -> /etc/local-socks/convert-any-proxy-to-local-socks-stable.js
```

修改 `node-health.env` 中的群晖地址、`SOURCE_URL` inventory 地址、Node/Mihomo 路径、服务脚本、配置所有者和对外地址。`START_PORT` 必须保持 `62000`，否则脚本会拒绝应用。然后设置权限：

```bash
chmod 0755 /etc/local-socks/check-ranking.sh /etc/local-socks/apply-ranking.sh
chmod 0755 /etc/local-socks/service-lib.sh /etc/init.d/local-socks
chmod 0644 /etc/local-socks/convert-ranking.mjs
chmod 0644 /etc/local-socks/convert-any-proxy-to-local-socks-stable.js
chmod 0600 /etc/local-socks/node-health.env
```

转换器依赖 `js-yaml`。启用定时任务前，用实际 `NODE_PATH` 验证：

```bash
NODE_PATH=/etc/local-socks/node_modules:/usr/lib/node_modules \
  /usr/bin/node -e "require('js-yaml'); console.log('js-yaml ok')"
```

如果模块不在上述目录，将其实际父目录写入 `node-health.env` 的 `NODE_PATH`，或者把 `JS_YAML_PATH` 设置为模块入口的绝对路径。依赖路径不能放在默认 `EXPORT_DIR=/root/local-socks` 内，因为 TXT 发布会原子替换整个导出目录；脚本会主动拒绝任何重叠路径。

定时任务为：

```cron
*/10 * * * * /etc/local-socks/check-ranking.sh
```

确认 `/etc/crontabs/root` 中只有这一条任务负责更新 local-socks 配置，不应同时存在旧 refresh/restart 定时任务。

轮询脚本应当：

1. 下载 `current.json`；即使版本未变化，也校验已应用配置 SHA-256、服务状态和 TXT 导出是否仍完整；
2. 下载完整 `inventory` Clash YAML，再次读取 `current.json`，仅当两次版本一致时继续；
3. 通过 `APPLY_COMMAND` 调用 local-socks 适配脚本，按状态中的稳定槽位显式分配固定端口；
4. 生成临时 Mihomo 配置并执行 Mihomo 自检；
5. 自检通过后原子替换正式配置并重启；
6. 成功后才记录已应用版本；失败时使用指数退避，避免反复重启。

`APPLY_COMMAND` 的固定接口是：

```text
apply-command INVENTORY_YAML CURRENT_JSON VERSION
```

仓库自带的 `apply-ranking.sh` 已经实现完整流程：调用稳定槽位转换器、执行 Mihomo 配置自检、原子替换、重启、读取 procd 的真实实例状态，并使用 Node `net` 并发确认新 YAML 中的每个 listener 都能在 `127.0.0.1` 建立 TCP；任一应存在的监听缺失都会恢复旧配置并重启旧服务。全局明确拒绝全部节点时，合法的零 listener 配置直接通过。只有全部成功才返回 0。自动确认不等同于节点真实代理出网验收，因此启用 cron 前仍必须按下文检查固定监听端口和 HTTPS 出口。不要把 `APPLY_COMMAND` 换成直接覆盖正式配置的脚本。

`service-lib.sh` 会把 OpenClash 当前核心原子复制为 `/etc/local-socks/bin/mihomo-local-socks` 后再运行，并把 `nofile` 提升到 `65535`。不要把 `MIHOMO_BIN` 改回 `/etc/openclash/core/clash_meta`；独立文件和进程名可保证 OpenClash 重启、更新或清理核心时不会误杀 local-socks。轮询器也不依赖 `/etc/init.d/local-socks status` 的模糊返回值，而是读取 ubus 中实例的真实 `running` 状态并连接一个实际 listener。排名、配置和 TXT 均一致但运行时停止时，它会直接从本地配置恢复，不依赖 NAS 或 Sub-Store，也不会改变节点顺序。

`apply-ranking.sh` 使用 `/etc/init.d/local-socks restart`，它只重启当前已经原子替换好的 `config.yaml`，可以继续保留。迁移后不要执行旧的 `cd /etc/local-socks && ./ctl restart`，因为该命令包含远程刷新并会覆盖健康排序。

手动维护的正确入口是：

```text
日常重测：带 Authorization: Bearer 调用 POST http://群晖IP:18887/api/run?mode=maintenance
全量重选：带 Authorization: Bearer 调用 POST http://群晖IP:18887/api/run?mode=rebuild
应用新版本：/etc/local-socks/check-ranking.sh
仅重启当前配置：/etc/init.d/local-socks restart
```

手动调用 node-health API 后，应先等待 `/healthz` 显示任务完成且 `last_success` 更新，再执行一次 `check-ranking.sh`。如果版本、配置校验和、服务状态和 TXT 都没有变化，轮询器才会直接退出，不会重复重启服务。

如果误执行了旧 `./ctl restart`，配置校验和会发生变化。直接运行轮询器即可自动识别漂移并重新应用，不需要删除版本文件：

```sh
/etc/local-socks/check-ranking.sh
```

这不会删除群晖检测历史或稳定槽位，只会强制 OpenWrt 重新下载、校验并应用当前 `current.json`。

稳定端口必须按“地区基准端口 + 槽位号 - 1”分配。地区基准端口已经统一写入 `deploy/config/config.example.yaml` 的 `local_socks.port_bases`，采用 `62000-64200` 新规划，不使用附件样例中的旧 `420xx` 端口。比如美国基准端口为 `62800`：

```text
62800 = 美国001
62801 = 美国002
62802 = 美国003
62803 起 = 美国动态候选
```

如果 `002` 只是连续第 1-2 次不可用，`62801` 不会改绑候补；恢复后计数归零。连续第 3 次仍不可用、节点从订阅消失、明确触发质量红线、被满足全部门槛的候补受控晋级替换，或运行全量 `rebuild` 时，才允许更换身份。发生单槽替换时只更新 `62801`，其他稳定端口不移动；没有合格候补时该端口留空，动态候选仍从 `62803` 开始。

### 启用 cron 前的真实验收

先手动运行一次，不要直接等 cron：

```sh
/etc/local-socks/check-ranking.sh
cat /etc/local-socks/cache/node-health/applied.version
cat /etc/local-socks/cache/node-health/applied.sha256
sha256sum /etc/local-socks/config.yaml
ubus call service list '{"name":"local-socks","verbose":true}'
ls -l /root/local-socks/*.txt /root/local-socks/README.txt
```

`applied.sha256` 必须等于当前 `config.yaml` 的 SHA-256，`README.txt` 必须包含相同 ranking version。再在 OpenWrt 上逐个确认美国固定端口已监听，并通过每个端口访问 HTTPS：

```sh
ss -lnt | grep -E ':6280[0-4][[:space:]]'
curl --socks5-hostname 127.0.0.1:62800 --max-time 20 https://api.ipify.org
curl --socks5-hostname 127.0.0.1:62802 --max-time 20 https://api.ipify.org
```

最后在 AdsPower 所在主机把 `127.0.0.1` 换成 `192.0.2.4` 再测一次。只有版本、TXT、固定端口和 HTTPS 出口都正确后，才写入 `*/10 * * * *` cron。

### 固定地址和防火墙

按现有架构，`192.0.2.4` 是 OpenWrt 面向 `192.0.2.0/24` 的接口地址。必须在 iKuai 中为该 OpenWrt 网卡设置静态 DHCP 租约或固定地址，否则 TXT 与 AdsPower 配置会在地址漂移后全部失效。

如果该接口属于 OpenWrt 的 `wan` zone，默认 INPUT 会拒绝 `62000-65535`。只允许 AdsPower/可信管理主机访问，不要向整个 WAN 或公网开放。下面把 `192.168.31.X` 换成 AdsPower 主机的固定 IP；如果实际接口属于其他 zone，相应修改 `src`：

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-AdsPower-local-socks'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].src_ip='192.168.31.X'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='62000-65535'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload
```

从 AdsPower 主机执行前述 SOCKS HTTPS 测试，确认放行；再从一个不在白名单的主机确认连接被拒绝。Mihomo 管理端口和群晖侧探测端口都不需要对该网段开放。

## 10. 失败保护和回滚

- inventory 下载失败：本轮任务失败，不发布新状态。
- 稳定节点连续第 1-2 次不可用：保留槽位身份；连续第 3 次或从 inventory 缺失：替换对应槽位或在无候补时留空。
- Mihomo 配置加载失败：本轮任务失败，保留上一版 `current.json`。
- 深检出口 IP 与快速检测出口 IP 不一致、地区证据覆盖不足或风险源大量返回空值：整轮 `rebuild` 不发布。
- IPQuality 第三方接口超时：标记不确定，不把节点误判为危险。
- 报告或状态无法原子写入：不推进当前版本。
- Sub-Store 状态读取、校验或身份匹配失败：本次 healthy 请求失败，不输出未过滤 inventory；客户端通常保留自己的旧缓存。
- OpenWrt 下载、转换或 Mihomo 自检失败：继续运行旧 local-socks 配置，不记录新版本。
- OpenWrt 发现同版本配置、服务或 TXT 被人工覆盖/删除：自动重新应用该版本。

如果需要完全退回旧 local-socks 刷新方式：

1. 从 `/etc/crontabs/root` 删除 `check-ranking.sh` 定时任务。
2. 从迁移备份目录恢复原 `crontab.root` 和需要的 local-socks 文件。
3. 执行 `/etc/init.d/cron restart`。
4. 使用 Mihomo 自检确认恢复的 `config.yaml` 有效，再按旧流程启动。

不要同时启用新旧两套更新 cron；否则最后执行的任务会覆盖前一套配置，稳定槽位无法保证。

升级项目前先备份：

```text
/volume1/docker/YOUR_PROJECT_DIR/data
/volume1/docker/YOUR_PROJECT_DIR/reports
```

代码升级方式：拉取经过确认的项目版本，在 Container Manager 中重新“构建/启动”项目。持久化目录不会随容器重建消失。若新版本异常，切回上一份项目代码并重新构建；不要删除 `data` 来解决普通升级问题，因为删除它会触发下一轮全量重建和稳定槽位重选。

如果确实要清空历史，应先备份 `data`，再明确执行全量 `rebuild`。这属于主动重新选优，不是日常维护动作。

## 11. 后续免维护边界

完成首次配置后，正常情况下不需要人工排序：

- node-health 每天自动维护质量状态；
- Sub-Store `healthy` 让所有下游订阅获得同一份“固定身份槽位 1-3 + 第 4 名以后动态健康排序”；
- OpenWrt 每 10 分钟校验版本、本地配置、服务和 TXT；版本变化或本地漂移时才原子应用；
- AdsPower 继续使用固定地区端口 001-003；
- 稳定槽位的保留/恢复/变更状态和详细检测结果写入群晖 `reports` 目录。

日常查看 `alerts/latest-run.md` 了解当前降级槽位，并监控 `alerts/YYYY-MM-DD-版本号.md` 新文件获知真实换槽；`slot-changes-latest.md` 首次发布时创建，发生过换槽后保留最近一次换槽，不会每天重写。只有机场大规模更新或你主动希望重新选优时，才手动调用一次 `rebuild`。
