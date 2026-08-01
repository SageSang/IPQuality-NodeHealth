# 群晖 + Sub-Store + OpenWrt 简化部署

这是当前推荐且实际要使用的链路：

```text
机场完整订阅
  -> Sub-Store inventory（不加健康脚本）
  -> 群晖 node-health 每天检测并发布 current.json
  -> Sub-Store healthy（最后一步运行健康排序脚本）
  -> OpenWrt 继续使用原 local-socks 转换流程
  -> 62000 起的地区端口、AdsPower、地区 TXT
```

OpenWrt 不直接读取 `current.json`，也不需要部署
`check-ranking.sh`。它只需要继续维护原来的转换器 URL，并把订阅 URL
换成 Sub-Store 的 `healthy` URL。

## 1. 稳定槽位规则

每个固定地区有三个稳定槽位。`001`、`002`、`003` 是固定身份，三者之间
没有实时名次关系。

- 首次运行、状态丢失或手动 `rebuild`：全量深检，由合格节点中最好的三个
  建立稳定槽位。
- 节点仍在完整订阅中，但本轮无法连接：连续第 1、2 次保留原槽位；连续第
  3 次仍不可用时，只用最高质量的合格候补替换该槽位。
- 不可用节点恢复连接：连续不可用计数立即归零。
- 节点已从完整订阅消失：本轮立即释放并尽量用最高质量合格候补替换，不等
  三轮。每天只扫描一次，所以订阅变化到下一次扫描之间的短窗口可以接受。
- 明确触发质量红线：立即替换对应槽位。
- 明显更优的高置信候补：满足连续完整检测、12 分优势和 7 天冷却等条件后，
  每个地区每轮最多替换一个最弱槽位。
- 第 4 名以后没有固定身份，每轮按置信度、质量分、延迟排序；不在当期健康
  白名单中的节点由 Sub-Store 删除。

地区识别已与 `rule_conf/meta.ini` 及其 Sub-Store 排序脚本对齐：支持国旗、
中文简繁体、国家全称、主要城市和英文别名；两位国家代码只接受大写完整单词。
当前固定端口规划覆盖香港、台湾、日本、新加坡、美国、韩国、英国、德国、
法国、加拿大、澳大利亚，其余 `meta.ini` 支持但没有固定端口段的国家仍归入
`other`，不会占用错误的国家端口。

配置项位于 `config.yaml`：

```yaml
policy:
  stable_slots: 3
  stable_unavailable_replace_after_runs: 3
```

## 2. 群晖目录

在群晖创建：

```text
/volume1/docker/YOUR_PROJECT_DIR/
├── config/
│   ├── config.yaml
│   └── mihomo-bootstrap.yaml
├── data/
├── reports/
└── project/
    ├── compose.yaml
    └── .env
```

文件来源：

```text
deploy/config/config.example.yaml -> config/config.yaml
deploy/mihomo/bootstrap.yaml       -> config/mihomo-bootstrap.yaml
deploy/compose.synology.yaml       -> project/compose.yaml
deploy/.env.example                -> project/.env
```

`data` 保存稳定槽状态和当期排序，`reports` 保存每次检测的 Markdown/JSON
报告。二者都映射到群晖，重建容器不会丢失。

## 3. Sub-Store 两个集合

建立两个基于同一批机场订阅的集合：

1. `inventory`：保留所有真实节点，不运行健康排序脚本，只给 node-health。
2. `healthy`：同一完整节点源，把
   `integrations/sub-store/health-ranking-operator.js` 设为最后一个 Script
   Operator，给 OpenWrt 和其他客户端。

脚本可从仓库固定地址加载：

```text
https://raw.githubusercontent.com/SageSang/IPQuality-NodeHealth/main/integrations/sub-store/health-ranking-operator.js
```

Operator 参数：

```json
{"rankingUrl":"http://NAS_LAN_IP:18887/current.json"}
```

两个下载链接都要带 `target=ClashMeta&noCache=true`：

```text
http://NAS_LAN_IP:3001/download/collection/inventory?target=ClashMeta&noCache=true
http://NAS_LAN_IP:3001/download/collection/healthy?target=ClashMeta&noCache=true
```

node-health 必须读取 `inventory`，不能读取 `healthy`，否则被删除的节点没有
机会在后续检测中恢复。

## 4. `.env`

修改群晖 `project/.env`：

```dotenv
PUID=你的DSM用户UID
PGID=你的DSM用户GID
TZ=Asia/Shanghai

NODE_HEALTH_STORAGE_ROOT=/volume1/docker/YOUR_PROJECT_DIR
NODE_HEALTH_CONFIG_PATH=/volume1/docker/YOUR_PROJECT_DIR/config/config.yaml
MIHOMO_BOOTSTRAP_PATH=/volume1/docker/YOUR_PROJECT_DIR/config/mihomo-bootstrap.yaml
NODE_HEALTH_BIND_IP=NAS_LAN_IP
NODE_HEALTH_PORT=18887
LOCAL_SOCKS_ADVERTISE_HOST=OPENWRT_LAN_IP
NODE_HEALTH_API_TOKEN=一段足够长的随机字符串

MIHOMO_IMAGE=metacubex/mihomo:v1.19.29
NODE_HEALTH_IMAGE=ghcr.io/sagesang/ipquality-node-health:latest
SUB_STORE_INVENTORY_URL=http://NAS_LAN_IP:3001/download/collection/inventory?target=ClashMeta&noCache=true
```

`NODE_HEALTH_API_TOKEN`、真实订阅链接、`data`、`reports` 不要提交到 Git。

## 5. Container Manager 部署

GitHub Actions 在 `main` 更新时构建：

```text
ghcr.io/sagesang/ipquality-node-health:latest
```

在 Container Manager 中新建“项目”，项目目录选择：

```text
/volume1/docker/YOUR_PROJECT_DIR/project
```

使用其中的 `compose.yaml` 启动。只对局域网绑定 `18887`，不配置公网域名、
Nginx 或端口转发。Mihomo 控制端口和探测端口只存在于 Docker 私有网络中。

启动后检查：

```bash
curl -fsS http://NAS_LAN_IP:18887/healthz
curl -fsS http://NAS_LAN_IP:18887/version
```

## 6. 首次全量检测

```bash
curl -fsS -X POST \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  'http://NAS_LAN_IP:18887/api/run?mode=rebuild'
```

接口启动后台任务后立即返回。通过 `/healthz` 查看 `running`、`last_success`
和 `last_error`。首次节点多时耗时会较长，不要在运行中重建容器。

成功后检查：

```bash
curl -fsS http://NAS_LAN_IP:18887/current.json
```

以及群晖目录：

```text
reports/scheduled/latest.md
reports/scheduled/latest.json
reports/alerts/latest-run.md
reports/alerts/slot-changes-latest.md
```

报告包含节点名称、原始服务器和端口、出口 IP、ASN、延迟、成功率、
Google/ChatGPT 状态、质量分、风险源、完整 IPQuality 详情、当前顺序、预计
OpenWrt SOCKS5 端口和可直接导入的 `socks5://地址:端口{节点名}`。

## 7. 验收 healthy 链接

连续请求两次 `healthy` URL，确认：

- Sub-Store 日志中两次都执行了 Script Operator；
- 每个地区前三个节点与 `current.json` 的稳定槽一致；
- 不在健康白名单中的节点没有输出；
- URL 带 `noCache=true`。

只有这一步通过后，才把 OpenWrt 的 `SUBSCRIPTION_URL` 换成 `healthy` URL。

## 8. OpenWrt 最终切换（Docker 验收后执行）

OpenWrt 保留原有两个远程链接：

```sh
CONVERTER_URL='原 rule_conf 转换器 URL'
SUBSCRIPTION_URL='新的 Sub-Store healthy URL'
START_PORT='62000'
```

原 `rule_conf/tools/convert-any-proxy-to-local-socks.js` 已支持：地区 200 端口
分段、节点名称、重复名称处理、mixed listener、LAN 监听和 `62000` 默认起点。

实际改造时还要做四项保护：

1. 下载并转换到候选文件，先用 Mihomo 校验，成功后才替换正式配置。
2. 候选配置哈希与当前配置相同则不重启，避免断网。
3. 最终配置明确设置 `ipv6: false` 和 `dns.ipv6: false`。
4. 重启成功后再生成地区 TXT，格式为
   `socks5://OPENWRT_LAN_IP:PORT{节点名称}`。

这一步等群晖首次全量检测和 `healthy` URL 验收完成后，再通过 SSH 修改；当前
不应提前改 OpenWrt。

## 9. 日常运行

默认每天 `05:30` 自动执行一次 `maintenance`。无需群晖 cron，也无需
OpenWrt 每 10 分钟读取 `current.json`。

`maintenance` 每天快速检查全部节点，深检所有稳定槽位、新节点、出口 IP
变化节点，以及按排名均匀轮转的约四分之一动态节点；完整检测并发默认为
`3`。未轮到的动态节点保留上次可信分数，正常约四天完成一轮动态池深检。

手动日常检测：

```bash
curl -fsS -X POST \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  'http://NAS_LAN_IP:18887/api/run?mode=maintenance'
```

机场大规模换线或你想让前三名重新竞选时，手动运行 `rebuild`。

更新镜像时，在 Container Manager 中重新构建/启动项目；`pull_policy: always`
会拉取最新镜像，持久化状态和报告不会被删除。

## 10. 临时机场全量审计

临时审计不会修改正式稳定槽：

```bash
curl -fsS -X POST 'http://NAS_LAN_IP:18887/api/v1/audits' \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  -H 'Content-Type: application/json' \
  --data '{"name":"provider-a","subscription_url":"http://NAS_LAN_IP:3001/download/collection/provider-a?target=ClashMeta&noCache=true"}'
```

默认只允许与正式 `inventory` 相同的协议、主机和端口。如需另一个
Sub-Store origin，先加入 `config.yaml` 的 `audit.allowed_origins`。
