# vdx — 可验证本地数据交换系统

纯 Go、单二进制、无区块链、无对象存储、无外部服务。把本地数据集封成**固定版本**，
接收方只拿到**任意一段记录**也能独立验证这些记录确实属于该版本、位置无误、未被篡改，
且无法把旧版本或其它位置的证明拼进来蒙混过关。

## 信任模型

- 发布方维护一个本地 append-only 仓库；每个版本产生一个不可变清单 manifest.json，
  其 version_id 是该版本 Merkle 树的根（SHA-256，hex）。
- 接收方通过任意**带外可信渠道**获得 (dataset_id, version, version_id) 锚点
  （例如随业务流程签发）。验证时只信任该锚点，不信任数据包自报的头部。
- 之后无论换什么传输通道（邮件、U盘、HTTP、消息队列……），证明与数据的对应关系不变。

## 身份如何确定（顺序与重复内容）

记录的叶子身份不是内容哈希，而是带域分离、长度前缀的哈希：

    leaf  = SHA256("vdx-leaf-v1"  || len(dataset_id) || dataset_id || version || index || len(content) || content)
    node  = SHA256("vdx-inner-v1" || left || right)        # 奇数节点复制自身晋升
    empty = SHA256("vdx-empty-v1" || dataset_id || version)

- 相同内容出现在不同位置（重复记录）→ 叶子不同，证明不可互换。
- 相同内容出现在不同版本 → 叶子不同；每条证明自带 version，旧证明只对旧版有效。
- 每个 Merkle 路径步骤带显式 left/right 方向，证明挪到另一个位置会因方向/高度不一致失败。

## 封版语义（中断保留旧版）

- 发布是 append-only：新文件必须把上一版全部记录作为逐字节前缀，只允许尾部追加。
- 新版本先写入同文件系统的暂存目录并 fsync，最后用**一次原子 rename** 落到
  versions/vN/，再原子更新 repo.json 头指针。
- 发布过程中任何一步失败都不移动头指针，旧版本目录、清单、证明完全不变且继续可验证；
  相同快照重复封版、删除记录、改动前缀一律拒绝。

## 数据包格式

vdx export 输出一个可直接发送的目录：

- bundle.json：dataset/version/root/总数/区间等自描述头；
- records.jsonl：区间内原始记录（LF、文件以换行结尾，空行即空记录）；
- proofs.jsonl：每行一条与记录按行一一对应的 Merkle 包含证明。

## 用法

    go build -o vdx ./cmd/vdx

    vdx init    --repo repo --dataset-id ledger-A
    vdx publish --repo repo --records v1.jsonl      # => sealed v1 version_id=...
    vdx publish --repo repo --records v2.jsonl      # 追加 => v2，v1 原封不动
    vdx info    --repo repo

    vdx export  --repo repo --version 1 --start 2 --end 4 --out pkg-v1

    # 接收方：用可信锚点独立验证（--version 可固定版本号）
    vdx verify  --bundle pkg-v1 --root <version_id-hex> \
                --dataset-id ledger-A --version 1 --report report.json

verify 退出码 0 表示全部通过，非 0 表示失败，并在 JSON 报告中逐条列出原因，覆盖：
记录篡改、记录缺失/多余、证明挪位、跨版本拼接、跨数据集、版本号不一致、区间越界。

## 目录

- cmd/vdx：CLI（init/publish/export/verify/info）。
- internal/merkle：域分离哈希、位置绑定 Merkle 树、包含证明与验证。
- internal/repo：append-only 仓库、原子封版、前缀一致性校验。
- internal/bundle：部分数据包导出与独立验证器。
- internal/manifest、internal/records：清单格式与规范化 JSONL 分帧。
- demo/run_demo.sh：端到端演示，产出真实数据包，并演示六类攻击全部被拒绝。

## 测试

    go test ./...
    bash demo/run_demo.sh
