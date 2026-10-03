# vdex — 可验证数据交换系统（基础层）

把本地 JSONL 数据集**封版（seal）**为不可变版本，接收方可只取部分记录，并在**不接触发布方存储、不接链、不依赖对象存储**的情况下独立验证记录确实属于该版本。传输通道（文件、消息、U 盘等）可以任意更换，证明与数据的绑定关系不变。

## 安全性质

- **固定版本**：每个版本有清单 `manifest.json`，包含版本号、Merkle 根、记录数、密封时间、前一版本根。版本目录只追加，永不修改。
- **位置即身份**：叶子哈希为 `SHA256("vdex-leaf-v1" || index || record)`。重复内容在不同位置有不同哈希；顺序改变根即改变。
- **证明不能挪位**：证明路径强制校验叶子中的 index 承诺与每一级兄弟节点的左右位置。把某条记录的证明挪到另一个位置会直接失败。
- **发布中断保留旧版**：seal 先写临时目录，成功后原子改名；失败清理临时目录且不推进版本号。新增记录总是生成新版本，旧证明只对旧根有效。
- **独立反拼接验证**：验证器只凭数据包内的清单和证明工作，可检出记录篡改、记录缺失、跨位置重放，以及把其他版本的条目拼进当前包。
- **信任边界在包外**：验证必须显式给出可信根（`-root`）。缺少可信依据时，材料即使完全自洽也只能证明自身一致，验证明确失败，不会从待验证材料自身补出认可它的依据。
- **分批接收、可接续**：同一验证请求可先固定记录集合、范围和可信根，材料分多批任意顺序到达；重复补交不改变要求，矛盾内容双方证据都保留。已核对部分可保存接续，但只有所需集合全部满足且无未解矛盾才形成完整结论。请求一旦被修改即为新的决定，不沿用旧的通过状态。

## 构建

```sh
go build ./...
go test ./...
go build -o vdex ./cmd/vdex
```

## 使用

```sh
# 1. 封版 v1（输入每行一条 JSON 记录）
./vdex seal -dataset users -input users.jsonl

# 2. 追加记录后再次封版，生成 v2，旧版保留
./vdex seal -dataset users -input users_v2.jsonl
./vdex versions

# 3. 只导出部分记录（索引从 0 开始，可任意顺序）
./vdex extract -version 1 -indices 0,3,7 -out part.json

# 4. 接收方独立验证（不需要发布方的 store）
#    接收方必须显式给出可信的数据集名、版本、可信根和期望的记录集合；
#    包内自报的清单不能替代这些条件。缺项、多余或重复条目都会失败，
#    并说明是哪一项要求未满足。省略 -root 时验证直接失败：
#    自洽的材料不等于可信的材料。
./vdex verify -package part.json -dataset users -version 1 -root <hex> -indices 0,3,7

# 5. 分批到达的材料：用 collect 累积验证，状态保存在会话文件中，
#    可随时中断并接续。PARTIAL 表示部分有效（已核对 2/4），
#    只有所需集合全部满足才输出 COMPLETE（退出码 0）。
./vdex collect -session s.json -dataset users -version 1 -root <hex> -indices 0,1,2,3 -package partA.json
./vdex collect -session s.json -dataset users -version 1 -root <hex> -indices 0,1,2,3 -package partB.json
#    之后修改请求（如改变 indices）即为新的决定：旧会话的通过状态
#    不再适用，必须重新开始。
```

验证通过退出码为 0；任何篡改或拼接导致失败时退出码为 1。

## 产物布局

```
vdex-store/
  versions/
    v000000000001/
      manifest.json   # 版本身份（根、记录数、前版根）
      records.jsonl   # 规范化后的原始记录
    v000000000002/
      ...
part.json             # 清单 + 选中记录 + 每条的 Merkle 包含证明
```

数据包是传输无关的单个 JSON 文件：以后增加任何传输通道，都只是搬运这个文件，证明语义不变。
