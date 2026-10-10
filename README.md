# DDoSMonitor（Java 21 移植版）

`1.py`（Scapy + 多平台防火墙的 DDoS 监测/自动封禁脚本）的 Java 重写版。
检测逻辑、阈值语义、攻击状态机、调试命令集、配置文件格式都与 Python 版保持一致；
抓包与防火墙换成三端原生后端，核心零第三方依赖（JNA 仅 Npcap 后端与 conhost 着色需要）。

**这份文档同时是源码导读**：先看下面的目录结构与线程模型，再看编译/运行，最后是各批变更与验证记录。

| | 现状 |
|---|---|
| 语言 / 源级 | Java 21（`javac --release 21`，`-Xlint:all` 零警告） |
| 源码规模 | 18 个 `.java` 源文件 → **37 个 class**（含内部类，不含 JNA） |
| 自检 | `SelfTest` **145 项**纯逻辑检查全过（不抓包、不下发规则） |
| 抓包后端 | `npcap`（JNA→wpcap.dll，默认）/ `external`（dumpcap·tcpdump）/ `sim`（模拟），自动降级 |
| 防火墙后端 | Windows `netsh` / Linux `iptables`+`ip6tables` 或 `nft` / macOS `pfctl` |
| 产物 | `dist\DDoSMonitor.jar`（fat-jar：程序 + JNA + 全平台本机库，`java -jar` 直接运行，约 1.9 MB） |
| 三端实测 | Windows 11 实测通过；Linux / macOS 代码就绪（`build.sh`）但**未在真机跑过** |

## 目录结构

```text
java/
├─ DDoSMonitor.java         主程序：参数解析、启动自检、主循环、调试 REPL、永久封禁、健康度输出
├─ PacketSource.java        抓包抽象（start / stop / describe / statsLine / isAlive）
├─ NpcapJnaSource.java      Npcap 后端（JNA → wpcap.dll），缺 jna.jar 时不参与编译
├─ ExternalPcapSource.java  后备后端：启动 dumpcap/tcpdump 并解析其 pcap 流
├─ SimSource.java           模拟流量源（无 Npcap/权限时自测，默认 dry-run）
├─ PcapParser.java          链路层/网络层/传输层解析（Ethernet/VLAN/SLL/NULL/RAW + IPv4/IPv6）
├─ PacketInfo.java          单个包的统计记录（record）
├─ RateCounter.java         滑动窗口按秒分桶计数（全局 + 每 IP + 协议分布）
├─ Firewall.java            防火墙后端（netsh / iptables·ip6tables / nft / pfctl）+ 幂等下发
├─ GeoResolver.java         异步归属地查询（单线程队列 + LRU 缓存）
├─ ConfigStore.java         配置默认值、范围校验、原子读写
├─ Json.java                手写 JSON 读写（容忍 BOM、深度上限 64）
├─ NetUtil.java             IP 归一化/分类、默认出口网卡、humanBytes/nowStr
├─ ConsoleInput.java        控制台行输入线程（x 进调试 / exit 退出 / REPL 共用同一个 reader）
├─ Color.java               ANSI 着色 + 自动降级（NO_COLOR / 重定向 / TERM=dumb）
├─ WindowsAnsi.java         传统 conhost 打开 VT 处理（JNA，可选编译）
├─ EnvironmentCheck.java    环境自检（`--check` 与启动前问题清单）
├─ SelfTest.java            145 项纯逻辑自检
├─ build.cmd / build.sh     Windows / Linux·macOS 构建脚本（含 fat-jar 打包）
├─ bench/                   一次性性能与设备探针（不参与 build.cmd 编译）
├─ lib/jna.jar              可选依赖：Npcap 后端 + conhost 着色（build 脚本自动下载）
├─ out/  build/  dist/      中间产物与 dist\DDoSMonitor.jar（已 gitignore）
├─ monitor_config.json      运行时生成（已 gitignore）
└─ ddos_alerts.log          运行日志，满 64 MB 轮转为 .1/.2/.3（已 gitignore）
```

## 模块与线程模型

### 数据流

```text
PacketSource（npcap / external / sim）
        │  Consumer<PacketInfo>（抓包线程回调）
        ▼
   handlePacket()  ──入向过滤 inbound_only──▶  RateCounter.add()      [synchronized(lock)]
   （累计包/字节、            （非本机目的地址丢弃）   按秒分桶、每 IP 与全局增量维护）
    攻击期累计）
        │
        │  每秒一次
        ▼
   evaluateLoop() → evaluateOnce()
        │
        ├─▶ 阈值判定 + 攻击状态机（峰值/总量/主要来源/攻击结束汇总）
        ├─▶ alert()：冷却去重 → 写日志（纯文本）→ 控制台彩色告警
        └─▶ Firewall.block()：同 IP 串行化 → 幂等下发 → 登记到期时间
                                   │
                        cleanerLoop() 每秒扫描到期条目 → 自动解封
```

### 线程一览

| 线程 | 由谁启动 | 职责 | 异常 / 死亡处理 |
|---|---|---|---|
| `main` | JVM | 参数解析、启动前自检、主循环（每 300 ms 看控制台请求） | `finally` 汇入 `shutdown()` |
| `检测循环` | `startGuarded` | 每秒 `evaluateOnce()` + 健康度输出 | 异常写日志并按 1~5 s 退避**重启**该线程 |
| `抓包看护` | `startGuarded` | 每 2 s 检查 `PacketSource.isAlive()` | 抓包死了就**自动重启抓包**（30 s 冷却） |
| `防火墙清理循环` | `startGuarded`（仅后端可用时） | 每秒扫描到期封禁并解封 | 同上 |
| `npcap-source` / `pcap-reader` / `sim-source` | 各抓包源自身 | 取包 → 解析 → 回调 `handlePacket` | `try/finally` 复位 `running`，由看护线程发现并重启 |
| `geo-worker` | `GeoResolver.start()` | 单线程查归属地（ip-api.com），失败记“查询失败” | 队列上限 4096，缓存 LRU 4096 |
| `console-input` | `ConsoleInput.start()` | 读行分发：`x` 进调试、`exit` 退出、调试模式转发给 REPL | stdin 结束则打印提示并停用热键（监控继续） |
| `ddos-shutdown-hook` | `Runtime` | Ctrl+C / SIGTERM 安全收尾 | 与 `finally` 共用幂等的 `shutdown()` |

### 关键不变式（护栏）

* **同 IP 串行**：`Firewall` 用引用计数地址锁，同一地址的“检查-下发”串行化；锁在最后一个使用者退出时回收，**失败也不留孤儿锁**。
* **抓包死亡必可见**：所有抓包源在 `finally` 里复位 `running`，`isAlive()` 由看护线程消费，不允许“线程死了而主循环空转”。
* **一切外部输入有上限**：`banned ≤ 1000`、单域名 DNS 结果 `≤ 32`、封禁跟踪表 `≤ 10 万`、归属地队列/缓存 `≤ 4096`、JSON 嵌套 `≤ 64 层`、VLAN `≤ 3 层`、日志 `64 MB × 3`。
* **写入不产生半个文件**：配置用临时文件 + `ATOMIC_MOVE` 原子替换；日志按大小轮转。
* **退出路径唯一**：`shutdown()` 幂等 —— 停抓包 → 停归属地 → 撤销规则（macOS 含对称的 `pfctl -X <token>`）。

## 文件清单（职责速查表）

| Java 文件 | 职责 | 对应 1.py / Python 版 |
|-|-|-|
| `DDoSMonitor.java` | 主程序：参数解析、启动前自检、主循环、调试 REPL（show/set/log/clear/ban/unban/block/unblock/fw）、永久封禁、健康度输出 | `class DDoSMonitor` + `main()` + 调试 REPL |
| `PacketSource.java` | 抓包抽象：`start/stop/describe/statsLine` + **`isAlive()`**（供看护线程判断抓包是否还活着） | `AsyncSniffer` 的抽象（可插拔抓包后端） |
| `NpcapJnaSource.java` | Npcap 后端：JNA 直调 `wpcap.dll`；网卡枚举与默认路由网卡选择；缺 `jna.jar` 时整个文件不参与编译 | `AsyncSniffer(filter="dst port N")` |
| `ExternalPcapSource.java` | 后备后端：启动 `dumpcap -w -` / `tcpdump -w -`，自己解析 pcap 流（含魔数/字节序/纳秒判断） | 无（新增） |
| `SimSource.java` | 模拟流量源：正常/攻击节律、亚毫秒自旋补齐（≈100 万 pkt/s 上限） | 无（新增） |
| `PcapParser.java` | 链路层（Ethernet/VLAN/SLL/NULL/RAW）与 IPv4/IPv6（含扩展头、分片）+ TCP/UDP/SCTP/DCCP 解析 | Scapy 替我们做的部分 |
| `PacketInfo.java` | 单个包交给统计层的记录：时间戳、源/目的地址、目的端口、SYN、帧长、负载长度、协议 | `handle_packet` 里的 `rec` 元组 |
| `RateCounter.java` | 滑动窗口按秒分桶：全局包/字节 + 每 IP 计数 + 协议分布，淘汰每秒最多一次 | `ip_records` / `all_records` 双端队列 |
| `Firewall.java` | 四类后端（netsh / iptables·ip6tables / nft / pfctl）、幂等下发、同 IP 串行化、到期解封、退出批量撤销、残留清理 | `class FirewallManager`（**修正**：IPv4/IPv6 分别下发） |
| `GeoResolver.java` | 异步归属地查询（ip-api.com）：单线程队列 + LRU 缓存，查不到不影响告警 | `_geo_worker` / `get_ip_location` |
| `ConfigStore.java` | 配置默认值、范围校验、`banned` 规范化、原子读写 | `DEFAULT_CONFIG` / `CONFIG_SPEC` / `validate_config_value` / `load_config` / `save_config` |
| `Json.java` | 手写 JSON 读写：容忍 UTF-8 BOM、解析深度上限 64 | `json` 模块 |
| `NetUtil.java` | IP 归一化（含 IPv4-mapped）、内网/保留地址分类、默认出口网卡解析、humanBytes/nowStr | `parse_ip` / `is_internal` / `human_bytes` / `now_str` |
| `ConsoleInput.java` | 控制台行输入线程：`x` 进调试、`exit` 退出；与 REPL 共用同一个 reader | `_keyboard_listener` + `read_line_with_hotkeys`（改为行输入） |
| `Color.java` | ANSI 着色（红=告警、黄=攻击中、绿=攻击结束）与自动降级 | 无（新增） |
| `WindowsAnsi.java` | 传统 conhost 打开 `ENABLE_VIRTUAL_TERMINAL_PROCESSING`（JNA，可选编译） | 无（新增） |
| `EnvironmentCheck.java` | 环境自检：平台/权限/抓包后端/防火墙后端/策略 → 结论与问题清单 | 无（新增） |
| `SelfTest.java` | 145 项纯逻辑自检（含本轮 17 项审计修复的回归用例） | 无（新增） |
| `build.cmd` / `build.sh` | 构建：定位 JDK → 取 jna.jar → 编译（`--release 21`）→ 打包 fat-jar | 构建脚本 |

## 环境要求

* **JDK 21+**（本机 `JAVA\\\_HOME=D:\\\\jdk-21.0.12.101-hotspot`，javac 21.0.12.1）
* **Npcap**（真实抓包需要）+ **管理员权限**（本机已装：`C:\\\\Windows\\\\System32\\\\Npcap\\\\wpcap.dll`）
* `lib/jna.jar`：`build.cmd` 会用 `curl` 从 Maven Central 自动下载（JNA 5.14.0，已验证 sha1）
* 可选：`dumpcap`/`tcpdump`（作为第二抓包后端，本机未安装）

## 编译

```bat
build.cmd
```

它会：定位 javac（JAVA\_HOME → PATH → 常见安装路径）→ 缺 `lib\\\\jna.jar` 就下载 →
用 `--release 21` 编译核心（零第三方依赖）→ 再编译 Npcap 后端。
缺少 jna.jar 时也能编译，只是 Npcap 后端不可用（程序会自动退回 external/sim）。

产物：`out\`（class 目录，37 个 class）+ `dist\DDoSMonitor.jar`（fat-jar：程序 + JNA + 全平台本机库，约 1.9 MB，
`java -jar` 直接运行，无需再指定 `-cp`）。

手动编译等价于：

```bat
javac -encoding UTF-8 --release 21 -d out Json.java NetUtil.java ConfigStore.java PacketInfo.java ^
      PacketSource.java PcapParser.java SimSource.java ExternalPcapSource.java Firewall.java ^
      GeoResolver.java ConsoleInput.java DDoSMonitor.java
javac -encoding UTF-8 --release 21 -cp "out;lib\\\\jna.jar" -d out NpcapJnaSource.java
```

> 源文件含中文，\\\*\\\*必须\\\*\\\*加 `-encoding UTF-8`（Windows 上 javac 默认 GBK 会乱码/报错）。

## 运行

```bat
rem 模拟流量自测：不需要管理员，默认 dry-run 不会下发任何规则
java -Dstdout.encoding=UTF-8 -cp "out;lib\\\\jna.jar" DDoSMonitor --source=sim --yes

rem 列出 Npcap 可见网卡（挑对网卡很重要，见下文）
java -Dstdout.encoding=UTF-8 -cp "out;lib\\\\jna.jar" DDoSMonitor --list-ifaces

rem 真实抓包 + 真实封禁（需要管理员）
java -Dstdout.encoding=UTF-8 -cp "out;lib\\\\jna.jar" DDoSMonitor --yes

rem 指定网卡
java -Dstdout.encoding=UTF-8 -cp "out;lib\\\\jna.jar" DDoSMonitor --iface="\\\\Device\\\\NPF\\\_{...}" --yes
```

控制台异常时可先 `chcp 65001` 再运行。

### 参数

|参数|说明|
|-|-|
|`--config <文件>`|配置文件路径（默认 `monitor\\\_config.json`）|
|`--source <类型>`|`auto`(默认) / `npcap` / `external` / `sim`|
|`--iface <网卡>`|抓包网卡；Npcap 形如 `\\\\Device\\\\NPF\\\_{...}`，tcpdump 可用 `any`|
|`--list-ifaces`|列出 Npcap 可见网卡后退出|
|`--dry-run`|只告警与登记，不真正下发防火墙规则|
|`--live`|即使 `--source=sim` 也真实下发规则（默认 sim 为 dry-run）|
|`--strict-internal`|只封公网：拒绝封禁内网/保留地址（等价 `allow_internal=0`）|
|`--allow-internal`|允许封禁内网/保留地址（默认行为，覆盖配置）|
|`--yes`|跳过“是否继续(y/n)”确认|
|`--sim-pps` / `--sim-attack-pps` / `--sim-period` / `--sim-attack`|模拟源速率与攻击节律|
|`--check`|只读环境自检：打印平台/权限/抓包与防火墙后端可用性后退出（不抓包、不下发规则、不生成配置）|
|`--no-color`|关闭彩色输出（等价 `color=0`；`NO_COLOR` 环境变量同样生效）|
|`--force-color`|强制彩色输出，跳过终端能力检测|
|`--inbound-only` / `--any-direction`|强制开启 / 关闭“只统计入向流量”（覆盖配置 `inbound_only`）|
|`--strict-internal` / `--allow-internal`|只封公网 / 允许封内网（覆盖配置 `allow_internal`）|

## 抓包后端

* **npcap**（默认）：JNA → `wpcap.dll`，等价于 Python 版的 Scapy+Npcap。会先用
`pcap\\\_findalldevs` 枚举网卡，**跳过 WAN Miniport / Loopback / 蓝牙 / Wi-Fi Direct 等伪适配器**
（这些适配器抓不到流量），再 `pcap\\\_open\\\_live` + `pcap\\\_compile("dst port N")`。
* **external**：`dumpcap -w -` 或 `tcpdump -w -`，Java 直接解析 pcap 流，零 jar 依赖。
* **sim**：模拟流量，用于验证检测/封禁逻辑；默认强制 dry-run，避免误封真实 IP。

## 与 Python 版的行为差异

1. **控制台热键**：JDK 没有等价的裸控制台 API（Python 用 `msvcrt`/`tty.setcbreak`），改为
行输入：`x` + 回车进入/退出调试模式，`exit` + 回车退出程序；调试命令集与 Python 版完全一致。
`Ctrl+C` 仍然可用——由 JVM 关闭钩子接管，**同样会先撤销防火墙规则再退出**。
2. **抓包实现**：Scapy → JNA 直调 wpcap；`PcapParser` 自己解析 Ethernet/VLAN/SLL/NULL/RAW、
IPv4/IPv6（含扩展头）、TCP/UDP/SCTP/DCCP。
3. **防火墙按地址族分流**（修正 Python 版的缺陷）：IPv4 走 `iptables`、IPv6 走 `ip6tables`；
nft 建 `blocklist4`/`blocklist6` 两个集合。Python 版对 IPv6 攻击者是静默封不住的。
4. **新增安全阀**：`--dry-run`、`--list-ifaces`、配置文件范围校验（阈值下限 1，避免 `>= 0` 恒真）、
sim 模式默认 dry-run。

## 内网地址封禁策略（本轮改动）

之前 `Firewall.block()` 会无条件拒绝内网/保留地址（`is_internal` 一刀切），
导致内网攻击源、同网段测试流量永远封不掉。现在改为：

* **内网/保留地址默认可封禁**：新增配置项 `allow_internal`（默认 1）。
* **只保留必要底线**：未指定（`0.0.0.0`）、组播、广播（`255.255.255.255`）、环回地址仍拒绝；
  解析不出来的字符串仍拒绝。
* **本机自身地址始终不封禁**：自动把本机接口地址收集为受保护集合，避免把自己封掉。
* **可退回旧行为**：`set allow_internal 0`，或启动加 `--strict-internal`。

风险提示：允许封内网后，自动封禁可能命中**网关或内网主机**，从而中断本机网络
（伪造成网关地址的洪泛尤其危险）。允许内网封禁且非 dry-run 时 banner 会给出提示；
必要时把 `block_duration` 调小，或先用 `--dry-run` 观察。

## 变更记录

* **第 1 批**：IP 判定改用标准库语义（补齐 CGNAT/文档段/组播）；封禁入库校验 + IPv4-mapped 归一化；
  配置范围校验（阈值下限 1）；检测线程异常兜底；Ctrl+C/SIGTERM 统一安全退出并先撤规则。
* **第 2 批**：`Firewall` 同 IP 串行化 + 幂等下发 + 启动清理残留规则 + 退出批量 flush；
  滑动窗口改按秒分桶计数（`RateCounter`）；新增入向过滤（`inbound_only`，默认开）。
  > 下面「已知限制」里提到的 in-flight 串行化、逐包记录两项，已在第 2 批完成。
* **打包**：`build.cmd` 第 4 步生成 `dist\DDoSMonitor.jar`（内含 JNA 及全平台本机库，`java -jar` 直接运行）。
* **本轮**：内网地址封禁策略（见上一节）；`Json` 解析容忍 UTF-8 BOM
  （记事本 / PowerShell 保存的配置可直接读取，修复前会报「非法数值（位置 0）」并退回默认配置）。
* **第 3 批（安全加固）**：按静态审计清单修掉 17 项缺陷，见下一节。

### 本轮验证

* `SelfTest` 从 81 项扩到 **107 项，全部通过**（新增内网可封禁、底线拒绝、受保护地址、严格模式等）
* 真实防火墙验证：`block 10.255.255.254` 确实生成 netsh 规则；`unblock` 后规则消失；退出后无残留
* 带 BOM 的配置文件可正常加载

## 第 3 批：审计清单修复（17 项）

审计按“失效模式”给出的清单，逐条修复情况如下（`SelfTest` 同步扩到 **145 项**）：

### 严重（监控静默失效 / 内存耗尽 / JVM 崩溃）

| # | 问题 | 修复 | 验证 |
|---|---|---|---|
| 1 | 抓包线程静默死亡，主循环毫不知情 → 监控变盲 | 三个抓包源都在 `try/finally` 里复位 `running`，并新增 `PacketSource.isAlive()`；`DDoSMonitor` 新增 **「抓包看护」守护线程**（`startGuarded`，2s 巡检 + 30s 冷却）自动重启抓包；`[健康]` 行新增 `抓包源 正常/已停止(看护将自动重启)` | 探针实测：杀掉抓包线程后看护自动重启成功（`重启次数=1`）；`SelfTest` 覆盖“handler 抛异常后 `isAlive()=false`” |
| 2 | `Firewall.ipLocks` 无界增长 → OOM（`doBlock` 失败留孤儿锁） | 地址锁改为**引用计数**（`LockRef.users`，`acquire/release` 成对，在 `finally` 里释放），最后一个使用者退出时立刻从表里删除；顺带用 `lockTableSize()` 暴露给自检 | `SelfTest`：连续封 21 个 IP 后锁表 = 0 |
| 3 | `NpcapJnaSource.stop()` join 超时仍关句柄 → use-after-free（SIGSEGV） | 2s 未退出先告警并**再等 5s**；仍不退就**跳过 `pcap_close`**（进程即将退出，句柄交给 OS 回收），绝不释放抓包线程还在用的 `pcap_t` | 代码级修复（需驱动卡死才能复现） |
| 4 | `pfctl -E` 引用计数泄漏（反复启停只增不减） | 先查 `pfctl -s info`，**只有 pf 未启用时才 `-E`**，并解析返回的 `token` 记住；退出时对称执行 `pfctl -X <token>`（`cleanupAll` 里调用，dry-run 也会释放） | macOS 未实测（本机无 pfctl） |

### 中等（资源无界 / 崩溃风险）

| # | 问题 | 修复 | 验证 |
|---|---|---|---|
| 5 | 日志无轮转 → 攻击者用海量源 IP 把磁盘写满 | 单文件 **64 MB** 上限，`log → .1 → .2 → .3` 滚动，最旧丢弃；`clear` 命令同时清理轮转备份 | 探针实测 4 次轮转：`log.1/.2/.3` 正确滚动、`.4` 不存在 |
| 6 | `banned` 列表与 `applyPersistentBans` 无上限 | `ConfigStore.MAX_BANNED = 1000`（加载与 `ban` 一起限流）；单个域名 DNS 解析结果 **上限 32 个**；启动应用永久封禁加 **30s 预算**，超时跳过剩余条目并告警 | `SelfTest`：1050 条 → 截到 1000 |
| 7 | `Json` 无深度限制 → `StackOverflowError` 崩 JVM | 解析器加深度计数，**64 层**上限，超出抛 `IllegalArgumentException`（可被 `catch (Exception)` 捕获） | `SelfTest`：10 万层嵌套被拒且不是 `StackOverflowError` |
| 8 | `evaluateOnce` 的 `topInfo.contains(stat)` 是 O(n²) | 改用 `HashSet<String> seen` 去重（O(n)）；几十万源 IP 时评估不再从 1ms 涨到几百 ms | 探针实测：字节数排不进 Top5 的 SYN 源仍被检出并告警 |

### 低危（顺手修）

| # | 问题 | 修复 |
|---|---|---|
| 9 | `PcapParser` DLT_NULL 分支 `len < 5` 时越界 | 长度检查从 `< 4` 收紧为 `< 5`（后面要读 `buf[off+4]` 的版本号） |
| 10 | `GeoResolver` 缓存 `clear()` 全清 → 缓存雪崩 | 改为**访问序 LRU**（`LruCache`），超限只淘汰最久未用的一条 |
| 11 | `ConfigStore.save` 直接覆盖，写一半崩溃配置损坏 | 写同目录临时文件 + `move` 原子替换（不支持 `ATOMIC_MOVE` 时回退普通 move）；POSIX 上对齐原文件权限；保存前对 config 取快照 |
| 12 | `cleanupStale` 无差别删除 `DDoS_Block_*`，会误删另一实例的规则 | netsh 规则名改为 `DDoS_Block_<PID>_<IP>`，清理时只删「自己的」和「属主进程已退出」的；其它**正在运行的实例**的规则保留并提示 |
| 13 | VLAN 标签 `while` 循环无层数上限 | 最多 **3 层**，超出按畸形帧丢弃 |
| 14 | 调试模式改 config 与主线程读 config 无同步 | 配置统一用 `Collections.synchronizedMap` 包装，保存/展示时取快照 |
| 15 | `build.cmd` `chcp 65001` 后不恢复原代码页 | 开头记录原代码页（`for /f ... in ('chcp')`），成功与失败两条退出路径都恢复 |
| 16 | `SimSource` 速率被 200µs 下限卡在 5000 pps | 间隔下限放宽到 1µs（≈100 万 pps），亚毫秒部分改用 `Thread.onSpinWait()` 自旋补齐；`--sim-pps` 帮助文本已注明会占用一个 CPU 核 |
| 17 | `Firewall.block` 的 10 万上限检查在 `synchronized` 外 | 上限检查移入 `synchronized (lock)`，与 `blocked` 的写入同一把锁；常量改为 `MAX_TRACKED_BLOCKS` |

> 说明：#4（pfctl 引用计数）与 #3（驱动卡死时的 use-after-free）只在 macOS / 真实驱动异常时才会触发，
> 本机（Windows 11 + netsh + Npcap）无法实测，属**代码级修复**；其余各项都有 `SelfTest` 用例或临时探针实测证据。

### 第 3 批补充（真机日志驱动）

在 `L:\cp\Monitor`（443 端口）用新构建的 jar 实跑后，从 `ddos_alerts.log` 又发现并修掉一处：

| 现象（真机日志） | 原因 | 修复 |
|---|---|---|
| 一次 58 秒攻击里，**同一个 IP 的【自动封禁】刷了 60 行**（每秒一行），而 netsh 规则只下发了一次 | `Firewall.block()` 对“已封禁、本次只是续期”的地址同样返回 `true`，`evaluateOnce` 只看返回值就写日志 | 新增 `Firewall.isTracked(ip)`；自动封禁只在**真正新下发**（`tracked == false`）时写日志，续期不再刷屏 |

验证：探针连续 3 轮评估同一个攻击 IP（每轮都在阈值之上、IP 始终已跟踪）→ **【自动封禁】只有 1 行**；
【DDoS 告警】仍按冷却独立判定（探针把 cooldown 设为 0，故 3 轮 3 条）。

> 规则下发一直是幂等的（`blocksIssued` 只 +1），这条修复只影响日志量，
> 避免给审计 #5 的“攻击者用告警把磁盘写满”那条路径加速。
>
> 同一次真机日志里还出现过一次 `【性能】评估耗时 514 ms（活跃IP=1）`：活跃 IP 只有 1 个，
> 可以排除 #8 的 O(n²) 路径，更像高 pps（≈8600 pkt/s、12 MB/s）下的 GC/调度抖动；
> 如需精确定位，可把该耗时拆成“计数 / 判定 / 封禁”三段（本次未做）。

### 第 3 批验证（本批实测证据）

* `build.cmd`：`-Xlint:all` 零警告，产出 `dist\DDoSMonitor.jar`（1.90 MB）
* `SelfTest`：**145 项全过**（原 124 项 + 21 项本轮回归用例）；用 jar 跑自检同样 145/145
* 自动封禁日志：探针连续 3 轮评估同一攻击 IP → 【自动封禁】只写 1 行（修复前每轮 1 行）
* 抓包看护：临时探针手动杀死抓包线程 → 看护自动重启（日志 `嗅探器已重启`，重启次数 1）
* 日志轮转：探针连续触发 4 次轮转，`log.1/.2/.3` 正确滚动、`.4` 不存在
* 归属地缓存：写入 5000 条后稳定在 4096（旧实现会整体清空），最久未用被淘汰、最新条目仍在
* `evaluateOnce`：改造后字节数排不进 Top5 的 SYN 源仍被检出并告警
* 代码页：`cmd /c "chcp & build.cmd & chcp"` 前后都是 936（修复前会残留 65001）
* 运行冒烟：`--source=sim` 正常告警与安全退出；调试模式 `set window 2` 原子保存成功且无 `.tmp` 残留
* `java -jar dist\DDoSMonitor.jar --check` 正常输出（只读，不下发规则）

## 性能诊断与计数器淘汰（本轮改动）

**背景**：怀疑 `RateCounter.add()` 每包调用 `evict()` 导致抓包线程拖死评估循环，从而“打满但无告警”。
用 `java/bench/RateCounterBench.java`（复现“抓包线程持锁喂包 + 评估线程每秒抢锁”）实测：

| 场景 | 纯 `add()` | 含淘汰的突发最差 | **评估抢锁等待** | 评估 tick 计算 |
|---|---|---|---|---|
| 1 源 IP、5k pps | 984 ns/包 | 50 µs/包 | **0 ms** | 0–1 ms |
| 20 万源 IP、30 万 pps | 698 → 636 ns/包 | 48–62 µs/包 | **0 ms** | 21–40 ms |

结论：`evict()` 的重活（遍历过期秒桶里的 IP）**每秒最多发生一次**（仅当某个秒桶跨过 cutoff 时），
不是每包；评估循环从未被饿死。但仍有两点值得改，已做：

* `add()` 里的淘汰改为**每秒最多尝试一次**（`lastEvictSec` 门控）：纯 `add()` 从 698 → 636 ns/包。
  仍保留在抓包路径上（不是只靠评估线程），这样即使评估线程卡住，窗口也不会无限增长。
* 新增**健康度输出**（每 `health_interval` 秒，默认 10，0 = 关闭）：
  `[健康] 窗口包数 N / 活跃IP M / 秒桶 K / 入向过滤丢弃 F / 上次评估 T ms / 累计 P 包 / 告警 A 次`
  —— 出现“打满但没反应”时，这一行立刻区分三种情况：**没收到包**（窗口包数=0）、
  **被入向过滤丢弃**（丢弃数暴涨）、**评估跟不上**（上次评估很大）。
* 新增**评估耗时告警**：`evaluateOnce` 超过 500 ms 时打印并写日志 `【性能】评估耗时 … ms`。
* 新增**启动行写日志**：`【启动】配置来源=… 目标端口=… 抓包后端=… 入向过滤=… 自动封禁=…`
  —— 端口/配置目录不对时，日志里能直接看出来。

### 一次真实排查的结论（用现网日志核对）

仓库根目录 `ddos_alerts.log`：16 条【DDoS 告警】+ 2 条【攻击结束】（127 万包 / 峰值 4868 pkt/s / 1.80 GB），
说明检测与评估一直正常；但**【自动封禁】= 0 条**——因为来源 `192.168.0.2` 是内网地址，
旧代码拒绝封内网，所以是“检测到了但防御没动作”。这正是上一节「内网地址封禁策略」要解决的问题，
现已改为默认可封内网，并用真实 netsh 规则验证过。

> 注意：`java/ddos_alerts.log` 只是开发时的测试日志（手动 block/unblock 各 2 条），不是生产日志。
> 程序把日志与配置写在**当前工作目录**，从哪个目录启动决定了读哪个 `monitor_config.json`。

### 抓包层诊断与网卡选择（本轮补充）

`[健康]` 行末尾新增 **Npcap 层计数**，用来区分“包根本没到 Java”和“到了但被丢掉”：

```
[健康] 窗口包数 24 / 活跃IP 1 / … / Npcap[调用=74 收包=55 超时=18 错误=0 零长=0
        非目标端口=0 解析失败=0 已计数=55 最近包[caplen=54 len=54 TCP 192.168.0.30->101.91.111.117:80]]
```

| 计数特征 | 含义 |
|---|---|
| `收包=0` 且 `超时` 很多 | Npcap 一个包都没交上来：**网卡选错**，或 BPF 过滤器不匹配 |
| `收包>0` 且 `零长>0` | 包交上来了但读出的 `caplen` 为 0（结构体/驱动异常）——本机实测不会发生 |
| `收包>0`、`已计数>0`，但 `入向过滤丢弃>0` | 流量不是发给本机的（`inbound_only=1` 丢弃） |
| `收包>0`、`非目标端口>0` | BPF 过滤器没生效（`pcap_compile` 失败时回退为用户态过滤） |

**网卡选择**改为按「默认路由出口网卡」挑选（UDP connect 取本地出口地址 → 匹配网卡显示名），
不再用“第一个 up 的网卡”：Hyper-V 虚拟网卡、VPN TAP 也常常是 up 的，但流量不走它们。
选错网卡的典型症状恰好就是「`收包=0`、入向过滤丢弃 `0`、窗口包数 `0`」而目标机确实在挨打。
`【抓包】` 日志行会记录实际使用的网卡与过滤器状态，可事后核对；也可用 `--list-ifaces` +
`--iface` 手工指定。

### 告警与状态行的彩色输出（本轮新增）

颜色约定：

| 输出行 | 颜色 |
|---|---|
| `【DDoS 告警 / …】…`（`alert()`） | **红** `ESC[31m` |
| `正在监测:遭遇DDoS攻击 / 遭遇SYN攻击｜…` | **黄** `ESC[33m` |
| `正在监测:…攻击结束｜…` | **绿** `ESC[32m` |
| `正在监测:状态正常｜…` | 默认色（不染色） |

```
[2026-10-03 22:27:58] 【DDoS 告警 / DDoS_ATTACK】单IP高频请求/流量异常 1.2.3.4 (100.0 req/s) | 攻击者IP: 1.2.3.4 | 归属地: 查询中
```

（上面是纯文本形式；终端支持颜色时整行会带对应颜色码，且以 `ESC[0m` 收尾。）

* 注意 `alert()` 原本**只写日志文件**、控制台上看不到告警；现在告警行会同时打印到控制台。
* **自动判定**：输出被重定向到文件/管道、环境变量 `NO_COLOR`、`TERM=dumb` → 自动退化为纯文本；
  **日志文件永远是纯文本**，不会写入任何转义字符。
* **Windows**：Windows Terminal（`WT_SESSION`）原生支持；传统 conhost 由
  `WindowsAnsi` 通过 JNA 调 `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)` 打开 ANSI 支持
  （需要 `lib/jna.jar`；缺它时该文件不参与编译，颜色自动退化，其余功能不受影响）。
* **开关**：`--no-color` / `set color 0`（配置项 `color`，默认 1）关闭；
  `--force-color` 跳过终端检测强制上色（终端识别不出来时的兜底）。

验证：`SelfTest` 全通过（当前 **145 项**，其中 6 项颜色用例）；实测（`--force-color`）告警行=红、攻击中=黄、
攻击结束=绿且均以 `ESC[0m` 收尾；重定向输出与日志文件里均无转义字符。

## 三端支持现状（重要：只有 Windows 实测过）

代码是按三端可移植写的，但**实测只在 Windows 上做过**。请按这张表理解可信度：

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 编译 | ✅ `build.cmd` 实测 | ⚠️ `build.sh` 已提供并在 Git Bash 下实跑通过，**未在真实 Linux 上运行** | ⚠️ 同上（含 `java_home` 探测） |
| 核心逻辑（SelfTest 145 项） | ✅ 实测通过 | ⚠️ 纯 JDK 代码，未运行 | ⚠️ 未运行 |
| 抓包（Npcap / libpcap，JNA） | ✅ 实测（Intel Wi-Fi 6E，抓到真实流量） | ⚠️ 需 `libpcap` + root/`CAP_NET_RAW` | ⚠️ 需 `libpcap`，未验证 |
| 防火墙 | ✅ `netsh` 实测（真建/真删规则、内网地址可封） | ⚠️ `iptables`/`ip6tables`（专用链）或 `nft`，**一行未跑** | ⚠️ `pfctl`，**一行未跑** |
| 外部抓包（dumpcap/tcpdump） | ⚠️ 本机没装 Wireshark | ⚠️ 未验证 | ⚠️ 未验证 |
| 彩色输出 | ✅ 实测（WT / conhost 两路） | ⚠️ 走 `TERM` 判定 | ⚠️ 同左 |
| 退出清理、配置、日志、地理查询 | ✅ 实测 | ⚠️ 与平台无关，但未运行 | ⚠️ 同左 |

静态审查发现并**已修**的三端硬伤：

* **PATH 不含 sbin**：Linux 非 root shell 的 `PATH` 常常没有 `/usr/sbin`、`/sbin`，`which()` 会
  误判“后端不可用”。现改为额外探测常见 bin/sbin 目录（含 macOS 的 `/opt/homebrew/*`），
  并把解析到的**绝对路径**用于命令行（`Firewall.locate/exe`）。
* **libpcap 描述为空**：Linux/macOS 上 `pcap_if_t.description` 通常为 NULL，原逻辑会把所有设备
  都当伪适配器，退化成“第一个设备”（可能是 `any`/`nflog`/`docker0`）。现改为 description 为空时
  用**设备名**判定，并排除 `any/lo/nflog/nfqueue/dbus-*/virbr*/docker*/veth*/tun*/utun*`。
* **macOS tcpdump 不支持 `-i any`**：现改为默认使用默认路由网卡名（取不到则 `en0`）。
* **默认出口网卡解析**统一为 `NetUtil.defaultInterfaceName()`（UDP connect + 反查网卡），
  避免选到 Hyper-V / VPN TAP / docker0 这类 up 但不承载默认流量的适配器。

**未修、但你必须在 macOS 上注意的坑**：`pfctl -a <anchor> -f -` 只是把规则加载进 anchor；
若 `/etc/pf.conf` 里没有 `anchor "com.ddos.monitor"` 引用，规则**不会被评估**——也就是
“不报错但也不拦截”。在 macOS 上使用前请确认 anchor 已被主线规则引用（`pfctl -sr` 能看到），
或改用 `pfctl -f` 直接加载。另外 Linux 抓包要 root/`CAP_NET_RAW`，`iptables`/`nft` 要 root
或 `CAP_NET_ADMIN`；`libpcap` 需自行安装（`apt install libpcap0.8` / `brew install libpcap`）。

### 在 Linux / macOS 上花 1 分钟自证

```bash
./build.sh
java -cp dist/DDoSMonitor.jar SelfTest          # 期望 145/145
sudo java -jar dist/DDoSMonitor.jar --source=sim --yes
# 进调试模式（输入 x），然后：
#   block 10.255.255.254        → 另开终端确认规则真的下发了
#   unblock 10.255.255.254      → 再确认规则被删掉
sudo iptables -S DDOS_BLOCK                     # Linux：应能看到 DROP 规则
sudo nft list set inet ddos_filter blocklist4   # 或 nft 后端
sudo pfctl -a com.ddos.monitor -t blocklist -T show   # macOS
```

### 环境自检：一条命令分清「我在哪、我能干什么」

```bat
java -jar dist\DDoSMonitor.jar --check        （Linux/macOS: java -jar dist/DDoSMonitor.jar --check）
```

只读、无副作用（不抓包、不创建链/表、不生成配置文件）。正常启动时也会打印同一份“实测版”报告。
本机（Windows）样例：

```
 环境自检（只读，不抓包、不下发规则）
   平台          : Windows 11 / amd64 / JDK 21.0.12.1
   权限          : 管理员（可抓包、可改防火墙）
   工作目录      : L:\虚拟机\java
   目标端口      : 80
   抓包后端      : Npcap（JNA → wpcap.dll）｜可用 ✓｜库=wpcap.dll｜网卡枚举=12 个｜默认网卡=\Device\NPF_{0ADBBACA-…}｜后备工具=未找到 dumpcap/tcpdump
   防火墙后端    : netsh 可用 ✓｜路径=C:\Windows\system32\netsh.exe（--check 不创建链/表）
   策略          : 入向过滤=开 内网封禁=开 自动封禁=开 dry-run=关
   结论          : 可抓包；可封禁
```

缺依赖时会把**原因和下一步**直接写出来（实测的降级样例，故意去掉 jna.jar）：

```
   抓包后端      : sim（模拟流量，仅自测）｜不可用 ✗｜原因：jar 内缺少 JNA（lib/jna.jar 未参与编译）
                   ｜后备工具=未找到 dumpcap/tcpdump → 可用 --source=sim 验证检测/封禁逻辑
   防火墙后端    : netsh 可用 ✓｜路径=C:\Windows\system32\netsh.exe（--check 不创建链/表）
   结论          : 无真实抓包（将退回模拟流量自测）；可封禁
```

各字段含义：**平台**（os/arch/JDK）、**权限**（Windows 用 `net session` 判定管理员；Linux/macOS 看是否
root 并提示 `CAP_NET_RAW`/`CAP_NET_ADMIN`）、**抓包后端**（Npcap/libpcap 能否加载、枚举到几块网卡、
默认会选哪一块、有无 dumpcap/tcpdump 兜底）、**防火墙后端**（后端名 + **解析到的绝对路径** + 不可用原因）、
**策略**（入向过滤/内网封禁/自动封禁/dry-run）、**结论**（可抓包？可封禁？还是仅告警）。
在 Linux/macOS 上先跑这条，就能立刻分清是“环境缺依赖”还是“程序有问题”。

## 已验证（本机实测）

* `javac 21.0.12.1` 编译，`-Xlint:all` **零警告**，**37 个 class**（含内部类，不含 JNA），`major version: 65`（Java 21）
* `build.cmd` 干净目录构建通过（退出码 0），产出 `dist\DDoSMonitor.jar`（1.90 MB）
* `java -cp dist\DDoSMonitor.jar SelfTest` → **145 项全过**；`java -jar dist\DDoSMonitor.jar --check` 正常输出
* **模拟源端到端**：`状态正常 → 遭遇SYN攻击 / 遭遇DDoS攻击 → 攻击结束`，攻击结束含峰值、
总流量/包数/时长、主要来源归属地；dry-run 自动封禁登记 12 条；调试 REPL
`show`/`fw`/`set window 2`/未知命令/`exit` 均正确；`exit` 退出码 0 并打印防火墙清理
* **Npcap 真实抓包**：打开 Intel Wi-Fi 6E AX210、`DLT=1`、BPF `dst port 80` 生效；
用 curl 产生 80 端口流量后被解析出 **40 个包**（协议分布 TCP），来源 `192.168.0.30`
被正确判为内网/保留IP 而未封禁
* 退出路径：`exit` 与关闭钩子两条路径都汇入同一套清理流程（含 60s 预算）

## 未验证（需要对应环境，请自行确认）

* Linux `iptables`/`ip6tables`/`nft`、macOS `pfctl` 的实际下发与撤销
* `external` 后端（本机没有 dumpcap/tcpdump）
* SCTP/DCCP 解析、IPv6 真实链路、VLAN 标签（无对应流量）
* **非 dry-run 的真实封禁效果**（没有在真机上真封 IP，避免误封）
* 高 pps 长时间稳定性（Scapy 同款上限问题在 Java 侧依然存在）

## 已知限制 / 与 Python 版相同的待办

* `Firewall.block()` 的“检查-下发”仍非原子：并发下可能对同一 IP 重复下发规则，
而解封只删一条 → 建议后续加 in-flight 集合串行化。
* 每个包仍生成一个对象记录（对应 Python 的元组记录），极高 pps 下开销大 → 建议改按秒分桶计数。
* 默认阈值偏低（`ip\\\_pps\\\_threshold=5`、`global\\\_pps\\\_threshold=20`），正常流量容易判成攻击。
* BPF 只匹配 `dst port`，**不区分方向**：本机自己访问外部 80 端口也会被计入（与 Python 版相同）；
如需仅入向，可在 `PcapParser`/过滤器里加方向判断。
* macOS 的 pf anchor 需要 `/etc/pf.conf` 引用才会被评估（见上文三端支持现状）。
* Linux/macOS 防火墙后端与 `external` 抓包后端仍未在真机实测。

