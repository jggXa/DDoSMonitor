import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DDoS 监测与自动封禁（1.py 的 Java 21 移植版）。
 *
 * <p>逻辑与 Python 版一一对应：同样的滑动窗口阈值判定、同样的攻击状态机
 * （峰值/总量/主要来源）、同样的自动封禁与告警冷却、同样的调试命令集。
 * 主要差异见 README.md（抓包后端、控制台热键、防火墙按地址族分流）。</p>
 */
public final class DDoSMonitor {

    private static final String CONFIG_FILE_DEFAULT = "monitor_config.json";
    private static final String LOG_FILE = "ddos_alerts.log";
    private static final Object LOG_LOCK = new Object();
    /** 单个日志文件大小上限（64 MB），超过就轮转，避免被海量源 IP 的告警把磁盘写满。 */
    private static final long MAX_LOG_BYTES = 64L * 1024 * 1024;
    /** 保留的轮转备份个数：ddos_alerts.log.1 ... ddos_alerts.log.3。 */
    private static final int LOG_BACKUPS = 3;
    /** 启动时应用永久封禁（含 DNS 解析）的总预算，超过就放弃剩余条目并提示。 */
    private static final long PERSISTENT_BAN_BUDGET_NANOS = 30L * 1_000_000_000L;
    /** 单个域名最多解析出多少个地址（防止被攻击者控制的 DNS 返回海量 A 记录）。 */
    private static final int MAX_RESOLVED_IPS = 32;
    /** 嗅探器自动重启的最小间隔（毫秒）：避免抓包一直起不来时刷屏。 */
    private static final long SNIFFER_RESTART_COOLDOWN_MS = 30_000L;

    // ------------------------------------------------------------ 运行参数

    private static final class Options {
        Path configFile = Paths.get(CONFIG_FILE_DEFAULT);
        String source = "auto";
        String iface;
        boolean yes;
        boolean dryRun;
        boolean live;
        boolean listIfaces;
        /** 关闭“只统计入向流量”。 */
        boolean anyDirection;
        /** 强制开启入向过滤（覆盖配置）。 */
        boolean forceInboundOnly;
        /** 严格模式：恢复“只封公网”，不封内网/保留地址。 */
        boolean strictInternal;
        /** 显式允许封禁内网地址（默认即允许，此开关用于覆盖配置）。 */
        boolean allowInternal;
        /** 关闭控制台彩色输出。 */
        boolean noColor;
        /** 强制开启彩色输出（跳过终端能力检测）。 */
        boolean forceColor;
        /** 只做环境自检后退出（只读，不抓包、不下发规则）。 */
        boolean check;
        int simNormalPps = 40;
        int simAttackPps = 3000;
        int simPeriod = 60;
        int simAttackSeconds = 10;
    }

    private static final class UsageError extends Exception {
        private static final long serialVersionUID = 1L;

        UsageError(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------ 数据结构

    private record AttackEnd(double duration, String type, String source, double peakPps,
                             double peakBps, long totalBytes, long totalPackets) {
    }

    /** 评估用的单 IP 快照：在锁内复制，锁外打印不会读到正在变化的数据。 */
    private record IpStat(String ip, long packets, long bytes, long syns) {
    }

    // ------------------------------------------------------------ 字段

    private final Map<String, Object> config;
    private final String configSource;
    private final Options options;
    private final Firewall firewall;
    private final GeoResolver geo = new GeoResolver();
    private final ConsoleInput console = new ConsoleInput();

    private int port;
    private int window;
    private long ipPpsThreshold;
    private long ipBpsThreshold;
    private long globalPpsThreshold;
    private long globalBpsThreshold;
    private int distinctIpThreshold;
    private long synThreshold;
    private long alertCooldown;

    private final RateCounter counter;
    private final Set<String> localAddresses;
    private final Map<String, Double> lastAlert = new HashMap<>();
    private final Object lock = new Object();
    /** 是否只统计入向流量（第 2 批新增，由配置 + 命令行决定）。 */
    private boolean inboundOnly;

    private volatile boolean stop;
    private final AtomicBoolean shutdownDone = new AtomicBoolean();
    private final AtomicLong totalAlerts = new AtomicLong();
    private volatile long totalPackets;
    private volatile long totalBytes;
    private volatile String lastState = "状态正常";
    private volatile int warnCount;
    /** 被入向过滤丢弃的包数（诊断“打满但没反应”用）。 */
    private volatile long filteredByInbound;
    /** 上次 evaluateOnce 的耗时（毫秒）。 */
    private volatile long lastTickMillis;
    /** 上次评估时窗口内的包数与活跃 IP 数（健康度输出用）。 */
    private volatile long lastWindowPackets;
    private volatile int lastActiveIps;
    /** 健康度输出间隔（秒，0 = 关闭）。 */
    private long healthInterval;
    /** 上一次输出健康度的时刻（秒）。 */
    private double lastHealthAt;

    private volatile PacketSource source;
    /** 保护 source 的替换：调试模式 set port 与看护线程可能同时重启嗅探器。 */
    private final Object sourceLock = new Object();
    /** 抓包源是否成功启动过：用于区分“还没启动”与“启动后死掉”（前者不该重试）。 */
    private volatile boolean snifferStarted;
    /** 上次自动重启嗅探器的时刻（毫秒），用于冷却。 */
    private volatile long lastRestartAttempt;
    private final AtomicLong snifferRestarts = new AtomicLong();

    private boolean attackActive;
    private String attackType;
    private Double attackStartTs;
    private double attackPeakPps;
    private double attackPeakBps;
    private long attackTotalBytes;
    private long attackTotalPackets;
    private String attackMainSource;

    // ------------------------------------------------------------ 入口

    public static void main(String[] args) {
        Options options;
        try {
            options = parseArgs(args);
        } catch (UsageError e) {
            System.out.println(e.getMessage());
            System.out.println(usage());
            return;
        }
        if (options.listIfaces) {
            listInterfaces();
            return;
        }
        if (options.check) {
            // 只读自检：不创建配置文件、不构造 Firewall（避免在 Linux 上创建链/表）、不打开网卡
            ConfigStore.LoadResult probe = ConfigStore.load(options.configFile, false);
            EnvironmentCheck.printReadOnly(
                    (int) ConfigStore.asLong(probe.config(), "port", 80),
                    ConfigStore.asLong(probe.config(), "inbound_only", 1) == 1 && !options.anyDirection,
                    ConfigStore.asLong(probe.config(), "allow_internal", 1) == 1 && !options.strictInternal,
                    ConfigStore.asLong(probe.config(), "auto_block", 1) == 1,
                    options.dryRun);
            return;
        }
        clearScreen();
        ConfigStore.LoadResult loaded = ConfigStore.load(options.configFile);

        // ------------------------------------------------------------ 启动前自检
        // 先自检再询问：**只有发现问题（错误或警告）才打断询问**；全绿灯则直接启动，不打扰。
        // --yes 表示"无论有没有问题都不要问"，但仍会把问题打印出来。
        int problemPort = (int) ConfigStore.asLong(loaded.config(), "port", 80);
        boolean problemInboundOnly =
                ConfigStore.asLong(loaded.config(), "inbound_only", 1) == 1 && !options.anyDirection;
        boolean problemAllowInternal =
                ConfigStore.asLong(loaded.config(), "allow_internal", 1) == 1 && !options.strictInternal;
        boolean problemAutoBlock = ConfigStore.asLong(loaded.config(), "auto_block", 1) == 1;
        List<String> problems = EnvironmentCheck.collectProblems(
                problemPort, problemInboundOnly, problemAllowInternal, problemAutoBlock, options.dryRun);
        if (!problems.isEmpty()) {
            System.out.println(Color.green("启动前自检发现 " + problems.size() + " 项需要留意（错误/警告）："));
            for (String problem : problems) {
                System.out.println(Color.green("  " + problem));
            }
            System.out.println();
            if (!options.yes) {
                System.out.print("是否继续(y/n): ");
                System.out.flush();
                String line;
                try {
                    line = ConsoleInput.sharedReader().readLine();
                } catch (IOException e) {
                    line = "";
                }
                String choice = line == null ? "" : line.trim().toLowerCase(Locale.ROOT);
                if (!choice.isEmpty() && !choice.equals("y")) {
                    System.out.println("已取消运行。");
                    return;
                }
            }
        }
        DDoSMonitor monitor = new DDoSMonitor(loaded.config(), loaded.source(), options);
        monitor.geo.start();
        monitor.start();
    }

    /** 打印 Npcap 可见的网卡列表（NpcapJnaSource 可能未编译，所以走反射）。 */
    private static void listInterfaces() {
        System.out.println("Npcap 可见网卡:");
        try {
            Class<?> cls = Class.forName("NpcapJnaSource");
            Object result = cls.getMethod("listDevices").invoke(null);
            if (!(result instanceof List<?> devices) || devices.isEmpty()) {
                System.out.println("  （未找到网卡：请确认已安装 Npcap 并以管理员运行）");
                return;
            }
            for (int i = 0; i < devices.size(); i++) {
                System.out.println("  [" + i + "] " + devices.get(i));
            }
            System.out.println();
            System.out.println("选定后这样使用: --iface=\"\\Device\\NPF_{...}\"");
        } catch (Throwable t) {
            System.out.println("  无法枚举网卡: " + t);
        }
    }

    private static String usage() {
        return """
                用法: java DDoSMonitor [选项]
                  --config <文件>     配置文件路径（默认 monitor_config.json）
                  --source <类型>     抓包后端: auto | npcap | external | sim（默认 auto）
                  --iface <网卡>      抓包网卡（Npcap 形如 \\Device\\NPF_{...}；tcpdump 可用 any）
                  --list-ifaces       列出 Npcap 可见网卡后退出
                  --any-direction     关闭“只统计入向流量”（默认只统计发给本机的包）
                  --inbound-only      强制开启入向过滤（覆盖配置）
                  --strict-internal   只封公网：拒绝封禁内网/保留地址（等价 allow_internal=0）
                  --allow-internal    允许封禁内网/保留地址（默认行为，覆盖配置）
                  --no-color          关闭控制台彩色输出（等价 color=0；NO_COLOR 环境变量同样生效）
                  --force-color       强制彩色输出，跳过终端能力检测
                  --check             只读环境自检：打印平台/权限/抓包与防火墙后端可用性后退出
                  --dry-run           只告警与登记，不真正下发防火墙规则
                  --live              即使使用 sim 也真实下发规则（默认 sim 为 dry-run）
                  --yes               跳过“是否继续(y/n)”确认
                  --sim-pps <n>       模拟源正常速率（默认 40 pkt/s；亚毫秒间隔用自旋补齐，
                                      上限约 100 万 pkt/s，追求高精度会占满一个 CPU 核）
                  --sim-attack-pps <n> 模拟源攻击速率（默认 3000 pkt/s，同上）
                  --sim-period <n>    模拟攻击周期秒数（默认 60，0 表示不攻击）
                  --sim-attack <n>    模拟攻击持续秒数（默认 10）
                """;
    }

    private static Options parseArgs(String[] args) throws UsageError {
        Options o = new Options();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new UsageError("无法识别的参数: " + arg);
            }
            String key = arg.substring(2);
            String value = null;
            int eq = key.indexOf('=');
            if (eq >= 0) {
                value = key.substring(eq + 1);
                key = key.substring(0, eq);
            }
            switch (key) {
                case "config":
                    o.configFile = Paths.get(need(args, i, value, key));
                    if (value == null) {
                        i++;
                    }
                    break;
                case "source":
                    o.source = need(args, i, value, key).toLowerCase(Locale.ROOT);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "iface":
                    o.iface = need(args, i, value, key);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "yes":
                    o.yes = true;
                    break;
                case "list-ifaces":
                case "list-iface":
                    o.listIfaces = true;
                    break;
                case "any-direction":
                case "any-dir":
                    o.anyDirection = true;
                    break;
                case "inbound-only":
                    o.forceInboundOnly = true;
                    break;
                case "strict-internal":
                    o.strictInternal = true;
                    break;
                case "allow-internal":
                    o.allowInternal = true;
                    break;
                case "no-color":
                case "nocolor":
                    o.noColor = true;
                    break;
                case "force-color":
                case "color":
                    o.forceColor = true;
                    break;
                case "check":
                case "check-env":
                    o.check = true;
                    break;
                case "dry-run":
                    o.dryRun = true;
                    break;
                case "live":
                    o.live = true;
                    break;
                case "sim-pps":
                    o.simNormalPps = parseIntArg(need(args, i, value, key), key);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "sim-attack-pps":
                    o.simAttackPps = parseIntArg(need(args, i, value, key), key);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "sim-period":
                    o.simPeriod = parseIntArg(need(args, i, value, key), key);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "sim-attack":
                    o.simAttackSeconds = parseIntArg(need(args, i, value, key), key);
                    if (value == null) {
                        i++;
                    }
                    break;
                case "help":
                case "h":
                    throw new UsageError("");
                default:
                    throw new UsageError("未知选项: --" + key);
            }
        }
        return o;
    }
    /** 数字参数解析：把裸 NumberFormatException 变成带用法的友好提示。 */
    private static int parseIntArg(String text, String key) throws UsageError {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            throw new UsageError(key + " 需要一个整数，收到: " + text);
        }
    }


    private static String need(String[] args, int index, String inlineValue, String key) throws UsageError {
        if (inlineValue != null) {
            return inlineValue;
        }
        if (index + 1 >= args.length) {
            throw new UsageError("选项 --" + key + " 缺少取值");
        }
        return args[index + 1];
    }

    private DDoSMonitor(LinkedHashMap<String, Object> config, String configSource, Options options) {
        // #14：配置在调试模式（输入线程）与评估循环（后台线程）之间共享。
        // 单个 get/put 需要内存可见性，且保存时要拿到一致快照，所以统一用同步包装。
        this.config = Collections.synchronizedMap(new LinkedHashMap<>(config));
        this.configSource = configSource;
        this.options = options;
        this.localAddresses = localAddresses();
        reloadFromConfig();
        this.counter = new RateCounter(window);
        this.firewall = new Firewall((int) ConfigStore.asLong(config, "block_duration", 300));
        boolean dryRun = options.dryRun;
        if ("sim".equals(options.source) && !options.live) {
            dryRun = true;
        }
        firewall.setDryRun(dryRun);
        firewall.setProtectedAddresses(localAddresses);
        resolveAllowInternal();
    }

    /** 本机所有接口地址（归一化），用于判断“这个包是不是发给本机的”。 */
    private static Set<String> localAddresses() {
        Set<String> out = new HashSet<>();
        try {
            for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                for (InetAddress addr : Collections.list(nic.getInetAddresses())) {
                    String norm = NetUtil.normIp(addr.getHostAddress());
                    if (norm != null) {
                        out.add(norm);
                    }
                }
            }
        } catch (Exception ignored) {
            // 取不到就留空集合，入向过滤会自动关闭，避免把流量全丢掉
        }
        return out;
    }

    private boolean isLocalAddress(String ip) {
        if (ip == null) {
            return false;
        }
        String norm = NetUtil.normIp(ip);
        return norm != null && localAddresses.contains(norm);
    }

    /** 供 sim 源使用：优先取一个 IPv4 本机地址作为目的地址。 */
    private String sampleLocalAddress() {
        for (String addr : localAddresses) {
            if (addr.indexOf(':') < 0) {
                return addr;
            }
        }
        return localAddresses.isEmpty() ? "127.0.0.1" : localAddresses.iterator().next();
    }

    private void reloadFromConfig() {
        port = (int) ConfigStore.asLong(config, "port", 80);
        window = (int) ConfigStore.asLong(config, "window", 3);
        ipPpsThreshold = ConfigStore.asLong(config, "ip_pps_threshold", 5);
        ipBpsThreshold = ConfigStore.asLong(config, "ip_bps_threshold", 512 * 1024);
        globalPpsThreshold = ConfigStore.asLong(config, "global_pps_threshold", 20);
        globalBpsThreshold = ConfigStore.asLong(config, "global_bps_threshold", 2 * 1024 * 1024);
        distinctIpThreshold = (int) ConfigStore.asLong(config, "distinct_ip_threshold", 20);
        synThreshold = ConfigStore.asLong(config, "syn_threshold", 10);
        alertCooldown = ConfigStore.asLong(config, "cooldown", 10);
        healthInterval = ConfigStore.asLong(config, "health_interval", 10);
        if (counter != null) {
            counter.setWindow(window);
        }
        resolveInboundOnly();
        resolveAllowInternal();
        Color.init(ConfigStore.asLong(config, "color", 1) == 1 && !options.noColor);
        if (options.forceColor) {
            Color.setEnabled(true);                          // 忽略终端检测，强制上色
        }
    }

    /** 内网封禁策略：默认允许（不再把内网/保留地址排除在封禁之外）。 */
    private void resolveAllowInternal() {
        if (firewall == null) {
            return;                     // 构造期 firewall 尚未创建，创建后由构造器再调用一次
        }
        boolean allow = ConfigStore.asLong(config, "allow_internal", 1) == 1;
        if (options.strictInternal) {
            allow = false;
        }
        if (options.allowInternal) {
            allow = true;
        }
        firewall.setAllowInternal(allow);
    }

    /** 入向过滤的最终开关：配置 + 命令行覆盖；本机地址集合为空时自动关闭。 */
    private void resolveInboundOnly() {
        boolean enabled = ConfigStore.asLong(config, "inbound_only", 1) == 1;
        if (options.anyDirection) {
            enabled = false;
        }
        if (options.forceInboundOnly) {
            enabled = true;
        }
        if (localAddresses == null || localAddresses.isEmpty()) {
            enabled = false;
        }
        inboundOnly = enabled;
    }

    @SuppressWarnings("unchecked")
    private List<String> banned() {
        Object value = config.get(ConfigStore.KEY_BANNED);
        if (value instanceof List<?> list) {
            return (List<String>) list;
        }
        List<String> fresh = new ArrayList<>();
        config.put(ConfigStore.KEY_BANNED, fresh);
        return fresh;
    }

    private String bannedPreview() {
        List<String> list = banned();
        if (list.isEmpty()) {
            return "无";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(5, list.size()); i++) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(list.get(i));
        }
        if (list.size() > 5) {
            sb.append(" ...(+").append(list.size() - 5).append(")");
        }
        return list.size() + " 项 [" + sb + "]";
    }

    // ------------------------------------------------------------ 界面

    private static void clearScreen() {
        try {
            if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                System.out.print("\u001B[2J\u001B[H");
                System.out.flush();
            }
        } catch (Exception ignored) {
            // 清屏失败无所谓
        }
    }

    private void printBanner() {
        clearScreen();
        System.out.println("=".repeat(72));
        System.out.println("  配置来源        : " + configSource);
        System.out.println("  单IP PPS 阈值   : " + ipPpsThreshold + " pkt/s");
        System.out.println("  单IP BPS 阈值   : " + NetUtil.humanBytes(ipBpsThreshold) + "/s");
        System.out.println("  全局 PPS 阈值   : " + globalPpsThreshold + " pkt/s");
        System.out.println("  全局 BPS 阈值   : " + NetUtil.humanBytes(globalBpsThreshold) + "/s");
        System.out.println("  分布式IP 阈值   : " + distinctIpThreshold + " 个");
        System.out.println("  SYN 包 阈值     : " + synThreshold + " 个");
        System.out.println("  统计滑动窗口    : " + window + " 秒");
        System.out.println("  入向过滤        : " + (inboundOnly
                ? "开启（只统计目的地址为本机的流量，本机 " + localAddresses.size() + " 个地址）"
                : "关闭（双向统计）"));
        System.out.println("  内网地址封禁    : " + (firewall.isAllowInternal()
                ? "允许（含内网/保留地址；" + firewall.protectedCount() + " 个本机地址受保护）"
                : "禁止（只封公网，set allow_internal 1 可放开）"));
        if (firewall.isAllowInternal() && !firewall.isDryRun()
                && ConfigStore.asLong(config, "auto_block", 1) == 1) {
            System.out.println("  内网封禁风险    : 自动封禁可能命中网关/内网主机，"
                    + "必要时 set allow_internal 0 退回“只封公网”");
        }
        String status = firewall.available() ? firewall.backend() : "不可用";
        String auto = ConfigStore.asLong(config, "auto_block", 1) == 1 ? "开启" : "关闭";
        String dry = firewall.isDryRun() ? "，dry-run 不真正下发" : "";
        System.out.println("  防火墙后端      : " + status + "（自动封禁: " + auto
                + "，封禁时长 " + firewall.duration() + "s" + dry + "）");
        System.out.println("  永久封禁列表    : " + bannedPreview());
        System.out.println("  详细日志        : 当前目录下 " + LOG_FILE);
        System.out.println("-".repeat(72));
        System.out.println("  输入 x + 回车   : 进入 / 退出 调试模式");
        System.out.println("  输入 exit + 回车: 退出程序");
        System.out.println("  Ctrl+C          : 退出程序（先撤销防火墙规则）");
        System.out.println("=".repeat(72));
        System.out.flush();
    }

    static void writeLog(String msg) {
        synchronized (LOG_LOCK) {
            try {
                Path log = Paths.get(LOG_FILE);
                rotateLogIfNeeded(log);
                Files.writeString(log,
                        "[" + NetUtil.nowStr() + "] " + msg + System.lineSeparator(),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (Exception ignored) {
                // 日志失败不影响监控
            }
        }
    }

    /**
     * 日志按大小轮转：单文件超过 {@link #MAX_LOG_BYTES} 时
     * {@code log → log.1 → log.2 → log.3}，最旧的一份丢弃。
     *
     * <p>告警冷却只对同一个 IP 生效，攻击者用海量不同源 IP 时每个 IP 都能写一条告警，
     * 日志会以 MB/s 增长；磁盘写满会顺带拖垮系统上其它服务，这正是 DDoS 的次要目标。</p>
     */
    private static void rotateLogIfNeeded(Path log) throws IOException {
        if (!Files.exists(log) || Files.size(log) < MAX_LOG_BYTES) {
            return;
        }
        Files.deleteIfExists(Paths.get(LOG_FILE + "." + LOG_BACKUPS));
        for (int i = LOG_BACKUPS - 1; i >= 1; i--) {
            Path from = Paths.get(LOG_FILE + "." + i);
            if (Files.exists(from)) {
                Files.move(from, Paths.get(LOG_FILE + "." + (i + 1)),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        }
        Files.move(log, Paths.get(LOG_FILE + ".1"), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("[" + NetUtil.nowStr() + "] [提示] 日志已达 "
                + (MAX_LOG_BYTES / 1024 / 1024) + " MB，已轮转为 " + LOG_FILE + ".1");
        System.out.flush();
    }

    // ------------------------------------------------------------ 生命周期

    public void start() {
        installShutdownHook();
        startGuarded(this::evaluateLoop, "检测循环");
        startGuarded(this::snifferWatchdogLoop, "抓包看护");
        if (firewall.available()) {
            startGuarded(() -> firewall.cleanerLoop(() -> stop), "防火墙清理循环");
        }
        printBanner();
        console.start();
        if (firewall.available()) {
            try {
                firewall.cleanupStale();              // 清掉上次被强杀时残留的规则
            } catch (Exception e) {
                System.out.println("[警告] 清理残留防火墙规则失败: " + e.getMessage());
            }
        }

        boolean ok;
        String msg;
        writeLog("【启动】配置来源=" + configSource + " 目标端口=" + port
                + " 抓包后端=" + options.source
                + " 入向过滤=" + (inboundOnly ? "开" : "关")
                + " 内网封禁=" + (firewall.isAllowInternal() ? "允许" : "禁止")
                + " 自动封禁=" + (ConfigStore.asLong(config, "auto_block", 1) == 1 ? "开" : "关")
                + " 防火墙=" + firewall.backend() + (firewall.isDryRun() ? "(dry-run)" : "")
                + " 窗口=" + window + "s");
        try {
            source = createSource();
            source.start(this::handlePacket);
            snifferStarted = true;
            ok = true;
            msg = source.describe();
        } catch (Exception e) {
            ok = false;
            msg = "嗅探器启动失败: " + e.getMessage();
        }
        if (!ok) {
            System.out.println("[错误] " + msg);
            System.out.println("[提示] Windows 请安装 Npcap 并以管理员运行；Linux 请使用 root 或 sudo。");
            System.out.println("[提示] 也可用 --source=sim 在无抓包环境下验证检测与封禁逻辑。");
            System.out.flush();
            writeLog(msg);
        } else {
            System.out.println("[" + NetUtil.nowStr() + "] " + msg);
            writeLog("【抓包】" + msg);
            if (!firewall.available()) {
                System.out.println("[警告] 当前平台（" + firewall.system()
                        + "）未找到可用的防火墙后端，仅提供告警功能。");
            }
            System.out.flush();
            applyPersistentBans();
        }

        // 环境自检（实测版）：抓包后端已确定、防火墙已初始化，明确告诉用户能干什么
        String capKind = source == null ? "未启动"
                : (source instanceof SimSource ? "sim（模拟流量）"
                : (source instanceof ExternalPcapSource ? "external" : "npcap"));
        EnvironmentCheck.printRuntime(port, configSource, capKind,
                (ok ? "已启动｜" : "启动失败｜") + msg, firewall,
                inboundOnly, firewall.isAllowInternal(),
                ConfigStore.asLong(config, "auto_block", 1) == 1, firewall.isDryRun());

        try {
            while (!stop) {
                if (console.isExitRequested()) {
                    System.out.println("\n[提示] 收到退出请求，正在安全退出（撤销防火墙规则）...");
                    break;
                }
                if (console.consumeDebugRequest()) {
                    console.enterDebugMode();
                    try {
                        enterDebugMode();
                    } finally {
                        console.leaveDebugMode();
                    }
                }
                Thread.sleep(300);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            shutdown();
        }
    }

    private void installShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (!shutdownDone.get()) {
                System.out.println("\n[提示] 收到退出信号（Ctrl+C / SIGTERM），"
                        + "正在安全退出（撤销防火墙规则）...");
                System.out.flush();
            }
            shutdown();
        }, "ddos-shutdown-hook"));
    }

    /** 幂等的收尾流程：停抓包、停地理查询、撤销防火墙规则。 */
    public void shutdown() {
        if (!shutdownDone.compareAndSet(false, true)) {
            return;
        }
        stop = true;
        synchronized (sourceLock) {
            // 与看护线程的重启互斥：否则可能“它刚建好的抓包源”逃过本次停止
            PacketSource s = source;
            source = null;
            if (s != null) {
                try {
                    s.stop();
                } catch (Exception ignored) {
                    // 忽略停止异常
                }
            }
        }
        geo.close();
        if (firewall.available()) {
            System.out.println("[" + NetUtil.nowStr() + "] 正在清理防火墙规则...");
            System.out.flush();
            try {
                firewall.cleanupAll(60.0);
            } catch (Exception e) {
                System.out.println("[错误] 清理防火墙规则失败: " + e.getMessage()
                        + "，请手动检查后端 " + firewall.backend() + "。");
            }
        }
        System.out.println("[" + NetUtil.nowStr() + "] 已停止监控。累计捕获 " + totalPackets
                + " 个包，触发 " + totalAlerts.get() + " 次告警。");
        System.out.flush();
    }

    /** 后台线程守护：异常记录并重启，避免检测逻辑静默失效。 */
    private void startGuarded(Runnable task, String name) {
        Thread thread = new Thread(() -> {
            int fails = 0;
            while (!stop) {
                try {
                    task.run();
                    return;
                } catch (Throwable e) {
                    fails++;
                    String detail = e.toString();
                    writeLog("【内部错误】" + name + " 异常（第 " + fails + " 次）: " + detail);
                    System.out.println("[" + NetUtil.nowStr() + "] [错误] " + name
                            + " 异常，已重启该线程: " + detail);
                    System.out.flush();
                    try {
                        Thread.sleep(Math.min(5000L, 1000L * fails));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }, name);
        thread.setDaemon(true);
        thread.start();
    }

    // ------------------------------------------------------------ 抓包源

    private PacketSource createSource() throws Exception {
        String kind = options.source;
        if ("auto".equals(kind)) {
            if (npcapAvailable()) {
                kind = "npcap";
            } else if (ExternalPcapSource.findTool() != null) {
                kind = "external";
            } else {
                kind = "sim";
                System.out.println("[提示] 既没有 Npcap 后端也没有 dumpcap/tcpdump，"
                        + "自动切换为模拟流量源（--source=sim）。");
            }
        }
        switch (kind) {
            case "npcap":
                return loadNpcapSource();
            case "external": {
                String tool = ExternalPcapSource.findTool();
                if (tool == null) {
                    throw new IllegalStateException(
                            "未找到 dumpcap/tcpdump，请安装 Wireshark 或改用 --source=sim");
                }
                String iface = options.iface;
                if (iface == null || iface.isEmpty()) {
                    boolean isDumpcap = tool.toLowerCase(Locale.ROOT).contains("dumpcap");
                    boolean mac = System.getProperty("os.name", "")
                            .toLowerCase(Locale.ROOT).contains("mac");
                    if (isDumpcap) {
                        iface = "1";                     // dumpcap 的接口编号，建议显式 --iface
                    } else if (mac) {
                        // macOS 的 tcpdump 不支持 -i any，必须指定具体网卡
                        String def = NetUtil.defaultInterfaceName();
                        iface = def != null ? def : "en0";
                    } else {
                        iface = "any";                   // Linux 支持 any（DLT_LINUX_SLL）
                    }
                    System.out.println("[提示] 未指定 --iface，使用 \"" + iface + "\"（"
                            + tool + "）。");
                }
                return new ExternalPcapSource(tool, port, iface);
            }
            case "sim":
                return new SimSource(port, sampleLocalAddress(), options.simNormalPps,
                        options.simAttackPps, options.simPeriod, options.simAttackSeconds);
            default:
                throw new IllegalArgumentException("未知的 --source: " + kind);
        }
    }

    private static boolean npcapAvailable() {
        try {
            Class.forName("NpcapJnaSource");
            Class.forName("com.sun.jna.Native");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private PacketSource loadNpcapSource() {
        try {
            Class<?> cls = Class.forName("NpcapJnaSource");
            return (PacketSource) cls.getConstructor(int.class, String.class)
                    .newInstance(port, options.iface);
        } catch (Throwable t) {
            throw new IllegalStateException("Npcap 后端不可用: " + t
                    + "（Npcap 后端需要 lib/jna.jar，运行 build.cmd 可自动下载；"
                    + "也可改用 --source=external 或 --source=sim）");
        }
    }

    private String restartSniffer() {
        synchronized (sourceLock) {
            if (stop) {
                return "程序正在退出，已放弃重启嗅探器";
            }
            PacketSource old = source;
            if (old != null) {
                try {
                    old.stop();
                } catch (Exception ignored) {
                    // 忽略
                }
            }
            source = null;
            snifferRestarts.incrementAndGet();
            try {
                PacketSource fresh = createSource();
                fresh.start(this::handlePacket);
                source = fresh;
                snifferStarted = true;
                if (stop) {
                    // 与 shutdown() 竞争：程序正在退出，绝不留一个刚起步的抓包线程
                    try {
                        fresh.stop();
                    } catch (Exception ignored) {
                        // 忽略
                    }
                    source = null;
                    return "程序正在退出，已放弃本次重启";
                }
                return "嗅探器已重启 (" + fresh.describe() + ")";
            } catch (Exception e) {
                source = null;
                return "嗅探器重启失败: " + e.getMessage();
            }
        }
    }

    /** 每 2 秒检查一次抓包线程是否还活着。 */
    private void snifferWatchdogLoop() {
        while (!stop) {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (stop) {
                return;
            }
            ensureSnifferAlive();
        }
    }

    /**
     * #1：抓包线程静默死亡（Npcap 驱动内部错误 / 网卡被拔出 / pcap 流畸形 / dumpcap 异常退出）
     * 时自动重启抓包。
     *
     * <p>没有这道看护时，抓包线程死了而主循环照常每秒空转、[健康] 一直显示“窗口包数 0”，
     * 攻击者只要触发一次驱动错误就能让监控彻底失效——这是 DDoS 防护最不能接受的失效模式。</p>
     */
    private void ensureSnifferAlive() {
        if (stop || !snifferStarted) {
            return;                                    // 还没启动过（或启动就失败）不在这里重试
        }
        PacketSource current = source;
        if (current != null && current.isAlive()) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastRestartAttempt < SNIFFER_RESTART_COOLDOWN_MS) {
            return;                                    // 冷却中：避免抓包起不来时反复刷屏
        }
        lastRestartAttempt = now;
        String what = current == null ? "嗅探器不存在" : "抓包线程已停止";
        String head = "[" + NetUtil.nowStr() + "] [警告] " + what
                + "，正在自动重启抓包（第 " + (snifferRestarts.get() + 1) + " 次）...";
        System.out.println(head);
        System.out.flush();
        writeLog("【警告】" + what + "，自动重启抓包");
        String result = restartSniffer();
        System.out.println("[" + NetUtil.nowStr() + "] [提示] " + result);
        System.out.flush();
        writeLog("【提示】" + result);
    }

    // ------------------------------------------------------------ 统计

    private void handlePacket(PacketInfo info) {
        if (inboundOnly && !isLocalAddress(info.dstIp)) {
            filteredByInbound++;                      // 只统计入向：本机自己发起的请求不计入
            return;
        }
        String src = info.srcIp;
        if (src == null) {
            return;
        }
        String norm = NetUtil.normIp(src);
        if (norm != null) {
            src = norm;
        }
        double ts = info.ts > 0 ? info.ts : System.currentTimeMillis() / 1000.0;
        synchronized (lock) {
            totalPackets++;
            totalBytes += info.length;
            if (attackActive) {
                attackTotalBytes += info.length;
                attackTotalPackets++;
            }
            counter.add(src, (long) (ts * 1000.0), info.length, info.syn, info.payloadLen, info.proto);
        }
    }

    // ------------------------------------------------------------ 检测主循环

    private void evaluateLoop() {
        while (!stop) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (stop) {
                return;
            }
            long t0 = System.nanoTime();
            evaluateOnce();
            lastTickMillis = (System.nanoTime() - t0) / 1_000_000;
            if (lastTickMillis > 500) {
                String msg = "【性能】评估耗时 " + lastTickMillis + " ms（窗口包数="
                        + lastWindowPackets + "，活跃IP=" + lastActiveIps + "，秒桶="
                        + counter.bucketCount() + "）";
                System.out.println("[" + NetUtil.nowStr() + "] " + msg);
                System.out.flush();
                writeLog(msg);
            }
            printHealthIfDue();
        }
    }

    /** 周期性健康度输出：一眼看出“有没有包、是不是被过滤了、评估是否跟得上”。 */
    private void printHealthIfDue() {
        if (healthInterval <= 0 || console.isInDebugMode()) {
            return;
        }
        double now = System.currentTimeMillis() / 1000.0;
        if (now - lastHealthAt < healthInterval) {
            return;
        }
        lastHealthAt = now;
        PacketSource current = source;
        String stats = current == null ? "" : current.statsLine();
        // 抓包源是在评估循环启动之后才创建的（前面还有自检/残留清理），
        // 所以“还没启动”不能报成“已停止”。
        String captureState;
        if (current != null && current.isAlive()) {
            captureState = "正常";
        } else if (!snifferStarted) {
            captureState = "尚未启动";
        } else {
            captureState = "已停止(看护将自动重启)";
        }
        System.out.println("[" + NetUtil.nowStr() + "] [健康] 窗口包数 " + lastWindowPackets
                + " / 活跃IP " + lastActiveIps
                + " / 秒桶 " + counter.bucketCount()
                + " / 入向过滤丢弃 " + filteredByInbound
                + " / 上次评估 " + lastTickMillis + " ms"
                + " / 累计 " + totalPackets + " 包"
                + " / 告警 " + totalAlerts.get() + " 次"
                + " / 抓包源 " + captureState
                + (stats.isEmpty() ? "" : " / " + stats));
        System.out.flush();
    }

    private void evaluateOnce() {
        double now = System.currentTimeMillis() / 1000.0;
        int w = Math.max(1, window);
        RateCounter.Global globalStat;
        int distinct;
        List<IpStat> topInfo;
        long attackBytesSnapshot;
        long attackPacketsSnapshot;
        synchronized (lock) {
            counter.evict((long) now);
            globalStat = counter.global();
            distinct = counter.activeIps();
            lastWindowPackets = globalStat.packets();
            lastActiveIps = distinct;
            List<IpStat> all = new ArrayList<>();
            for (Map.Entry<String, RateCounter.IpCount> e : counter.entries()) {
                RateCounter.IpCount c = e.getValue();
                all.add(new IpStat(e.getKey(), c.packets, c.bytes, c.syns));
            }
            all.sort((a, b) -> Long.compare(b.bytes(), a.bytes()));
            topInfo = all.size() > 5 ? new ArrayList<>(all.subList(0, 5)) : all;
            // #3：SYN Flood 惯用 54 字节小包，按字节数排不进 Top5 就会被漏检。
            // 这里把「SYN 数已超阈值」的 IP 一并并入候选集合，复用下面的统一判定与告警，
            // 避免只检查字节数前 5 名造成的漏报。
            // #8：去重改用 HashSet（原来是 List.contains → O(n²)）。分布式 DDoS 用几十万个
            // 不同源 IP 时，评估循环会从 1ms 涨到几百 ms，检测严重滞后。
            // 注意：all.size() <= 5 时 topInfo 就是 all 本身，此时不能改它（会 CME），
            // 因此限定在 >5 分支。
            if (all.size() > 5) {
                Set<String> seen = new HashSet<>();
                for (IpStat stat : topInfo) {
                    seen.add(stat.ip());
                }
                for (IpStat stat : all) {
                    if (stat.syns() >= synThreshold && seen.add(stat.ip())) {
                        topInfo.add(stat);
                    }
                }
            }
            attackBytesSnapshot = attackTotalBytes;
            attackPacketsSnapshot = attackTotalPackets;
        }

        double gPps = globalStat.packets() / (double) w;
        double gBps = globalStat.bytes() / (double) w;
        String currentAttack = "状态正常";
        String attackSource = null;
        boolean isSynAttack = false;
        boolean isDdosAttack = false;
        List<String> autoBlockIps = new ArrayList<>();

        if (gPps >= globalPpsThreshold || gBps >= globalBpsThreshold) {
            isDdosAttack = true;
            attackSource = "多IP/全网";
        }
        if (distinct >= distinctIpThreshold) {
            isDdosAttack = true;
            attackSource = "分布式大量IP";
        }

        for (IpStat stat : topInfo) {
            String ip = stat.ip();
            double ipPps = stat.packets() / (double) w;
            double ipBps = stat.bytes() / (double) w;
            if (ipPps >= ipPpsThreshold || ipBps >= ipBpsThreshold) {
                isDdosAttack = true;
                if (attackSource == null || isPseudo(attackSource)) {
                    attackSource = ip;
                }
                alert("单IP高频请求/流量异常 " + ip + " (" + fmt1(ipPps) + " req/s)",
                        ip, "DDoS_ATTACK");
                autoBlockIps.add(ip);
            }
            if (stat.syns() >= synThreshold) {
                isSynAttack = true;
                attackSource = ip;
                alert("SYN Flood " + ip + " (" + fmt1(stat.syns() / (double) w) + " pkt/s)",
                        ip, "SYN_ATTACK");
                autoBlockIps.add(ip);
            }
        }

        if (isSynAttack) {
            currentAttack = "遭遇SYN攻击";
        } else if (isDdosAttack) {
            currentAttack = "遭遇DDoS攻击";
        }

        boolean attackJustEnded = false;
        AttackEnd endSnapshot = null;
        synchronized (lock) {
            if (!"状态正常".equals(currentAttack)) {
                if (!attackActive) {
                    attackActive = true;
                    attackStartTs = now;
                    attackPeakPps = 0;
                    attackPeakBps = 0;
                    attackMainSource = attackSource;
                    attackTotalBytes = 0;
                    attackTotalPackets = 0;
                }
                attackType = "遭遇SYN攻击".equals(currentAttack) ? "SYN" : "DDoS";
                if (gPps > attackPeakPps) {
                    attackPeakPps = gPps;
                }
                if (gBps > attackPeakBps) {
                    attackPeakBps = gBps;
                }
                if (attackSource != null) {
                    attackMainSource = attackSource;
                }
            } else if (attackActive) {
                attackJustEnded = true;
                endSnapshot = new AttackEnd(
                        Math.max(0.0, now - (attackStartTs == null ? now : attackStartTs)),
                        attackType,
                        attackMainSource == null ? "未知" : attackMainSource,
                        attackPeakPps, attackPeakBps,
                        attackBytesSnapshot, attackPacketsSnapshot);
                attackActive = false;
                attackType = null;
                attackStartTs = null;
                attackPeakPps = 0;
                attackPeakBps = 0;
                attackTotalBytes = 0;
                attackTotalPackets = 0;
                attackMainSource = null;
            }
        }

        if (ConfigStore.asLong(config, "auto_block", 1) == 1 && !autoBlockIps.isEmpty()) {
            for (String ip : new LinkedHashSet<>(autoBlockIps)) {
                if (!firewall.available()) {
                    continue;
                }
                // 内网/保留地址不在这里排除，准入策略统一由 Firewall 决定。
                // 注意：block() 对“已封禁”的地址也会返回 true（表示续期成功），
                // 所以只有本次是新下发的才写日志；否则攻击持续期间这一行会每秒重复刷
                // （真机 443 端口日志里实测：一次 58 秒攻击刷了 60 行同 IP 的【自动封禁】）。
                boolean tracked = firewall.isTracked(ip);
                if (firewall.block(ip, false) && !tracked) {
                    writeLog("【自动封禁】" + ip + " 已加入 " + firewall.backend()
                            + " 黑名单，时长 " + firewall.duration() + "s");
                }
            }
        }

        if (!currentAttack.equals(lastState)) {
            if (!console.isInDebugMode()) {
                if (attackJustEnded && endSnapshot != null) {
                    printAttackEnd(endSnapshot);
                } else if ("状态正常".equals(currentAttack)) {
                    System.out.println("[" + NetUtil.nowStr() + "]正在监测:状态正常｜警告次数:"
                            + warnCount + "｜防御状态:无");
                } else {
                    warnCount++;
                    printAttackState(currentAttack, attackSource, globalStat, topInfo, gPps, gBps, w);
                }
                System.out.flush();
            }
            lastState = currentAttack;
        }
    }

    private void printAttackEnd(AttackEnd end) {
        String srcDisp = isPseudo(end.source())
                ? end.source() : end.source() + "(" + geo.lookup(end.source()) + ")";
        String peakStr = fmt1(end.peakPps()) + "pkt/s " + NetUtil.humanBytes(end.peakBps()) + "/s";
        System.out.println(Color.green("[" + NetUtil.nowStr() + "]正在监测:" + end.type() + "攻击结束"
                + "｜警告次数:" + warnCount
                + "｜防御状态:结束拦截"
                + "｜信息:主要来源:" + srcDisp
                + "｜攻击峰值:" + peakStr
                + "｜攻击流量:" + NetUtil.humanBytes(end.totalBytes()) + " / "
                + end.totalPackets() + " 包 / " + fmt1(end.duration()) + " 秒"));
        writeLog("【攻击结束】类型:" + end.type() + " 持续:" + fmt1(end.duration()) + "s 峰值:"
                + peakStr + " 总流量:" + NetUtil.humanBytes(end.totalBytes()) + " 总包数:"
                + end.totalPackets() + " 主要来源:" + srcDisp);
    }

    private void printAttackState(String currentAttack, String attackSource, RateCounter.Global globalStat,
                                  List<IpStat> topInfo, double gPps, double gBps, int w) {
        String location = attackSource != null ? geo.lookup(attackSource) : "未知";
        // 伪来源（多IP/全网、分布式大量IP）不需要再跟一个括号归属地
        String sourceDisp = isPseudo(attackSource) ? String.valueOf(attackSource)
                : attackSource + "(" + location + ")";
        StringBuilder topStr = new StringBuilder();
        for (int i = 0; i < Math.min(3, topInfo.size()); i++) {
            IpStat stat = topInfo.get(i);
            if (topStr.length() > 0) {
                topStr.append(" | ");
            }
            topStr.append(stat.ip()).append(':')
                    .append(NetUtil.humanBytes(stat.bytes() / (double) w)).append("/s");
        }
        StringBuilder info = new StringBuilder();
        info.append("主要来源:").append(sourceDisp)
                .append(" | 全局速率:").append(fmt1(gPps)).append("pkt/s ")
                .append(NetUtil.humanBytes(gBps)).append("/s");
        if (topStr.length() > 0) {
            info.append(" | Top3: ").append(topStr);
        }
        if (!globalStat.protos().isEmpty()) {
            StringBuilder protos = new StringBuilder();
            for (Map.Entry<String, Integer> e : globalStat.protos().entrySet()) {
                if (protos.length() > 0) {
                    protos.append(' ');
                }
                protos.append(e.getKey()).append(':').append(e.getValue());
            }
            info.append(" | 协议分布: ").append(protos);
        }
        System.out.println(Color.yellow("[" + NetUtil.nowStr() + "]正在监测:" + currentAttack
                + "｜警告次数:" + warnCount
                + "｜防御状态:" + defenseLabel()
                + "｜" + info));
    }

    private String defenseLabel() {
        if (!firewall.available()) {
            return "仅告警(防火墙不可用)";
        }
        return firewall.isDryRun() ? "拦截(dry-run，未真正下发)" : "拦截";
    }

    private static boolean isPseudo(String value) {
        return value == null || "多IP/全网".equals(value) || "分布式大量IP".equals(value)
                || "未知".equals(value);
    }

    private static String fmt1(double value) {
        return String.format(Locale.ROOT, "%.1f", value);
    }

    /** 告警（带冷却），对应 Python 的 _alert。 */
    private void alert(String msg, String ip, String kind) {
        String key = ip != null ? kind + ":" + ip : kind;
        double now = System.currentTimeMillis() / 1000.0;
        synchronized (lock) {
            Double last = lastAlert.get(key);
            if (last != null && now - last < alertCooldown) {
                return;
            }
            lastAlert.put(key, now);
            if (lastAlert.size() > 4096) {
                double cutoff = now - alertCooldown * 10.0;
                lastAlert.entrySet().removeIf(e -> e.getValue() < cutoff);
            }
                // 兜底：若剪掉的都是新鲜条目则一个也删不掉，此时直接清空，避免无界增长
                if (lastAlert.size() > 4096) {
                    lastAlert.clear();
                }
        }
        totalAlerts.incrementAndGet();
        String text = "【DDoS 告警 / " + kind + "】" + msg;
        if (ip != null) {
            text += " | 攻击者IP: " + ip + " | 归属地: " + geo.lookup(ip);
        }
        writeLog(text);   // 日志永远写：调试模式下也必须留证据
        if (!console.isInDebugMode()) {
            System.out.println(Color.red("[" + NetUtil.nowStr() + "] " + text));
            System.out.flush();
        }
    }

    // ------------------------------------------------------------ 永久封禁

    private void applyPersistentBans() {
        if (!firewall.available()) {
            return;
        }
        List<String> list = new ArrayList<>(banned());     // 快照，避免遍历时被调试命令改动
        if (list.isEmpty()) {
            return;
        }
        int total = 0;
        int skipped = 0;
        // 启动预算：banned 里可能是大量域名，逐条 DNS 解析（解析超时由攻击者控制的 DNS 拖住）
        // 会让启动时间爆炸，所以超过预算就放弃剩余条目并明确提示。
        long deadline = System.nanoTime() + PERSISTENT_BAN_BUDGET_NANOS;
        for (int i = 0; i < list.size(); i++) {
            if (System.nanoTime() > deadline) {
                skipped = list.size() - i;
                break;
            }
            for (String ip : resolveEntry(list.get(i))) {
                // 内网地址默认可封禁（是否允许由 allow_internal 决定）
                if (firewall.block(ip, true)) {
                    total++;
                }
            }
        }
        if (total > 0) {
            System.out.println("[" + NetUtil.nowStr() + "] 已应用 " + list.size()
                    + " 条永久封禁条目（共 " + total + " 个 IP）");
            System.out.flush();
        }
        if (skipped > 0) {
            String warn = "【警告】应用永久封禁超过 "
                    + (PERSISTENT_BAN_BUDGET_NANOS / 1_000_000_000L) + "s 预算，剩余 "
                    + skipped + " 条未处理；请精简 banned 或改用 IP 条目";
            System.out.println("[" + NetUtil.nowStr() + "] " + warn);
            System.out.flush();
            writeLog(warn);
        }
    }

    /** 对应 Python 的 resolve_entry：字面量 IP 直接归一化，否则做一次 DNS 解析。 */
    static List<String> resolveEntry(String entry) {
        List<String> out = new ArrayList<>();
        if (entry == null) {
            return out;
        }
        String text = entry.trim();
        if (text.isEmpty()) {
            return out;
        }
        String norm = NetUtil.normIp(text);
        if (norm != null) {
            out.add(norm);
            return out;
        }
        try {
            int seen = 0;
            for (InetAddress addr : InetAddress.getAllByName(text)) {
                if (++seen > MAX_RESOLVED_IPS) {
                    // 上限：攻击者控制的 DNS 可以返回海量 A/AAAA 记录，
                    // 不限量会让封禁表与启动流程一起被拖垮。
                    System.out.println("[警告] " + text + " 解析出的地址超过 "
                            + MAX_RESOLVED_IPS + " 个，只取前 " + MAX_RESOLVED_IPS + " 个。");
                    break;
                }
                String host = addr.getHostAddress();
                int scope = host.indexOf('%');
                if (scope >= 0) {
                    host = host.substring(0, scope);
                }
                if (!out.contains(host)) {
                    out.add(host);
                }
            }
        } catch (UnknownHostException e) {
            // 解析失败：交给调用方报错
        }
        return out;
    }

    /** 说明某个地址为什么被策略拒绝，便于用户理解失败原因。 */
    private String rejectHint(List<String> ips) {
        for (String ip : ips) {
            String norm = NetUtil.normIp(ip);
            if (norm == null) {
                continue;
            }
            if (firewall.isProtectedAddress(norm)) {
                return norm + " 是本机地址，始终不封禁（避免自断连接）";
            }
            if (!NetUtil.isBlockableAddress(norm)) {
                return norm + " 属于未指定/组播/广播/环回，不允许封禁";
            }
            if (!firewall.isAllowInternal() && NetUtil.isInternal(norm)) {
                return norm + " 是内网/保留地址，当前 allow_internal=0 不允许封禁";
            }
        }
        return "封禁策略拒绝";
    }

    private void doBan(String entry) {
        String text = entry == null ? "" : entry.trim();
        if (text.isEmpty()) {
            System.out.println("用法: ban <IP或域名>");
            return;
        }
        if (!firewall.available()) {
            System.out.println("[失败] 当前平台防火墙后端不可用。");
            return;
        }
        List<String> list = banned();
        boolean already = list.contains(text);
        if (already) {
            System.out.println("[提示] " + text + " 已在永久封禁列表中，重新解析并应用...");
        }
        List<String> ips = resolveEntry(text);
        if (ips.isEmpty()) {
            System.out.println("[失败] 无法解析: " + text);
            return;
        }
        List<String> blocked = new ArrayList<>();
        for (String ip : ips) {
            if (firewall.block(ip, true)) {
                blocked.add(ip);
            }
        }
        if (blocked.isEmpty()) {
            System.out.println("[失败] 未能封禁 " + text + " 的任何地址（"
                    + rejectHint(ips) + "）。");
            return;
        }
        if (!already) {
            if (list.size() >= ConfigStore.MAX_BANNED) {
                // 上限：否则配置文件会无限增长，且每次启动都要逐条 DNS 解析 + 下发规则
                System.out.println("[警告] 永久封禁列表已达上限 " + ConfigStore.MAX_BANNED
                        + " 条，本次封禁只在本次运行内生效（请先 unban 清理）。");
                writeLog("【警告】banned 已达上限 " + ConfigStore.MAX_BANNED + "，"
                        + text + " 未写入配置");
            } else {
                list.add(text);
            }
        }
        ConfigStore.save(options.configFile, config);
        System.out.println("[成功] 已永久封禁 " + text + " → " + String.join(", ", blocked));
        writeLog("【永久封禁】" + text + " 解析为 " + blocked + "，已加入 "
                + firewall.backend() + " 黑名单");
    }

    private void doUnban(String entry) {
        String text = entry == null ? "" : entry.trim();
        if (text.isEmpty()) {
            System.out.println("用法: unban <IP或域名>");
            return;
        }
        List<String> list = banned();
        if (!list.contains(text)) {
            System.out.println("[提示] " + text + " 不在永久封禁列表中");
            return;
        }
        list.remove(text);
        ConfigStore.save(options.configFile, config);
        List<String> ips = resolveEntry(text);
        for (String ip : ips) {
            firewall.unblock(ip);
        }
        System.out.println("[成功] 已解除永久封禁 " + text + " → 已解封 " + ips.size() + " 个地址");
        writeLog("【解除永久封禁】" + text + " 已从 " + firewall.backend() + " 黑名单移除");
    }

    // ------------------------------------------------------------ 调试模式

    private void enterDebugMode() {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("进入调试模式。日志记录已暂停。");
        System.out.println("输入 help 查看命令，输入 exit 返回监控。");
        System.out.println("=".repeat(60));
        System.out.flush();
        while (true) {
            String line = console.readLine("[调试]＞＞＞ ");
            if (line == null) {
                if (!console.isExitRequested() && !stop) {
                    System.out.println("退出调试模式，恢复监控...");
                }
                return;
            }
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.indexOf('\u0018') >= 0) {
                System.out.println("退出调试模式，恢复监控...");
                return;
            }
            String[] parts = trimmed.split("\\s+");
            String cmd = parts[0].toLowerCase(Locale.ROOT);
            switch (cmd) {
                case "help":
                    printHelp();
                    break;
                case "show":
                    showConfig();
                    break;
                case "set":
                    handleSet(parts);
                    break;
                case "log":
                    showLog(parts.length > 1 ? parts[1] : ".");
                    break;
                case "clear":
                    clearLog();
                    break;
                case "ban":
                    if (parts.length < 2) {
                        System.out.println("用法: ban <IP或域名>");
                        break;
                    }
                    doBan(parts[1]);
                    afterBanChange();
                    break;
                case "unban":
                    if (parts.length < 2) {
                        System.out.println("用法: unban <IP或域名>");
                        break;
                    }
                    doUnban(parts[1]);
                    afterBanChange();
                    break;
                case "block":
                    handleBlock(parts);
                    break;
                case "unblock":
                    handleUnblock(parts);
                    break;
                case "fw":
                    showFirewall();
                    break;
                case "exit":
                    System.out.println("退出调试模式，恢复监控...");
                    return;
                default:
                    System.out.println("未知命令: " + cmd + "，输入 help 查看帮助。");
            }
        }
    }

    private void printHelp() {
        System.out.println("可用命令:");
        System.out.println("  help                 - 显示此帮助");
        System.out.println("  show                 - 查看当前所有阈值配置");
        System.out.println("  set <键> <值>        - 修改配置（立即生效并保存）");
        System.out.println("  log [目录]           - 查看日志（默认当前目录）");
        System.out.println("  clear                - 清空当前目录下的日志文件");
        System.out.println("  ban <IP/域名>        - 永久封禁，写入配置并重启后仍然生效");
        System.out.println("  unban <IP/域名>      - 解除永久封禁");
        System.out.println("  block <IP>           - 临时封禁（到期自动解封，不写入配置）");
        System.out.println("  unblock <IP>         - 解除临时封禁");
        System.out.println("  fw                   - 查看防火墙状态和已封禁列表");
        System.out.println("  exit                 - 退出调试模式");
        System.out.println();
        System.out.println("可用配置键（均为整数，方括号内为允许范围）:");
        for (Map.Entry<String, long[]> e : ConfigStore.spec().entrySet()) {
            long[] range = e.getValue();
            System.out.println(String.format(Locale.ROOT, "  %-22s [%d, %d]",
                    e.getKey(), range[0], range[1]));
        }
        System.out.println();
        System.out.println("提示: set port <新端口> 会立即重启嗅探器并监听新端口。");
    }

    private void showConfig() {
        System.out.println("--- 当前配置 ---");
        // 取快照再遍历：配置是同步 map，边遍历边被调试命令修改会 ConcurrentModificationException
        LinkedHashMap<String, Object> snapshot;
        synchronized (config) {
            snapshot = new LinkedHashMap<>(config);
        }
        for (Map.Entry<String, Object> e : snapshot.entrySet()) {
            if (e.getKey().startsWith("_")) {
                continue;
            }
            System.out.println(String.format(Locale.ROOT, "  %-22s = %s", e.getKey(), e.getValue()));
        }
        System.out.println("----------------");
        System.out.println("  当前嗅探端口   = " + port);
        System.out.println("----------------");
    }

    private void handleSet(String[] parts) {
        if (parts.length < 3) {
            System.out.println("用法: set <键> <值>");
            System.out.println("示例: set ip_pps_threshold 50");
            System.out.println("示例: set port 8080");
            return;
        }
        String key = parts[1];
        String raw = parts[2];
        ConfigStore.Validation validation = ConfigStore.validate(key, raw);
        if (!validation.ok()) {
            System.out.println("[失败] " + validation.error());
            System.out.println("可用配置键: " + String.join(", ", ConfigStore.spec().keySet()));
            return;
        }
        long value = validation.value().longValue();
        Object oldValue = config.get(key);
        config.put(key, validation.value());
        if (!ConfigStore.save(options.configFile, config)) {
            config.put(key, oldValue);
            System.out.println("[失败] 配置保存失败，已回滚。");
            return;
        }
        reloadFromConfig();
        if ("block_duration".equals(key)) {
            firewall.setDuration((int) value);
        }
        System.out.println("[成功] " + key + ": " + oldValue + " -> " + value + "  (已保存，立即生效)");
        if ("port".equals(key)) {
            System.out.println("[提示] 正在重启嗅探器，监听新端口 " + port + " ...");
            System.out.flush();
            System.out.println("[提示] " + restartSniffer());
        }
        printBanner();
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("已重新配置。继续在调试模式中。");
        System.out.println("=".repeat(60));
        System.out.flush();
    }

    private void showLog(String dir) {
        Path logFile = Paths.get(dir, LOG_FILE);
        if (!Files.exists(logFile)) {
            System.out.println("未找到日志文件: " + logFile);
            return;
        }
        try {
            List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
            System.out.println("--- " + logFile + " 最后 20 行 ---");
            int from = Math.max(0, lines.size() - 20);
            for (int i = from; i < lines.size(); i++) {
                System.out.println(lines.get(i));
            }
            System.out.println("------------------------");
        } catch (IOException e) {
            System.out.println("读取日志失败: " + e.getMessage());
        }
    }

    private void clearLog() {
        Path logFile = Paths.get(LOG_FILE);
        boolean any = Files.exists(logFile);
        try {
            if (any) {
                Files.writeString(logFile, "", StandardCharsets.UTF_8);
            }
            for (int i = 1; i <= LOG_BACKUPS; i++) {          // 轮转备份一并清掉
                any |= Files.deleteIfExists(Paths.get(LOG_FILE + "." + i));
            }
        } catch (IOException e) {
            System.out.println("清空日志失败: " + e.getMessage());
            return;
        }
        System.out.println(any ? "日志已清空（含轮转备份）。" : "当前没有日志文件。");
    }

    private void afterBanChange() {
        printBanner();
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("永久封禁列表已更新。继续在调试模式中。");
        System.out.println("=".repeat(60));
        System.out.flush();
    }

    private void handleBlock(String[] parts) {
        if (parts.length < 2) {
            System.out.println("用法: block <IP>");
            return;
        }
        String raw = parts[1];
        if (!firewall.available()) {
            System.out.println("[失败] 当前平台防火墙后端不可用。");
            return;
        }
        String norm = NetUtil.normIp(raw);
        if (norm == null) {
            System.out.println("[失败] 不是合法的 IP 地址: " + raw);
            return;
        }
        if (firewall.isProtectedAddress(norm)) {
            System.out.println("[失败] " + norm + " 是本机地址，拒绝封禁（避免自断连接）。");
            return;
        }
        if (!NetUtil.isBlockableAddress(norm)) {
            System.out.println("[失败] " + norm + " 属于未指定/组播/广播/环回，不允许封禁。");
            return;
        }
        if (NetUtil.isInternal(norm) && !firewall.isAllowInternal()) {
            System.out.println("[失败] " + norm + " 是内网/保留地址，当前策略不允许"
                    + "（set allow_internal 1 可放开）。");
            return;
        }
        if (firewall.block(norm, false)) {
            String note = NetUtil.isInternal(norm) ? "（内网/保留地址）" : "";
            System.out.println("[成功] 已临时封禁 " + norm + note + "（后端: " + firewall.backend()
                    + "，时长 " + firewall.duration() + "s）");
            writeLog("【临时封禁】" + norm + " 已加入 " + firewall.backend() + " 黑名单");
        } else {
            System.out.println("[失败] 封禁 " + norm + " 失败，请检查权限（root/管理员）。");
        }
    }

    private void handleUnblock(String[] parts) {
        if (parts.length < 2) {
            System.out.println("用法: unblock <IP>");
            return;
        }
        String norm = NetUtil.normIp(parts[1]);
        if (norm == null) {
            System.out.println("[失败] 不是合法的 IP 地址: " + parts[1]);
            return;
        }
        firewall.unblock(norm);
        System.out.println("[成功] 已从黑名单移除 " + norm);
        if (banned().contains(norm)) {
            System.out.println("[提示] " + norm + " 仍在永久封禁列表(banned)中，重启后会重新封禁；"
                    + "如需彻底解除请用: unban " + norm);
        }
        writeLog("【临时解封】" + norm + " 已从 " + firewall.backend() + " 黑名单移除");
    }

    private void showFirewall() {
        System.out.println("平台: " + firewall.system());
        System.out.println("后端: " + firewall.backend() + "  可用: " + firewall.available());
        System.out.println("封禁时长: " + firewall.duration() + "s");
        System.out.println("模拟模式: " + (firewall.isDryRun() ? "开启（不下发真实规则）" : "关闭"));
        System.out.println("自动封禁: "
                + (ConfigStore.asLong(config, "auto_block", 1) == 1 ? "开启" : "关闭"));
        System.out.println("永久封禁条目 (" + banned().size() + "): "
                + (banned().isEmpty() ? "无" : String.join(", ", banned())));
        LinkedHashMap<String, Long> items = firewall.snapshot();
        System.out.println("当前防火墙内 " + items.size() + " 条规则:");
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Long> e : items.entrySet()) {
            long expires = e.getValue();
            if (expires == Firewall.PERMANENT) {
                System.out.println(String.format(Locale.ROOT, "  %-24s 永久", e.getKey()));
            } else {
                System.out.println(String.format(Locale.ROOT, "  %-24s 剩余 %ds",
                        e.getKey(), Math.max(0, (expires - now) / 1000)));
            }
        }
        System.out.println("----------------");
    }
}
