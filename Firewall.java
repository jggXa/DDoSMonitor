import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

/**
 * 多平台防火墙后端（iptables / nft / netsh advfirewall / pfctl）。
 *
 * <p>第 2 批的三处改动：</p>
 * <ol>
 *   <li><b>同 IP 串行化</b>：每个地址一把锁，杜绝“检查-下发”竞态导致的重复规则
 *       （重复 {@code iptables -I} / netsh 规则会让解封只删掉一条，残留规则永久拦截）。</li>
 *   <li><b>下发幂等</b>：Linux 用专用链 {@code DDOS_BLOCK} 且先 {@code -C} 再 {@code -I}；
 *       nft/pfctl 本身是集合语义；解封用 {@code -D}/{@code delete element}/{@code -T delete}。</li>
 *   <li><b>残留清理</b>：进程被强杀时不会执行退出清理，所以启动时先清掉上次遗留的规则
 *       （netsh 删 {@code DDoS_Block_*}、nft 重建表、iptables 清空专用链、pfctl 重写 anchor）；
 *       退出时对 Linux/macOS 用一条批量 flush 代替逐条删除。</li>
 * </ol>
 */
public final class Firewall {

    /** 永久封禁在 expires 里的表示。 */
    public static final long PERMANENT = Long.MAX_VALUE;

    private static final int CMD_TIMEOUT_SECONDS = 6;
    /** iptables 专用链：只放我们自己的规则，退出/启动时整体 flush，绝不误删管理员规则。 */
    private static final String CHAIN = "DDOS_BLOCK";
    private static final String NFT_TABLE = "ddos_filter";
    private static final String NFT_SET4 = "blocklist4";
    private static final String NFT_SET6 = "blocklist6";
    private static final String PF_TABLE = "blocklist";

    public record Result(boolean ok, String output) {
    }

    private final String system;
    private final String anchor = "com.ddos.monitor";
    private final Object lock = new Object();
    private final LinkedHashMap<String, Long> blocked = new LinkedHashMap<>();
    /** 已跟踪封禁条数的软上限（检查在 {@link #lock} 内，见 {@link #block}）。 */
    private static final int MAX_TRACKED_BLOCKS = 100_000;
    /**
     * 每个地址一把锁：同 IP 的下发串行化，不同 IP 仍可并行。
     *
     * <p>锁对象带引用计数（{@link LockRef#users}），最后一个使用者释放时立刻从表里移除。
     * 早期实现是 {@code computeIfAbsent} 且只在“成功封禁”后才移除，于是 {@code doBlock}
     * 偶发失败（权限抖动 / 命令超时 / netsh 偶发失败）就会留下孤儿锁；攻击者用海量源 IP
     * 打过来、只要偶发失败一次，这张表就无界增长 → OOM。</p>
     */
    private final Map<String, LockRef> ipLocks = new ConcurrentHashMap<>();
    private final AtomicLong blocksIssued = new AtomicLong();
    /** 本进程实例标识（PID）：netsh 规则名带上它，清理时才能只动自己的规则。 */
    private final String instanceTag = String.valueOf(ProcessHandle.current().pid());
    /** pfctl -E 拿到的引用计数 token；非 null 表示本进程 +1 过，退出时要对称 -X。 */
    private volatile String pfToken;

    private volatile int durationSeconds;
    private volatile boolean dryRun;
    /** 是否允许封禁内网/保留地址（默认允许；设为 false 即恢复“只封公网”的严格模式）。 */
    private volatile boolean allowInternal = true;
    /** 始终拒绝封禁的地址：本机自身地址（避免自断连接）。 */
    private final java.util.Set<String> protectedAddresses = ConcurrentHashMap.newKeySet();
    private String backend = "none";
    private boolean available;

    /** 地址锁 + 引用计数；{@code users} 由 {@link Firewall#lock} 保护。 */
    private static final class LockRef {
        private final Object mutex = new Object();
        private int users;
    }

    /** 取得（或创建）地址锁并 +1 引用；必须与 {@link #release} 成对使用。 */
    private LockRef acquire(String norm) {
        synchronized (lock) {
            LockRef ref = ipLocks.computeIfAbsent(norm, key -> new LockRef());
            ref.users++;
            return ref;
        }
    }

    /** 释放地址锁引用；最后一个使用者退出时把锁从表里删掉，保证这张表不无界增长。 */
    private void release(String norm, LockRef ref) {
        synchronized (lock) {
            ref.users--;
            if (ref.users <= 0) {
                ipLocks.remove(norm, ref);
            }
        }
    }

    public Firewall(int durationSeconds) {
        this.durationSeconds = Math.max(1, durationSeconds);
        String os = System.getProperty("os.name", "");
        String lower = os.toLowerCase(Locale.ROOT);
        if (lower.contains("win")) {
            this.system = "Windows";
        } else if (lower.contains("linux")) {
            this.system = "Linux";
        } else if (lower.contains("mac")) {
            this.system = "Darwin";
        } else {
            this.system = os;
        }
        initBackend();
    }

    // ------------------------------------------------------------ 初始化

    private void initBackend() {
        // 关键：available 不能只看“命令是否存在”，必须看真实探测结果，
        // 否则非 root / 非管理员时会显示“可封禁”但实际每条规则都失败（#5）。
        if ("Linux".equals(system)) {
            if (which("iptables")) {
                backend = "iptables";
                available = iptablesEnsureChain();
            } else if (which("nft")) {
                backend = "nft";
                available = nftEnsure();
            }
        } else if ("Windows".equals(system)) {
            if (which("netsh")) {
                backend = "netsh";
                available = run(Arrays.asList("netsh", "advfirewall", "show", "allprofiles", "state"), null).ok();
                if (!available) {
                    System.out.println("[警告] netsh 存在但查询失败（通常是没有管理员权限），防火墙后端不可用。");
                }
            }
        } else if ("Darwin".equals(system)) {
            if (which("pfctl")) {
                backend = "pfctl";
                available = pfEnsure();
            }
        }
        if (!available && !"none".equals(backend)) {
            System.out.println("[警告] 防火墙后端 " + backend + " 初始化失败：本次只告警、不下发任何规则。");
            System.out.flush();
        }
    }

    private boolean nftEnsure() {
        if (!run(Arrays.asList("nft", "add", "table", "inet", NFT_TABLE), null).ok()
                && !run(Arrays.asList("nft", "list", "table", "inet", NFT_TABLE), null).ok()) {
            return false;                                        // 表建不了也读不了 → 后端不可用
        }
        run(Arrays.asList("nft", "add", "chain", "inet", NFT_TABLE, "input",
                "{ type filter hook input priority 0; }"), null);
        run(Arrays.asList("nft", "add", "set", "inet", NFT_TABLE, NFT_SET4,
                "{ type ipv4_addr; }"), null);
        run(Arrays.asList("nft", "add", "set", "inet", NFT_TABLE, NFT_SET6,
                "{ type ipv6_addr; }"), null);
        Result listed = run(Arrays.asList("nft", "list", "chain", "inet", NFT_TABLE, "input"), null);
        String existing = listed.ok() ? listed.output() : "";
        if (!existing.contains("@" + NFT_SET4)) {                 // 已有就不再重复加，避免越跑越多
            run(Arrays.asList("nft", "add", "rule", "inet", NFT_TABLE, "input",
                    "ip", "saddr", "@" + NFT_SET4, "drop"), null);
        }
        if (!existing.contains("@" + NFT_SET6)) {
            run(Arrays.asList("nft", "add", "rule", "inet", NFT_TABLE, "input",
                    "ip6", "saddr", "@" + NFT_SET6, "drop"), null);
        }
        return true;
    }

    private boolean pfEnsure() {
        String rules = "table <" + PF_TABLE + "> persist\nblock drop from <" + PF_TABLE + "> to any\n";
        Result loaded = run(Arrays.asList("pfctl", "-a", anchor, "-f", "-"), rules);
        if (!loaded.ok()) {
            return false;
        }
        pfEnable();
        return true;
    }

    /**
     * 启用 pf，并记住 {@code pfctl -E} 返回的引用计数 token。
     *
     * <p>{@code pfctl -E} 每次执行都会 +1 引用计数，必须用 {@code pfctl -X <token>} 对称释放；
     * 否则反复启动/退出只会累加，跑几次后 -E 就开始失败，pf 无法被正确管理
     * （其它依赖 pf 的软件也跟着受影响）。这里再加一道保险：先查状态，只有 pf 未启用时才 -E。</p>
     */
    private void pfEnable() {
        if (pfToken != null) {
            return;                                   // 本进程已经 +1 过，不再重复计数
        }
        Result info = run(Arrays.asList("pfctl", "-s", "info"), null);
        if (info.ok() && info.output().contains("Status: Enabled")) {
            return;                                   // 别人已启用 pf：不需要也不应该再加引用计数
        }
        Result enabled = run(Arrays.asList("pfctl", "-E"), null);
        if (!enabled.ok()) {
            System.out.println("[警告] pfctl -E 失败，pf 可能未启用: " + enabled.output());
            System.out.flush();
            return;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("token\\s*:\\s*(\\d+)").matcher(enabled.output());
        if (m.find()) {
            pfToken = m.group(1);
        } else {
            // 已经 +1 却拿不到 token：退出时无法对称释放，必须明确告诉用户
            System.out.println("[警告] 已执行 pfctl -E，但未能解析引用计数 token，"
                    + "退出时不会执行 pfctl -X，请留意 pf 引用计数: " + enabled.output());
            System.out.flush();
        }
    }

    /** 释放本进程通过 {@code pfctl -E} 拿到的引用计数（与 {@link #pfEnable} 严格对称）。 */
    private void pfDisable() {
        String token = pfToken;
        if (token == null) {
            return;                                   // 没加过引用计数，绝不去减别人的
        }
        pfToken = null;
        Result r = run(Arrays.asList("pfctl", "-X", token), null);
        if (!r.ok()) {
            System.out.println("[警告] pfctl -X " + token + " 失败: " + r.output());
            System.out.flush();
        }
    }

    /** 建立/清空 iptables 专用链并挂到 INPUT 首位（幂等）。 */
    private boolean iptablesEnsureChain() {
        boolean touched = false;
        for (String tool : new String[]{"iptables", "ip6tables"}) {
            if (!which(tool)) {
                continue;
            }
            // #1：链若已存在且含非本工具的规则，绝不清空——宁可降级也不能静默破坏他人规则
            Result listed = run(Arrays.asList(tool, "-S", CHAIN), null);
            if (listed.ok() && hasForeignRules(listed.output())) {
                System.out.println("[警告] " + tool + " 的 " + CHAIN + " 链中存在非本工具下发的规则，"
                        + "为避免破坏它们，本次不清空该链；防火墙后端降级为不可用。");
                System.out.flush();
                return false;
            }
            run(Arrays.asList(tool, "-N", CHAIN), null);          // 已存在会失败，忽略
            if (run(Arrays.asList(tool, "-F", CHAIN), null).ok()) {
                touched = true;
            }
            if (!run(Arrays.asList(tool, "-C", "INPUT", "-j", CHAIN), null).ok()) {
                run(Arrays.asList(tool, "-I", "INPUT", "1", "-j", CHAIN), null);
            }
        }
        if (!touched) {
            System.out.println("[警告] iptables 专用链初始化失败（通常需要 root 或缺少 CAP_NET_ADMIN），封禁不会生效。");
            System.out.flush();
        }
        return touched;
    }

    /**
     * 判断 {@code iptables -S <链>} 的输出中是否含**非本工具**下发的规则。
     *
     * <p>本工具只往专用链里写形如 {@code -A DDOS_BLOCK -s <ip> -j DROP} 的规则；
     * 只要出现别的 {@code -A} 行，说明这条链被第三方（管理员手建 / 另一份实例 / 安全软件）占用。</p>
     */
    private static boolean hasForeignRules(String listing) {
        if (listing == null) {
            return false;
        }
        for (String line : listing.split("\\R")) {
            String s = line.trim();
            if (s.isEmpty() || s.startsWith("-N ") || s.startsWith("-P ")) {
                continue;                                        // 链创建/内建策略行不是规则
            }
            if (s.startsWith("-A ") && !s.matches("-A " + CHAIN + " -s \\S+ -j DROP")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 启动时清理上次异常退出残留的规则。
     *
     * <p>进程被 kill -9 / 强杀时不会执行退出清理，规则会留在系统里；
     * 这里按后端逐一清理，避免“重启后旧规则还在拦人”。</p>
     */
    public void cleanupStale() {
        if (!available) {
            return;
        }
        switch (backend) {
            case "netsh": {
                // #12：规则名里带下发进程的 PID（DDoS_Block_<pid>_<ip>）。
                // 只清理“自己进程的”和“所属进程已不存在的”规则，绝不碰另一份正在运行的实例。
                String query = "Get-NetFirewallRule -DisplayName 'DDoS_Block_*' "
                        + "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName";
                Result listed = run(powershell(query), null, 30);
                List<String> mine = new ArrayList<>();
                int foreign = 0;
                for (String line : listed.output().split("\\R")) {
                    String name = line.trim();
                    if (!name.startsWith("DDoS_Block_")) {
                        continue;
                    }
                    String owner = ruleOwnerPid(name);
                    if (owner != null && !owner.equals(instanceTag) && isProcessAlive(owner)) {
                        foreign++;                    // 另一份实例正在使用，保留不动
                        continue;
                    }
                    // owner == null 是旧版本的无 PID 命名，无法归属，按残留处理
                    mine.add(name);
                }
                if (foreign > 0) {
                    System.out.println("[提示] 检测到 " + foreign
                            + " 条属于其它正在运行的实例的 netsh 规则，已保留不动。");
                    System.out.flush();
                }
                if (!mine.isEmpty()) {
                    int removed = 0;
                    for (int from = 0; from < mine.size(); from += 32) {
                        List<String> chunk = mine.subList(from, Math.min(from + 32, mine.size()));
                        StringBuilder names = new StringBuilder();
                        for (String name : chunk) {
                            if (names.length() > 0) {
                                names.append(',');
                            }
                            names.append('\'').append(name).append('\'');
                        }
                        Result r = run(powershell("Remove-NetFirewallRule -DisplayName " + names
                                + " -ErrorAction SilentlyContinue"), null, 60);
                        if (r.ok()) {
                            removed += chunk.size();
                        }
                    }
                    System.out.println("[提示] 已清理上次残留的 " + removed + " 条 netsh 防火墙规则。");
                    System.out.flush();
                }
                break;
            }
            case "nft":
                // #1：绝不 delete table——同名表可能是别人的。只清空我们自己的集合，
                // 集合不存在时该命令会失败且无副作用。
                run(Arrays.asList("nft", "flush", "set", "inet", NFT_TABLE, NFT_SET4), null);
                run(Arrays.asList("nft", "flush", "set", "inet", NFT_TABLE, NFT_SET6), null);
                nftEnsure();
                break;
            case "iptables":
                iptablesEnsureChain();                            // 建链 + 清空 + 挂载
                break;
            case "pfctl":
                pfEnsure();                                       // 重写 anchor，旧表内容一并清掉
                break;
            default:
                break;
        }
    }

    private static List<String> powershell(String command) {
        return Arrays.asList("powershell", "-NoProfile", "-NonInteractive", "-Command", command);
    }

    /** netsh 规则名：带本进程 PID，便于只清理自己的规则。 */
    private String ruleName(String ip) {
        return "DDoS_Block_" + instanceTag + "_" + ip;
    }

    /** 从 {@code DDoS_Block_<pid>_<ip>} 里取出 PID；旧格式（无 PID）返回 null。 */
    static String ruleOwnerPid(String ruleName) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^DDoS_Block_(\\d+)_").matcher(ruleName);
        return m.find() ? m.group(1) : null;
    }

    /** 该 PID 对应的进程是否还活着（判断规则是否属于另一份运行中的实例）。 */
    private static boolean isProcessAlive(String pid) {
        try {
            return ProcessHandle.of(Long.parseLong(pid)).map(ProcessHandle::isAlive).orElse(false);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // ------------------------------------------------------------ 下发/撤销

    private static boolean isV6(String ip) {
        return ip.indexOf(':') >= 0;
    }

    private Result doBlock(String ip) {
        switch (backend) {
            case "iptables": {
                String tool = isV6(ip) ? "ip6tables" : "iptables";
                if (!which(tool)) {
                    return new Result(false, tool + " 不存在");
                }
                if (run(Arrays.asList(tool, "-C", CHAIN, "-s", ip, "-j", "DROP"), null).ok()) {
                    return new Result(true, "规则已存在");        // 幂等
                }
                return run(Arrays.asList(tool, "-I", CHAIN, "-s", ip, "-j", "DROP"), null);
            }
            case "nft":
                return run(Arrays.asList("nft", "add", "element", "inet", NFT_TABLE,
                        isV6(ip) ? NFT_SET6 : NFT_SET4, "{ " + ip + " }"), null);
            case "netsh":
                return run(Arrays.asList("netsh", "advfirewall", "firewall", "add", "rule",
                        "name=" + ruleName(ip), "dir=in", "action=block", "remoteip=" + ip), null);
            case "pfctl":
                return run(Arrays.asList("pfctl", "-a", anchor, "-t", PF_TABLE,
                        "-T", "add", ip), null);
            default:
                return new Result(false, "无可用防火墙后端");
        }
    }

    private void doUnblock(String ip) {
        switch (backend) {
            case "iptables":
                run(Arrays.asList(isV6(ip) ? "ip6tables" : "iptables",
                        "-D", CHAIN, "-s", ip, "-j", "DROP"), null);
                break;
            case "nft":
                run(Arrays.asList("nft", "delete", "element", "inet", NFT_TABLE,
                        isV6(ip) ? NFT_SET6 : NFT_SET4, "{ " + ip + " }"), null);
                break;
            case "netsh":
                run(Arrays.asList("netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=" + ruleName(ip)), null);
                break;
            case "pfctl":
                run(Arrays.asList("pfctl", "-a", anchor, "-t", PF_TABLE,
                        "-T", "delete", ip), null);
                break;
            default:
                break;
        }
    }

    /**
     * 封禁一个地址。
     *
     * <p>准入策略（按顺序）：能解析 → 不是未指定/组播/广播/环回 →
     * 不在受保护集合（本机地址）→ 若 {@code allow_internal=false} 则再拒绝内网/保留地址。
     * 也就是说 <b>内网地址默认可封禁</b>，不会被无条件跳过。</p>
     *
     * <p>同一个地址的下发是串行化的：第二个调用者会等第一个完成后再检查状态，
     * 因此不会重复下发规则。</p>
     */
    public boolean block(String ip, boolean permanent) {
        if (!available || ip == null || ip.isEmpty()) {
            return false;
        }
        String norm = NetUtil.normIp(ip);
        if (norm == null || !NetUtil.isBlockableAddress(norm)) {
            return false;
        }
        if (protectedAddresses.contains(norm)) {
            return false;
        }
        if (!allowInternal && NetUtil.isInternal(norm)) {
            return false;
        }
        long expires = permanent ? PERMANENT : System.currentTimeMillis() + durationSeconds * 1000L;
        LockRef ref = acquire(norm);
        try {
            synchronized (ref.mutex) {
                synchronized (lock) {
                    if (blocked.containsKey(norm)) {
                        blocked.put(norm, expires);               // 已封禁：只续期，不重复下发
                        return true;
                    }
                    // 上限护栏（#17）：攻击者可用海量源 IP 打进来。检查必须与 blocked 的写入
                    // 在同一把锁里，否则多线程会同时通过检查，软上限被突破。
                    if (blocked.size() >= MAX_TRACKED_BLOCKS) {
                        return false;                             // 已达跟踪上限，拒绝新封禁
                    }
                }
                blocksIssued.incrementAndGet();
                boolean ok = dryRun || doBlock(norm).ok();
                if (ok) {
                    synchronized (lock) {
                        blocked.put(norm, expires);
                    }
                }
                return ok;
            }
        } finally {
            // 无论成功还是失败都释放引用计数：#2 的孤儿锁泄漏正是“失败时不回收”造成的。
            release(norm, ref);
        }
    }

    public void unblock(String ip) {
        String norm = NetUtil.normIp(ip);
        if (norm == null) {
            return;
        }
        LockRef ref = acquire(norm);
        try {
            synchronized (ref.mutex) {
                synchronized (lock) {
                    blocked.remove(norm);
                }
                if (!dryRun) {
                    doUnblock(norm);
                }
            }
        } finally {
            release(norm, ref);
        }
    }

    public boolean isPermanent(String ip) {
        String norm = NetUtil.normIp(ip);
        if (norm == null) {
            return false;
        }
        synchronized (lock) {
            Long exp = blocked.get(norm);
            return exp != null && exp == PERMANENT;
        }
    }

    /**
     * 该地址当前是否已被跟踪（已下发并登记在案）。
     *
     * <p>用于区分「本次真的新下发了规则」与「只是给已封禁的地址续期」：
     * {@link #block} 两种情况都返回 {@code true}，调用方若不区分，攻击持续期间
     * 每秒都会把同一条“已加入黑名单”写进日志（真机日志里实测过一次攻击刷 60 行）。</p>
     */
    public boolean isTracked(String ip) {
        String norm = NetUtil.normIp(ip);
        if (norm == null) {
            return false;
        }
        synchronized (lock) {
            return blocked.containsKey(norm);
        }
    }

    /** 到期自动解封；stop 置位后返回。 */
    public void cleanerLoop(BooleanSupplier stop) {
        while (!stop.getAsBoolean()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            long now = System.currentTimeMillis();
            List<String> expired = new ArrayList<>();
            synchronized (lock) {
                java.util.Iterator<Map.Entry<String, Long>> it = blocked.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, Long> e = it.next();
                    long exp = e.getValue();
                    if (exp == PERMANENT) {
                        continue;
                    }
                    if (now >= exp) {
                        expired.add(e.getKey());
                        it.remove();
                    }
                }
            }
            for (String ip : expired) {
                if (!dryRun) {
                    doUnblock(ip);
                }
                // 锁表由引用计数自行回收（见 release()）；这里不再直接 remove，
                // 否则会把别的线程正在持有的锁删掉，破坏同 IP 串行化。
            }
        }
    }

    /**
     * 退出前撤销全部规则。
     *
     * <p>Linux/macOS 用一条批量 flush（iptables -F 专用链 / nft flush set / pfctl -T flush）
     * 代替逐条删除；netsh 没有批量接口，保留逐条删除并受 budget 限制。</p>
     */
    public int cleanupAll(double budgetSeconds) {
        List<String> ips;
        synchronized (lock) {
            ips = new ArrayList<>(blocked.keySet());
        }
        int count = ips.size();
        if (!dryRun && count > 0) {
            if ("netsh".equals(backend)) {
                long deadline = System.nanoTime() + (long) (budgetSeconds * 1_000_000_000L);
                int done = 0;
                for (String ip : ips) {
                    if (System.nanoTime() > deadline) {
                        System.out.println("[警告] 清理超时，仍有 " + (count - done)
                                + " 条规则未撤销，请手动检查防火墙后端 " + backend + "。");
                        break;
                    }
                    doUnblock(ip);
                    done++;
                }
            } else {
                flushAll();
            }
        }
        if ("pfctl".equals(backend)) {
            // 即使一条规则都没有，也要释放本进程 pfctl -E 拿到的引用计数（dry-run 也会 -E）
            pfDisable();
        }
        synchronized (lock) {
            blocked.clear();
            // 不 clear ipLocks：正在 block() 里的线程释放引用后会自行回收，
            // 直接清空会让它 release 到删不掉的旧对象，且可能破坏串行化。
        }
        return count;
    }

    private void flushAll() {
        switch (backend) {
            case "iptables":
                for (String tool : new String[]{"iptables", "ip6tables"}) {
                    if (which(tool)) {
                        run(Arrays.asList(tool, "-F", CHAIN), null);
                    }
                }
                break;
            case "nft":
                run(Arrays.asList("nft", "flush", "set", "inet", NFT_TABLE, NFT_SET4), null);
                run(Arrays.asList("nft", "flush", "set", "inet", NFT_TABLE, NFT_SET6), null);
                break;
            case "pfctl":
                run(Arrays.asList("pfctl", "-a", anchor, "-t", PF_TABLE, "-T", "flush"), null);
                break;
            default:
                break;
        }
    }

    // ------------------------------------------------------------ 进程调用

    public Result run(List<String> cmd, String stdinData) {
        return run(cmd, stdinData, CMD_TIMEOUT_SECONDS);
    }

    public Result run(List<String> cmd, String stdinData, int timeoutSeconds) {
        Process process = null;
        try {
            // 自动把 argv[0] 换成解析到的绝对路径：Linux/macOS 上非 root shell 的 PATH
            // 常常不含 /usr/sbin、/sbin，只靠 PATH 会找不到 iptables/nft/pfctl。
            List<String> resolved = new ArrayList<>(cmd);
            if (!resolved.isEmpty()) {
                resolved.set(0, exe(resolved.get(0)));
            }
            ProcessBuilder pb = new ProcessBuilder(resolved);
            pb.redirectErrorStream(true);
            process = pb.start();
            try (OutputStream os = process.getOutputStream()) {
                if (stdinData != null) {
                    os.write(stdinData.getBytes(StandardCharsets.UTF_8));
                }
            }
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), Charset.defaultCharset()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Result(false, "命令超时: " + String.join(" ", cmd));
            }
            return new Result(process.exitValue() == 0, sb.toString().trim());
        } catch (Exception e) {
            if (process != null) {
                process.destroyForcibly();
            }
            return new Result(false, String.valueOf(e));
        }
    }

    /** 非 Windows 上 sbin 目录常常不在 PATH 里（尤其是非 root shell），这里一并探测。 */
    private static final String[] COMMON_BIN_DIRS = {
        "/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin",
        "/opt/homebrew/bin", "/opt/homebrew/sbin", "/opt/local/sbin", "/opt/local/bin"
    };

    private static final java.util.Map<String, String> TOOL_CACHE = new java.util.concurrent.ConcurrentHashMap<>();

    /** 解析可执行文件：先查 PATH，再查常见 sbin/bin 目录；找不到返回 null。 */
    public static String locate(String cmd) {
        String cached = TOOL_CACHE.get(cmd);
        if (cached != null) {
            return cached.isEmpty() ? null : cached;
        }
        String found = locateUncached(cmd);
        TOOL_CACHE.put(cmd, found == null ? "" : found);
        return found;
    }

    private static String locateUncached(String cmd) {
        boolean windows = System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("win");
        List<String> exts = new ArrayList<>();
        exts.add("");
        if (windows) {
            exts.add(".exe");
            exts.add(".cmd");
            exts.add(".bat");
        }
        List<String> dirs = new ArrayList<>();
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(File.pathSeparator)) {
                if (!dir.isEmpty()) {
                    dirs.add(dir);
                }
            }
        }
        if (!windows) {
            dirs.addAll(Arrays.asList(COMMON_BIN_DIRS));   // PATH 之外的兜底
        }
        for (String dir : dirs) {
            for (String ext : exts) {
                Path p = Paths.get(dir, cmd + ext);
                if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                    return p.toString();
                }
            }
        }
        return null;
    }

    /** 供命令行使用：解析到绝对路径就用绝对路径，否则原样返回交给 ProcessBuilder 自己找。 */
    public static String exe(String cmd) {
        String found = locate(cmd);
        return found != null ? found : cmd;
    }

    public static boolean which(String cmd) {
        return locate(cmd) != null;
    }

    // ------------------------------------------------------------ 状态查询

    public String system() {
        return system;
    }

    public String backend() {
        return backend;
    }

    public boolean available() {
        return available;
    }

    public int duration() {
        return durationSeconds;
    }

    public void setDuration(int seconds) {
        this.durationSeconds = Math.max(1, seconds);
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public void setDryRun(boolean value) {
        this.dryRun = value;
    }

    /** 是否允许封禁内网/保留地址（默认 true）。 */
    public boolean isAllowInternal() {
        return allowInternal;
    }

    public void setAllowInternal(boolean value) {
        this.allowInternal = value;
    }

    /** 设置始终不封禁的地址集合（本机自身地址），传入的字符串会被归一化。 */
    public void setProtectedAddresses(java.util.Collection<String> addresses) {
        protectedAddresses.clear();
        if (addresses == null) {
            return;
        }
        for (String addr : addresses) {
            String norm = NetUtil.normIp(addr);
            if (norm != null) {
                protectedAddresses.add(norm);
            }
        }
    }

    public boolean isProtectedAddress(String ip) {
        String norm = NetUtil.normIp(ip);
        return norm != null && protectedAddresses.contains(norm);
    }

    /** 受保护地址（本机地址）数量，供界面显示。 */
    public int protectedCount() {
        return protectedAddresses.size();
    }

    /** 真正下发给操作系统的规则条数（诊断与自检用）。 */
    public long blocksIssued() {
        return blocksIssued.get();
    }

    /**
     * 地址锁表的条目数（诊断与自检用）。
     *
     * <p>正常情况下它随封禁/解封回收，不会持续增长；自检用它验证
     * “doBlock 失败也不留孤儿锁”。</p>
     */
    public int lockTableSize() {
        synchronized (lock) {
            return ipLocks.size();
        }
    }

    /** 当前内存里记录的封禁列表快照：ip → 到期毫秒（PERMANENT 表示永久）。 */
    public LinkedHashMap<String, Long> snapshot() {
        synchronized (lock) {
            return new LinkedHashMap<>(blocked);
        }
    }
}
