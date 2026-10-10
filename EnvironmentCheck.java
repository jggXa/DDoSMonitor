import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * 运行环境自检：分清「我在哪个平台 / 有没有权限 / 抓包后端与防火墙后端到底能不能用 /
 * 结论是可封禁还是只能告警」。
 *
 * <p>两种用法：</p>
 * <ul>
 *   <li>{@code --check}：只读探测（不构造防火墙、不打开网卡、不下发规则），打印完整报告后退出；</li>
 *   <li>正常启动：抓包器启动成功后打印同一份报告的“实测版”。</li>
 * </ul>
 */
public final class EnvironmentCheck {

    private EnvironmentCheck() {
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    /** 平台 / 架构 / JDK 版本。 */
    public static String platform() {
        return System.getProperty("os.name", "?") + " / " + System.getProperty("os.arch", "?")
                + " / JDK " + System.getProperty("java.version", "?");
    }

    /** 权限：抓包与改防火墙都需要它，这里给出明确结论而不是让用户猜。 */
    public static String privilege() {
        if (isWindows()) {
            boolean admin = runOk("net", "session");
            return admin ? "管理员（可抓包、可改防火墙）"
                    : "非管理员（抓包与防火墙都需要以管理员运行）";
        }
        String user = System.getProperty("user.name", "?");
        if ("root".equals(user)) {
            return "root（可抓包、可改防火墙）";
        }
        return user + "（非 root：抓包需 root 或 CAP_NET_RAW，封禁需 root 或 CAP_NET_ADMIN"
                + (Firewall.locate("sudo") != null ? "；可用 sudo 运行" : "") + "）";
    }

    /** 抓包后端探测结果。 */
    public record Capture(String kind, boolean ok, String detail) {
    }

    /**
     * 只读探测抓包能力：是否编译进了 JNA 后端、库能否加载、能枚举到几块网卡、默认会选哪一块，
     * 以及是否有 dumpcap/tcpdump 作为后备。
     */
    public static Capture capture(int port) {
        boolean jna = classPresent("com.sun.jna.Native");
        boolean jnaSource = classPresent("NpcapJnaSource");
        String external = ExternalPcapSource.findTool();
        String libName = isWindows() ? "wpcap.dll" : "libpcap";

        String kind;
        boolean ok = false;
        StringBuilder detail = new StringBuilder();

        if (jnaSource && jna) {
            kind = isWindows() ? "Npcap（JNA → wpcap.dll）" : "libpcap（JNA → libpcap）";
            try {
                Class<?> cls = Class.forName("NpcapJnaSource");
                Object devices = cls.getMethod("listDevices").invoke(null);
                int count = devices instanceof List<?> list ? list.size() : 0;
                Method first = cls.getDeclaredMethod("firstDevice");
                first.setAccessible(true);
                Object chosen = first.invoke(null);
                ok = count > 0 && chosen != null;
                detail.append(ok ? "可用 ✓" : "不可用 ✗")
                        .append("｜库=").append(libName)
                        .append("｜网卡枚举=").append(count).append(" 个")
                        .append("｜默认网卡=").append(chosen == null ? "（无）" : chosen);
                if (!ok) {
                    detail.append("｜原因：枚举不到网卡（").append(libName)
                            .append(isWindows() ? " 未安装或权限不足）" : " 未安装）");
                }
            } catch (Throwable t) {
                Throwable cause = t.getCause() != null ? t.getCause() : t;
                detail.append("不可用 ✗｜库=").append(libName)
                        .append("｜原因：").append(cause)
                        .append(isWindows()
                                ? "（请安装 Npcap 并以管理员运行）"
                                : "（请安装 libpcap：apt install libpcap0.8 / brew install libpcap）");
            }
        } else if (!jna) {
            kind = "（无 JNA 后端）";
            detail.append("不可用 ✗｜原因：jar 内缺少 JNA（lib/jna.jar 未参与编译）");
        } else {
            kind = "（无抓包类）";
            detail.append("不可用 ✗｜原因：jar 内没有 NpcapJnaSource");
        }

        detail.append("｜后备工具=").append(external == null ? "未找到 dumpcap/tcpdump" : external);
        if (!ok && external != null) {
            kind = "external（" + external + "）";
            ok = true;
            detail.append(" → 可改用 --source=external");
        }
        if (!ok) {
            kind = "sim（模拟流量，仅自测）";
            detail.append(" → 可用 --source=sim 验证检测/封禁逻辑");
        }
        return new Capture(kind, ok, detail.toString());
    }

    /** 防火墙后端：后端名、是否可用、解析到的绝对路径、不可用原因。 */
    public static String firewall(Firewall fw) {
        String backend = fw.backend();
        boolean available = fw.available();
        String tool = toolOf(backend);
        String path = tool == null ? null : Firewall.locate(tool);
        StringBuilder sb = new StringBuilder();
        sb.append(backend).append(available ? " 可用 ✓" : " 不可用 ✗");
        if (path != null) {
            sb.append("｜路径=").append(path);
        }
        if (!available) {
            sb.append("｜原因：").append(missingReason(fw.system()));
        }
        return sb.toString();
    }

    /** 只读探测防火墙后端（不创建链/表，无副作用），供 --check 使用。 */
    public static String firewallProbe() {
        String system = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String backend;
        if (system.contains("win")) {
            backend = "netsh";
        } else if (system.contains("mac")) {
            backend = "pfctl";
        } else {
            backend = Firewall.which("iptables") ? "iptables" : (Firewall.which("nft") ? "nft" : "none");
        }
        if ("none".equals(backend)) {
            return "none 不可用 ✗｜原因：" + missingReason("Linux");
        }
        String path = Firewall.locate(backend);
        if (path == null) {
            return backend + " 不可用 ✗｜原因：" + missingReason(
                    system.contains("win") ? "Windows" : (system.contains("mac") ? "Darwin" : "Linux"));
        }
        return backend + " 可用 ✓｜路径=" + path + "（--check 不创建链/表）";
    }

    private static String toolOf(String backend) {
        return switch (backend) {
            case "iptables", "nft", "netsh", "pfctl" -> backend;
            default -> null;
        };
    }

    private static String missingReason(String system) {
        return switch (system) {
            case "Linux" -> "未找到 iptables/ip6tables 或 nft（需安装，且 /usr/sbin 可达）";
            case "Windows" -> "未找到 netsh（系统异常？）";
            case "Darwin" -> "未找到 pfctl（应随系统自带）";
            default -> "未知平台，未找到可用后端";
        };
    }

    /** 一句话结论：能不能抓包、能不能封禁。 */
    public static String conclusion(String captureKind, boolean captureOk,
                                    boolean firewallAvailable, boolean dryRun) {
        StringBuilder sb = new StringBuilder();
        if (captureOk) {
            sb.append("可抓包");
        } else if (captureKind.startsWith("sim")) {
            sb.append("无真实抓包（将退回模拟流量自测）");
        } else {
            sb.append("抓包不可用");
        }
        if (firewallAvailable) {
            sb.append(dryRun ? "；可封禁（当前 dry-run：只登记不下发）" : "；可封禁");
        } else {
            sb.append("；仅告警（防火墙后端不可用，不会下发任何规则）");
        }
        return sb.toString();
    }

    /** 是否具备管理员 / root 权限（抓包与改防火墙都需要）。 */
    public static boolean privileged() {
        if (isWindows()) {
            return runOk("net", "session");
        }
        return "root".equals(System.getProperty("user.name", "?"));
    }

    /**
     * 启动前的问题清单：**错误与警告都算**，空列表表示"全绿灯"（可静默直接启动）。
     *
     * <p>调用时机在 main 的询问之前，因此这里只做只读探测（不构造防火墙、不打开网卡、不下发规则）。</p>
     */
    public static List<String> collectProblems(int port, boolean inboundOnly, boolean allowInternal,
                                               boolean autoBlock, boolean dryRun) {
        List<String> problems = new ArrayList<>();
        if (!privileged()) {
            problems.add("[错误] 权限不足：抓包与封禁都需要管理员/root，请以管理员身份运行");
        }
        Capture capture = capture(port);
        if (!capture.ok()) {
            problems.add("[错误] 抓包后端不可用：" + capture.detail());
        } else if (!(capture.kind().contains("Npcap") || capture.kind().contains("libpcap"))) {
            problems.add("[警告] 抓包走的是后备方案（" + capture.kind() + "）：确认它真的能收到流量");
        }
        String fw = firewallProbe();
        if (!fw.contains("可用 ✓")) {
            problems.add("[错误] 防火墙后端不可用：" + fw
                    + (autoBlock ? "；自动封禁已开启，届时无法下发任何规则，只能告警" : ""));
        }
        if (allowInternal) {
            problems.add("[警告] 内网封禁已开启：自动封禁可能命中网关/内网主机，"
                    + "必要时 set allow_internal 0 退回「只封公网」");
        }
        if (dryRun) {
            problems.add("[警告] dry-run 已开启：只登记不实际封禁（正式防护请关闭）");
        }
        if (!inboundOnly) {
            problems.add("[警告] 入向过滤已关闭：两个方向都统计，阈值判定更容易误报");
        }
        return problems;
    }

    /** 打印完整报告（--check 用；只读，不改动系统）。 */
    public static void printReadOnly(int port, boolean inboundOnly, boolean allowInternal,
                                     boolean autoBlock, boolean dryRun) {
        Capture capture = capture(port);
        String fw = firewallProbe();
        boolean fwOk = fw.contains("可用 ✓");
        System.out.println("=".repeat(72));
        System.out.println(" 环境自检（只读，不抓包、不下发规则）");
        System.out.println("   平台          : " + platform());
        System.out.println("   权限          : " + privilege());
        System.out.println("   工作目录      : " + Paths.get("").toAbsolutePath());
        System.out.println("   目标端口      : " + port);
        System.out.println("   抓包后端      : " + capture.kind() + "｜" + capture.detail());
        System.out.println("   防火墙后端    : " + fw);
        System.out.println("   策略          : 入向过滤=" + onOff(inboundOnly)
                + " 内网封禁=" + onOff(allowInternal)
                + " 自动封禁=" + onOff(autoBlock)
                + " dry-run=" + onOff(dryRun));
        System.out.println("   结论          : " + conclusion(capture.kind(), capture.ok(), fwOk, dryRun));
        List<String> problems = collectProblems(port, inboundOnly, allowInternal, autoBlock, dryRun);
        if (problems.isEmpty()) {
            System.out.println(Color.green("   需要留意      : 无（全绿灯，启动时不会打断询问）"));
        } else {
            System.out.println(Color.green("   需要留意      : " + problems.size() + " 项（启动时会先列出并询问是否继续）"));
            for (String problem : problems) {
                System.out.println(Color.green("     - " + problem));
            }
        }
        System.out.println("=".repeat(72));
    }

    /** 正常启动时打印的实测版报告（抓包后端已确定、防火墙已初始化）。 */
    public static void printRuntime(int port, String configSource, String captureKind, String captureDetail,
                                    Firewall firewall, boolean inboundOnly, boolean allowInternal,
                                    boolean autoBlock, boolean dryRun) {
        System.out.println("=".repeat(72));
        System.out.println(" 环境自检");
        System.out.println("   平台          : " + platform());
        System.out.println("   权限          : " + privilege());
        System.out.println("   配置来源      : " + configSource + "（目标端口 " + port + "）");
        System.out.println("   抓包后端      : " + captureKind + "｜" + captureDetail);
        System.out.println("   防火墙后端    : " + firewall(firewall));
        System.out.println("   策略          : 入向过滤=" + onOff(inboundOnly)
                + " 内网封禁=" + onOff(allowInternal)
                + " 自动封禁=" + onOff(autoBlock)
                + " dry-run=" + onOff(dryRun));
        System.out.println("   结论          : " + conclusion(captureKind, captureUsable(captureKind),
                firewall.available(), dryRun));
        System.out.println("=".repeat(72));
        System.out.flush();
    }

    /** 已启动的抓包后端是否真的能抓到流量（sim 视为“无真实抓包”）。 */
    private static boolean captureUsable(String captureKind) {
        return !(captureKind.contains("模拟") || captureKind.startsWith("sim")
                || captureKind.contains("未启动") || captureKind.contains("失败"));
    }

    private static String onOff(boolean value) {
        return value ? "开" : "关";
    }

    private static boolean classPresent(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean runOk(String... cmd) {
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            process = pb.start();
            process.getOutputStream().close();
            process.getInputStream().readAllBytes();
            return process.waitFor(6, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
