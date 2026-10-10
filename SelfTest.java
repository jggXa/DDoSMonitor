import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 自检程序：不抓包、不下发规则，只验证纯逻辑。
 *
 * <pre>java -cp out SelfTest</pre>
 */
public final class SelfTest {

    private static final AtomicInteger PASSED = new AtomicInteger();
    private static final List<String> FAILED = new ArrayList<>();

    private SelfTest() {
    }

    public static void main(String[] args) throws Exception {
        testNetUtil();
        testConfigValidation();
        testJsonRoundTrip();
        testRateCounter();
        testPcapParser();
        testFirewallConcurrency();
        testLocalAddresses();
        testColor();
        testPortability();
        testEnvironmentCheck();
        testHardening();

        System.out.println();
        System.out.println("通过 " + PASSED.get() + " 项，失败 " + FAILED.size() + " 项");
        for (String f : FAILED) {
            System.out.println("  失败: " + f);
        }
        if (!FAILED.isEmpty()) {
            System.exit(1);
        }
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            PASSED.incrementAndGet();
        } else {
            FAILED.add(name);
            System.out.println("  [FAIL] " + name);
        }
    }

    // ------------------------------------------------------------ 地址分类

    private static void testNetUtil() {
        System.out.println("== NetUtil 地址分类 ==");
        check("8.8.8.8 可封禁", !NetUtil.isInternal("8.8.8.8"));
        check("1.2.3.4 可封禁", !NetUtil.isInternal("1.2.3.4"));
        check("10.0.0.1 内网", NetUtil.isInternal("10.0.0.1"));
        check("172.16.0.1 内网", NetUtil.isInternal("172.16.0.1"));
        check("172.32.0.1 可封禁(边界)", !NetUtil.isInternal("172.32.0.1"));
        check("192.168.0.30 内网", NetUtil.isInternal("192.168.0.30"));
        check("127.0.0.1 环回", NetUtil.isInternal("127.0.0.1"));
        check("100.64.0.1 CGNAT", NetUtil.isInternal("100.64.0.1"));
        check("192.0.2.5 文档段", NetUtil.isInternal("192.0.2.5"));
        check("0.0.0.0 未指定", NetUtil.isInternal("0.0.0.0"));
        check("224.0.0.1 组播", NetUtil.isInternal("224.0.0.1"));
        check("::1 环回", NetUtil.isInternal("::1"));
        check("fd00::1 ULA", NetUtil.isInternal("fd00::1"));
        check("fe80::1 链路本地", NetUtil.isInternal("fe80::1"));
        check("2001:db8::1 文档段", NetUtil.isInternal("2001:db8::1"));
        check("2001:4860:4860::8888 可封禁", !NetUtil.isInternal("2001:4860:4860::8888"));
        check("::ffff:10.0.0.1 归一化为内网", NetUtil.isInternal("::ffff:10.0.0.1"));
        check("::ffff:8.8.8.8 归一化为可封禁", !NetUtil.isInternal("::ffff:8.8.8.8"));
        check("乱码不可封禁", NetUtil.isInternal("not-an-ip"));
        check("空值不可封禁", NetUtil.isInternal(null));
        check("归一化 IPv6", "2001:db8::1".equals(NetUtil.normIp("2001:0db8:0000:0000:0000:0000:0000:0001")));
        check("归一化 IPv4", "1.2.3.4".equals(NetUtil.normIp(" 1.2.3.4 ")));
        check("human_bytes", "1.00 KB".equals(NetUtil.humanBytes(1024)));
        // 封禁底线：内网不再被一刀切拒绝，只挡未指定/组播/广播/环回
        check("底线：内网可封禁", NetUtil.isBlockableAddress("10.0.0.1"));
        check("底线：CGNAT 可封禁", NetUtil.isBlockableAddress("100.64.0.1"));
        check("底线：文档段可封禁", NetUtil.isBlockableAddress("192.0.2.5"));
        check("底线：ULA 可封禁", NetUtil.isBlockableAddress("fd00::1"));
        check("底线：公网可封禁", NetUtil.isBlockableAddress("8.8.8.8"));
        check("底线：未指定拒绝", !NetUtil.isBlockableAddress("0.0.0.0"));
        check("底线：组播拒绝", !NetUtil.isBlockableAddress("224.0.0.1"));
        check("底线：环回拒绝", !NetUtil.isBlockableAddress("127.0.0.1"));
        check("底线：广播拒绝", !NetUtil.isBlockableAddress("255.255.255.255"));
        check("底线：非法值拒绝", !NetUtil.isBlockableAddress("nope"));
    }

    // ------------------------------------------------------------ 配置校验

    private static void testConfigValidation() {
        System.out.println("== ConfigStore 校验 ==");
        check("阈值 0 被拒（>=0 会恒真）", !ConfigStore.validate("ip_pps_threshold", "0").ok());
        check("阈值 5 通过", ConfigStore.validate("ip_pps_threshold", "5").ok());
        check("port 70000 被拒", !ConfigStore.validate("port", "70000").ok());
        check("port 8080 通过", ConfigStore.validate("port", "8080").ok());
        check("window 0 被拒（会除零）", !ConfigStore.validate("window", "0").ok());
        check("非数字被拒", !ConfigStore.validate("window", "abc").ok());
        check("未知键被拒", !ConfigStore.validate("banned", "x").ok());
        check("auto_block 接受 bool", ConfigStore.validate("auto_block", Boolean.TRUE).ok());
        check("auto_block 2 被拒", !ConfigStore.validate("auto_block", 2).ok());
        check("inbound_only 0/1 通过",
                ConfigStore.validate("inbound_only", 0).ok() && ConfigStore.validate("inbound_only", 1).ok());
        check("浮点整数值通过", ConfigStore.validate("window", 3.0).ok());
        check("浮点非整数被拒", !ConfigStore.validate("window", 3.5).ok());
        check("banned 去重与清洗",
                ConfigStore.normalizeBanned(List.of("a", "a", " ", 5, "b")).equals(List.of("a", "b")));
        check("默认配置含 inbound_only", ConfigStore.defaults().containsKey("inbound_only"));
        check("默认配置含 allow_internal", ConfigStore.defaults().containsKey("allow_internal"));
        check("allow_internal 默认为允许", ConfigStore.asLong(ConfigStore.defaults(), "allow_internal", -1) == 1);
        check("SPEC 与 DEFAULT_CONFIG 键一一对应", sameKeys());
    }

    private static boolean sameKeys() {
        Set<String> specKeys = new HashSet<>(ConfigStore.spec().keySet());
        Set<String> defaultKeys = new HashSet<>(ConfigStore.defaults().keySet());
        defaultKeys.remove(ConfigStore.KEY_NOTE);
        defaultKeys.remove(ConfigStore.KEY_BANNED);
        return specKeys.equals(defaultKeys);
    }

    private static void testJsonRoundTrip() throws Exception {
        System.out.println("== Json 往返 ==");
        LinkedHashMap<String, Object> config = ConfigStore.defaults();
        config.put("banned", new ArrayList<>(List.of("evil.com", "1.2.3.4")));
        Path tmp = Files.createTempFile("ddos-config", ".json");
        try {
            Json.writeFile(tmp, config);
            Object parsed = Json.parseFile(tmp);
            check("顶层是对象", parsed instanceof Map);
            Map<?, ?> map = (Map<?, ?>) parsed;
            check("中文说明保持原样",
                    "阈值配置，调试模式使用 set <键> <值> 可修改，或直接编辑本文件"
                            .equals(map.get("_说明")));
            check("整数保持整数", Integer.valueOf(80).equals(map.get("port")));
            check("数组保持数组", map.get("banned") instanceof List
                    && ((List<?>) map.get("banned")).size() == 2);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    // ------------------------------------------------------------ 分桶计数

    private static void testRateCounter() {
        System.out.println("== RateCounter 分桶计数 ==");
        RateCounter counter = new RateCounter(3);
        long base = 1_000_000L;                       // 第 1000 秒
        for (int i = 0; i < 10; i++) {
            counter.add("1.1.1.1", base, 100, i < 3, 50, "TCP");
        }
        for (int i = 0; i < 5; i++) {
            counter.add("2.2.2.2", base, 200, false, 0, "UDP");
        }
        counter.evict(1000);
        RateCounter.Global g = counter.global();
        check("全局包数 15", g.packets() == 15);
        check("全局字节 2000", g.bytes() == 2000);
        check("活跃 IP 2", counter.activeIps() == 2);
        check("协议分布 TCP=10 UDP=5", Integer.valueOf(10).equals(g.protos().get("TCP"))
                && Integer.valueOf(5).equals(g.protos().get("UDP")));
        Map<String, RateCounter.IpCount> per = new LinkedHashMap<>();
        for (Map.Entry<String, RateCounter.IpCount> e : counter.entries()) {
            per.put(e.getKey(), e.getValue());
        }
        check("单 IP 计数正确", per.get("1.1.1.1").packets == 10 && per.get("1.1.1.1").bytes == 1000
                && per.get("1.1.1.1").syns == 3);
        check("第二个 IP 计数正确", per.get("2.2.2.2").packets == 5 && per.get("2.2.2.2").bytes == 1000);

        // 第 1004 秒：1000 秒的桶应被淘汰（窗口 3 秒）
        counter.add("3.3.3.3", 1_004_000L, 10, false, 0, "TCP");
        counter.evict(1004);
        RateCounter.Global g2 = counter.global();
        check("过期桶被淘汰", g2.packets() == 1);
        check("totals 同步递减到 0", counter.activeIps() == 1);
        check("淘汰后无残留 IP",
                counter.entries().stream().noneMatch(e -> e.getKey().equals("1.1.1.1")));

        // 缩小窗口后立即淘汰
        counter.setWindow(1);
        counter.evict(1004);
        check("窗口缩到 1 秒后仍保留当秒桶", counter.global().packets() == 1);
        counter.evict(1006);
        check("窗口外清空", counter.global().packets() == 0 && counter.activeIps() == 0);
        check("窗口值不小于 1", new RateCounter(0).window() == 1);
    }

    // ------------------------------------------------------------ 报文解析

    private static void testPcapParser() {
        System.out.println("== PcapParser 报文解析 ==");

        byte[] frame = new byte[54];
        // 以太网头
        frame[12] = (byte) 0x08;
        frame[13] = 0x00;
        // IPv4
        frame[14] = 0x45;
        frame[16] = 0;
        frame[17] = 48;                                  // 总长 48 = 20 + 20 + 8? 这里用 40 也匹配
        frame[14 + 2] = 0;
        frame[14 + 3] = 40;                              // total length = 40
        frame[14 + 8] = 64;
        frame[14 + 9] = 6;                               // TCP
        frame[14 + 12] = 1;
        frame[14 + 13] = 2;
        frame[14 + 14] = 3;
        frame[14 + 15] = 4;
        frame[14 + 16] = 5;
        frame[14 + 17] = 6;
        frame[14 + 18] = 7;
        frame[14 + 19] = 8;
        // TCP：源端口 40000(0x9C40) 在 +0..1，目的端口 80 在 +2..3
        int tcp = 14 + 20;
        frame[tcp] = (byte) 0x9C;
        frame[tcp + 1] = 0x40;
        frame[tcp + 2] = 0x00;
        frame[tcp + 3] = 80;
        frame[tcp + 12] = 0x50;                           // 数据偏移 5
        frame[tcp + 13] = 0x02;                           // SYN
        PacketInfo tcpInfo = PcapParser.parse(frame, 0, frame.length, PcapParser.DLT_EN10MB, 1.5, 54);
        check("TCP 解析非空", tcpInfo != null);
        if (tcpInfo != null) {
            check("TCP 目的端口 80", tcpInfo.dstPort == 80);
            check("TCP SYN 置位", tcpInfo.syn);
            check("TCP 源地址", "1.2.3.4".equals(tcpInfo.srcIp));
            check("TCP 目的地址（入向过滤要用）", "5.6.7.8".equals(tcpInfo.dstIp));
            check("TCP 协议名", "TCP".equals(tcpInfo.proto));
            check("TCP 帧长", tcpInfo.length == 54);
            check("TCP 无负载", tcpInfo.payloadLen == 0);
        }

        // VLAN 标签 + IPv4
        byte[] vlan = new byte[58];
        vlan[12] = (byte) 0x81;
        vlan[13] = 0x00;
        vlan[16] = (byte) 0x08;
        vlan[17] = 0x00;
        System.arraycopy(frame, 14, vlan, 18, 40);
        PacketInfo vlanInfo = PcapParser.parse(vlan, 0, vlan.length, PcapParser.DLT_EN10MB, 1.6, 58);
        check("VLAN 标签可解析", vlanInfo != null && vlanInfo.dstPort == 80);

        // IPv6 + UDP
        byte[] v6 = new byte[62];
        v6[12] = (byte) 0x86;
        v6[13] = (byte) 0xDD;
        v6[14] = 0x60;                                    // version 6
        v6[18] = 0;                                       // payload length = 8
        v6[19] = 8;
        v6[20] = 17;                                      // next header = UDP
        v6[21] = 64;
        v6[22 + 0] = 0x20;
        v6[22 + 1] = 0x01;
        v6[22 + 2] = 0x0d;
        v6[22 + 3] = (byte) 0xb8;
        v6[22 + 15] = 1;                                  // 源 2001:db8::1
        v6[38 + 0] = 0x20;
        v6[38 + 1] = 0x01;
        v6[38 + 2] = 0x0d;
        v6[38 + 3] = (byte) 0xb8;
        v6[38 + 15] = 2;                                  // 目的 2001:db8::2
        // UDP：源端口 1234 在 +0..1，目的端口 80 在 +2..3，长度 8 在 +4..5
        int udp = 14 + 40;
        v6[udp] = 0x04;
        v6[udp + 1] = (byte) 0xD2;
        v6[udp + 2] = 0x00;
        v6[udp + 3] = 80;
        v6[udp + 4] = 0x00;
        v6[udp + 5] = 8;
        PacketInfo udpInfo = PcapParser.parse(v6, 0, v6.length, PcapParser.DLT_EN10MB, 1.7, 62);
        check("IPv6/UDP 解析非空", udpInfo != null);
        if (udpInfo != null) {
            check("IPv6 目的端口 80", udpInfo.dstPort == 80);
            check("IPv6 源地址压缩形式", "2001:db8::1".equals(udpInfo.srcIp));
            check("IPv6 目的地址压缩形式", "2001:db8::2".equals(udpInfo.dstIp));
            check("UDP 非 SYN", !udpInfo.syn);
        }
        check("非 IP 以太网帧返回 null",
                PcapParser.parse(new byte[60], 0, 60, PcapParser.DLT_EN10MB, 1, 60) == null);

        // DLT_NULL（BSD loopback）：4 字节地址族 + IPv4
        byte[] nullFrame = new byte[4 + 40];
        nullFrame[0] = 2;                                 // AF_INET（本机字节序）
        System.arraycopy(frame, 14, nullFrame, 4, 40);
        PacketInfo nullInfo = PcapParser.parse(nullFrame, 0, nullFrame.length,
                PcapParser.DLT_NULL, 1.8, 44);
        check("DLT_NULL 帧可解析", nullInfo != null && nullInfo.dstPort == 80);
        // #9：len == 4 时还会去读 buf[off+4]（IP 版本号）→ AIOOBE，必须安全返回 null
        check("DLT_NULL len=4 不越界（返回 null）",
                PcapParser.parse(new byte[4], 0, 4, PcapParser.DLT_NULL, 1.8, 4) == null);

        // #13：超过 3 层 VLAN 标签视为畸形帧，循环必须有界
        byte[] tooManyTags = new byte[14 + 4 * 4 + 40];
        tooManyTags[12] = (byte) 0x81;
        tooManyTags[13] = 0x00;
        for (int off : new int[]{16, 20, 24}) {           // 第 1~3 层标签的 TPID
            tooManyTags[off] = (byte) 0x81;
            tooManyTags[off + 1] = 0x00;
        }
        check("4 层 VLAN 标签被拒绝",
                PcapParser.parse(tooManyTags, 0, tooManyTags.length,
                        PcapParser.DLT_EN10MB, 1.9, tooManyTags.length) == null);
    }

    // ------------------------------------------------------------ 防火墙并发

    private static void testFirewallConcurrency() throws Exception {
        System.out.println("== Firewall 并发幂等（dry-run）==");
        Firewall fw = new Firewall(300);
        fw.setDryRun(true);
        if (!fw.available()) {
            System.out.println("  （无可用后端，跳过）");
            return;
        }
        String same = "45.33.77.11";
        int threads = 24;
        Thread[] pool = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            pool[i] = new Thread(() -> fw.block(same, false));
        }
        for (Thread t : pool) {
            t.start();
        }
        for (Thread t : pool) {
            t.join();
        }
        check("同 IP 并发 24 次只下发 1 条规则", fw.blocksIssued() == 1);
        check("封禁表只有 1 项", fw.snapshot().size() == 1);

        for (int i = 0; i < 20; i++) {
            fw.block("45.33.77." + (100 + i), false);
        }
        check("20 个不同 IP 各下发 1 条", fw.blocksIssued() == 21);
        check("封禁表 21 项", fw.snapshot().size() == 21);
        // #2：地址锁表必须随每次 block() 结束回收，绝不随封禁数量累积
        check("地址锁表不随封禁累积（=0）", fw.lockTableSize() == 0);

        check("IPv4-mapped 写法命中同一 IP（不重复下发）",
                fw.block("::ffff:45.33.77.11", false) && fw.blocksIssued() == 21);
        // 区分“新下发”与“仅续期”：自动封禁日志只该在 tracked=false 时写
        check("isTracked：已封禁为 true / 未封禁为 false",
                fw.isTracked("45.33.77.11") && !fw.isTracked("45.33.77.250"));
        check("isTracked：非法地址为 false", !fw.isTracked("not-an-ip"));
        check("非法地址拒绝", !fw.block("not-an-ip", false));
        check("占位字符串拒绝", !fw.block("多IP/全网", false));

        int cleaned = fw.cleanupAll(5);
        check("清理数量正确", cleaned == 21);
        check("清理后封禁表为空", fw.snapshot().isEmpty());
        check("清理后地址锁表为空", fw.lockTableSize() == 0);

        // ---- 内网地址封禁策略（本次改动：默认允许）----
        check("内网地址可封禁", fw.block("192.168.1.1", false));
        check("内网封禁确实下发了规则", fw.blocksIssued() == 22);
        check("10/8 可封禁", fw.block("10.1.2.3", false));
        check("CGNAT 可封禁", fw.block("100.64.0.7", false));
        check("IPv6 ULA 可封禁", fw.block("fd00::1", false));
        check("未指定地址拒绝", !fw.block("0.0.0.0", false));
        check("组播地址拒绝", !fw.block("224.0.0.1", false));
        check("环回地址拒绝", !fw.block("127.0.0.1", false));
        check("广播地址拒绝", !fw.block("255.255.255.255", false));

        fw.setProtectedAddresses(List.of("10.9.9.9", "fd00::9"));
        check("本机(受保护)地址拒绝", !fw.block("10.9.9.9", false) && !fw.block("fd00::9", false));
        check("受保护判定可查询",
                fw.isProtectedAddress("10.9.9.9") && !fw.isProtectedAddress("8.8.8.8"));
        check("受保护地址不影响其它内网地址", fw.block("10.9.9.10", false));

        fw.setAllowInternal(false);
        check("严格模式下内网被拒", !fw.block("10.1.2.4", false));
        check("严格模式下公网仍可封", fw.block("45.33.77.200", false));
        fw.setAllowInternal(true);
        check("放开后内网可再封", fw.block("10.1.2.4", false));

        fw.cleanupAll(5);
        fw.setDryRun(false);
    }

    // ------------------------------------------------------------ 跨平台辅助

    private static void testPortability() {
        System.out.println("== 跨平台辅助 ==");
        String def = NetUtil.defaultInterfaceName();
        check("默认出口网卡可解析（或明确返回 null）", def == null || !def.isEmpty());
        System.out.println("  默认出口网卡: " + def);

        check("which() 对不存在的命令返回 false",
                !Firewall.which("definitely-not-a-real-cmd-xyz"));
        check("locate() 对不存在的命令返回 null",
                Firewall.locate("definitely-not-a-real-cmd-xyz") == null);
        check("exe() 找不到时原样返回命令名",
                "definitely-not-a-real-cmd-xyz".equals(Firewall.exe("definitely-not-a-real-cmd-xyz")));

        boolean windows = System.getProperty("os.name", "")
                .toLowerCase(java.util.Locale.ROOT).contains("win");
        if (windows) {
            check("Windows 能定位 netsh", Firewall.which("netsh"));
            check("Windows 解析出绝对路径",
                    Firewall.exe("netsh").toLowerCase(java.util.Locale.ROOT).endsWith("netsh.exe"));
        } else {
            // Linux/macOS：sbin 常常不在 PATH 里，locate() 会额外探测常见目录
            check("非 Windows 下 locate 至少能解析一个系统命令或全部返回 null",
                    Firewall.locate("sh") != null || Firewall.locate("ls") != null
                            || Firewall.locate("definitely-not-a-real-cmd-xyz") == null);
        }
    }

    // ------------------------------------------------------------ 彩色输出

    private static void testColor() {
        System.out.println("== Color（告警红色）==");
        Color.setEnabled(false);
        check("关闭时 red() 返回纯文本", "x".equals(Color.red("x")));
        check("关闭时 green()/yellow() 也是纯文本",
                "x".equals(Color.green("x")) && "x".equals(Color.yellow("x")));

        Color.setEnabled(true);
        String red = Color.red("告警");
        check("开启时 red() 带 31 号色且以 RESET 结尾",
                red.startsWith("\u001B[31m") && red.endsWith("\u001B[0m") && red.contains("告警"));
        check("green() 用 32 号色", Color.green("x").startsWith("\u001B[32m"));
        check("yellow() 用 33 号色", Color.yellow("x").startsWith("\u001B[33m"));

        // 日志文件必须是纯文本：把 ANSI 转义剥掉后应与原文完全一致
        check("剥掉 ANSI 转义后与原文一致（日志写纯文本）",
                "告警".equals(Color.red("告警").replaceAll("\u001B\\[[0-9;]*m", "")));
        Color.setEnabled(false);
    }

    // ------------------------------------------------------------ 环境自检

    private static void testEnvironmentCheck() {
        System.out.println("== 环境自检 ==");
        check("platform() 非空", EnvironmentCheck.platform() != null
                && !EnvironmentCheck.platform().isEmpty());
        check("privilege() 有结论", EnvironmentCheck.privilege() != null
                && !EnvironmentCheck.privilege().isEmpty());
        System.out.println("  平台/权限: " + EnvironmentCheck.platform() + " | "
                + EnvironmentCheck.privilege());

        EnvironmentCheck.Capture capture = EnvironmentCheck.capture(80);
        check("capture() 返回结论且不抛异常", capture != null
                && capture.kind() != null && !capture.kind().isEmpty());
        System.out.println("  抓包探测: " + capture.kind() + "｜" + capture.detail());

        String fw = EnvironmentCheck.firewallProbe();
        check("firewallProbe() 有结论", fw != null && !fw.isEmpty());
        System.out.println("  防火墙探测: " + fw);

        check("conclusion 能分清可封禁/仅告警/无真实抓包",
                EnvironmentCheck.conclusion("npcap", true, true, false).contains("可封禁")
                        && EnvironmentCheck.conclusion("npcap", true, false, false).contains("仅告警")
                        && EnvironmentCheck.conclusion("sim（模拟流量）", false, true, false)
                                .contains("模拟"));
    }

    // ------------------------------------------------------------ 入向过滤基础

    private static void testLocalAddresses() throws Exception {
        System.out.println("== 本机地址（入向过滤用）==");
        Set<String> local = new HashSet<>();
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            for (InetAddress addr : Collections.list(nic.getInetAddresses())) {
                String norm = NetUtil.normIp(addr.getHostAddress());
                if (norm != null) {
                    local.add(norm);
                }
            }
        }
        check("能取到本机地址", !local.isEmpty());
        check("8.8.8.8 不是本机地址", !local.contains("8.8.8.8"));
        System.out.println("  本机地址: " + local);
    }

    // ------------------------------------------------------------ 加固回归（审计修复项）

    private static void testHardening() throws Exception {
        System.out.println("== 加固回归（审计修复项）==");

        // #7：JSON 深度限制——超深嵌套必须是可捕获的异常，而不是 StackOverflowError 崩 JVM
        StringBuilder okDeep = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            okDeep.append('[');
        }
        for (int i = 0; i < 30; i++) {
            okDeep.append(']');
        }
        check("30 层嵌套正常解析", Json.parse(okDeep.toString()) instanceof List);

        StringBuilder bomb = new StringBuilder();
        for (int i = 0; i < 100_000; i++) {
            bomb.append('[');
        }
        try {
            Json.parse(bomb.toString());
            check("10 万层嵌套被拒绝（竟然没抛异常）", false);
        } catch (IllegalArgumentException e) {
            check("10 万层嵌套被拒绝且不是 StackOverflowError", true);
        } catch (Throwable t) {
            check("10 万层嵌套抛 " + t.getClass().getSimpleName() + "（应为 IllegalArgumentException）", false);
        }

        // #6：banned 条目上限
        List<Object> huge = new ArrayList<>();
        for (int i = 0; i < ConfigStore.MAX_BANNED + 50; i++) {
            huge.add("host" + i + ".example");
        }
        check("banned 上限 " + ConfigStore.MAX_BANNED + " 条生效",
                ConfigStore.normalizeBanned(huge).size() == ConfigStore.MAX_BANNED);
        check("字面量 IP 解析为 1 条",
                DDoSMonitor.resolveEntry("8.8.8.8").equals(List.of("8.8.8.8")));
        check("非法条目解析为空", DDoSMonitor.resolveEntry("not a host").isEmpty());

        // #11：配置原子写入：写完后不留 .tmp，内容可读回
        Path dir = Files.createTempDirectory("ddos-atomic");
        Path cfg = dir.resolve("monitor_config.json");
        LinkedHashMap<String, Object> conf = ConfigStore.defaults();
        check("原子保存成功", ConfigStore.save(cfg, conf));
        check("保存后内容可读回", Json.parseFile(cfg) instanceof Map);
        try (java.util.stream.Stream<Path> stream = Files.list(dir)) {
            check("目录中不残留 .tmp", stream
                    .noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }
        Files.deleteIfExists(cfg);
        Files.deleteIfExists(dir);

        // #12：netsh 规则名里的 PID 归属解析
        check("netsh 规则名 PID 可解析",
                "4242".equals(Firewall.ruleOwnerPid("DDoS_Block_4242_1.2.3.4")));
        check("旧格式规则名视为无主（PID=null）",
                Firewall.ruleOwnerPid("DDoS_Block_1.2.3.4") == null);

        // #1：抓包线程存活探测——看护线程靠它发现“静默死亡”
        SimSource sim = new SimSource(80, "127.0.0.1", 10, 20, 0, 0);
        check("未启动时 isAlive()=false", !sim.isAlive());
        sim.start(p -> { });
        check("启动后 isAlive()=true", sim.isAlive());
        sim.stop();
        check("stop() 后 isAlive()=false", !sim.isAlive());

        Thread.UncaughtExceptionHandler old = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            // 自检里故意制造线程死亡，吞掉栈信息
        });
        try {
            SimSource broken = new SimSource(80, "127.0.0.1", 50, 100, 0, 0);
            broken.start(p -> {
                throw new IllegalStateException("self-test: 故意让抓包线程死掉");
            });
            long deadline = System.currentTimeMillis() + 2000;
            while (broken.isAlive() && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            check("抓包线程异常退出后 isAlive()=false（看护可据此重启）", !broken.isAlive());
            broken.stop();
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(old);
        }
    }
}
