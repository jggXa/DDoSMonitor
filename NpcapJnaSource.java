import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 通过 JNA 调用 Npcap / libpcap（wpcap.dll 或 libpcap.so）实时抓包。
 *
 * <p>这是与 Python 版 Scapy + Npcap 最接近的路径。编译需要 lib/jna.jar
 * （build.cmd 会用 curl 自动下载），运行时需要管理员/root 权限。</p>
 *
 * <p>本类只在 lib/jna.jar 存在时才参与编译；主程序通过反射加载它，
 * 因此缺少该 jar 时其余功能仍可正常编译运行。</p>
 */
public final class NpcapJnaSource implements PacketSource {

    /** wpcap 的函数子集。 */
    public interface Wpcap extends Library {

        Wpcap INSTANCE = Native.load(libraryName(), Wpcap.class);

        Pointer pcap_open_live(String device, int snaplen, int promisc, int toMs, byte[] errbuf);

        int pcap_datalink(Pointer handle);

        int pcap_compile(Pointer handle, BpfProgram program, String filter, int optimize, int netmask);

        int pcap_setfilter(Pointer handle, BpfProgram program);

        void pcap_freecode(BpfProgram program);

        int pcap_next_ex(Pointer handle, PointerByReference header, PointerByReference data);

        String pcap_lookupdev(byte[] errbuf);

        int pcap_findalldevs(PointerByReference devices, byte[] errbuf);

        void pcap_freealldevs(Pointer devices);

        String pcap_geterr(Pointer handle);

        void pcap_close(Pointer handle);
    }

    /** struct pcap_if { struct pcap_if *next; char *name; char *description;
     *  struct pcap_addr *addresses; bpf_u_int32 flags; } */
    public static class PcapIf extends Structure {
        public Pointer next;
        public String name;
        public String description;
        public Pointer addresses;
        public int flags;

        public PcapIf() {
            super();
        }

        public PcapIf(Pointer p) {
            super(p);
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("next", "name", "description", "addresses", "flags");
        }
    }

    /** struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; } */
    public static class BpfProgram extends Structure {
        public int bf_len;
        public Pointer bf_insns;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("bf_len", "bf_insns");
        }
    }

    /** struct pcap_pkthdr { struct timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; } */
    public static class PcapPkthdr extends Structure {
        public NativeLong tv_sec;
        public NativeLong tv_usec;
        public int caplen;
        public int len;

        public PcapPkthdr() {
            super();
        }

        public PcapPkthdr(Pointer p) {
            super(p);
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("tv_sec", "tv_usec", "caplen", "len");
        }
    }

    private final int port;
    private final String requestedIface;

    private volatile Pointer handle;
    private volatile boolean running;
    private volatile String device = "";
    private volatile int linkType = PcapParser.DLT_EN10MB;
    private volatile boolean filtered;

    // 抓包层计数：区分“Npcap 没给包”与“给了包但被跳过/过滤”
    private final AtomicLong calls = new AtomicLong();
    private final AtomicLong delivered = new AtomicLong();
    private final AtomicLong timeouts = new AtomicLong();
    private final AtomicLong errors = new AtomicLong();
    private final AtomicLong zeroLen = new AtomicLong();
    private final AtomicLong wrongPort = new AtomicLong();
    private final AtomicLong parseFailed = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private volatile String lastPacket = "";

    private Thread thread;

    public NpcapJnaSource(int port, String iface) {
        this.port = port;
        this.requestedIface = iface;
    }

    private static String libraryName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("win") ? "wpcap" : "pcap";
    }

    /** 供反射加载失败时给出提示。 */
    public static boolean libPresent() {
        try {
            Class.forName("com.sun.jna.Native");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public void start(Consumer<PacketInfo> handler) throws Exception {
        byte[] errbuf = new byte[256];
        String target = requestedIface;
        if (target == null || target.isEmpty()) {
            target = firstDevice();
        }
        if (target == null || target.isEmpty()) {
            target = Wpcap.INSTANCE.pcap_lookupdev(errbuf);
        }
        if (target == null || target.isEmpty()) {
            throw new IllegalStateException("找不到可用网卡: " + cString(errbuf)
                    + "（可用 --iface 指定，Npcap 设备名形如 \\Device\\NPF_{...}）");
        }
        Pointer h = Wpcap.INSTANCE.pcap_open_live(target, 65535, 1, 200, errbuf);
        if (h == null) {
            String detail = cString(errbuf);
            List<String> devices = listDevices();
            throw new IllegalStateException("pcap_open_live 失败: " + detail
                    + "（请以管理员/root 运行，并确认已安装 Npcap）"
                    + (devices.isEmpty() ? "" : "；可用网卡: " + String.join(" | ", devices)));
        }
        handle = h;
        device = target;
        linkType = Wpcap.INSTANCE.pcap_datalink(h);

        BpfProgram program = new BpfProgram();
        if (Wpcap.INSTANCE.pcap_compile(h, program, "dst port " + port, 1, 0xFFFFFF00) == 0) {
            filtered = Wpcap.INSTANCE.pcap_setfilter(h, program) == 0;
            Wpcap.INSTANCE.pcap_freecode(program);
        }

        running = true;
        thread = new Thread(() -> loop(handler), "npcap-source");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop(Consumer<PacketInfo> handler) {
        // 整个循环体包在 try/finally 里：无论因为驱动错误、rc<0、handler 抛异常还是
        // 正常停止而退出，都必须把 running 置回 false。否则线程已经死了、running 仍是
        // true，DDoSMonitor 会以为抓包仍在工作而每秒空转（[健康] 窗口包数 0），
        // 一次驱动错误就能让监控静默失效。
        try {
            while (running) {
                Pointer h = handle;
                if (h == null) {
                    return;
                }
                calls.incrementAndGet();
                PointerByReference headerRef = new PointerByReference();
                PointerByReference dataRef = new PointerByReference();
                int rc;
                try {
                    rc = Wpcap.INSTANCE.pcap_next_ex(h, headerRef, dataRef);
                } catch (Throwable t) {
                    if (running) {
                        System.out.println("[错误] 抓包失败: " + t.getMessage());
                        System.out.flush();
                    }
                    return;
                }
                if (rc == 0) {
                    timeouts.incrementAndGet();
                    continue;                              // 超时（200ms），回到循环顶部检查停止标志
                }
                if (rc < 0) {
                    errors.incrementAndGet();
                    if (running) {
                        String err;
                        try {
                            err = Wpcap.INSTANCE.pcap_geterr(h);
                        } catch (Throwable t) {
                            err = t.toString();
                        }
                        System.out.println("[错误] pcap_next_ex 返回 " + rc + ": " + err);
                        System.out.flush();
                    }
                    return;
                }
                Pointer headerPtr = headerRef.getValue();
                Pointer dataPtr = dataRef.getValue();
                if (headerPtr == null || dataPtr == null) {
                    parseFailed.incrementAndGet();
                    continue;
                }
                PcapPkthdr header = new PcapPkthdr(headerPtr);
                header.read();
                delivered.incrementAndGet();
                int caplen = header.caplen;
                if (caplen <= 0 || caplen > 262144) {
                    zeroLen.incrementAndGet();             // 结构体错位/驱动异常会在这里暴涨
                    continue;
                }
                byte[] data = dataPtr.getByteArray(0, caplen);
                double ts = header.tv_sec.longValue() + header.tv_usec.longValue() / 1_000_000.0;
                int frameLen = Math.max(header.len, caplen);
                PacketInfo info = PcapParser.parse(data, 0, caplen, linkType, ts, frameLen);
                if (info == null) {
                    parseFailed.incrementAndGet();
                    continue;
                }
                if (info.dstPort != port) {
                    wrongPort.incrementAndGet();           // BPF 未生效时会大量出现
                    continue;
                }
                accepted.incrementAndGet();
                lastPacket = "caplen=" + caplen + " len=" + header.len
                        + " " + info.proto + " " + info.srcIp + "->" + info.dstIp + ":" + info.dstPort;
                handler.accept(info);
            }
        } finally {
            running = false;                               // 让 isAlive() 立刻反映“抓包已停”
        }
    }

    /** 抓包线程是否仍在工作；线程异常退出后为 false，DDoSMonitor 会据此重启抓包。 */
    @Override
    public boolean isAlive() {
        Thread t = thread;
        return running && t != null && t.isAlive();
    }

    @Override
    public String statsLine() {
        return "Npcap[调用=" + calls.get() + " 收包=" + delivered.get()
                + " 超时=" + timeouts.get() + " 错误=" + errors.get()
                + " 零长=" + zeroLen.get() + " 非目标端口=" + wrongPort.get()
                + " 解析失败=" + parseFailed.get() + " 已计数=" + accepted.get()
                + (lastPacket.isEmpty() ? "" : " 最近包[" + lastPacket + "]") + "]";
    }

    @Override
    public void stop() {
        running = false;
        // 先让抓包线程自己退出（pcap_next_ex 每 200ms 返回一次超时），
        // 再关闭句柄：否则线程可能拿着已释放的指针调 pcap_geterr，触发非法内存访问。
        Thread t = thread;
        if (t != null && t != Thread.currentThread()) {
            try {
                t.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (t.isAlive()) {
                // 线程可能正卡在驱动调用里（GC 停顿 / 页面换入 / 驱动卡顿），再给 5 秒
                System.out.println("[警告] 抓包线程未在 2s 内退出，再等 5s 后才会关闭句柄"
                        + "（避免 use-after-free）...");
                System.out.flush();
                try {
                    t.join(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (t.isAlive()) {
                // 此时若 pcap_close，抓包线程下一轮 pcap_next_ex/pcap_geterr 就会访问
                // 已释放的 pcap_t → SIGSEGV（JVM 直接崩溃，正是退出路径上最常见的崩溃）。
                // 进程马上就结束了，句柄交给操作系统回收，宁可漏一次 close 也不能崩。
                System.out.println("[警告] 抓包线程仍未退出，跳过 pcap_close 以避免崩溃。");
                System.out.flush();
                handle = null;
                return;
            }
        }
        Pointer h = handle;
        handle = null;
        if (h != null) {
            try {
                Wpcap.INSTANCE.pcap_close(h);
            } catch (Throwable ignored) {
                // 忽略关闭异常
            }
        }
    }

    @Override
    public String describe() {
        return "Npcap 实时抓包（网卡 " + device + "，DLT=" + linkType
                + (filtered ? "，BPF 过滤器 dst port " + port + " 已生效" : "，BPF 未生效，退化为用户态过滤")
                + "）";
    }

    private static String cString(byte[] buf) {
        int end = 0;
        while (end < buf.length && buf[end] != 0) {
            end++;
        }
        // pcap 的错误缓冲区是本地 ANSI 编码（中文 Windows 为 GBK），不能用 UTF-8 解
        java.nio.charset.Charset charset = java.nio.charset.Charset.defaultCharset();
        try {
            charset = java.nio.charset.Charset.forName(Native.getDefaultStringEncoding());
        } catch (Throwable ignored) {
            // 取不到就沿用默认字符集
        }
        String text = new String(buf, 0, end, charset);
        if (text.indexOf('\uFFFD') >= 0) {
            text = new String(buf, 0, end, java.nio.charset.StandardCharsets.UTF_8);
        }
        return text;
    }

    /** 枚举网卡名（按 pcap_findalldevs 顺序）。 */
    public static List<String> listDevices() {
        List<String> names = new ArrayList<>();
        PointerByReference ref = new PointerByReference();
        byte[] errbuf = new byte[256];
        if (Wpcap.INSTANCE.pcap_findalldevs(ref, errbuf) != 0) {
            return names;
        }
        Pointer head = ref.getValue();
        try {
            Pointer cursor = head;
            for (int guard = 0; cursor != null && guard < 256; guard++) {
                PcapIf device = new PcapIf(cursor);
                device.read();
                String name = device.name;
                if (name != null && !name.isEmpty()) {
                    String desc = device.description;
                    names.add(desc == null || desc.isEmpty() ? name : name + " — " + desc);
                }
                cursor = device.next;
            }
        } finally {
            if (head != null) {
                Wpcap.INSTANCE.pcap_freealldevs(head);
            }
        }
        return names;
    }

    private static String firstDevice() {
        PointerByReference ref = new PointerByReference();
        byte[] errbuf = new byte[256];
        if (Wpcap.INSTANCE.pcap_findalldevs(ref, errbuf) != 0) {
            return null;
        }
        String target = defaultRouteDisplayName();
        Pointer head = ref.getValue();
        String exact = null;
        String prefixed = null;
        String chosen = null;
        String fallback = null;
        try {
            Pointer cursor = head;
            for (int guard = 0; cursor != null && guard < 256; guard++) {
                PcapIf device = new PcapIf(cursor);
                device.read();
                if (device.name != null && !device.name.isEmpty()) {
                    if (fallback == null) {
                        fallback = device.name;
                    }
                    // 注意：libpcap 在 Linux/macOS 上 description 通常是 NULL，
                    // 此时设备名（eth0/en0/any…）才是可比对、可判定的依据。
                    String desc = device.description == null
                            ? "" : device.description.toLowerCase(Locale.ROOT);
                    String label = desc.isEmpty()
                            ? device.name.toLowerCase(Locale.ROOT) : desc;
                    // 优先级 1/2：与“默认路由所在网卡”同名（Hyper-V、WAN Miniport、
                    // VPN TAP、docker0 这类 up 但不同路由的适配器会被排除在外）
                    if (target != null) {
                        if (exact == null && label.equals(target)) {
                            exact = device.name;
                        }
                        if (prefixed == null && label.startsWith(target)) {
                            prefixed = device.name;
                        }
                    }
                    // 优先级 3：跳过伪适配器后的第一个（前两档都落空时用）
                    if (chosen == null && !isPseudoDevice(label)) {
                        chosen = device.name;
                    }
                }
                cursor = device.next;
            }
        } finally {
            if (head != null) {
                Wpcap.INSTANCE.pcap_freealldevs(head);
            }
        }
        if (exact != null) {
            return exact;
        }
        if (prefixed != null) {
            return prefixed;
        }
        return chosen != null ? chosen : fallback;
    }

    /** 默认路由出口网卡的显示名（小写）；由 {@link NetUtil#defaultInterfaceName()} 提供。 */
    private static String defaultRouteDisplayName() {
        String name = NetUtil.defaultInterfaceName();
        return name == null ? null : name.toLowerCase(Locale.ROOT);
    }

    private static boolean isPseudoDevice(String label) {
        if (label == null || label.isEmpty()) {
            return true;
        }
        String d = label.toLowerCase(Locale.ROOT);
        // Windows 的伪适配器
        if (d.contains("wan miniport") || d.contains("loopback")
                || d.contains("wi-fi direct") || d.contains("bluetooth")
                || d.contains("network monitor")) {
            return true;
        }
        // Linux/macOS 上的非物理设备（description 为空时比对的就是设备名）
        for (String pseudo : new String[]{"any", "lo", "nflog", "nfqueue",
                "bluetooth-monitor", "dbus-system", "dbus-session"}) {
            if (d.equals(pseudo)) {
                return true;
            }
        }
        for (String prefix : new String[]{"virbr", "docker", "veth", "br-", "tun", "tap", "utun"}) {
            if (d.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
