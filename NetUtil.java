import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Locale;

/**
 * 地址判定与格式化工具。
 *
 * <p>对应 Python 版的 parse_ip / is_internal / human_bytes / now_str。
 * 地址分类不再用前缀字符串匹配，而是显式按 CIDR 判定，
 * 覆盖 100.64.0.0/10(CGNAT)、198.18.0.0/15、192.0.2.0/24 等保留段。</p>
 */
public final class NetUtil {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private NetUtil() {
    }

    public static String nowStr() {
        return LocalDateTime.now().format(TIMESTAMP);
    }

    /** 人类可读的字节数，与 Python 版 human_bytes 输出格式一致。 */
    public static String humanBytes(double n) {
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        for (String unit : units) {
            if (n < 1024) {
                return String.format(Locale.ROOT, "%.2f %s", n, unit);
            }
            n /= 1024;
        }
        return String.format(Locale.ROOT, "%.2f PB", n);
    }

    /**
     * 解析字面量 IP，绝不做 DNS 解析；IPv4-mapped 的 IPv6 归一化为 IPv4。
     *
     * @return 解析失败返回 null，便于区分“写错了”和“是内网地址”
     */
    public static InetAddress parseIp(String text) {
        if (text == null) {
            return null;
        }
        String s = text.trim();
        if (s.isEmpty()) {
            return null;
        }
        if (s.length() > 2 && s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length() - 1);
        }
        int scope = s.indexOf('%');
        if (scope >= 0) {
            s = s.substring(0, scope);
        }
        if (s.indexOf(':') >= 0) {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex && c != ':' && c != '.') {
                    return null;                     // 不是 IPv6 字面量，避免 InetAddress 触发 DNS
                }
            }
            try {
                InetAddress addr = InetAddress.getByName(s);
                if (addr instanceof Inet6Address v6) {
                    byte[] raw = v6.getAddress();
                    if (isV4Mapped(raw)) {
                        byte[] v4 = new byte[4];
                        System.arraycopy(raw, 12, v4, 0, 4);
                        return InetAddress.getByAddress(v4);
                    }
                }
                return addr;
            } catch (UnknownHostException e) {
                return null;
            }
        }
        return parseIpv4Literal(s);
    }

    private static InetAddress parseIpv4Literal(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            for (int j = 0; j < part.length(); j++) {
                char c = part.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
            }
            int v = Integer.parseInt(part);
            if (v > 255) {
                return null;
            }
            bytes[i] = (byte) v;
        }
        try {
            return InetAddress.getByAddress(bytes);   // 长度 4 → Inet4Address，不查 DNS
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean isV4Mapped(byte[] b) {
        if (b.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return b[10] == (byte) 0xFF && b[11] == (byte) 0xFF;
    }

    /** 归一化后的字符串形式，用作封禁表/本机地址集合的键；非法输入返回 null。 */
    public static String normIp(String text) {
        InetAddress addr = parseIp(text);
        if (addr == null) {
            return null;
        }
        if (addr instanceof Inet6Address) {
            // Java 的 getHostAddress() 不做压缩，这里压成 2001:db8::1 这种形式，
            // 与 Python 的 str(addr) 一致（也保证同一地址的不同写法归一化结果相同）
            return PcapParser.ipv6String(addr.getAddress(), 0);
        }
        String s = addr.getHostAddress();
        int scope = s.indexOf('%');
        return scope >= 0 ? s.substring(0, scope) : s;
    }

    /** 判断地址是否“非全球可路由”（内网、环回、链路本地、保留、组播、未指定、非法值）。 */
    public static boolean isInternal(String ip) {
        InetAddress addr = parseIp(ip);
        return addr == null || !isGlobal(addr);
    }

    /**
     * 默认路由出口网卡的名称（跨平台；取不到返回 null）。
     *
     * <p>做法：UDP connect 一个公网地址（不会真的发包），让操作系统按路由表选出本地出口地址，
     * 再反查拥有该地址的网卡。这样能避开 Hyper-V / VPN TAP / docker0 这类 up 但不承载
     * 默认流量的适配器——选错网卡的症状正是“一个包都收不到”。</p>
     */
    public static String defaultInterfaceName() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 53);
            InetAddress local = socket.getLocalAddress();
            if (local == null || local.isAnyLocalAddress()) {
                return null;
            }
            for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nic.isUp() || nic.isLoopback()) {
                    continue;
                }
                for (InetAddress addr : Collections.list(nic.getInetAddresses())) {
                    if (addr.equals(local)) {
                        return nic.getDisplayName();
                    }
                }
            }
        } catch (Exception ignored) {
            // 取不到就由调用方回退
        }
        return null;
    }

    /**
     * 封禁下发的底线校验：必须是能解析的地址，且不是未指定 / 组播 / 广播 / 环回。
     *
     * <p>内网与其它保留地址<b>不再</b>在这里一刀切拒绝——是否允许封禁内网地址由
     * {@link Firewall} 的 allow_internal 策略决定；本机自身地址由受保护集合单独拦截。</p>
     */
    public static boolean isBlockableAddress(String ip) {
        InetAddress addr = parseIp(ip);
        if (addr == null || addr.isAnyLocalAddress() || addr.isMulticastAddress()
                || addr.isLoopbackAddress()) {
            return false;
        }
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            int b0 = b[0] & 0xFF;
            int b1 = b[1] & 0xFF;
            int b2 = b[2] & 0xFF;
            int b3 = b[3] & 0xFF;
            if (b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255) {
                return false;                            // 255.255.255.255 广播
            }
        }
        return true;
    }

    public static boolean isGlobal(InetAddress addr) {
        byte[] b = addr.getAddress();
        return b.length == 4 ? isGlobalV4(b) : isGlobalV6(b);
    }

    private static boolean isGlobalV4(byte[] b) {
        int b0 = b[0] & 0xFF;
        int b1 = b[1] & 0xFF;
        int b2 = b[2] & 0xFF;
        if (b0 == 0) {
            return false;                                   // 0.0.0.0/8
        }
        if (b0 == 10) {
            return false;                                   // 10.0.0.0/8
        }
        if (b0 == 100 && b1 >= 64 && b1 <= 127) {
            return false;                                   // 100.64.0.0/10 (CGNAT)
        }
        if (b0 == 127) {
            return false;                                   // 127.0.0.0/8
        }
        if (b0 == 169 && b1 == 254) {
            return false;                                   // 169.254.0.0/16
        }
        if (b0 == 172 && b1 >= 16 && b1 <= 31) {
            return false;                                   // 172.16.0.0/12
        }
        if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) {
            return false;                                   // 192.0.0.0/24, 192.0.2.0/24
        }
        if (b0 == 192 && b1 == 168) {
            return false;                                   // 192.168.0.0/16
        }
        if (b0 == 198 && (b1 == 18 || b1 == 19)) {
            return false;                                   // 198.18.0.0/15
        }
        if (b0 == 198 && b1 == 51 && b2 == 100) {
            return false;                                   // 198.51.100.0/24
        }
        if (b0 == 203 && b1 == 0 && b2 == 113) {
            return false;                                   // 203.0.113.0/24
        }
        return b0 < 224;                                    // 224.0.0.0/4 组播、240.0.0.0/4 保留、广播
    }

    private static boolean isGlobalV6(byte[] b) {
        boolean allZero = true;
        for (byte x : b) {
            if (x != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            return false;                                   // ::
        }
        boolean loopback = true;
        for (int i = 0; i < 15; i++) {
            if (b[i] != 0) {
                loopback = false;
                break;
            }
        }
        if (loopback && b[15] == 1) {
            return false;                                   // ::1
        }
        int b0 = b[0] & 0xFF;
        int b1 = b[1] & 0xFF;
        if ((b0 & 0xFE) == 0xFC) {
            return false;                                   // fc00::/7 ULA
        }
        if (b0 == 0xFE && (b1 & 0xC0) == 0x80) {
            return false;                                   // fe80::/10 链路本地
        }
        if (b0 == 0xFF) {
            return false;                                   // ff00::/8 组播
        }
        if (b0 == 0x20 && b1 == 0x01 && (b[2] & 0xFF) == 0x0D && (b[3] & 0xFF) == 0xB8) {
            return false;                                   // 2001:db8::/32 文档段
        }
        if (b0 == 0x01 && b1 == 0x00) {
            boolean rest = true;
            for (int i = 2; i < 8; i++) {
                if (b[i] != 0) {
                    rest = false;
                    break;
                }
            }
            if (rest) {
                return false;                               // 100::/64 discard-only
            }
        }
        return true;
    }
}
