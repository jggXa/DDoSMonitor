import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * 外部抓包工具数据源：启动 dumpcap / tcpdump，把它们写到 stdout 的 pcap 流
 * 直接在 Java 里解析。零第三方依赖，适合没有 Npcap 或不方便用 JNA 的环境。
 */
public final class ExternalPcapSource implements PacketSource {

    private final String tool;
    private final List<String> command;
    private final int port;

    private volatile Process process;
    private volatile boolean running;
    private Thread reader;

    public ExternalPcapSource(String tool, int port, String iface) {
        this.tool = tool;
        this.port = port;
        List<String> cmd = new ArrayList<>();
        cmd.add(tool);
        if (tool.toLowerCase(Locale.ROOT).contains("dumpcap")) {
            cmd.addAll(Arrays.asList("-q", "-i", iface, "-f", "dst port " + port, "-w", "-"));
        } else {
            cmd.addAll(Arrays.asList("-i", iface, "-s", "0", "-U", "-w", "-",
                    "dst port " + port));
        }
        this.command = cmd;
    }

    /** 查找可用的抓包工具，返回可执行文件路径；都找不到返回 null。 */
    public static String findTool() {
        String resolved = Firewall.locate("dumpcap");
        if (resolved == null) {
            resolved = Firewall.locate("tcpdump");
        }
        if (resolved != null) {
            return resolved;
        }
        String[] guesses = {
            "C:\\Program Files\\Wireshark\\dumpcap.exe",
            "C:\\Program Files (x86)\\Wireshark\\dumpcap.exe",
            "/usr/sbin/tcpdump", "/usr/bin/tcpdump",
            "/usr/sbin/dumpcap", "/usr/bin/dumpcap",
            "/opt/homebrew/bin/tcpdump", "/opt/homebrew/sbin/dumpcap"
        };
        for (String guess : guesses) {
            Path p = Paths.get(guess);
            if (Files.isRegularFile(p)) {
                return guess;
            }
        }
        return null;
    }

    @Override
    public void start(Consumer<PacketInfo> handler) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        process = pb.start();
        running = true;
        reader = new Thread(() -> {
            try {
                readPcapStream(process.getInputStream(), handler);
                if (running) {
                    System.out.println("[错误] 抓包流已结束（" + tool + " 是否已退出？）");
                    System.out.flush();
                }
            } catch (Exception e) {
                if (running) {
                    System.out.println("[错误] 抓包流已中断: " + e.getMessage());
                    System.out.flush();
                }
            } finally {
                // 读取线程无论因何结束（EOF、流畸形、进程被杀），都要把 running 置 false，
                // 否则 isAlive() 会一直为 true，DDoSMonitor 无从发现“抓包已死”。
                running = false;
            }
        }, "pcap-reader");
        reader.setDaemon(true);
        reader.start();
        Thread.sleep(300);
        if (!process.isAlive()) {
            running = false;
            int code = process.exitValue();
            throw new IllegalStateException("抓包工具立即退出（exit=" + code
                    + "），请检查是否以管理员/root 运行、接口名与过滤器是否正确");
        }
    }

    private void readPcapStream(InputStream in, Consumer<PacketInfo> handler) throws IOException {
        DataInputStream din = new DataInputStream(new BufferedInputStream(in, 1 << 16));
        byte[] global = new byte[24];
        din.readFully(global);
        long magic = u32be(global, 0);
        boolean little;
        boolean nano;
        if (magic == 0xA1B2C3D4L) {
            little = false;
            nano = false;
        } else if (magic == 0xD4C3B2A1L) {
            little = true;
            nano = false;
        } else if (magic == 0xA1B23C4DL) {
            little = false;
            nano = true;
        } else if (magic == 0x4D3CB2A1L) {
            little = true;
            nano = true;
        } else {
            throw new IOException("无法识别的 pcap 魔数: 0x" + Long.toHexString(magic));
        }
        int linkType = (int) u32(global, 20, little);
        byte[] record = new byte[16];
        while (running) {
            try {
                din.readFully(record);
            } catch (EOFException eof) {
                return;
            }
            long tsSec = u32(record, 0, little);
            long tsFrac = u32(record, 4, little);
            long inclLen = u32(record, 8, little);
            long origLen = u32(record, 12, little);
            if (inclLen <= 0 || inclLen > 262144) {
                // 越界长度通常意味着流已畸形（工具异常退出 / 编码错误）：
                // 抛异常而不是静默 return，让上层日志留下证据并触发看护重启。
                throw new IOException("pcap 记录长度非法: " + inclLen + "（流可能已损坏）");
            }
            byte[] data = new byte[(int) inclLen];
            din.readFully(data);
            double ts = tsSec + (nano ? tsFrac / 1_000_000_000.0 : tsFrac / 1_000_000.0);
            int frameLen = origLen > 0 ? (int) Math.min(origLen, Integer.MAX_VALUE) : data.length;
            PacketInfo info = PcapParser.parse(data, 0, data.length, linkType, ts, frameLen);
            if (info != null && info.dstPort == port) {
                handler.accept(info);
            }
        }
    }

    private static long u32be(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static long u32(byte[] b, int off, boolean little) {
        if (little) {
            return ((long) (b[off + 3] & 0xFF) << 24) | ((b[off + 2] & 0xFF) << 16)
                    | ((b[off + 1] & 0xFF) << 8) | (b[off] & 0xFF);
        }
        return u32be(b, off);
    }

    /** 读取线程与抓包进程都还活着才算“在抓包”。 */
    @Override
    public boolean isAlive() {
        Thread r = reader;
        Process p = process;
        return running && r != null && r.isAlive() && p != null && p.isAlive();
    }

    @Override
    public void stop() {
        running = false;
        Process p = process;
        if (p != null) {
            p.destroy();
            try {
                if (!p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public String describe() {
        return "外部抓包工具 " + tool + "（" + String.join(" ", command) + "）";
    }
}
