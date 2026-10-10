import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * RateCounter 性能基准。
 *
 * <p>复现真实竞争关系：一个线程按目标 pps 模拟抓包（持锁调用 {@code counter.add}），
 * 另一个线程模拟评估循环（每秒抢同一把锁做 evict + global + entries + sort），
 * 逐秒输出「抓包侧最慢 1000 包批次」与「评估侧抢锁等待 / 计算耗时」。</p>
 *
 * <pre>
 * 用法: java -cp out RateCounterBench [源IP数] [每秒包数] [秒数]
 *   java -cp out RateCounterBench 1 5000 6          # 单源 5k pps（生产实际场景）
 *   java -cp out RateCounterBench 200000 300000 8   # 20 万源 IP、30 万 pps（压力场景）
 * </pre>
 */
public final class RateCounterBench {

    private RateCounterBench() {
    }

    public static void main(String[] args) throws Exception {
        int ips = args.length > 0 ? Integer.parseInt(args[0]) : 200_000;
        int pps = args.length > 1 ? Integer.parseInt(args[1]) : 300_000;
        int seconds = args.length > 2 ? Integer.parseInt(args[2]) : 6;
        int window = 3;

        String[] pool = new String[Math.max(1, ips)];
        Random rnd = new Random(42);
        for (int i = 0; i < pool.length; i++) {
            pool[i] = "10." + ((i >> 16) & 0xFF) + "." + ((i >> 8) & 0xFF) + "." + (i & 0xFF);
        }

        final RateCounter counter = new RateCounter(window);
        final Object lock = new Object();                       // 等价 DDoSMonitor.lock
        final long baseSec = 1_700_000_000L;

        final List<String> evalLog = new ArrayList<>();
        final boolean[] stop = {false};
        final long[] waitMax = {0};
        final long[] workMax = {0};
        final long[] simSec = {baseSec};                        // 模拟时钟，供评估侧淘汰使用

        Thread evaluator = new Thread(() -> {
            while (!stop[0]) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    return;
                }
                if (stop[0]) {
                    return;
                }
                long t0 = System.nanoTime();
                long t1;
                long activeIps;
                synchronized (lock) {
                    t1 = System.nanoTime();
                    counter.evict(simSec[0]);
                    RateCounter.Global g = counter.global();
                    List<Map.Entry<String, RateCounter.IpCount>> entries = counter.entries();
                    entries.sort((a, b) -> Long.compare(b.getValue().bytes, a.getValue().bytes));
                    long sink = 0;
                    for (int i = 0; i < Math.min(5, entries.size()); i++) {
                        sink += entries.get(i).getValue().bytes;
                    }
                    if (sink == Long.MIN_VALUE || g.packets() < 0) {
                        System.out.print("");
                    }
                    activeIps = counter.activeIps();
                }
                long t2 = System.nanoTime();
                long wait = (t1 - t0) / 1_000_000;
                long work = (t2 - t1) / 1_000_000;
                if (wait > waitMax[0]) {
                    waitMax[0] = wait;
                }
                if (work > workMax[0]) {
                    workMax[0] = work;
                }
                synchronized (evalLog) {
                    evalLog.add(String.format("     评估 tick: 抢锁等待 %d ms，计算 %d ms，活跃IP %d",
                            wait, work, activeIps));
                }
            }
        }, "evaluator");
        evaluator.setDaemon(true);
        evaluator.start();

        long totalPackets = (long) pps * seconds;
        long sent = 0;
        long feedStart = System.nanoTime();
        long addNanos = 0;
        long addPackets = 0;
        long worstBurstNsPerPacket = 0;
        int lastSecond = -1;
        long secondPackets = 0;
        long secondWorstBurst = 0;

        System.out.println("=== RateCounter 基准 ===");
        System.out.printf("源 IP 数=%d  目标 pps=%d  秒数=%d  窗口=%d%n", pool.length, pps, seconds, window);

        while (true) {
            double elapsed = (System.nanoTime() - feedStart) / 1_000_000_000.0;
            int secIndex = (int) elapsed;
            if (secIndex >= seconds) {
                break;
            }
            simSec[0] = baseSec + secIndex;
            long shouldHaveSent = (long) (elapsed * pps);
            long burstStart = System.nanoTime();
            int burst = 0;
            while (sent < shouldHaveSent && sent < totalPackets) {
                long ts = (baseSec + secIndex) * 1000L + (sent % 1000);
                String ip = pool[rnd.nextInt(pool.length)];
                synchronized (lock) {                            // 等价 handlePacket 持锁
                    counter.add(ip, ts, 100, (sent & 7) == 0, 50, "TCP");
                }
                sent++;
                burst++;
                secondPackets++;
            }
            if (burst > 0) {
                long burstNanos = System.nanoTime() - burstStart;  // 纯 add()，不含限速 sleep
                addNanos += burstNanos;
                addPackets += burst;
                long nsPerPacket = burstNanos / burst;
                if (nsPerPacket > worstBurstNsPerPacket) {
                    worstBurstNsPerPacket = nsPerPacket;
                }
                if (burstNanos > secondWorstBurst) {
                    secondWorstBurst = burstNanos;
                }
            }
            if (secIndex != lastSecond) {
                if (lastSecond >= 0) {
                    System.out.printf("  第 %d 秒: 喂入 %d 包，最慢单次突发 %.2f ms / %d 包，活跃IP %d%n",
                            lastSecond, secondPackets, secondWorstBurst / 1e6,
                            Math.max(1, pps / 1000), counter.activeIps());
                }
                lastSecond = secIndex;
                secondPackets = 0;
                secondWorstBurst = 0;
            }
            Thread.sleep(1);
        }
        long feedNanos = System.nanoTime() - feedStart;
        System.out.printf("  第 %d 秒: 喂入 %d 包，最慢单次突发 %.2f ms，活跃IP %d%n",
                lastSecond, secondPackets, secondWorstBurst / 1e6, counter.activeIps());

        stop[0] = true;
        evaluator.interrupt();
        evaluator.join(3000);
        synchronized (evalLog) {
            for (String line : evalLog) {
                System.out.println(line);
            }
        }

        System.out.printf("抓包侧：喂入 %d 包 / %.2f s → 实际 %.0f pkt/s；纯 add() 平均 %.0f ns/包；"
                        + "含淘汰的突发最差 %d ns/包%n",
                sent, feedNanos / 1e9, sent / (feedNanos / 1e9),
                addPackets == 0 ? 0 : (double) addNanos / addPackets, worstBurstNsPerPacket);
        System.out.printf("评估侧：抢锁等待最大 %d ms，计算最大 %d ms%n", waitMax[0], workMax[0]);
        System.out.printf("计数器状态：活跃 IP=%d，秒桶=%d%n", counter.activeIps(), counter.bucketCount());
    }
}
