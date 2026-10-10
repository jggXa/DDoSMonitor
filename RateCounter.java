import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 滑动窗口速率统计：按秒分桶。
 *
 * <p>对应 Python 版的 {@code ip_records / all_records}（每个包一个元组的双端队列），
 * 但每包只做几次整数加法、不分配逐包对象，评估时也不需要重新扫描窗口内的所有包：
 * 全局量是 O(窗口秒数)，每个 IP 的量靠增量维护的 totals 表 O(活跃IP数)。</p>
 *
 * <p>窗口语义与原版一致：统计最近 {@code window} 秒
 * （即丢弃 {@code 秒 <= now - window} 的桶）。</p>
 */
public final class RateCounter {

    /** 单个 IP 的窗口计数。 */
    public static final class IpCount {
        public long packets;
        public long bytes;
        public long syns;
        public long payloadBytes;
    }

    /** 窗口内的全局统计快照（record，构造后不再变化）。 */
    public record Global(long packets, long bytes, Map<String, Integer> protos) {
    }

    private static final class Second {
        final long sec;
        final Map<String, IpCount> byIp = new HashMap<>();
        final Map<String, Integer> protos = new HashMap<>();
        long packets;
        long bytes;

        Second(long sec) {
            this.sec = sec;
        }
    }

    private final ArrayDeque<Second> seconds = new ArrayDeque<>();
    private final Map<String, IpCount> totals = new HashMap<>();
    private Second current = new Second(Long.MIN_VALUE);
    private int window;
    /** 上一次尝试淘汰的秒；用于把淘汰限制为“每秒最多一次”。 */
    private long lastEvictSec = Long.MIN_VALUE;

    public RateCounter(int window) {
        this.window = Math.max(1, window);
    }

    /** 运行中修改滑动窗口（调试命令 set window）。 */
    public void setWindow(int window) {
        this.window = Math.max(1, window);
    }

    public int window() {
        return window;
    }

    /** 记一个包。 */
    public void add(String ip, long tsMillis, int length, boolean syn, int payload, String proto) {
        long sec = Math.floorDiv(tsMillis, 1000L);
        Second bucket = bucketFor(sec);

        IpCount total = totals.computeIfAbsent(ip, key -> new IpCount());
        IpCount local = bucket.byIp.computeIfAbsent(ip, key -> new IpCount());
        total.packets++;
        total.bytes += length;
        total.payloadBytes += payload;
        if (syn) {
            total.syns++;
        }
        local.packets++;
        local.bytes += length;
        local.payloadBytes += payload;
        if (syn) {
            local.syns++;
        }

        bucket.packets++;
        bucket.bytes += length;
        if (proto != null) {
            bucket.protos.merge(proto, 1, Integer::sum);
        }
        // 每秒最多“尝试”一次淘汰：避免每包都走一遍淘汰检查（虽然不淘汰时只是 peek 一次）。
        // 仍然保留在抓包路径上而不是只靠评估线程——万一评估线程卡住/挂掉，
        // 窗口也不会无限增长（totals/秒桶 会持续被修剪）。
        if (sec != lastEvictSec) {
            lastEvictSec = sec;
            evict(sec);
        }
    }

    private Second bucketFor(long sec) {
        if (sec == current.sec) {
            return current;
        }
        for (Second s : seconds) {                       // 时间戳轻微乱序时复用已有桶
            if (s.sec == sec) {
                current = s;
                return s;
            }
        }
        Second fresh = new Second(sec);
        seconds.addLast(fresh);
        current = fresh;
        return fresh;
    }

    /** 淘汰过期秒桶，并同步递减 totals。调用方需要 synchronized（与抓包线程一致）。 */
    public void evict(long nowSec) {
        long cutoff = nowSec - window;
        while (!seconds.isEmpty() && seconds.peekFirst().sec <= cutoff) {
            Second old = seconds.pollFirst();
            for (Map.Entry<String, IpCount> e : old.byIp.entrySet()) {
                IpCount total = totals.get(e.getKey());
                if (total == null) {
                    continue;
                }
                IpCount part = e.getValue();
                total.packets -= part.packets;
                total.bytes -= part.bytes;
                total.syns -= part.syns;
                total.payloadBytes -= part.payloadBytes;
                if (total.packets <= 0) {
                    totals.remove(e.getKey());
                }
            }
            if (current == old) {
                current = new Second(Long.MIN_VALUE);
            }
        }
    }

    /** 窗口内的全局统计。 */
    public Global global() {
        long packets = 0;
        long bytes = 0;
        Map<String, Integer> protos = new HashMap<>();
        for (Second s : seconds) {
            packets += s.packets;
            bytes += s.bytes;
            for (Map.Entry<String, Integer> e : s.protos.entrySet()) {
                protos.merge(e.getKey(), e.getValue(), Integer::sum);
            }
        }
        return new Global(packets, bytes, protos);
    }

    /** 活跃 IP 数（窗口内有包的 IP）。 */
    public int activeIps() {
        return totals.size();
    }

    /** 当前保留的秒桶数量（诊断用：正常应约为 window + 1）。 */
    public int bucketCount() {
        return seconds.size();
    }

    /** 只读遍历：调用方必须持有与 {@link #add} 相同的锁。 */
    public List<Map.Entry<String, IpCount>> entries() {
        return new ArrayList<>(totals.entrySet());
    }

    public void clear() {
        seconds.clear();
        totals.clear();
        current = new Second(Long.MIN_VALUE);
    }
}
