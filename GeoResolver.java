import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * 异步归属地查询（ip-api.com），对应 Python 版 _geo_worker / get_ip_location。
 *
 * <p>单线程队列 + 缓存：调用方拿到的是“查询中”，稍后再打印就是结果，
 * 与 Python 版行为一致。缓存上限 4096 条，超出后按 LRU 淘汰最久未用的一条
 * （早期实现是整体 {@code clear()}，攻击者用海量不同 IP 就能让缓存反复失效、
 * 每次都重新发起 HTTP 查询，形成缓存雪崩）。</p>
 */
public final class GeoResolver {

    private static final int MAX_CACHE = 4096;

    /** 访问序 LRU：超上限时只淘汰最久未使用的一条，其余缓存继续命中。 */
    private static final class LruCache extends LinkedHashMap<String, String> {
        private static final long serialVersionUID = 1L;

        private final int max;

        LruCache(int max) {
            super(16, 0.75f, true);
            this.max = max;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > max;
        }
    }

    private final Map<String, String> cache = Collections.synchronizedMap(new LruCache(MAX_CACHE));
    private final ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<>();
    private final Map<String, Boolean> pending = new ConcurrentHashMap<>();
    private final HttpClient http;

    private volatile boolean stopped;
    private Thread worker;

    public GeoResolver() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public void start() {
        worker = new Thread(this::loop, "geo-worker");
        worker.setDaemon(true);
        worker.start();
    }

    public void close() {
        stopped = true;
        if (worker != null) {
            worker.interrupt();
        }
    }

    /** 查询入口；与 Python 版一样，未命中缓存时返回“查询中”并排队。 */
    public String lookup(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "未知";
        }
        if (ip.equals("多IP/全网") || ip.equals("分布式大量IP") || ip.equals("未知")) {
            return ip;
        }
        if (NetUtil.isInternal(ip)) {
            return "内网/保留IP";
        }
        String hit = cache.get(ip);
        if (hit != null) {
            return hit;
        }
        // 队列上限护栏：DDoS 典型形态是几十万不同源 IP，无界队列会 OOM
        if (pending.size() >= MAX_CACHE) {
            return "查询中";   // 丢弃新查询，避免雪崩
        }
        if (pending.putIfAbsent(ip, Boolean.TRUE) == null) {
            queue.add(ip);
        }
        return "查询中";
    }

    private void loop() {
        while (!stopped) {
            String ip = queue.poll();
            if (ip == null) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                continue;
            }
            String loc;
            try {
                loc = query(ip);
            } catch (Exception e) {
                loc = "查询失败";
            }
            // 超上限由 LruCache 自行淘汰最久未用的一条，不再整体 clear（缓存雪崩）
            cache.put(ip, loc);
            pending.remove(ip);
        }
    }

    private String query(String ip) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://ip-api.com/json/" + ip + "?lang=zh-CN"))
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
        HttpResponse<String> response = http.send(request,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Object parsed = Json.parse(response.body());
        if (parsed instanceof Map<?, ?> map) {
            if (!"success".equals(String.valueOf(map.get("status")))) {
                return "未知";
            }
            StringBuilder sb = new StringBuilder();
            appendField(sb, map.get("country"));
            appendField(sb, map.get("regionName"));
            appendField(sb, map.get("city"));
            appendField(sb, map.get("isp"));
            String loc = sb.toString().trim();
            return loc.isEmpty() ? "未知" : loc;
        }
        return "未知";
    }

    private static void appendField(StringBuilder sb, Object value) {
        if (value == null) {
            return;
        }
        String s = String.valueOf(value).trim();
        if (s.isEmpty()) {
            return;
        }
        if (sb.length() > 0) {
            sb.append(' ');
        }
        sb.append(s);
    }
}
