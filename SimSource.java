import java.util.Random;
import java.util.function.Consumer;

/**
 * 模拟流量源：不需要 Npcap、不需要管理员权限，用来验证阈值判定、
 * 状态机、告警冷却与封禁登记逻辑（配合 --dry-run 不会真的下发规则）。
 */
public final class SimSource implements PacketSource {

    private final int port;
    private final String dstIp;
    private final int normalPps;
    private final int attackPps;
    private final int periodSeconds;
    private final int attackSeconds;
    private final Random random = new Random(20240601L);
    private final String[] normalPool;
    private final String[] attackPool;

    private volatile boolean running;
    private volatile boolean attackingNow;
    private final java.util.concurrent.atomic.AtomicLong generated =
            new java.util.concurrent.atomic.AtomicLong();
    private Thread thread;

    public SimSource(int port, String dstIp, int normalPps, int attackPps,
                     int periodSeconds, int attackSeconds) {
        this.port = port;
        this.dstIp = dstIp;
        this.normalPps = Math.max(1, normalPps);
        this.attackPps = Math.max(this.normalPps + 1, attackPps);
        this.periodSeconds = periodSeconds;
        this.attackSeconds = attackSeconds;
        this.normalPool = buildPool(random, 4);
        this.attackPool = buildPool(random, 64);
    }

    private static String[] buildPool(Random r, int count) {
        int[] prefixes = {5, 14, 27, 36, 42, 45, 58, 61, 77, 91, 103, 106, 111, 118, 121, 125,
                141, 150, 157, 163, 171, 175, 180, 182, 185, 186, 190, 193, 195, 197, 200,
                201, 202, 210, 211, 218, 219, 220, 221, 222};
        String[] pool = new String[count];
        for (int i = 0; i < count; i++) {
            pool[i] = prefixes[r.nextInt(prefixes.length)] + "." + (1 + r.nextInt(254)) + "."
                    + (1 + r.nextInt(254)) + "." + (1 + r.nextInt(254));
        }
        return pool;
    }

    @Override
    public void start(Consumer<PacketInfo> handler) {
        running = true;
        thread = new Thread(() -> loop(handler), "sim-source");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop(Consumer<PacketInfo> handler) {
        long started = System.nanoTime();
        try {
            while (running) {
                double elapsed = (System.nanoTime() - started) / 1_000_000_000.0;
                boolean attacking = periodSeconds > 0 && attackSeconds > 0
                        && (elapsed % periodSeconds) < attackSeconds;
                attackingNow = attacking;
                int pps = attacking ? attackPps : normalPps;
                // 速率上限：不再用 200µs 下限（那会把速率硬顶在 5000 pps，配置再高也打不到）。
                // 亚毫秒间隔改用自旋补齐——Thread.sleep 在 Windows 上粒度约 1~15ms，睡不准。
                long interval = Math.max(1_000L, 1_000_000_000L / pps);
                long next = System.nanoTime();
                for (int i = 0; i < pps && running; i++) {
                    handler.accept(nextPacket(attacking));
                    next += interval;
                    long sleep = next - System.nanoTime();
                    if (sleep <= 0) {
                        continue;                          // 已经落后：不补睡，尽快追赶
                    }
                    if (sleep > 2_000_000L) {
                        // 先睡掉大部分（留 1ms 余量），剩下的交给自旋
                        try {
                            Thread.sleep((sleep - 1_000_000L) / 1_000_000L);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    while (running && System.nanoTime() < next) {
                        Thread.onSpinWait();
                    }
                }
            }
        } finally {
            running = false;                               // 线程退出后 isAlive() 必须立刻为 false
        }
    }

    /** 模拟源线程是否仍在产生流量。 */
    @Override
    public boolean isAlive() {
        Thread t = thread;
        return running && t != null && t.isAlive();
    }

    private PacketInfo nextPacket(boolean attacking) {
        generated.incrementAndGet();
        String src;
        boolean syn = false;
        if (attacking) {
            src = attackPool[random.nextInt(attackPool.length)];
            syn = random.nextInt(3) == 0;
        } else {
            src = normalPool[random.nextInt(normalPool.length)];
        }
        int length = 60 + random.nextInt(1400);
        int payload = Math.max(0, length - 54);
        return new PacketInfo(System.currentTimeMillis() / 1000.0, src, dstIp, port, syn,
                length, payload, "TCP");
    }

    @Override
    public void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
        }
    }

    @Override
    public String describe() {
        return "模拟流量源（正常 " + normalPps + " pkt/s，攻击 " + attackPps + " pkt/s，"
                + "每 " + periodSeconds + "s 攻击 " + attackSeconds + "s），监听目标端口 " + port;
    }

    @Override
    public String statsLine() {
        return "模拟源[已生成=" + generated.get() + " 攻击中=" + (attackingNow ? "是" : "否") + "]";
    }
}
