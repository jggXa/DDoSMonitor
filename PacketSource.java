import java.util.function.Consumer;

/**
 * 抓包数据源抽象。三种实现：
 *
 * <ul>
 *   <li>{@link NpcapJnaSource} —— 通过 JNA 调用 Npcap 的 wpcap.dll（默认，需要 lib/jna.jar）</li>
 *   <li>{@link ExternalPcapSource} —— 启动 dumpcap/tcpdump 并解析其输出的 pcap 流</li>
 *   <li>{@link SimSource} —— 模拟流量，用于在没有 Npcap/权限时验证检测与封禁逻辑</li>
 * </ul>
 */
public interface PacketSource extends AutoCloseable {

    /** 启动抓包，解析出的包交给 handler 回调。启动失败抛异常。 */
    void start(Consumer<PacketInfo> handler) throws Exception;

    /** 请求停止；可重复调用。 */
    void stop();

    /** 供界面显示的一句话描述。 */
    String describe();

    /**
     * 抓包层计数（诊断“打满但一个包都没收到”用）：区分
     * “Npcap 根本没给包”与“给了包但被端口过滤/解析跳过”。默认空。
     */
    default String statsLine() {
        return "";
    }

    /**
     * 后台抓包线程是否仍在工作。
     *
     * <p>抓包线程可能因为驱动错误、网卡被拔出、pcap 流畸形、dumpcap 异常退出而
     * <b>静默结束</b>；此时主循环仍会每秒空转，界面显示“窗口包数 0”，
     * 攻击者只要触发一次驱动错误就能让监控彻底失效。DDoSMonitor 依赖本方法
     * 发现这种“假死”并自动重启抓包。</p>
     *
     * <p>默认返回 {@code true}：没有后台线程的数据源不会触发重启。</p>
     */
    default boolean isAlive() {
        return true;
    }

    @Override
    default void close() {
        stop();
    }
}
