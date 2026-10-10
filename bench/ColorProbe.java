import java.util.stream.Collectors;

/**
 * 颜色探针：打印终端判定结果、实际发出的转义字节，以及告警行的红色效果示例。
 *
 * <pre>java -cp "out;lib\jna.jar" ColorProbe</pre>
 */
public final class ColorProbe {

    private ColorProbe() {
    }

    private static String hex(String s) {
        return s.chars().mapToObj(c -> String.format("%02X", c)).collect(Collectors.joining(" "));
    }

    public static void main(String[] args) {
        System.out.println("System.console() = " + System.console());
        System.out.println("WT_SESSION      = " + System.getenv("WT_SESSION"));
        System.out.println("NO_COLOR        = " + System.getenv("NO_COLOR"));

        Color.init(true);
        System.out.println("Color.init(true) -> isEnabled() = " + Color.isEnabled()
                + "（重定向/不支持时为 false，自动退化成纯文本）");

        Color.setEnabled(true);
        String sample = Color.red("[2026-10-03 22:30:00] 【DDoS 告警 / DDoS_ATTACK】"
                + "单IP高频请求/流量异常 1.2.3.4 (100.0 req/s) | 攻击者IP: 1.2.3.4 | 归属地: 查询中");
        System.out.println("红色告警行（开启颜色）: " + sample);
        System.out.println("前 6 个字节 = " + hex(sample.substring(0, 6))
                + "   (1B 5B 33 31 6D = ESC[31m 红色)");

        Color.setEnabled(false);
        System.out.println("同一行的纯文本形式: " + Color.red("示例告警"));
        Color.setEnabled(true);
    }
}
