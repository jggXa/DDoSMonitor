import java.util.Locale;

/**
 * 控制台彩色输出（ANSI 转义）。
 *
 * <p>设计原则：</p>
 * <ul>
 *   <li>终端不支持（输出被重定向到文件/管道、Windows 旧控制台且无法开启 VT）时自动退化为纯文本，
 *       不会把 {@code ←[31m} 之类的转义序列打到日志或管道里；</li>
 *   <li>日志文件永远写纯文本——{@link DDoSMonitor#writeLog} 不经过本类；</li>
 *   <li>可用配置项 {@code color=0} 或命令行 {@code --no-color} 关闭，环境变量 {@code NO_COLOR} 也生效。</li>
 * </ul>
 */
public final class Color {

    private static final String RESET = "\u001B[0m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";

    private static volatile boolean enabled;

    private Color() {
    }

    /** 按“用户是否想要 + 终端是否支持”决定是否启用。 */
    public static void init(boolean userWants) {
        setEnabled(userWants && capable());
    }

    public static void setEnabled(boolean value) {
        enabled = value;
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static String red(String text) {
        return wrap(RED, text);
    }

    public static String yellow(String text) {
        return wrap(YELLOW, text);
    }

    public static String green(String text) {
        return wrap(GREEN, text);
    }

    private static String wrap(String code, String text) {
        return enabled ? code + text + RESET : text;
    }

    /** 当前终端是否支持 ANSI 颜色。 */
    private static boolean capable() {
        String noColor = System.getenv("NO_COLOR");
        if (noColor != null && !noColor.isEmpty()) {
            return false;
        }
        if (System.console() == null) {
            return false;                      // 输出被重定向到文件/管道，不要污染内容
        }
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            if (System.getenv("WT_SESSION") != null) {
                return true;                   // Windows Terminal 原生解析 ANSI
            }
            return enableWindowsVt();          // 旧 conhost：尝试打开 VT 处理
        }
        String term = System.getenv("TERM");
        return term == null || !term.toLowerCase(Locale.ROOT).contains("dumb");
    }

    /** 旧版 Windows 控制台需要显式开启 ENABLE_VIRTUAL_TERMINAL_PROCESSING（通过 JNA）。 */
    private static boolean enableWindowsVt() {
        try {
            Class<?> cls = Class.forName("WindowsAnsi");
            Object result = cls.getMethod("enable").invoke(null);
            return Boolean.TRUE.equals(result);
        } catch (Throwable t) {
            return false;                      // 没有 jna.jar 就退化
        }
    }
}
