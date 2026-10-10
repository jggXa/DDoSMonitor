import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 控制台输入线程。
 *
 * <p>Python 版用 msvcrt / tty.setcbreak 做单键热键（Ctrl+X 进调试、Ctrl+C 退出）。
 * JDK 没有等价的裸控制台 API，这里改为行输入：</p>
 *
 * <ul>
 *   <li>非调试模式：输入 {@code x} + 回车 → 进入调试模式；{@code exit} + 回车 → 退出程序</li>
 *   <li>调试模式：所有行都交给调试 REPL 消费（同一个 reader，避免抢输入）</li>
 *   <li>Ctrl+C：由 JVM 的关闭钩子接管，仍然会先撤销防火墙规则再退出</li>
 * </ul>
 */
public final class ConsoleInput {

    /**
     * 全进程共用同一个 System.in 读取器：main 里的 “是否继续(y/n)” 与调试 REPL
     * 都必须走它，否则 BufferedReader 会预读并吞掉后续输入。
     */
    private static final BufferedReader SHARED_READER =
            new BufferedReader(new InputStreamReader(System.in, Charset.defaultCharset()));

    public static BufferedReader sharedReader() {
        return SHARED_READER;
    }

    private final BlockingQueue<String> lines = new LinkedBlockingQueue<>();
    private final AtomicBoolean debugMode = new AtomicBoolean(false);

    private volatile boolean debugRequested;
    private volatile boolean exitRequested;
    private volatile boolean inputClosed;
    private Thread thread;

    public void start() {
        thread = new Thread(this::loop, "console-input");
        thread.setDaemon(true);
        thread.start();
    }

    /** 是否处于调试模式：监控输出据此暂停，避免插进调试提示行。 */
    public boolean isInDebugMode() {
        return debugMode.get();
    }

    private void loop() {
        try {
            String line;
            while ((line = SHARED_READER.readLine()) != null) {
                if (debugMode.get()) {
                    lines.put(line);
                    continue;
                }
                String trimmed = line.trim();
                if (trimmed.indexOf('\u0018') >= 0 || trimmed.equalsIgnoreCase("x")
                        || trimmed.equalsIgnoreCase("debug")) {
                    debugRequested = true;
                } else if (trimmed.equalsIgnoreCase("exit") || trimmed.equalsIgnoreCase("quit")
                        || trimmed.equalsIgnoreCase("q")) {
                    exitRequested = true;
                } else if (!trimmed.isEmpty()) {
                    System.out.println("[提示] 顶层命令只有 x（进入调试模式）和 exit（退出程序）。");
                    System.out.flush();
                }
            }
        } catch (Exception e) {
            // 输入流被关闭，按“不可用”处理
        }
        inputClosed = true;
        System.out.println("[提示] 标准输入已结束，热键与调试模式不可用（监控继续运行）。");
        System.out.flush();
    }

    public boolean consumeDebugRequest() {
        if (debugRequested) {
            debugRequested = false;
            return true;
        }
        return false;
    }

    public boolean isExitRequested() {
        return exitRequested;
    }

    public void requestExit() {
        exitRequested = true;
    }

    /** 进入调试模式：切换派发目标并清掉切模式前积压的行。 */
    public void enterDebugMode() {
        lines.clear();
        debugMode.set(true);
    }

    public void leaveDebugMode() {
        debugMode.set(false);
        lines.clear();
    }

    /**
     * 调试 REPL 读取一行。
     *
     * @return 读取到的行；返回 null 表示应当退出调试模式（程序正在收尾或输入已结束）
     */
    public String readLine(String prompt) {
        System.out.print(prompt);
        System.out.flush();
        while (true) {
            if (exitRequested) {
                return null;
            }
            String line;
            try {
                line = lines.poll(200, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            if (line != null) {
                return line;
            }
            if (inputClosed) {
                return null;
            }
        }
    }
}
