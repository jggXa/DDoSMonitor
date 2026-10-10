import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

/**
 * 为 Windows 旧版控制台（conhost）打开 ANSI/VT 转义支持。
 *
 * <p>Windows Terminal 自己解析 ANSI，不需要这一步；但双击 .cmd 打开的传统控制台窗口
 * 必须调用 {@code SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)} 才会把
 * {@code \u001B[31m} 当颜色而不是当乱码。</p>
 *
 * <p>本类只在 lib/jna.jar 存在时参与编译；{@link Color} 通过反射调用它，
 * 因此缺少 jna.jar 时其它功能仍能编译运行（只是没有颜色）。</p>
 */
public final class WindowsAnsi {

    private static final int STD_OUTPUT_HANDLE = -11;
    private static final int ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

    private WindowsAnsi() {
    }

    /** kernel32 的最小函数子集。 */
    public interface Kernel32 extends Library {

        Pointer GetStdHandle(int stdHandle);

        boolean GetConsoleMode(Pointer handle, IntByReference mode);

        boolean SetConsoleMode(Pointer handle, int mode);
    }

    /** @return true 表示当前控制台已支持 ANSI 转义 */
    public static boolean enable() {
        try {
            Kernel32 kernel32 = Native.load("kernel32", Kernel32.class);
            Pointer handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE);
            if (handle == null) {
                return false;
            }
            IntByReference mode = new IntByReference();
            if (!kernel32.GetConsoleMode(handle, mode)) {
                return false;                  // 不是控制台（已重定向）
            }
            int current = mode.getValue();
            if ((current & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) {
                return true;
            }
            return kernel32.SetConsoleMode(handle, current | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        } catch (Throwable t) {
            return false;
        }
    }
}
