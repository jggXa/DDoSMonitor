import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

import java.lang.reflect.Method;

/**
 * JNA 结构体布局探针：验证 pcap_pkthdr 的字段宽度与偏移是否符合 Windows 的 C 布局。
 *
 * <pre>java -cp "out;lib\jna.jar" StructProbe</pre>
 *
 * Windows x64 上 C 的 long 是 32 位，期望 NativeLong.SIZE = 4、结构体 16 字节、
 * caplen 位于偏移 8。除了打印尺寸，还做一次字节级验证：按该布局写入原生内存，
 * 再让 JNA 读回来，看 caplen 是否等于写入值。
 */
public final class StructProbe {

    private StructProbe() {
    }

    private static int offset(Structure structure, String field) throws Exception {
        Method m = Structure.class.getDeclaredMethod("fieldOffset", String.class);
        m.setAccessible(true);
        return (Integer) m.invoke(structure, field);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("os.name             = " + System.getProperty("os.name"));
        System.out.println("os.arch             = " + System.getProperty("os.arch"));
        System.out.println("Native.POINTER_SIZE = " + Native.POINTER_SIZE);
        System.out.println("NativeLong.SIZE     = " + NativeLong.SIZE + "   <- C long 宽度（Windows 应为 4）");

        NpcapJnaSource.PcapPkthdr header = new NpcapJnaSource.PcapPkthdr();
        System.out.println("PcapPkthdr.size()   = " + header.size() + "   <- 期望 16");
        System.out.println("  偏移 tv_sec  = " + offset(header, "tv_sec"));
        System.out.println("  偏移 tv_usec = " + offset(header, "tv_usec"));
        System.out.println("  偏移 caplen  = " + offset(header, "caplen") + "   <- 期望 8");
        System.out.println("  偏移 len     = " + offset(header, "len"));
        System.out.println("BpfProgram.size()   = " + new NpcapJnaSource.BpfProgram().size()
                + "   <- 期望 16（u_int 4 + 指针 8，含 4 字节填充）");

        // 字节级验证：按 Windows 布局写入，再让 JNA 读回来
        Memory mem = new Memory(16);
        mem.clear();
        mem.setInt(0, 0x6A123456);          // tv_sec
        mem.setInt(4, 1_000_000);           // tv_usec
        mem.setInt(8, 64);                  // caplen（若错位读成高 32 位，这里会读出 0）
        mem.setInt(12, 100);                // len
        NpcapJnaSource.PcapPkthdr readBack = new NpcapJnaSource.PcapPkthdr(mem);
        readBack.read();
        System.out.println("字节级读回：tv_sec=" + readBack.tv_sec
                + " tv_usec=" + readBack.tv_usec
                + " caplen=" + readBack.caplen
                + " len=" + readBack.len);

        boolean ok = NativeLong.SIZE == 4 && header.size() == 16
                && offset(header, "caplen") == 8 && readBack.caplen == 64;
        System.out.println(ok
                ? "结论：布局与 Windows C 结构一致，caplen 能正确读出 —— 结构体错位不成立"
                : "结论：布局与期望不符，结构体读取出错！");
    }
}
