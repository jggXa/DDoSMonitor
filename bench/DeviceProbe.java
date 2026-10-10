import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

/**
 * 抓包设备选择探针：打印 Java 看到的网卡、Npcap 设备顺序，以及 firstDevice() 实际选了谁。
 *
 * <pre>java -cp "out;lib\jna.jar" DeviceProbe</pre>
 */
public final class DeviceProbe {

    private DeviceProbe() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== Java NetworkInterface ===");
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            StringBuilder addrs = new StringBuilder();
            for (InetAddress addr : Collections.list(nic.getInetAddresses())) {
                addrs.append(addr.getHostAddress()).append(' ');
            }
            System.out.printf("  name=%-10s up=%-5s loop=%-5s displayName=%-42s addrs=%s%n",
                    nic.getName(), nic.isUp(), nic.isLoopback(), nic.getDisplayName(), addrs);
        }

        System.out.println("=== Npcap 设备（枚举顺序）===");
        List<String> devices = NpcapJnaSource.listDevices();
        for (int i = 0; i < devices.size(); i++) {
            System.out.println("  [" + i + "] " + devices.get(i));
        }

        Method m = NpcapJnaSource.class.getDeclaredMethod("firstDevice");
        m.setAccessible(true);
        Object chosen = m.invoke(null);
        System.out.println("firstDevice() 选择 = " + chosen);
    }
}
