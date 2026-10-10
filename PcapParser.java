/**
 * pcap 记录的链路层/网络层/传输层解析。
 *
 * <p>{@link NpcapJnaSource} 与 {@link ExternalPcapSource} 共用这段逻辑，
 * 相当于 Python 版里 Scapy 帮我们做掉的那部分工作。</p>
 */
public final class PcapParser {

    public static final int DLT_NULL = 0;
    public static final int DLT_EN10MB = 1;
    public static final int DLT_RAW = 101;
    public static final int DLT_LINUX_SLL = 113;
    public static final int DLT_IPV4 = 228;
    public static final int DLT_IPV6 = 229;

    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_IPV6 = 0x86DD;
    /** VLAN 标签层数上限：畸形/恶意帧可以塞任意多层 0x8100，逐层循环必须有界。 */
    private static final int MAX_VLAN_LAYERS = 3;

    private PcapParser() {
    }

    /**
     * @param buf      报文缓冲区
     * @param off      报文起始偏移
     * @param len      可用长度
     * @param linkType pcap 链路类型（DLT_*）
     * @param ts       时间戳（秒）
     * @param frameLen 要记入统计的帧长
     * @return 解析结果；不是关心的协议或数据不完整时返回 null
     */
    public static PacketInfo parse(byte[] buf, int off, int len, int linkType, double ts, int frameLen) {
        if (buf == null || len <= 0 || off < 0 || off + len > buf.length) {
            return null;
        }
        switch (linkType) {
            case DLT_EN10MB: {
                if (len < 14) {
                    return null;
                }
                int etherType = u16(buf, off + 12);
                int header = 14;
                int vlanLayers = 0;
                while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
                    if (++vlanLayers > MAX_VLAN_LAYERS || header + 4 > len) {
                        return null;          // 超过 3 层 VLAN 或长度不足：按畸形帧丢弃
                    }
                    etherType = u16(buf, off + header + 2);
                    header += 4;
                }
                if (etherType == ETHERTYPE_IPV4) {
                    return parseIpv4(buf, off + header, len - header, ts, frameLen);
                }
                if (etherType == ETHERTYPE_IPV6) {
                    return parseIpv6(buf, off + header, len - header, ts, frameLen);
                }
                return null;
            }
            case DLT_IPV4:
                return parseIpv4(buf, off, len, ts, frameLen);
            case DLT_IPV6:
                return parseIpv6(buf, off, len, ts, frameLen);
            case DLT_LINUX_SLL: {
                if (len < 16) {
                    return null;
                }
                int proto = u16(buf, off + 14);
                if (proto == ETHERTYPE_IPV4) {
                    return parseIpv4(buf, off + 16, len - 16, ts, frameLen);
                }
                if (proto == ETHERTYPE_IPV6) {
                    return parseIpv6(buf, off + 16, len - 16, ts, frameLen);
                }
                return null;
            }
            case DLT_NULL: {
                // #9：后面要读 buf[off + 4]（IP 版本号），所以长度至少 5；
                // 原来只检查 len < 4，len == 4 的帧会 AIOOBE 把抓包线程打挂。
                if (len < 5) {
                    return null;
                }
                long leFamily = u32le(buf, off);
                long beFamily = u32be(buf, off);
                int header = 4;
                if (leFamily == 2 || beFamily == 2) {
                    return parseIpv4(buf, off + header, len - header, ts, frameLen);
                }
                if (leFamily == 30 || leFamily == 28 || leFamily == 10
                        || beFamily == 30 || beFamily == 28 || beFamily == 10) {
                    return parseIpv6(buf, off + header, len - header, ts, frameLen);
                }
                int version = (buf[off + header] & 0xF0) >> 4;
                if (version == 4) {
                    return parseIpv4(buf, off + header, len - header, ts, frameLen);
                }
                if (version == 6) {
                    return parseIpv6(buf, off + header, len - header, ts, frameLen);
                }
                return null;
            }
            case DLT_RAW:
            default: {
                int version = (buf[off] & 0xF0) >> 4;
                if (version == 4) {
                    return parseIpv4(buf, off, len, ts, frameLen);
                }
                if (version == 6) {
                    return parseIpv6(buf, off, len, ts, frameLen);
                }
                return null;
            }
        }
    }

    private static PacketInfo parseIpv4(byte[] b, int off, int len, double ts, int frameLen) {
        if (len < 20) {
            return null;
        }
        int versionIhl = b[off] & 0xFF;
        if ((versionIhl >> 4) != 4) {
            return null;
        }
        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || ihl > len) {
            return null;
        }
        int totalLen = u16(b, off + 2);
        int end = (totalLen >= ihl && totalLen <= len) ? off + totalLen : off + len;
        int fragment = u16(b, off + 6);
        if ((fragment & 0x1FFF) != 0) {
            return null;                                  // 非首片：没有传输层首部
        }
        int proto = b[off + 9] & 0xFF;
        String src = ipv4String(b, off + 12);
        String dst = ipv4String(b, off + 16);
        int l4Off = off + ihl;
        int l4Len = end - l4Off;
        if (l4Len <= 0) {
            return null;
        }
        return parseTransport(b, l4Off, l4Len, src, dst, ts, frameLen, proto, l4Len);
    }

    private static PacketInfo parseIpv6(byte[] b, int off, int len, double ts, int frameLen) {
        if (len < 40) {
            return null;
        }
        if ((b[off] & 0xF0) != 0x60) {
            return null;
        }
        int payloadLen = u16(b, off + 4);
        int next = b[off + 6] & 0xFF;
        String src = ipv6String(b, off + 8);
        String dst = ipv6String(b, off + 24);
        int pos = off + 40;
        int end = Math.min(off + 40 + payloadLen, off + len);
        for (int guard = 0; guard < 8; guard++) {
            if (next == 6 || next == 17 || next == 132 || next == 33) {
                int avail = end - pos;
                if (avail <= 0) {
                    return null;
                }
                return parseTransport(b, pos, avail, src, dst, ts, frameLen, next, avail);
            }
            if (next == 0 || next == 43 || next == 60) {           // 逐跳/路由/目的选项
                if (pos + 2 > end) {
                    return null;
                }
                int hlen = (b[pos + 1] & 0xFF) * 8 + 8;
                next = b[pos] & 0xFF;
                pos += hlen;
            } else if (next == 51) {                              // 认证头
                if (pos + 2 > end) {
                    return null;
                }
                int hlen = (b[pos + 1] & 0xFF) * 4 + 8;
                next = b[pos] & 0xFF;
                pos += hlen;
            } else if (next == 44) {                              // 分片头
                if (pos + 8 > end) {
                    return null;
                }
                int fragOffset = u16(b, pos + 2) & 0xFFF8;
                next = b[pos] & 0xFF;
                if (fragOffset != 0) {
                    return null;
                }
                pos += 8;
            } else {
                return null;
            }
            if (pos > end) {
                return null;
            }
        }
        return null;
    }

    private static PacketInfo parseTransport(byte[] b, int off, int len, String src, String dst,
                                             double ts, int frameLen, int proto, int ipPayload) {
        switch (proto) {
            case 6: {                                          // TCP
                if (len < 20) {
                    return null;
                }
                int dport = u16(b, off + 2);
                int dataOff = ((b[off + 12] & 0xFF) >> 4) * 4;
                int flags = b[off + 13] & 0xFF;
                boolean syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                int payload = ipPayload - dataOff;
                if (payload < 0) {
                    payload = 0;
                }
                return new PacketInfo(ts, src, dst, dport, syn, frameLen, payload, "TCP");
            }
            case 17: {                                         // UDP
                if (len < 8) {
                    return null;
                }
                int dport = u16(b, off + 2);
                int udpLen = u16(b, off + 4);
                int payload = udpLen >= 8 ? udpLen - 8 : 0;
                if (payload > ipPayload) {
                    payload = Math.max(0, ipPayload - 8);
                }
                return new PacketInfo(ts, src, dst, dport, false, frameLen, payload, "UDP");
            }
            case 132: {                                        // SCTP
                if (len < 12) {
                    return null;
                }
                int dport = u16(b, off + 2);
                return new PacketInfo(ts, src, dst, dport, false, frameLen,
                        Math.max(0, ipPayload - 12), "SCTP");
            }
            case 33: {                                         // DCCP
                if (len < 16) {
                    return null;
                }
                int dport = u16(b, off + 2);
                int dataOff = ((b[off + 8] & 0xFF) >> 2) * 4;
                if (dataOff < 16 || dataOff > ipPayload) {
                    dataOff = 16;
                }
                return new PacketInfo(ts, src, dst, dport, false, frameLen,
                        Math.max(0, ipPayload - dataOff), "DCCP");
            }
            default:
                return null;
        }
    }

    // ------------------------------------------------------------ 小工具

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static long u32be(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static long u32le(byte[] b, int off) {
        return ((long) (b[off + 3] & 0xFF) << 24) | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 1] & 0xFF) << 8) | (b[off] & 0xFF);
    }

    public static String ipv4String(byte[] b, int off) {
        return (b[off] & 0xFF) + "." + (b[off + 1] & 0xFF) + "."
                + (b[off + 2] & 0xFF) + "." + (b[off + 3] & 0xFF);
    }

    public static String ipv6String(byte[] b, int off) {
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) {
            g[i] = ((b[off + i * 2] & 0xFF) << 8) | (b[off + i * 2 + 1] & 0xFF);
        }
        int bestStart = -1;
        int bestLen = 0;
        int curStart = -1;
        int curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (g[i] == 0) {
                if (curStart < 0) {
                    curStart = i;
                }
                curLen++;
                if (curLen > bestLen) {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }
        if (bestLen < 2) {
            bestStart = -1;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                sb.append(':');
            }
            sb.append(Integer.toHexString(g[i]));
        }
        return sb.toString();
    }
}
