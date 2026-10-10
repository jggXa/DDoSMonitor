/**
 * 从线路上解析出来的一个包的关键信息。
 *
 * <p>第 2 批新增 {@link #dstIp}：用于“只统计入向流量”的过滤
 * （Python 版只匹配 dst port，本机自己访问外部 80 端口也会被计入）。</p>
 */
public final class PacketInfo {

    /** 抓包时刻，单位秒，语义与 Python 的 time.time() 一致。 */
    public final double ts;
    /** 源地址字符串（可能是 IPv6，使用前会经 NetUtil 归一化）。 */
    public final String srcIp;
    /** 目的地址字符串；入向过滤要用。 */
    public final String dstIp;
    public final int dstPort;
    /** 是否 SYN 置位且 ACK 未置位（SYN Flood 判定用）。 */
    public final boolean syn;
    /** 帧长（对应 Python 的 len(pkt)）。 */
    public final int length;
    public final int payloadLen;
    /** TCP / UDP / SCTP / DCCP。 */
    public final String proto;

    public PacketInfo(double ts, String srcIp, String dstIp, int dstPort, boolean syn,
                      int length, int payloadLen, String proto) {
        this.ts = ts;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.syn = syn;
        this.length = length;
        this.payloadLen = payloadLen;
        this.proto = proto;
    }
}
