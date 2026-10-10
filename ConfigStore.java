import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 配置的默认值、范围校验与读写。
 *
 * <p>对应 Python 版 DEFAULT_CONFIG / CONFIG_SPEC / validate_config_value /
 * _normalize_banned / load_config / save_config。</p>
 */
public final class ConfigStore {

    /** 可调键 → [最小值, 最大值]。阈值下限为 1：判定用 &gt;=，取 0 会让条件恒真。 */
    private static final LinkedHashMap<String, long[]> SPEC = buildSpec();

    public static final String KEY_NOTE = "_说明";
    public static final String KEY_BANNED = "banned";
    /**
     * 永久封禁条目上限。
     *
     * <p>条目无上限时：配置文件会无限增长，启动时 {@link #normalizeBanned} 与
     * applyPersistentBans 都要逐条处理（含 DNS 解析），启动时间爆炸。</p>
     */
    public static final int MAX_BANNED = 1000;

    private ConfigStore() {
    }

    private static LinkedHashMap<String, long[]> buildSpec() {
        LinkedHashMap<String, long[]> spec = new LinkedHashMap<>();
        spec.put("port", new long[]{1, 65535});
        spec.put("window", new long[]{1, 3600});
        spec.put("ip_pps_threshold", new long[]{1, 1000000000L});
        spec.put("ip_bps_threshold", new long[]{1, 1000000000000L});
        spec.put("global_pps_threshold", new long[]{1, 1000000000L});
        spec.put("global_bps_threshold", new long[]{1, 1000000000000L});
        spec.put("distinct_ip_threshold", new long[]{1, 10000000L});
        spec.put("syn_threshold", new long[]{1, 1000000000L});
        spec.put("cooldown", new long[]{0, 86400});
        spec.put("auto_block", new long[]{0, 1});
        spec.put("block_duration", new long[]{1, 7L * 86400});
        spec.put("inbound_only", new long[]{0, 1});
        spec.put("allow_internal", new long[]{0, 1});
        spec.put("health_interval", new long[]{0, 86400});
        spec.put("color", new long[]{0, 1});
        return spec;
    }

    /** 每次返回一份全新的可修改副本（与 Python 的 DEFAULT_CONFIG.copy() 语义一致）。 */
    public static LinkedHashMap<String, Object> defaults() {
        LinkedHashMap<String, Object> c = new LinkedHashMap<>();
        c.put(KEY_NOTE, "阈值配置，调试模式使用 set <键> <值> 可修改，或直接编辑本文件");
        c.put("port", 80);
        c.put("window", 3);
        c.put("ip_pps_threshold", 5);
        c.put("ip_bps_threshold", 524288);
        c.put("global_pps_threshold", 20);
        c.put("global_bps_threshold", 2097152);
        c.put("distinct_ip_threshold", 20);
        c.put("syn_threshold", 10);
        c.put("cooldown", 10);
        c.put("auto_block", 1);
        c.put("block_duration", 300);
        c.put("inbound_only", 1);
        c.put("allow_internal", 1);
        c.put("health_interval", 10);
        c.put("color", 1);
        c.put(KEY_BANNED, new ArrayList<String>());
        return c;
    }

    public static Map<String, long[]> spec() {
        return SPEC;
    }

    /** 校验结果：ok 为 true 时 value 是规范化后的整数。 */
    public record Validation(boolean ok, Long value, String error) {

        static Validation pass(long v) {
            return new Validation(true, Long.valueOf(v), "");
        }

        static Validation fail(String msg) {
            return new Validation(false, null, msg);
        }
    }

    public static Validation validate(String key, Object raw) {
        long[] range = SPEC.get(key);
        if (range == null) {
            return Validation.fail("不支持修改的配置键: " + key);
        }
        long num;
        if (raw instanceof Boolean b) {
            num = b.booleanValue() ? 1L : 0L;
        } else if (raw instanceof Integer i) {
            num = i.longValue();
        } else if (raw instanceof Long l) {
            num = l.longValue();
        } else if (raw instanceof Double d) {
            double dv = d.doubleValue();
            if (Double.isNaN(dv) || Double.isInfinite(dv) || dv != Math.rint(dv)) {
                return Validation.fail("需要整数，收到 " + raw);
            }
            num = (long) dv;
        } else if (raw instanceof String s) {
            try {
                num = Long.parseLong(s.trim());
            } catch (NumberFormatException e) {
                return Validation.fail("需要整数，收到 \"" + s + "\"");
            }
        } else {
            return Validation.fail("不支持的取值类型: "
                    + (raw == null ? "null" : raw.getClass().getSimpleName()));
        }
        if (num < range[0] || num > range[1]) {
            return Validation.fail("超出允许范围 [" + range[0] + ", " + range[1] + "]，收到 " + num);
        }
        return Validation.pass(num);
    }

    /** 永久封禁列表只保留非空字符串并去重（保持原有顺序），并强制 {@link #MAX_BANNED} 上限。 */
    public static List<String> normalizeBanned(Object value) {
        List<String> out = new ArrayList<>();
        if (!(value instanceof List<?> list)) {
            if (value != null) {
                System.out.println("[警告] banned 必须是列表，已忽略: " + value);
            }
            return out;
        }
        int dropped = 0;
        for (Object item : list) {
            if (!(item instanceof String s)) {
                System.out.println("[警告] 忽略 banned 中的非字符串条目: " + item);
                continue;
            }
            String entry = s.trim();
            if (entry.isEmpty() || out.contains(entry)) {
                continue;
            }
            if (out.size() >= MAX_BANNED) {
                dropped++;
                continue;
            }
            out.add(entry);
        }
        if (dropped > 0) {
            System.out.println("[警告] 永久封禁列表超过上限 " + MAX_BANNED + " 条，已忽略多出的 "
                    + dropped + " 条（请先 unban 清理）。");
        }
        return out;
    }

    public record LoadResult(LinkedHashMap<String, Object> config, String source) {
    }

    public static LoadResult load(Path file) {
        return load(file, true);
    }

    /**
     * @param createIfMissing 配置文件不存在时是否写出默认配置。
     *                        {@code --check} 这类只读场景传 false，避免自检产生副作用。
     */
    public static LoadResult load(Path file, boolean createIfMissing) {
        LinkedHashMap<String, Object> config = defaults();
        String source = "默认配置";
        if (Files.exists(file)) {
            try {
                Object parsed = Json.parseFile(file);
                if (!(parsed instanceof Map<?, ?> map)) {
                    throw new IllegalArgumentException("配置文件顶层必须是 JSON 对象");
                }
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    String key = String.valueOf(e.getKey());
                    if (!config.containsKey(key)) {
                        System.out.println("[警告] 忽略未知配置键: " + key);
                        continue;
                    }
                    if (SPEC.containsKey(key)) {
                        Validation v = validate(key, e.getValue());
                        if (!v.ok()) {
                            System.out.println("[警告] 配置项 " + key + "=" + display(e.getValue())
                                    + " 无效（" + v.error() + "），沿用默认值 " + config.get(key));
                            continue;
                        }
                        config.put(key, v.value());
                    } else {
                        config.put(key, e.getValue());
                    }
                }
                source = "外部配置文件 (" + file + ")";
            } catch (Exception ex) {
                System.out.println("[警告] 读取 " + file + " 失败: " + ex.getMessage() + "，将使用默认配置。");
                config = defaults();
            }
        } else if (createIfMissing) {
            try {
                writeAtomically(file, config);
                System.out.println("[提示] 已生成默认配置文件: " + file);
            } catch (IOException ex) {
                System.out.println("[警告] 生成配置文件失败: " + ex.getMessage());
            }
        }
        config.put(KEY_BANNED, normalizeBanned(config.get(KEY_BANNED)));
        return new LoadResult(config, source);
    }

    /**
     * 保存配置。
     *
     * <p>先在 {@code config} 上加锁取一份快照再序列化：调试模式 {@code set} 改配置与
     * 主线程读配置是并发的（配置用 {@link java.util.Collections#synchronizedMap} 包装），
     * 直接边遍历边写会 ConcurrentModificationException 或写出半新半旧的配置。</p>
     */
    public static boolean save(Path file, Map<String, Object> config) {
        try {
            LinkedHashMap<String, Object> snapshot;
            synchronized (config) {
                snapshot = new LinkedHashMap<>(config);
            }
            writeAtomically(file, snapshot);
            return true;
        } catch (IOException e) {
            System.out.println("[保存失败] " + e.getMessage());
            return false;
        }
    }

    /**
     * 原子写文件：先写同目录下的临时文件，再 move 覆盖目标。
     *
     * <p>{@code Files.writeString} 直接覆盖目标时，写到一半进程崩溃/断电会留下半截 JSON，
     * 配置就此损坏（下次启动只能回退默认配置）。原子替换保证“要么旧内容、要么新内容”。</p>
     */
    private static void writeAtomically(Path file, Object value) throws IOException {
        Path target = file.toAbsolutePath();
        Path dir = target.getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        Path tmp = Files.createTempFile(dir, "ddos-cfg", ".tmp");
        try {
            // createTempFile 在 POSIX 上是 0600，直接 move 会把配置文件变成“仅属主可读写”；
            // 这里对齐目标文件（存在就用它的权限，否则用默认的 rw-r--r--）。
            try {
                if (Files.exists(target)) {
                    Files.setPosixFilePermissions(tmp, Files.getPosixFilePermissions(target));
                } else {
                    Files.setPosixFilePermissions(tmp,
                            java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
                }
            } catch (UnsupportedOperationException | IOException ignored) {
                // Windows / 非 POSIX 文件系统：没有 POSIX 权限概念，忽略
            }
            Json.writeFile(tmp, value);
            try {
                Files.move(tmp, target,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static String display(Object value) {
        return value instanceof String s ? "\"" + s + "\"" : String.valueOf(value);
    }

    // ------------------------------------------------------------ 取值辅助

    public static long asLong(Map<String, Object> config, String key, long fallback) {
        Object v = config.get(key);
        if (v instanceof Number n) {
            return n.longValue();
        }
        return fallback;
    }

    public static String asString(Map<String, Object> config, String key, String fallback) {
        Object v = config.get(key);
        return v instanceof String s ? s : fallback;
    }
}
