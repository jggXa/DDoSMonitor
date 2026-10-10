import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 读写：只覆盖本工具配置文件需要的形状
 * （对象 / 数组 / 整数 / 浮点 / 字符串 / 布尔 / null）。
 *
 * <p>对应 Python 版的 json 模块子集，为了做到零第三方依赖而手写。</p>
 */
public final class Json {

    private Json() {
    }

    /** 解析 JSON 文本。对象按出现顺序返回 {@link LinkedHashMap}（保持键顺序）。 */
    public static Object parse(String text) {
        String src = text;
        if (src != null && !src.isEmpty() && src.charAt(0) == '\uFEFF') {
            src = src.substring(1);      // 容忍 UTF-8 BOM（记事本 / PowerShell Set-Content 常见）
        }
        Parser p = new Parser(src);
        p.skipWs();
        Object value = p.readValue();
        p.skipWs();
        if (p.pos < p.src.length()) {
            throw new IllegalArgumentException("JSON 尾部存在多余内容（位置 " + p.pos + "）");
        }
        return value;
    }

    public static Object parseFile(Path path) throws IOException {
        return parse(Files.readString(path, StandardCharsets.UTF_8));
    }

    /** 以 4 空格缩进写出，中文原样输出（等价 Python 的 indent=4, ensure_ascii=False）。 */
    public static void writeFile(Path path, Object value) throws IOException {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, 0);
        sb.append('\n');
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ 序列化

    private static void writeValue(StringBuilder sb, Object value, int depth) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean b) {
            sb.append(b.booleanValue() ? "true" : "false");
        } else if (value instanceof Number n) {
            sb.append(n.toString());
        } else if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                indent(sb, depth + 1);
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(": ");
                writeValue(sb, e.getValue(), depth + 1);
                if (++i < map.size()) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            indent(sb, depth);
            sb.append('}');
        } else if (value instanceof List<?> list) {
            if (list.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(sb, depth + 1);
                writeValue(sb, list.get(i), depth + 1);
                if (i + 1 < list.size()) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            indent(sb, depth);
            sb.append(']');
        } else {
            writeString(sb, String.valueOf(value));
        }
    }

    private static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) {
            sb.append("    ");
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // ------------------------------------------------------------------ 解析

    /**
     * 嵌套层数上限。
     *
     * <p>递归下降解析器对 {@code {[[[[...]]]]}} 这类深度嵌套是“一层一个栈帧”，
     * 十万层会抛 StackOverflowError —— 它是 Error，不被 {@code catch (Exception)}
     * 捕获，JVM 直接崩掉且没有任何提示。这里统一在入口拦住。</p>
     */
    private static final int MAX_DEPTH = 64;

    private static final class Parser {

        private final String src;
        private int pos;
        private int depth;

        Parser(String src) {
            this.src = src;
        }

        void skipWs() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        Object readValue() {
            skipWs();
            if (pos >= src.length()) {
                throw error("意外的结尾");
            }
            if (depth >= MAX_DEPTH) {
                throw error("JSON 嵌套层数超过上限 " + MAX_DEPTH);
            }
            depth++;
            try {
                char c = src.charAt(pos);
                switch (c) {
                    case '{':
                        return readObject();
                    case '[':
                        return readArray();
                    case '"':
                        return readString();
                    case 't':
                        expectLiteral("true");
                        return Boolean.TRUE;
                    case 'f':
                        expectLiteral("false");
                        return Boolean.FALSE;
                    case 'n':
                        expectLiteral("null");
                        return null;
                    default:
                        return readNumber();
                }
            } finally {
                depth--;
            }
        }

        private Map<String, Object> readObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (pos < src.length() && src.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                String key = readString();
                skipWs();
                expect(':');
                map.put(key, readValue());
                skipWs();
                if (pos >= src.length()) {
                    throw error("对象未闭合");
                }
                char c = src.charAt(pos++);
                if (c == ',') {
                    continue;
                }
                if (c == '}') {
                    return map;
                }
                throw error("对象中期望 ',' 或 '}'");
            }
        }

        private List<Object> readArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWs();
            if (pos < src.length() && src.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWs();
                if (pos >= src.length()) {
                    throw error("数组未闭合");
                }
                char c = src.charAt(pos++);
                if (c == ',') {
                    continue;
                }
                if (c == ']') {
                    return list;
                }
                throw error("数组中期望 ',' 或 ']'");
            }
        }

        private String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= src.length()) {
                    throw error("字符串未闭合");
                }
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= src.length()) {
                    throw error("转义序列不完整");
                }
                char e = src.charAt(pos++);
                switch (e) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (pos + 4 > src.length()) {
                            throw error("\\u 转义不完整");
                        }
                        sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw error("非法转义 \\" + e);
                }
            }
        }

        private Object readNumber() {
            int start = pos;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                boolean part = (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.'
                        || c == 'e' || c == 'E';
                if (!part) {
                    break;
                }
                pos++;
            }
            String text = src.substring(start, pos);
            if (text.isEmpty()) {
                throw error("非法数值");
            }
            try {
                if (text.indexOf('.') < 0 && text.indexOf('e') < 0 && text.indexOf('E') < 0) {
                    long v = Long.parseLong(text);
                    if (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) {
                        return Integer.valueOf((int) v);
                    }
                    return Long.valueOf(v);
                }
                return Double.valueOf(Double.parseDouble(text));
            } catch (NumberFormatException ex) {
                throw error("非法数值: " + text);
            }
        }

        private void expectLiteral(String literal) {
            if (!src.startsWith(literal, pos)) {
                throw error("非法字面量");
            }
            pos += literal.length();
        }

        private void expect(char c) {
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw error("期望 '" + c + "'");
            }
            pos++;
        }

        private IllegalArgumentException error(String msg) {
            return new IllegalArgumentException(msg + "（位置 " + pos + "）");
        }
    }
}
