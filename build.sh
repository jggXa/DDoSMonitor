#!/usr/bin/env bash
# ============================================================================
#  DDoSMonitor 构建脚本（Linux / macOS；对应 Windows 的 build.cmd）
#  1) 定位 javac / jar（JAVA_HOME → PATH → macOS java_home）
#  2) 缺少 lib/jna.jar 时用 curl/wget 从 Maven Central 下载
#  3) 用 --release 21 编译：核心零依赖；NpcapJnaSource/WindowsAnsi 仅在 jna.jar 存在时编译
#  4) 打包可运行 jar：dist/DDoSMonitor.jar（含 JNA 及其各平台本机库）
# ============================================================================
set -eu

cd "$(dirname "$0")"

LIB=lib
OUT=out
BUILD=build
STAGE="$BUILD/jar"
DIST=dist
JAR_NAME=DDoSMonitor.jar
JNA_VER=5.14.0
JNA_JAR="$LIB/jna.jar"
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VER/jna-$JNA_VER.jar"

# 类路径分隔符：Windows 上的 Git Bash/MSYS 用 ;，其它用 :
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) SEP=';' ;;
  *) SEP=':' ;;
esac

echo "============================================================"
echo " DDoSMonitor 构建（Java 21 源级，JDK 21+ 编译）"
echo "============================================================"

# ---------------------------------------------------------- 1. 找 JDK
JAVAC=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
  JAVAC="$JAVA_HOME/bin/javac"
elif command -v javac >/dev/null 2>&1; then
  JAVAC="$(command -v javac)"
elif [ -x /usr/libexec/java_home ]; then
  JH="$(/usr/libexec/java_home 2>/dev/null || true)"
  if [ -n "$JH" ] && [ -x "$JH/bin/javac" ]; then
    JAVAC="$JH/bin/javac"
  fi
fi
if [ -z "$JAVAC" ]; then
  echo "[错误] 找不到 javac，请安装 JDK 21+（Debian/Ubuntu: apt install openjdk-21-jdk；"
  echo "       macOS: brew install openjdk@21）并设置 JAVA_HOME。"
  exit 1
fi
JAR="$(dirname "$JAVAC")/jar"
if [ ! -x "$JAR" ]; then
  echo "[错误] 在同目录找不到 jar: $JAR"
  exit 1
fi

JAVAC_VER="$("$JAVAC" -version 2>&1 | awk '{print $2}')"
MAJOR="${JAVAC_VER%%.*}"
case "$MAJOR" in
  ''|*[!0-9]*) MAJOR=0 ;;
esac
echo "[1/4] javac: $JAVAC"
"$JAVAC" -version
if [ "$MAJOR" -lt 21 ]; then
  echo "[错误] 需要 JDK 21 或更高版本，当前为 $JAVAC_VER"
  exit 1
fi

# ---------------------------------------------------------- 2. jna.jar
mkdir -p "$LIB"
if [ -f "$JNA_JAR" ]; then
  echo "[2/4] 已存在 $JNA_JAR，跳过下载。"
else
  echo "[2/4] 下载 JNA（仅 Npcap/libpcap 抓包后端需要）..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 -o "$JNA_JAR" "$JNA_URL" || rm -f "$JNA_JAR"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 15 -O "$JNA_JAR" "$JNA_URL" || rm -f "$JNA_JAR"
  else
    echo "      [警告] 没有 curl/wget，跳过下载"
  fi
  if [ -f "$JNA_JAR" ]; then
    echo "      下载完成: $JNA_JAR"
  else
    echo "      [警告] 下载失败，将只编译核心：抓包后端需改用 --source=external / sim"
  fi
fi

# ---------------------------------------------------------- 3. 编译
mkdir -p "$OUT"
CORE_SRC="$(ls *.java | grep -v -e '^NpcapJnaSource\.java$' -e '^WindowsAnsi\.java$')"
echo "[3/4] 编译核心（--release 21）..."
# shellcheck disable=SC2086
"$JAVAC" -encoding UTF-8 --release 21 -Xlint:all -d "$OUT" $CORE_SRC
if [ -f "$JNA_JAR" ]; then
  echo "      编译抓包后端（-cp $OUT$SEP$JNA_JAR）..."
  "$JAVAC" -encoding UTF-8 --release 21 -cp "$OUT$SEP$JNA_JAR" -d "$OUT" \
      NpcapJnaSource.java WindowsAnsi.java
else
  echo "      跳过抓包后端（缺少 $JNA_JAR）"
fi

# ---------------------------------------------------------- 4. 打包 jar
rm -rf "$BUILD"
mkdir -p "$STAGE" "$DIST"
FAT=0
if [ -f "$JNA_JAR" ]; then
  echo "[4/4] 打包 $DIST/$JAR_NAME（合并 JNA 及其本机库）..."
  JNA_ABS="$(cd "$(dirname "$JNA_JAR")" && pwd)/$(basename "$JNA_JAR")"
  ( cd "$STAGE" && "$JAR" xf "$JNA_ABS" )
  # JNA 自带 MANIFEST 里写着 Main-Class: com.sun.jna.Native，必须删掉换成我们自己的
  rm -f "$STAGE/META-INF/MANIFEST.MF"
  rm -f "$STAGE"/META-INF/*.SF "$STAGE"/META-INF/*.RSA "$STAGE"/META-INF/*.DSA 2>/dev/null || true
  FAT=1
else
  echo "[4/4] 打包 $DIST/$JAR_NAME（无 JNA，抓包后端不可用）..."
fi
cp "$OUT"/*.class "$STAGE"/

cat > "$BUILD/MANIFEST.MF" <<'EOF'
Manifest-Version: 1.0
Main-Class: DDoSMonitor
Implementation-Title: DDoSMonitor
Implementation-Version: 1.0
Implementation-Vendor: DDoSMonitor
EOF

"$JAR" --create --file "$DIST/$JAR_NAME" --manifest "$BUILD/MANIFEST.MF" -C "$STAGE" .
ls -l "$DIST/$JAR_NAME" | awk '{print "      jar 大小: " $5 " 字节"}'

echo
echo "============================================================"
echo " 编译 + 打包成功。"
echo "------------------------------------------------------------"
echo " 自检（113 项纯逻辑检查）:"
echo "   java -cp $DIST/$JAR_NAME SelfTest"
echo
echo " 模拟流量自测（不需要 root，默认 dry-run）:"
echo "   java -Dstdout.encoding=UTF-8 -jar $DIST/$JAR_NAME --source=sim --yes"
echo
echo " 真实抓包 + 真实封禁（需要 root/CAP_NET_RAW，且已装 libpcap）:"
echo "   sudo java -Dstdout.encoding=UTF-8 -jar $DIST/$JAR_NAME --yes"
if [ "$FAT" -eq 0 ]; then
  echo
  echo " 注意：缺少 $JNA_JAR，Npcap/libpcap 与彩色 VT 支持未打入；"
  echo "       --source=external（tcpdump/dumpcap）与 --source=sim 仍可用。"
fi
echo "============================================================"
