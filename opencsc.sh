#!/bin/bash

# OpenClaw 安全检测与配置管理脚本（精确扫描版）
# 功能：
# 1. 检测绑定 IP 是否为公开地址
# 2. 检测端口是否为默认端口（18789）
# 3. 检测端口是否放行（防火墙+监听状态）
# 4. 分析安全风险程度
# 5. 查看当前配置
# 6. 修改配置（端口/绑定模式）
#
# 特性：
# - 自动扫描系统目录（/etc, /opt, /usr/local），并对文件内容校验，确保找到真正的配置文件
# - 非终端环境自动禁用颜色，避免输出转义字符

set -euo pipefail

# 颜色定义（根据终端情况自动禁用）
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi

# 默认配置
OPENCLAW_DEFAULT_PORT="18789"
DEFAULT_PORTS=("80" "443" "8080" "8443" "22" "21" "23" "3389" "3306" "5432" "6379" "27017")
# 常见配置文件路径（优先检查，这些路径通常可信）
DEFAULT_CONFIG_PATHS=(
    "/etc/openclaw/config.json"
    "/etc/openclaw.json"
    "/usr/local/openclaw/config.json"
    "/usr/local/openclaw.json"
    "/opt/openclaw/config.json"
    "/opt/openclaw.json"
)
# 环境变量可覆盖
CONFIG_FILE="${OPENCLAW_CONFIG:-}"

# 显示使用方法
usage() {
    cat <<EOF
${BLUE}OpenClaw 安全检测与配置管理（精确扫描版）${NC}

使用方法: $0 [选项] [子命令]

选项:
  -c, --config <文件>   指定配置文件路径（跳过自动扫描）
  -h, --help            显示帮助信息

子命令:
  check       运行安全检测（默认）
  view        查看当前配置
  set-port    修改端口（需要参数：新端口号）
  set-bind    修改绑定模式（需要参数：loopback/lan/any）
  help        显示帮助信息

示例:
  $0 check                         # 自动查找有效配置文件并检测
  $0 -c /path/to/config.json view  # 查看指定配置
  $0 set-port 20000                 # 修改端口为 20000
  $0 set-bind lan                    # 修改绑定为局域网
EOF
}

# 检查文件是否为有效的 OpenClaw 配置文件
is_valid_config() {
    local file=$1
    # 简单检查：是否包含 "port" 和 "bind" 字段
    if grep -q '"port"' "$file" 2>/dev/null && grep -q '"bind"' "$file" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# 查找配置文件（精确扫描版）
find_config() {
    # 如果已通过环境变量或-c指定，直接使用
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        if is_valid_config "$CONFIG_FILE"; then
            echo "$CONFIG_FILE"
            return 0
        else
            echo -e "${YELLOW}警告: 指定的配置文件 $CONFIG_FILE 似乎不是有效的 OpenClaw 配置文件${NC}" >&2
            return 1
        fi
    fi

    # 检查预设路径（这些路径通常可信）
    for path in "${DEFAULT_CONFIG_PATHS[@]}"; do
        if [[ -f "$path" ]] && is_valid_config "$path"; then
            echo "$path"
            return 0
        fi
    done

    # 自动扫描系统程序目录
    echo -e "${CYAN}未在常见位置找到有效配置文件，正在自动扫描系统目录，请稍候...${NC}" >&2
    # 只扫描系统程序目录，避免用户缓存
    SEARCH_DIRS=("/etc" "/opt" "/usr/local")
    for dir in "${SEARCH_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi
        # 使用 find 搜索，限制深度为 5，避免过深遍历
        while IFS= read -r file; do
            if is_valid_config "$file"; then
                echo -e "${GREEN}找到有效配置文件: $file${NC}" >&2
                echo "$file"
                return 0
            fi
        done < <(find "$dir" -maxdepth 5 -type f -name "openclaw.json" 2>/dev/null)
    done

    echo -e "${YELLOW}未找到有效的 openclaw.json 配置文件。${NC}" >&2
    echo -e "${YELLOW}请使用 -c 参数手动指定配置文件路径，或设置 OPENCLAW_CONFIG 环境变量。${NC}" >&2
    return 1
}

# 从 JSON 中提取值（优先使用 jq）
get_json_value() {
    local key=$1
    local file=$2
    if command -v jq &>/dev/null; then
        jq -r "$key // empty" "$file" 2>/dev/null || true
    else
        # 回退 grep/sed 方法（支持跨行）
        sed -n ':a;N;$!ba;s/\n/ /g' "$file" | grep -o "\"$key\":[[:space:]*\"[^\"]*\"\|[0-9]*" | head -1 | sed -E 's/.*: ?"?([^",]*)"?.*/\1/'
    fi
}

# 提取配置
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}错误: 配置文件不存在: $CONFIG_FILE${NC}" >&2
        echo -e "${YELLOW}请使用 -c 参数指定配置文件路径。${NC}" >&2
        exit 1
    fi

    if ! is_valid_config "$CONFIG_FILE"; then
        echo -e "${RED}错误: 文件 $CONFIG_FILE 不是有效的 OpenClaw 配置文件（缺少 port 或 bind 字段）${NC}" >&2
        exit 1
    fi

    GATEWAY_PORT=$(get_json_value '.port' "$CONFIG_FILE")
    GATEWAY_BIND=$(get_json_value '.bind' "$CONFIG_FILE")
    GATEWAY_MODE=$(get_json_value '.mode' "$CONFIG_FILE")
    GATEWAY_TOKEN=$(get_json_value '.token' "$CONFIG_FILE")
    FEISHU_APP_ID=$(get_json_value '.feishu.appId' "$CONFIG_FILE")
    FEISHU_ENABLED=$(get_json_value '.feishu.enabled' "$CONFIG_FILE")
    VERSION=$(get_json_value '.lastTouchedVersion' "$CONFIG_FILE")
}

# 查看配置
view_config() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}   OpenClaw 当前配置${NC}"
    echo -e "${BLUE}======================================${NC}\n"

    load_config

    echo -e "${YELLOW}[Gateway]${NC}"
    echo "  端口:      $GATEWAY_PORT"
    echo "  绑定模式:  $GATEWAY_BIND"
    echo "  运行模式:  $GATEWAY_MODE"
    echo "  Token:     ${GATEWAY_TOKEN:0:8}...${GATEWAY_TOKEN: -8}"
    echo ""

    echo -e "${YELLOW}[飞书集成]${NC}"
    echo "  App ID:    $FEISHU_APP_ID"
    echo "  启用状态:  $([[ "$FEISHU_ENABLED" == "true" ]] && echo "是" || echo "否")"
    echo ""

    echo -e "${YELLOW}[版本]${NC}"
    echo "  版本:      $VERSION"
    echo ""
}

# 备份配置文件
backup_config() {
    local bak="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CONFIG_FILE" "$bak"
    echo -e "${GREEN}配置文件已备份到: $bak${NC}"
}

# 修改端口
set_port() {
    local new_port=$1
    if [[ -z "$new_port" ]]; then
        echo -e "${RED}错误: 请指定新端口号${NC}" >&2
        exit 1
    fi
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
        echo -e "${RED}错误: 端口号必须是 1-65535 的数字${NC}" >&2
        exit 1
    fi

    load_config
    echo -e "${YELLOW}当前端口: $GATEWAY_PORT -> 新端口: $new_port${NC}"
    read -p "是否继续？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "已取消"
        exit 0
    fi

    backup_config
    if command -v jq &>/dev/null; then
        jq --arg p "$new_port" '.port = ($p | tonumber)' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    else
        sed -i "s/\"port\": [0-9]*/\"port\": $new_port/" "$CONFIG_FILE"
    fi
    echo -e "${GREEN}端口已修改为: $new_port${NC}"
    restart_prompt
}

# 修改绑定模式
set_bind() {
    local new_bind=$1
    if [[ -z "$new_bind" ]]; then
        echo -e "${RED}错误: 请指定绑定模式 (loopback/lan/any)${NC}" >&2
        exit 1
    fi
    case $new_bind in
        loopback|lan|any) ;;
        *) echo -e "${RED}错误: 无效模式，可用: loopback, lan, any${NC}" >&2; exit 1 ;;
    esac

    load_config
    echo -e "${YELLOW}当前绑定: $GATEWAY_BIND -> 新模式: $new_bind${NC}"
    read -p "是否继续？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "已取消"
        exit 0
    fi

    backup_config
    if command -v jq &>/dev/null; then
        jq --arg b "$new_bind" '.bind = $b' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    else
        sed -i "s/\"bind\": \"[^\"]*\"/\"bind\": \"$new_bind\"/" "$CONFIG_FILE"
    fi
    echo -e "${GREEN}绑定模式已修改为: $new_bind${NC}"
    restart_prompt
}

# 重启提示
restart_prompt() {
    echo -e "${YELLOW}注意: 需要重启 OpenClaw 使配置生效${NC}"
    local service=$(systemctl list-units --full -all | grep -i openclaw | awk '{print $1}' | head -1)
    if [[ -n "$service" ]]; then
        echo "建议运行: sudo systemctl restart $service"
    else
        echo "请手动重启 OpenClaw 进程"
    fi
}

# 检测防火墙是否放行端口
check_firewall() {
    local port=$1
    local fw_open=false
    local fw_tool=""

    # iptables (legacy 和 nft)
    if command -v iptables &>/dev/null; then
        if sudo -n iptables -L INPUT -n 2>/dev/null | grep -q ":$port\b.*ACCEPT"; then
            fw_open=true
            fw_tool="iptables"
        fi
    fi
    # nftables
    if command -v nft &>/dev/null; then
        if sudo -n nft list ruleset 2>/dev/null | grep -q "dport $port.*accept"; then
            fw_open=true
            fw_tool="nftables"
        fi
    fi
    # ufw
    if command -v ufw &>/dev/null; then
        if sudo -n ufw status 2>/dev/null | grep -q "$port.*ALLOW"; then
            fw_open=true
            fw_tool="ufw"
        fi
    fi
    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        if sudo -n firewall-cmd --list-ports 2>/dev/null | grep -q "$port/tcp"; then
            fw_open=true
            fw_tool="firewalld"
        fi
    fi

    if $fw_open; then
        echo -e "${GREEN}已放行 (通过 $fw_tool)${NC}"
        return 0
    else
        # 尝试判断防火墙是否启用但未放行
        if command -v ufw &>/dev/null && sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then
            echo -e "${YELLOW}未放行 (ufw 已启用)${NC}"
        elif command -v firewall-cmd &>/dev/null && sudo -n firewall-cmd --state 2>/dev/null | grep -q "running"; then
            echo -e "${YELLOW}未放行 (firewalld 运行中)${NC}"
        elif command -v iptables &>/dev/null && sudo -n iptables -L INPUT -n 2>/dev/null | grep -q "Chain INPUT (policy DROP)"; then
            echo -e "${YELLOW}可能未放行 (iptables 默认策略 DROP)${NC}"
        else
            echo -e "${GREEN}防火墙未拦截或规则未生效${NC}"
        fi
        return 1
    fi
}

# 检测端口监听状态
check_listening() {
    local port=$1
    local expected_bind=$2
    local listening=false
    local addr=""

    if command -v ss &>/dev/null; then
        addr=$(ss -tlnp "sport = :$port" 2>/dev/null | awk 'NR>1 {print $4}' | head -1)
    elif command -v netstat &>/dev/null; then
        addr=$(netstat -tlnp 2>/dev/null | grep ":$port" | awk '{print $4}' | head -1)
    fi

    if [[ -n "$addr" ]]; then
        listening=true
        echo -e "${GREEN}是 (监听在 $addr)${NC}"
    else
        echo -e "${RED}否 (可能未运行或配置错误)${NC}"
    fi
    $listening
}

# 风险评分与建议
risk_analysis() {
    local bind=$1
    local port=$2
    local mode=$3
    local token=$4
    local fw_open=$5
    local listening=$6

    local score=0
    local factors=()
    local suggestions=()

    # IP 绑定风险
    case "$bind" in
        loopback) ;;
        lan)      score=$((score + 20)); factors+=("绑定到局域网");;
        any|0.0.0.0) score=$((score + 40)); factors+=("绑定到所有接口");;
        *)        score=$((score + 30)); factors+=("绑定到自定义IP（可能暴露）");;
    esac

    # 端口风险
    if [[ "$port" == "$OPENCLAW_DEFAULT_PORT" ]]; then
        score=$((score + 50)); factors+=("使用 OpenClaw 默认端口 18789")
        suggestions+=("将端口改为非默认端口（如 20000-60000）")
    elif [[ " ${DEFAULT_PORTS[@]} " =~ " ${port} " ]]; then
        score=$((score + 20)); factors+=("使用常见默认端口")
    fi

    # 模式风险
    if [[ "$mode" == "cloud" ]]; then
        score=$((score + 30)); factors+=("运行在云模式")
    fi

    # Token 强度简单判断
    if [[ ${#token} -lt 16 ]]; then
        score=$((score + 10)); factors+=("Token 长度不足 16 位")
        suggestions+=("使用更长的随机 Token")
    fi

    # 防火墙状态
    if $fw_open; then
        if [[ "$bind" != "loopback" ]]; then
            score=$((score + 10)); factors+=("防火墙放行且非本地绑定")
        fi
    else
        score=$((score - 10))
    fi

    if ! $listening; then
        echo -e "${YELLOW}警告: 端口未监听，请检查服务状态${NC}"
        suggestions+=("检查 OpenClaw 服务是否运行")
        score=0
    fi

    (( score = score < 0 ? 0 : (score > 100 ? 100 : score) ))

    echo -e "${YELLOW}[4] 风险因素${NC}"
    if [[ ${#factors[@]} -gt 0 ]]; then
        for f in "${factors[@]}"; do echo "  • ${YELLOW}$f${NC}"; done
    else
        echo "  • 无明显风险因素"
    fi
    echo ""
    echo -e "风险评分: ${score}/100"
    if (( score < 30 )); then
        echo -e "风险等级: ${GREEN}低风险 ✓${NC}"
    elif (( score < 60 )); then
        echo -e "风险等级: ${YELLOW}中等风险 ⚠${NC}"
    else
        echo -e "风险等级: ${RED}高风险 ✗${NC}"
    fi

    echo ""
    echo -e "${YELLOW}[5] 安全加固建议${NC}"
    if [[ ${#suggestions[@]} -gt 0 ]]; then
        for s in "${suggestions[@]}"; do echo "  • ${RED}$s${NC}"; done
    fi
    cat <<EOF
  • 启用防火墙，仅放行必要端口
  • 定期更新 OpenClaw 版本
  • 使用强 Token 并定期更换
  • 考虑使用 Tailscale 等安全隧道访问
EOF
}

# 安全检测主函数
security_check() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}   OpenClaw 安全检测脚本（精确扫描版）${NC}"
    echo -e "${BLUE}======================================${NC}\n"

    load_config

    # [1] IP 绑定检测
    echo -e "${YELLOW}[1] IP 地址检测${NC}"
    echo "----------------------------------------"
    case "$GATEWAY_BIND" in
        loopback) bind_ip="127.0.0.1"; bind_type="回环地址"; risk_ip="低";;
        lan)      bind_ip="局域网"; bind_type="局域网"; risk_ip="中";;
        any|0.0.0.0) bind_ip="0.0.0.0 (所有接口)"; bind_type="所有接口"; risk_ip="高";;
        *)        bind_ip="$GATEWAY_BIND"; bind_type="自定义IP"; risk_ip="中";;
    esac
    echo -e "配置绑定模式: ${GREEN}$GATEWAY_BIND${NC}"
    echo -e "解析为: ${GREEN}$bind_ip${NC}"
    echo -e "风险评估: $([[ "$risk_ip" == "低" ]] && echo "${GREEN}低" || [[ "$risk_ip" == "中" ]] && echo "${YELLOW}中" || echo "${RED}高")风险"
    echo ""

    # [2] 端口检测
    echo -e "${YELLOW}[2] 端口检测${NC}"
    echo "----------------------------------------"
    echo -e "当前配置端口: ${GREEN}$GATEWAY_PORT${NC}"
    if [[ "$GATEWAY_PORT" == "$OPENCLAW_DEFAULT_PORT" ]]; then
        echo -e "端口类型: ${RED}OpenClaw 默认端口 (18789)${NC} - 高风险"
    elif [[ " ${DEFAULT_PORTS[@]} " =~ " ${GATEWAY_PORT} " ]]; then
        echo -e "端口类型: ${YELLOW}常见默认端口${NC} - 中等风险"
    else
        echo -e "端口类型: ${GREEN}非标准端口${NC} - 低风险"
    fi
    echo ""

    # [3] 端口放行与监听检测
    echo -e "${YELLOW}[3] 端口放行与监听检测${NC}"
    echo "----------------------------------------"
    echo -n "防火墙放行状态: "
    fw_open=false
    if check_firewall "$GATEWAY_PORT"; then
        fw_open=true
    fi
    echo -n "端口监听状态: "
    listening=false
    if check_listening "$GATEWAY_PORT" "$GATEWAY_BIND"; then
        listening=true
    fi
    echo ""

    risk_analysis "$GATEWAY_BIND" "$GATEWAY_PORT" "$GATEWAY_MODE" "$GATEWAY_TOKEN" "$fw_open" "$listening"

    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}   检测完成${NC}"
    echo -e "${BLUE}======================================${NC}"
}

# 主函数
main() {
    # 解析全局选项
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                break
                ;;
        esac
    done

    # 查找配置文件
    if [[ -z "$CONFIG_FILE" ]]; then
        CONFIG_FILE=$(find_config) || {
            exit 1
        }
        echo -e "${CYAN}使用配置文件: $CONFIG_FILE${NC}"
    elif [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}错误: 指定的配置文件不存在: $CONFIG_FILE${NC}" >&2
        exit 1
    fi

    # 处理子命令
    local cmd="${1:-check}"
    shift 2>/dev/null || true

    case "$cmd" in
        check)
            security_check
            ;;
        view)
            view_config
            ;;
        set-port)
            set_port "$1"
            ;;
        set-bind)
            set_bind "$1"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            echo -e "${RED}错误: 未知命令 '$cmd'${NC}" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"