#!/bin/bash

# 交互式菜单函数（关键修复）
interactive_menu() {
    trap 'cleanup' EXIT
    local -n options_ref=$1
    local title=${2:-"请选择一个选项:"}
    local selected=0
    local num_options=${#options_ref[@]}
    
    # 初始化终端
    local OLD_TERM=$(stty -g)
    stty -echo -icanon time 0 min 0
    tput smcup >/dev/tty
    tput civis >/dev/tty
    clear >/dev/tty
    
    # 颜色定义
    local COLOR_NORMAL=$(tput sgr0)
    local COLOR_HIGHLIGHT=$(tput rev)
    local COLOR_TITLE=$(tput setaf 4)
    local COLOR_SELECTION=$(tput setaf 2)

    # 显示菜单（修复污染源）
    show_menu() {
        tput cup 0 0 >/dev/tty
        printf "${COLOR_TITLE}%s${COLOR_NORMAL}\n\n" "$title" >/dev/tty
        
        for ((i=0; i<num_options; i++)); do
            if ((i == selected)); then
                printf "${COLOR_HIGHLIGHT}${COLOR_SELECTION}➔ %s${COLOR_NORMAL}\n" "${options_ref[$i]}" >/dev/tty
            else
                printf "  %s\n" "${options_ref[$i]}" | expand -t4 >/dev/tty
            fi
        done
        tput ed >/dev/tty
    }

    # 事件处理
    local buffer=""
    local return_index=-1
    
    while true; do
        show_menu
        read -rsn1 input
        buffer+="$input"
        
        case "$buffer" in
            $'\x1B[A')  # 上箭头
                ((selected = (selected - 1 + num_options) % num_options))
                buffer=""
                ;;
            $'\x1B[B')  # 下箭头
                ((selected = (selected + 1) % num_options))
                buffer=""
                ;;
            "")  # 回车
                return_index=$selected
                break
                ;;
            [qQ])  # 退出
                break
                ;;
            *)
                [[ ! "$buffer" =~ ^$'\x1B' ]] && buffer=""
                ;;
        esac
    done

    # 清理终端
    cleanup() { 
        tput sgr0 2>/dev/null >/dev/tty
        stty "$OLD_TERM" 2>/dev/null
        tput cnorm >/dev/tty
        tput rmcup >/dev/tty
    }
    cleanup

    # 关键修复：确保纯净数字输出
    if (( return_index >= 0 )); then
        printf "%d" "$return_index"  # 使用printf避免换行符[4](@ref)
        return 0
    else
        return 1
    fi
}

# # ============== 调用示例 ============== #
# source ./interactive_menu.sh
# menu_items=("查看CPU信息" "检查磁盘空间" "监控网络状态" "返回上级菜单")
# 
# # 捕获纯净数字索引
# choice_index=$(interactive_menu menu_items "系统管理主菜单")
# interactive_menu_exit=$?
# 
# # 安全获取选项（避免空值）
# if [[ -n "$choice_index" ]] && [[ "$choice_index" =~ ^[0-9]+$ ]]; then
#     selected_item="${menu_items[$choice_index]}"
# else
#     selected_item="无效选择"
# fi
# 
# case $interactive_menu_exit in
#     0) echo "用户选择: $selected_item (索引: $choice_index)" ;;
#     1) echo "用户取消选择" ;;
# esac

export -f interactive_menu








interactive_menu_csv() {
    trap 'cleanup' EXIT
    local csv_data="$1"
    local select_tip=${2:-"请选择一个选项:"}
    local selected=0
    local return_index=-1
    
    # 解析CSV数据
    IFS=$'\n' read -d '' -r -a lines <<< "$csv_data"
    local header="${lines[0]}"
    local -a options=("${lines[@]:1}")
    local num_options=${#options[@]}
    
    # 字符宽度映射表 - 针对常见中文字符优化
    declare -A char_width_map
    
    # 计算字符串的显示宽度（考虑全角字符）
    str_display_width() {
		local str="$1"
		local width=0
		local char full_char hex_bytes codepoint
		
		# 按字符遍历字符串
		while IFS= read -r -n1 char; do
			[[ -z "$char" ]] && continue  # 跳过空字符
			
			# 读取完整UTF-8字符
			full_char="$char"
			local first_byte=$(printf "%d" "'$char")
			
			# 1字节字符（ASCII）
			if (( first_byte < 128 )); then
				((width++))
				continue
			fi
			
			# 多字节字符处理
			if (( first_byte >= 194 && first_byte <= 223 )); then  # 2字节
				read -r -n1 char; full_char+="$char"
			elif (( first_byte >= 224 && first_byte <= 239 )); then  # 3字节
				read -r -n1 char; full_char+="$char"
				read -r -n1 char; full_char+="$char"
			elif (( first_byte >= 240 && first_byte <= 244 )); then  # 4字节
				read -r -n1 char; full_char+="$char"
				read -r -n1 char; full_char+="$char"
				read -r -n1 char; full_char+="$char"
			fi
			
			# 获取UTF-8字节的十六进制表示
			hex_bytes=$(echo -n "$full_char" | xxd -p)
			
			# 转换UTF-8到Unicode码点
			case ${#hex_bytes} in
				4)  # 2字节
					codepoint=$(((0x${hex_bytes:0:2} & 0x1F) << 6 | (0x${hex_bytes:2:2} & 0x3F))) ;;
				6)  # 3字节
					codepoint=$(((0x${hex_bytes:0:2} & 0x0F) << 12 | (0x${hex_bytes:2:2} & 0x3F) << 6 | (0x${hex_bytes:4:2} & 0x3F))) ;;
				8)  # 4字节
					codepoint=$(((0x${hex_bytes:0:2} & 0x07) << 18 | (0x${hex_bytes:2:2} & 0x3F) << 12 | (0x${hex_bytes:4:2} & 0x3F) << 6 | (0x${hex_bytes:6:2} & 0x3F))) ;;
				*)  # 其他情况
					codepoint=0 ;;
			esac
			
			# 判断宽字符（添加韩文字母范围 U+3130–U+318F）
			if (( codepoint >= 0x4E00 && codepoint <= 0x9FFF || codepoint >= 0x3400 && codepoint <= 0x4DBF || codepoint >= 0x3040 && codepoint <= 0x309F || codepoint >= 0x30A0 && codepoint <= 0x30FF || codepoint >= 0x3130 && codepoint <= 0x318F || codepoint >= 0xAC00 && codepoint <= 0xD7AF || codepoint >= 0xFF00 && codepoint <= 0xFFEF || codepoint >= 0x3000 && codepoint <= 0x303F )); then
				((width += 2))
			else
				((width++))
			fi
		done <<< "$str"
		
		echo "$width"
	}
    
    # 确定每列的最大宽度
    local -a max_widths
    IFS=',' read -r -a headers <<< "$header"
    for ((i=0; i<${#headers[@]}; i++)); do
        max_widths[$i]=$(str_display_width "${headers[$i]}")
    done
    
    # 计算每列的最大宽度（包括选项）
    for line in "${options[@]}"; do
        IFS=',' read -r -a fields <<< "$line"
        for ((i=0; i<${#fields[@]}; i++)); do
            local width=$(str_display_width "${fields[$i]}")
            if (( width > max_widths[i] )); then
                max_widths[$i]=$width
            fi
        done
    done
    
    # 列间隔设置
    local MIN_SPACING=3
    local MAX_SPACING=5
    local num_columns=${#max_widths[@]}
    
    # 计算总内容宽度
    local total_content_width=0
    for width in "${max_widths[@]}"; do
        ((total_content_width += width))
    done
    
    # 获取终端宽度
    local term_width=$(tput cols)
    local available_space=$((term_width - total_content_width))
    
    # 计算最佳间隔
    if (( num_columns > 1 )); then
        local ideal_spacing=$((available_space / (num_columns - 1)))
        if (( ideal_spacing < MIN_SPACING )); then
            spacing=$MIN_SPACING
        elif (( ideal_spacing > MAX_SPACING )); then
            spacing=$MAX_SPACING
        else
            spacing=$ideal_spacing
        fi
    else
        spacing=$MIN_SPACING
    fi
    
    # 格式化行数据
    format_row() {
        local -a fields=("$@")
        local formatted=""
        
        for ((i=0; i<${#fields[@]}; i++)); do
            local field="${fields[$i]}"
            local field_width=$(str_display_width "$field")
            local padding=$((max_widths[i] - field_width))
            
            formatted+="${field}"
            
            # 添加填充空格
            for ((j=0; j<padding; j++)); do
                formatted+=" "
            done
            
            # 添加列间隔，最后一列除外
            if (( i < ${#fields[@]} - 1 )); then
                for ((j=0; j<spacing; j++)); do
                    formatted+=" "
                done
            fi
        done
        
        echo "$formatted"
    }
    
    # 格式化表头
    IFS=',' read -r -a header_fields <<< "$header"
    formatted_header=$(format_row "${header_fields[@]}")
    
    # 格式化选项
    local -a formatted_options
    for line in "${options[@]}"; do
        IFS=',' read -r -a fields <<< "$line"
        formatted_options+=("$(format_row "${fields[@]}")")
    done
    
    # 初始化终端
    local OLD_TERM=$(stty -g)
    stty -echo -icanon time 0 min 0
    tput smcup >/dev/tty
    tput civis >/dev/tty
    clear >/dev/tty
    
    # 颜色定义
    local COLOR_NORMAL=$(tput sgr0)
    local COLOR_HIGHLIGHT=$(tput rev)
    local COLOR_select_tip=$(tput setaf 4)    # 蓝色标题
    local COLOR_HEADER=$(tput setaf 6)    # 青色表头
    local COLOR_SELECTION=$(tput setaf 2) # 绿色选中项
    local COLOR_PROMPT=$(tput setaf 3)    # 黄色提示
    
    # 高亮整行（包括间隔）
    highlight_line() {
        local line="$1"
        local highlighted="${COLOR_HIGHLIGHT}${COLOR_SELECTION}➔ ${line}${COLOR_NORMAL}"
        echo "$highlighted"
    }
    
    # 显示菜单
    show_menu() {
        tput cup 0 0 >/dev/tty
        
        # 显示表头
        printf "  ${COLOR_HEADER}%s${COLOR_NORMAL}\n\n" "$formatted_header" >/dev/tty
        
        # 显示选项
        for ((i=0; i<num_options; i++)); do
            if ((i == selected)); then
                printf "%s\n" "$(highlight_line "${formatted_options[$i]}")" >/dev/tty
            else
                printf "  %s\n" "${formatted_options[$i]}" >/dev/tty
            fi
        done
        
        # 计算提示信息应该显示的位置
        local prompt_row=$((num_options + 3))
        tput cup $prompt_row 0 >/dev/tty
        tput el >/dev/tty
        printf "${COLOR_PROMPT}%s${COLOR_NORMAL}\n" "$select_tip" >/dev/tty
        printf "${COLOR_PROMPT}↑↓: 选择  Enter: 确认  Q: 退出${COLOR_NORMAL}\n" >/dev/tty
        
        # 清除屏幕剩余部分
        tput ed >/dev/tty
    }

    # 事件处理
    local buffer=""
    
    while true; do
        show_menu
        read -rsn1 input
        buffer+="$input"
        
        case "$buffer" in
            $'\x1B[A')  # 上箭头
                ((selected = (selected - 1 + num_options) % num_options))
                buffer=""
                ;;
            $'\x1B[B')  # 下箭头
                ((selected = (selected + 1) % num_options))
                buffer=""
                ;;
            "")  # 回车
                return_index=$selected
                break
                ;;
            [qQ])  # 退出
                break
                ;;
            *)
                [[ ! "$buffer" =~ ^$'\x1B' ]] && buffer=""
                ;;
        esac
    done

    # 清理终端
    cleanup() { 
        tput sgr0 2>/dev/null >/dev/tty
        stty "$OLD_TERM" 2>/dev/null
        tput cnorm >/dev/tty
        tput rmcup >/dev/tty
    }
    cleanup

    # 返回选择结果
    if (( return_index >= 0 )); then
        printf "%d" "$return_index"
        return 0
    else
        return 1
    fi
}

# # ============== 调用示例 ============== #
# source ./interactive_menu_csv.sh
# csv="SSID名称,MAC地址,加密类型,握手信息
# 好日子-WiFi-5G,11:22:33:AA:BB:CC,WPA2,2 handshake
# 303-4g,22:55:44:22:EE:DD,WPA2,1 handshake
# 303,55:66:77:88:99:AA,WPA2,1 handshake"
# 
# selected=$(interactive_menu_csv "$csv" "请选择一个WiFi网络:")
# if [ $? -eq 0 ]; then
#     echo "你选择了选项 $selected"
# else
#     echo "已取消选择"
# fi

export -f interactive_menu_csv