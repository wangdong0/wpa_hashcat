#!/bin/bash

file_selector() {
    # 保存原始终端状态
    local OLD_TERM
    OLD_TERM=$(stty -g 2>/dev/null)
    
    # 保存当前进程ID（用于本地化信号处理）
    local TOP_PID=$$
    
    # 清理函数 - 完全恢复原始状态
    cleanup() {
        # 恢复主屏幕缓冲区
        echo -en "\033[?1049l" >&2
        
        # 恢复光标
        tput cnorm >&2
        
        # 重置文本样式
        tput sgr0 >&2
        
        # 恢复终端设置（仅在OLD_TERM有值时）
        if [[ -n "$OLD_TERM" ]]; then
            stty "$OLD_TERM" >&2
        fi
    }
	
	normalize_path() {
		local path="$1"
		# 替换任意数量连续斜杠为单斜杠
		path=$(echo "$path" | sed 's|//\+|/|g')
		# 特殊处理根目录的异常形式
		[[ "$path" == "//" ]] && path="/"
		echo "$path"
	}

    # 信号捕获
    trap 'cleanup; exit 1' EXIT INT TERM
    
    # 设置起始目录（支持可选参数）
    local start_dir="${1:-$(pwd)}"
    local restrict_mode=0
	local custom_prompt
	local file_exts=() 
	
	# 修复参数解析逻辑
	if [[ "$2" == "-r" || "$2" == "--restrict" ]]; then
		restrict_mode=1
		custom_prompt="${3:-请选择一个文件:}"
		if [[ -n "${4:-}" ]]; then
			IFS=',' read -ra file_exts <<< "${4// /}"   # 移除空格并分割
		fi
	else
		# 当没有使用-r选项时，第二个参数是提示
		custom_prompt="${2:-请选择一个文件:}"
		if [[ -n "${3:-}" ]]; then
			IFS=',' read -ra file_exts <<< "${3// /}"   # 移除空格并分割
		fi
	fi
	
    local current_dir="$start_dir"
    current_dir=$(normalize_path "$current_dir")
    local dir_stack=("$current_dir")
    local selected=0 current_page=0 selected_file=""

    # 定义颜色（局部变量）
    local COLOR_NORMAL=$(tput sgr0)
    local COLOR_HIGHLIGHT=$(tput rev)
    local COLOR_TITLE=$(tput setaf 14)
    local COLOR_SELECTION=$(tput setaf 2)
    local COLOR_DIR=$(tput setaf 6)
    local COLOR_BACK=$(tput setaf 3)
    local COLOR_PAGE=$(tput setaf 5)

    # 启用备用屏幕缓冲区
    echo -en "\033[?1049h" >&2
    
    # 隐藏光标
    tput civis >&2
    
    # 获取目录内容
    get_directory_contents() {
        local dir="$1"
        local contents=()
        
		# 添加上级目录选项
        [[ "$dir" != "/" && ( "$restrict_mode" -eq 0 || "$current_dir" != "$start_dir" ) ]]  && contents+=("..")
        
		# 获取目录（始终显示）
        while IFS= read -r -d $'\0' item; do
            [[ -d "$item" ]] && contents+=("${item#$dir/}/")
        done < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
		
		# 获取文件（支持多种后缀过滤）
		if (( ${#file_exts[@]} > 0 )); then
			# 修复：构建正确的find查询条件
			local find_args=()
			for ext in "${file_exts[@]}"; do
				# 移除可能的空格
				ext="${ext// /}"
				[[ -n "$ext" ]] && find_args+=(-name "*.${ext}" -o)
			done
			
			# 移除最后一个多余的 -o
			if (( ${#find_args[@]} > 0 )); then
				unset 'find_args[${#find_args[@]}-1]'
				
				# 执行带后缀过滤的查询
				while IFS= read -r -d $'\0' item; do
					contents+=("${item#$dir/}")
				done < <(find "$dir" -mindepth 1 -maxdepth 1 -type f \( "${find_args[@]}" \) -print0 2>/dev/null)
			fi
		else
			# 无后缀过滤时获取所有文件
			while IFS= read -r -d $'\0' item; do
				[[ -f "$item" ]] && contents+=("${item#$dir/}")
			done < <(find "$dir" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
		fi
        
        echo "${contents[@]}"
    }

    # 显示菜单（输出到 STDERR）
    show_menu() {
        local terminal_rows=$(tput lines)
        local terminal_cols=$(tput cols)
        ((items_per_page = terminal_rows - 6))
        
        tput clear >&2
        tput cup 0 0 >&2
        
        # 显示标题
        if [[ "$restrict_mode" -eq 0 ]]; then
            echo -e "${COLOR_TITLE}当前目录: $current_dir" >&2
        else
            if [ "$current_dir" == "$start_dir" ]; then
                echo -e "${COLOR_TITLE}当前目录 (锁定): $current_dir" >&2
            else
                echo -e "${COLOR_TITLE}当前目录: $current_dir" >&2
            fi
        fi
        echo -e "${custom_prompt}${COLOR_NORMAL}" >&2
        echo >&2

        # 获取内容
        local MENU_OPTIONS=($(get_directory_contents "$current_dir"))
        local num_options=${#MENU_OPTIONS[@]}
        ((total_pages = (num_options + items_per_page - 1) / items_per_page))
        ((start_index = current_page * items_per_page))
        ((end_index = start_index + items_per_page))
        ((end_index > num_options)) && end_index=$num_options

        # 显示选项
        for ((i = start_index; i < end_index; i++)); do
            local item="${MENU_OPTIONS[$i]}"
            local display_item="$item"
            local display_index=$((i - start_index))
            
            if [[ "$item" == ".." ]]; then
                display_item="${COLOR_BACK}[返回上级]${COLOR_NORMAL}"
            elif [[ "$item" == */ ]]; then
                display_item="${COLOR_DIR}[目录] ${item%/}${COLOR_NORMAL}"
            fi
            
            if [[ $display_index -eq $selected ]]; then
                echo -e "${COLOR_HIGHLIGHT}${COLOR_SELECTION}➔ $display_item${COLOR_NORMAL}" >&2
            else
                echo -e "  $display_item" >&2
            fi
        done

        # 显示页码
        tput cup $((terminal_rows - 2)) 0 >&2
        if ((total_pages > 1)); then
            echo -e "${COLOR_PAGE}页码: $((current_page + 1))/$total_pages" >&2
            echo -en "↑/↓ 导航  ←/→ 翻页  Enter 确认  B 返回上级  Q 退出${COLOR_NORMAL}" >&2
        else
            echo -en "${COLOR_PAGE}↑/↓ 导航  Enter 确认  B 返回上级  Q 退出${COLOR_NORMAL}" >&2
        fi
        tput ed >&2
    }

    # 主循环
    show_menu
    local key
    while true; do
        # 读取单个键
        IFS= read -rsn1 key
        
        # 处理方向键
        if [[ "$key" == $'\x1B' ]]; then
            # 读取额外的2个字节（方向键）
            read -rsn2 -t 0.01 key
            case "$key" in
                '[A') # 上箭头
                    if (( selected > 0 )); then
                        ((selected--))
                    elif (( current_page > 0 )); then
                        ((current_page--))
                        # 计算上一页的项目数
                        local prev_items=$(( (terminal_rows - 6) ))
                        ((selected = prev_items - 1))
                    fi
                    show_menu
                    ;;
                '[B') # 下箭头
                    local terminal_rows=$(tput lines)
                    ((items_per_page = terminal_rows - 6))
                    local MENU_OPTIONS=($(get_directory_contents "$current_dir"))
                    local num_options=${#MENU_OPTIONS[@]}
                    ((items_on_page = items_per_page))
                    (( items_on_page > num_options - current_page * items_per_page )) && \
                        items_on_page=$(( num_options - current_page * items_per_page ))
                    
                    if (( selected < items_on_page - 1 )); then
                        ((selected++))
                    elif (( current_page < total_pages - 1 )); then
                        ((current_page++))
                        selected=0
                    fi
                    show_menu
                    ;;
                '[D') # 左箭头
                    if (( current_page > 0 )); then
                        ((current_page--))
                        selected=0
                        show_menu
                    fi
                    ;;
                '[C') # 右箭头
                    local terminal_rows=$(tput lines)
                    ((items_per_page = terminal_rows - 6))
                    local MENU_OPTIONS=($(get_directory_contents "$current_dir"))
                    local num_options=${#MENU_OPTIONS[@]}
                    ((total_pages = (num_options + items_per_page - 1) / items_per_page))
                    
                    if (( current_page < total_pages - 1 )); then
                        ((current_page++))
                        selected=0
                        show_menu
                    fi
                    ;;
            esac
        else
            # 处理普通键
            case "$key" in
                '') # 回车
                    local terminal_rows=$(tput lines)
                    ((items_per_page = terminal_rows - 6))
                    local MENU_OPTIONS=($(get_directory_contents "$current_dir"))
                    local num_options=${#MENU_OPTIONS[@]}
                    ((global_index = current_page * items_per_page + selected))
                    
                    if (( global_index < num_options )); then
                        local selected_item="${MENU_OPTIONS[$global_index]}"
                        
                        if [[ "$selected_item" == ".." ]]; then
                            if [[ "$restrict_mode" -eq 1 ]] && [ "$current_dir" == "$start_dir" ]; then
                                continue
                            fi
                            [[ "$current_dir" != "/" ]] && current_dir=$(dirname "$current_dir")
                            [[ "$current_dir" == "//" ]] && current_dir="/"
                            current_dir=$(normalize_path "$current_dir")
                            dir_stack+=("$current_dir")
                            current_page=0
                            selected=0
                            show_menu
                        elif [[ "$selected_item" == */ ]]; then
                            local new_dir=$(normalize_path "$current_dir/${selected_item%/}")
                            dir_stack+=("$new_dir")
                            current_dir="$new_dir"
                            current_page=0
                            selected=0
                            show_menu
                        else
                            selected_file=$(normalize_path "${current_dir%/}/$selected_item")
                            break
                        fi
                    fi
                    ;;
                [bB]) # 返回上级
                    if [[ "$restrict_mode" -eq 1 ]] && [ "$current_dir" == "$start_dir" ]; then
                        continue
                    fi
                    [[ "$current_dir" != "/" ]] && current_dir=$(dirname "$current_dir")
                    current_dir=$(normalize_path "$current_dir")
                    dir_stack+=("$current_dir")
                    current_page=0
                    selected=0
                    show_menu
                    ;;
                [qQ]) # 退出
                    selected_file=""
                    break
                    ;;
            esac
        fi
    done

    cleanup
    echo "$selected_file"  # 输出结果到 STDOUT
    [[ -n "$selected_file" ]] && return 0 || return 1
}

# 使用示例
# source ./file_selector.sh
# echo "==== 文件选择器演示 ===="
# echo "当前目录内容:"
# ls -l
# 
# selected_path=$(file_selector "$HOME" -r "请选择文本文件:" "txt")
# 
# if [[ -n "$selected_path" ]]; then
#     echo "您选择了: $selected_path"
#     echo "文件内容:"
#     head -n 5 "$selected_path" 2>/dev/null || echo "（目录内容无法显示）"
# else
#     echo "未选择文件"
# fi
# 
# echo "==== 脚本继续执行 ===="

export -f file_selector