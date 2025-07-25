#!/bin/bash

# 获取脚本的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/file_selector.sh"
source "$SCRIPT_DIR/interactive_menu.sh"
source "$SCRIPT_DIR/auto_extract.sh"
source "$SCRIPT_DIR/hashcat.rc"


function get_info_from_hc22000() {
	local hc22000_file=${1}
	local hash_info=$(hcxhashtool -i "$hc22000_file" --info=stdout 2>/dev/null | iconv -c -t UTF-8)
	
	if [ "$hash_info" == "no hashes loaded" ]; then
		return 1
	fi
	echo "$hash_info" | awk -F': ' '
		# 定义函数：格式化MAC地址为 XX:XX:XX:XX:XX:XX
		function format_mac(mac) {
			# 转换为大写
			mac = toupper(mac)
			# 插入冒号：每两个字符后添加一个冒号
			result = substr(mac, 1, 2)
			for (i = 3; i <= length(mac); i += 2) {
				result = result ":" substr(mac, i, 2)
			}
			return result
		}
		
		BEGIN {
			ssid = ""; mac_ap = ""; key_version = ""; in_group = 0
			has_mic = 0; has_pmkid = 0
		}
		/^[[:space:]]*$/ {
			if (in_group && ssid != "" && mac_ap != "" && key_version != "") {
				print ssid "," mac_ap "," key_version "," has_mic "," has_pmkid
				ssid = ""; mac_ap = ""; key_version = ""
				has_mic = 0; has_pmkid = 0
			}
			in_group = 0
		}
		/^SSID\.{0,}:/ {
			ssid = $2
			in_group = 1
		}
		/^MAC_AP\.{0,}:/ {
			# 提取MAC地址部分(冒号后第一个空格前的内容)
			mac_part = $2
			# 移除括号及其内容
			sub(/[[:space:]]*\(.*/, "", mac_part)
			# 格式化MAC地址
			mac_ap = format_mac(mac_part)
		}
		/^KEY VERSION\.{0,}:/ {
			key_version = $2
		}
		/^MIC\.{0,}:/ {
			has_mic = 1
		}
		/^PMKID\.{0,}:/ {
			has_pmkid = 1
		}
		END {
			if (ssid != "" && mac_ap != "" && key_version != "") {
				print ssid "," mac_ap "," key_version "," has_mic "," has_pmkid
			}
		}
	' | awk -F',' '
		BEGIN {
			FS = ","  # 字段分隔符为逗号
			idx = 0
		}
		
		# 处理每一行数据，按MAC地址分组累加，并记录顺序
		{
			mac = $2
			if (!seen[mac]) {  # 首次出现的MAC地址
				order[idx++] = mac
				seen[mac] = 1
			}
			ssid[mac] = $1
			key_version[mac] = $3
			mic_sum[mac] += $4 + 0  # 转换为数字
			pmkid_sum[mac] += $5 + 0  # 转换为数字
		}
		
		# 按原始顺序输出结果
		END {
			print "SSID名称,MAC地址,加密类型,握手信息"
			for (i = 0; i < idx; i++) {
				mac = order[i]
				# 构建汇总字符串
				result = ""
				if (mic_sum[mac] > 0) {
					result = mic_sum[mac] " handshake"
				}
				if (pmkid_sum[mac] > 0) {
					if (result != "") {
						result = result " & "
					}
					result = result pmkid_sum[mac] " pmkid"
				}
				# 输出合并后的行
				print ssid[mac] "," mac "," key_version[mac] "," result
			}
		}
	'
}

convert_hc22000_file=/tmp/wpa_hashcat_temp.hc22000

function cap_to_hc22000() {

	local cap_file=${1}
	local hc22000_file=${2}
	
	case "${cap_file}" in
		*.cap|*.pcap|*.pcapng)
			local hcxpcapngtool_output=$(hcxpcapngtool "${cap_file}" -o "${hc22000_file}" 2>&1)
			if [ ! -f "$hc22000_file" ]; then
				if echo "$hcxpcapngtool_output" | grep -q "Information: no hashes written to hash files"; then
					echo "[!] 报文中未包含足够的WPA/WPA2握手信息！"
					if echo "$hcxpcapngtool_output" | grep -q "(PMK not recoverable)";then
						echo "[i] 检测到WPA3的握手信息(注意：WPA3无法通过hash计算破解，若攻击目标为WPA3网络，这是不可取的)。"
					fi
				elif echo "$hcxpcapngtool_output" | grep -q "unsupported dump file format"; then
					echo "[!] 不支持的文件格式，请确保文件没有损坏。"
				else
					echo "[!] 未知错误，报文转换hc22000格式失败！"
				fi
				read -p "输入回车键退出..."
				exit 1
			fi
			;;
		*.hccapx)
			"$SCRIPT_DIR/hccapx_to_hc22000.py" "${cap_file}" -o "${hc22000_file}" >/dev/null 2>&1
			if [ ! -f "$hc22000_file" ]; then
				echo "[!] 报文转换hc22000格式失败，请确保文件没有损坏！"
				read -p "输入回车键退出..."
				exit 1
			fi
			;;
		*.hc22000)
			get_info_from_hc22000 "${cap_file}" >/dev/null 2>&1
			if [ $? != 0 ]; then
				echo "[!] 未读取到可用的哈希信息，请确保文件没有损坏！"
				read -p "输入回车键退出..."
				exit 1
			fi
			cp "${cap_file}" "${hc22000_file}"
			;;
		*)
			echo "[!] 不支持的握手包文件格式！(目前支持格式 .cap .pcap .pcapng .hccapx .hc22000)" >&2
			read -p "输入回车键退出..."
			exit 1
			;;
	esac
	
	
}

function exitWhenFileAbsent() {
	local file
	local error_text
	
	while [[ $# -gt 0 ]]; do
		case "$1" in
			-f)
				if [ -n "$2" ]; then
					case "$2" in
						-[a-z]) ;;
						*) file="$2"; shift ;;
					esac
				fi
				;;
			-t)
				if [ -n "$2" ]; then
					case "$2" in
						-[a-z]) ;;
						*) error_text="$2"; shift ;;
					esac
				fi
				;;
			esac
			shift
	done
	error_text=${error_text:-"[!] 文件为空或不存在！"}
	
	if [ -n "$file" ]; then
		if [ -f "$file" ] || [ "$(ls -A "$file" 2>/dev/null | wc -l)" -gt 0 ]; then
			return 0
		fi
	fi
	echo "${error_text}"
	read -p "输入回车键退出..."
	exit 1
}


function format_crack_options() {
  local input="$1"
  local output=""
  local IFS=$'\n'
  local line_num=0
  
  input=$(echo "$input" | grep -v '^$')
  for line in $input; do
    
    # 分割字段
    IFS=',' read -r col1 col2 col3 col4 col5 col6 <<< "$line"
    
    # 处理第一列：添加序号
    processed_col1="($line_num) $col1"
	((line_num++))
    
    # 处理第四列：添加方括号
    if [[ -n "$col4" ]]; then
      processed_col4="[${col4}]"
    else
      processed_col4=""
    fi
    
    # 处理第六列：添加星号
    stars=""
    recommend=""
    if [[ -n "$col6" && "$col6" -gt 0 ]]; then
      # 生成星号
      for ((i=1; i<=col6; i++)); do
        stars+="⭐️"
      done
      
      # 检查是否需要添加推荐
      if [[ "$col6" -ge 5 ]]; then
        recommend="(推荐)"
      fi
    fi
    processed_col6="${stars}${recommend}"
    
    # 拼接结果
    output+="${processed_col1},${col2},${col3},${processed_col4},${col5},${processed_col6}\n"
  done
  
  # 输出结果(去除末尾的换行符)
  echo -e "${output%\\n}"
}


function calculate_password_count_of_mask() {

	# 定义标准组合字符集及其长度
	declare -A charsets=(
		["l"]=26    # ?l: 小写字母
		["u"]=26    # ?u: 大写字母
		["d"]=10    # ?d: 数字
		["h"]=16    # ?h: 十六进制小写
		["H"]=16    # ?H: 十六进制大写
		["s"]=33    # ?s: 特殊字符(包括空格)
		["a"]=95    # ?a: 所有可打印字符
		["b"]=256   # ?b: 二进制字节
	)
	
	# 计算自定义组合的大小(正确处理特殊字符)
	calculate_size() {
		local str="$1"
		local len=${#str}
		local i=0
		local size=0
	
		while ((i < len)); do
			char="${str:$i:1}"
			
			if [[ "$char" == "?" ]]; then
				# 处理占位符
				if ((i+1 < len)); then
					next_char="${str:$((i+1)):1}"
					if [[ -n "${charsets[$next_char]}" ]]; then
						size=$((size + ${charsets[$next_char]}))
						i=$((i+2))
						continue
					fi
				fi
			fi
			
			# 普通字符计数
			size=$((size + 1))
			i=$((i+1))
		done
	
		echo "$size"
	}
	
	calculate_mask_of_hcmask() {
		input=${1}
		#input='?l?d?u,?l?d,?l?d*!$@_,?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d'
		# 安全分割输入字符串(避免特殊字符被解释)
		parts=()
		current=""
		len=${#input}
		for ((i=0; i<len; i++)); do
			char="${input:$i:1}"
			if [[ "$char" == "," ]]; then
				parts+=("$current")
				current=""
			else
				current+="$char"
			fi
		done
		parts+=("$current")  # 添加最后一个部分
		
		# 获取模式字符串和自定义定义
		pattern=${parts[-1]}
		custom_defs=("${parts[@]:0:${#parts[@]}-1}")
		
		# 计算自定义组合的大小
		declare -a custom_sizes
		for def in "${custom_defs[@]}"; do
			size=$(calculate_size "$def")
			custom_sizes+=("$size")
			#echo "定义: '$def' = 大小: $size" >&2
		done
		
		# 解析模式字符串并构建表达式
		expr="1"
		i=0
		len=${#pattern}
		
		while ((i < len)); do
			char="${pattern:$i:1}"
			
			if [[ "$char" == "?" ]]; then
				if ((i+1 < len)); then
					next_char="${pattern:$((i+1)):1}"
					
					# 处理自定义组合引用(?1, ?2 等)
					if [[ "$next_char" =~ [0-9] ]]; then
						index=$((next_char))
						if ((index >= 1 && index <= ${#custom_sizes[@]})); then
							value=${custom_sizes[$((index-1))]}
							expr="$expr * $value"
							#echo "处理 ?$next_char = $value" >&2
							i=$((i+2))
							continue
						fi
					# 处理预定义占位符
					elif [[ -n "${charsets[$next_char]}" ]]; then
						value=${charsets[$next_char]}
						expr="$expr * $value"
						#echo "处理 ?$next_char = $value" >&2
						i=$((i+2))
						continue
					fi
				fi
			fi
			
			# 处理普通字符(大小为1)
			expr="$expr * 1"
			#echo "处理 '$char' = 1" >&2
			i=$((i+1))
		done
		
		# 计算最终结果
		#echo "最终表达式: $expr" >&2
		result=$(echo "$expr" | bc)
		echo "$result"
	}
	
	
	calculate_mask_of_string() {
		# 输入字符串
		input_str="$1"
		#$input_str="-1 ?l?u ?1?l?l?l?l?l19?d?d"
		
		# 分割输入字符串为数组
		IFS=' ' read -ra parts <<< "$input_str"
		
		# 存储自定义组合的字典
		declare -A custom_dict
		pattern=""
		i=0
		
		# 解析自定义组合和模式字符串
		while [ $i -lt ${#parts[@]} ]; do
			part="${parts[$i]}"
			if [[ "$part" == -* ]]; then
				# 提取自定义组合ID(去掉'-')
				custom_id="${part:1}"
				((i++))
				if [ $i -ge ${#parts[@]} ]; then
					#echo "Error: Missing definition for custom set $custom_id"
					return 1
				fi
				def_str="${parts[$i]}"
				total_size=0
				
				# 解析定义字符串
				j=0
				while [ $j -lt ${#def_str} ]; do
					if [ "${def_str:$j:1}" = "?" ]; then
						# 处理占位符
						((j++))
						if [ $j -lt ${#def_str} ]; then
							char="${def_str:$j:1}"
							if [[ "$char" =~ [0-9a-zA-Z] ]]; then
								# 预定义占位符
								if [ -n "${charsets[$char]}" ]; then
									total_size=$((total_size + ${charsets[$char]}))
								fi
								((j++))
							else
								# 无效占位符，视为固定字符'?'
								total_size=$((total_size + 1))
								((j++))
							fi
						else
							# '?' 在末尾，视为固定字符
							total_size=$((total_size + 1))
						fi
					else
						# 处理固定字符
						total_size=$((total_size + 1))
						((j++))
					fi
				done
				
				# 存储自定义组合大小
				custom_dict[$custom_id]=$total_size
			else
				# 第一个非自定义组合标识的部分作为模式字符串
				pattern="$part"
				break
			fi
			((i++))
		done
		
		if [ -z "$pattern" ]; then
			#echo "Error: Pattern string not found"
			return 1
		fi
		
		# 计算模式字符串的组合总数
		total_combinations=1
		j=0
		while [ $j -lt ${#pattern} ]; do
			if [ "${pattern:$j:1}" = "?" ]; then
				# 处理占位符
				((j++))
				if [ $j -lt ${#pattern} ]; then
					char="${pattern:$j:1}"
					if [[ "$char" =~ [0-9] ]]; then
						# 自定义占位符
						if [ -n "${custom_dict[$char]}" ]; then
							size=${custom_dict[$char]}
						else
							size=0
						fi
					else
						# 预定义占位符
						if [ -n "${charsets[$char]}" ]; then
							size=${charsets[$char]}
						else
							size=0
						fi
					fi
					total_combinations=$((total_combinations * size))
					((j++))
				else
					# '?' 在末尾，视为固定字符(大小为1)
					((j++))
				fi
			else
				# 处理固定字符(大小为1)
				((j++))
			fi
		done
		
		echo "$total_combinations"
	}
	

	local mask=$1
	local password_count
	
	if [[ $mask == *.hcmask ]]; then
		if [ -f "$mask" ]; then
			password_count=0
			local count
			while read -r line; do
				count=$(calculate_mask_of_hcmask "$line")
				if [[ -n $count ]]; then
					password_count=$((password_count+count))
				fi
			done < <(sed -e '/^$/d' -e '/^#/d' -e 's/\\,//g' -e 's/??//g' "$mask")
		fi
	else
		password_count=$(calculate_mask_of_string "$mask")
	fi
	echo $password_count
}


#确保密码大于等于8
#function run_hashcat_wpa() {
#	
#}









####################主程序######################

version=0.10
echo ""
echo -e         "\033[1m                             __              __              __  \033[0m"
echo -e         "\033[1m   _    __ ___  ___ _       / /  ___ _ ___  / /  ____ ___ _ / /_ \033[0m"
echo -e         '\033[1m  | |/|/ // _ \/ _ `/      / _ \/ _ `/(_-< / _ \/ __// _ `// __/ \033[0m'
echo -e "\033[32m\033[1m  |__,__// .__/\_,_/ ____ /_//_/\_,_//___//_//_/\__/ \_,_/ \__/  \033[0m"
echo -e "\033[32m\033[1m        /_/         /___/                                        \033[0m"
echo ""
sleep 0.1
echo -e                "—————————————————————————————————————————————————————————————————"
sleep 0.1
echo -e                "        \033[36m\033[1mwpa_hashcat v${version}\033[0m (by \033[33m小网洞\033[0m) 基于hashcat,hcxtools       "
sleep 0.1
echo -e                "—————————————————————————————————————————————————————————————————"
sleep 0.1
#echo -e               "        wpa_hashcat v0.10 (by 小网洞) 基于hashcat,hcxtools       "
echo ""
echo "[+] 脚本启动！"

###0.检查依赖###
#hashcat,hcxtools,python,xxd,7z,zip



###1.选择握手包文件###

zenity_enable=true

if [ -n "${1}" ]; then
	cap_file=${1}
	exitWhenFileAbsent -f "${cap_file}" -t "[!] 文件${cap_file}不存在！"
else
	echo "[+] 等待用户选择握手包文件..."
	sleep 0.2
	if $zenity_enable; then
		# 使用zenity弹出文件选择器
		cap_file=$(zenity --file-selection \
			--title="请选择握手包文件" \
			--file-filter="握手包文件 (*.cap *.pcap *.pcapng *.hccapx *.hc22000)|*.cap *.pcap *.pcapng *.hccapx *.hc22000" \
			--file-filter="所有文件 (*)|*" \
			2>/dev/null)
		
		if [ $? != 0 ]; then
			zenity_enable=false
			echo "[i] 对话框未能启动 (当前可能为非图形化环境)。"
			cap_file=$(file_selector "$pwd" "请选择握手包文件 (cap,pcap,pcapng,hccapx,hc22000):" "cap,pcap,pcapng,hccapx,hc22000")
		fi
	else
		cap_file=$(file_selector "$pwd" "请选择握手包文件 (cap,pcap,pcapng,hccapx,hc22000):" "cap,pcap,pcapng,hccapx,hc22000")
	fi
	
	exitWhenFileAbsent -f "${cap_file}" -t "[!] 未选择任何文件，脚本退出。"
	
	echo "[+] 已选择握手包文件: ${cap_file}"
fi


rm "$convert_hc22000_file" >/dev/null 2>&1
cap_to_hc22000 "${cap_file}" "${convert_hc22000_file}"
hash_info=$(get_info_from_hc22000 "${convert_hc22000_file}")
if [ -n "$hash_info" ]; then
	if [[ $(echo "$hash_info" | wc -l) -gt 2 ]]; then
		selected_wifi=$(interactive_menu_csv "$hash_info" "请选择一个需要破解的WiFi网络 (取消则破解所有):")
		if [ $? -eq 0 ]; then
			((selected_wifi++))
			selected_wifi_info=$(echo "$hash_info" | sed '1d' | sed -n "${selected_wifi}p")
			selected_wifi_essid=$(echo $selected_wifi_info | awk -F, '{print $1}')
			selected_wifi_bssid=$(echo $selected_wifi_info | awk -F, '{print $2}')
			echo "[+] 已选择目标 ${selected_wifi_essid} (${selected_wifi_bssid})"
			selected_wifi_bssid=$(echo $selected_wifi_bssid | tr '[:upper:]' '[:lower:]' | sed 's/://g')
			hash=$(cat "${convert_hc22000_file}" | grep $selected_wifi_bssid | head -n 1)
		else
			echo "[+] 未选择，默认破解所有哈希。"
			hash=$convert_hc22000_file
		fi
	else
		hash=$convert_hc22000_file
	fi
else
	echo "[!] 未知错误，未读取到可用的哈希信息！"
	read -p "输入回车键退出..."
	exit 1
fi



###2.选择破解选项###

crack_title="破解方式,版本,作者,密码量,说明,推荐度"
crack_default_options="自定义字典,,,,,"
crack_custom_options="
常用弱密,1.0,HULUGANG,≈2500万,顺序字符、姓名、日期、谐音、数字字母组合等,5
8位纯数字,1.0,小网洞,1亿,8位纯数字,5
地区手机号,1.0,随风无限,20万~2亿,11位中国大陆移动、电信、联通手机号(2024年),5
8位数字字母规律,1.0,小网洞,≈673亿,字母+数字、数字+字母、数字字母混合,2
运营商光猫规律,1.0,随风无限,≈1万2千亿,ChinaNet/CMCC/CU光猫默认密码规律,2
"

#字母姓名日期组合,1.0,小网洞,,单字母/拼音/姓名及缩写+年月日/规律数字符号组合,4
#字母+手机号,1.0,小网洞,104万-104亿,手机号(11位)前加26个字母含大小写,1
#已知姓+手机号,1.0,小网洞,40万~4亿,手机号(11位)前/前后加姓名拼音,1
#已知姓名缩写+手机号,1.0,小网洞,20万~2亿,手机号(11位)前加姓名缩写,1
#电信光猫规律,1.0,小网洞,,电信ChinaNet-XXXX光猫默认密码规律,1
#移动光猫规律,1.0,小网洞,,移动CMCC-XXXX光猫默认密码规律,1
#联通光猫规律,1.0,小网洞,,联通CU_XXXX光猫默认密码规律,1


crack_options="${crack_default_options}${crack_custom_options}"
crack_options_csv=$(echo "$crack_title" | cat - <(format_crack_options "$crack_options"))


crack_choice_index=$(interactive_menu_csv "$crack_options_csv" "请选择破解选项:")
if [ -z "$crack_choice_index" ]; then
	echo "[!] 未选择破解方式，脚本退出。"
	read -p "输入回车键退出..."
	exit 1
fi

IFS=$'\n' read -d '' -r -a crack_options_array <<EOF
$(echo "$crack_options" | grep -v '^$' | cut -d',' -f1)
EOF
crack_selected_option="${crack_options_array[$crack_choice_index]}"

echo "[+] 选择${crack_selected_option}破解..."



###3.根据选择破解###
default_dict_path="$SCRIPT_DIR/dict"
optimization_parameter="$HASHCAT_OPTS"
output_parameter="$HASHCAT_OUTPUT"

#逻辑规律

case "$crack_choice_index" in
	0) #自定义字典
		if $zenity_enable; then
			dict_file=$(zenity --file-selection \
				--title="请选择字典文件" \
				--file-filter="字典文件 (*.txt *.dict *.dic)|*.txt *.dict *.dic" \
				--file-filter="所有文件 (*)|*" \
				2>/dev/null)
		else
			dict_file=$(file_selector "$pwd" "请选择字典文件(txt,dict,dic):" "txt,dict,dic")
		fi
		exitWhenFileAbsent -f "${dict_file}" -t "[!] 未选择任何文件，脚本退出。"
		echo "[+] 执行${crack_selected_option}跑包..."
		key_cout=$(cat "$dict_file" | grep -v '^$' | wc -l)
		echo -e "[i] 密码量${key_cout}。"
		hashcat -m 22000 -a 0 $hash "${dict_file}" $optimization_parameter $output_parameter
		;;
    1) #常用弱密
		dict_file="$default_dict_path/easy_dict/easy_dict.txt"
		if [ ! -f "${dict_file}" ]; then
			dict_archive_file="$default_dict_path/easy_dict.7z"
			exitWhenFileAbsent -f "${dict_archive_file}" -t "[!] 字典文件${dict_archive_file}不存在！"
			echo "[i] 正在解压字典文件..."
			auto_extract "$dict_archive_file" >/dev/null 2>&1
			exitWhenFileAbsent -f "${dict_file}" -t "[!] 字典文件${dict_archive_file}解压失败！"
		fi
		echo "[+] 执行${crack_selected_option}跑包..."
		key_cout=$(cat "$dict_file" | grep -v '^$' | wc -l)
		echo -e "[i] 密码量${key_cout}。"
		hashcat -m 22000 -a 0 $hash "${dict_file}" $optimization_parameter $output_parameter
		;;
    2) #8位纯数字
		echo "[+] 执行${crack_selected_option}跑包..."
		mask=?d?d?d?d?d?d?d?d
		key_cout=$(calculate_password_count_of_mask "$mask")
		echo -e "[i] 密码量${key_cout}。"
		hashcat -m 22000 -a 3 $hash $mask $optimization_parameter $output_parameter
		;;
    3) #地区手机号
		dict_path="$default_dict_path/phone_number"
		if ! [ "$(ls -A "$dict_path" 2>/dev/null | wc -l)" -gt 0 ]; then
			dict_archive_file="$default_dict_path/phone_number.zip"
			exitWhenFileAbsent -f "${dict_archive_file}" -t "[!] 字典文件${dict_archive_file}不存在！"
			echo "[i] 正在解压字典文件..."
			auto_extract "$dict_archive_file" >/dev/null 2>&1
			exitWhenFileAbsent -f "${dict_path}" -t "[!] 字典文件${dict_archive_file}解压失败！"
		fi
		dict_file=$(file_selector "$dict_path" -r "请根据所在地区选择:")
		exitWhenFileAbsent -f "${dict_file}" -t "[!] 未选择任何文件，脚本退出。"
		echo -e "[+] 执行\033[36m${area}\033[0m${crack_selected_option}跑包..."
		area=$(basename "$dict_file" ".txt")
		mask=?d?d?d?d
		key_cout=$(($(cat "$dict_file" | grep -v '^$' | wc -l) * $(calculate_password_count_of_mask "$mask")))
		echo -e "[i] 密码量${key_cout}。"
		hashcat -m 22000 -a 6 $hash "${dict_file}" $mask $optimization_parameter $output_parameter
		;;
	4) #8位字母数字规律
		mask_file="$default_dict_path/letter&num(8)/letter&num(8).hcmask"
		if [ ! -f "$mask_file" ]; then
			mask_archive_file="$default_dict_path/letter&num(8).zip"
			exitWhenFileAbsent -f "${mask_archive_file}" -t "[!] 掩码文件${mask_archive_file}不存在！"
			echo "[i] 正在解压掩码文件..."
			auto_extract "$mask_archive_file" >/dev/null 2>&1
			exitWhenFileAbsent -f "${mask_file}" -t "[!] 字典文件${mask_archive_file}解压失败！"
		fi
		echo "[+] 执行${crack_selected_option}跑包..."
		key_cout=$(calculate_password_count_of_mask "$mask_file")
		echo -e "[i] 密码量${key_cout}。"
		hashcat -m 22000 -a 3 $hash $mask_file $optimization_parameter $output_parameter
		;;
	5) #运营商光猫规律
		dict_file1="$default_dict_path/ct&cm&cu/first4.txt"
		dict_file2="$default_dict_path/ct&cm&cu/last4.txt"
		if [ ! -f "${dict_file1}" ] || [ ! -f "${dict_file2}" ]; then
			dict_archive_file="$default_dict_path/ct&cm&cu.zip"
			exitWhenFileAbsent -f "${dict_archive_file}" -t "[!] 字典文件${dict_archive_file}不存在！"
			echo "[i] 正在解压字典文件..."
			auto_extract "$dict_archive_file" >/dev/null 2>&1
			exitWhenFileAbsent -f "${dict_file1}" -t "[!] 字典文件${dict_archive_file}解压失败！"
			exitWhenFileAbsent -f "${dict_file2}" -t "[!] 字典文件${dict_archive_file}解压失败！"
		fi
		echo "[+] 执行${crack_selected_option}跑包..."
		key_cout1=$(cat "$dict_file1" | grep -v '^$' | wc -l)
		key_cout2=$(cat "$dict_file2" | grep -v '^$' | wc -l)
		echo -e "[i] 密码量$(echo "$key_cout1 * $key_cout2" | bc)。"
		hashcat -m 22000 -a 1 $hash "${dict_file1}" "${dict_file2}" $optimization_parameter $output_parameter
		;;
	#6) #姓名日期规律
	#	dict_path="$default_dict_path/name&date"
	#	if ! [ "$(ls -A "$dict_path" 2>/dev/null | wc -l)" -gt 0 ]; then
	#		dict_archive_file="$default_dict_path/name&date.zip"
	#		exitWhenFileAbsent -f "${dict_archive_file}" -t "[!] 字典文件${dict_archive_file}不存在！"
	#		echo "[i] 正在解压字典文件..."
	#		auto_extract "$dict_archive_file" >/dev/null 2>&1
	#		exitWhenFileAbsent -f "${dict_file}" -t "[!] 字典文件${dict_archive_file}解压失败！"
	#	fi
	#	echo "[+] 执行${crack_selected_option}跑包..."
	#	#常见单词/字符组合(含首字母大写和全大写) + 年/日月 [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/char(4).txt" "${dict_path}/yyyy_1960-2030(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/char(4).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j "!A u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/word(4).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/char(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/char(4).txt" -k "!A u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/word(4).txt" -k "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/char(4).txt" "${dict_path}/mmdd(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/char(4).txt" "${dict_path}/mmdd(4).txt" -j "!A u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/word(4).txt" "${dict_path}/mmdd(4).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/char(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/char(4).txt" -k "!A u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/word(4).txt" -k "T0" $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 常见数字组合 [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j "T0" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j "u" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -k "T0" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -k "u" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j ">5" -k "_3" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j ">5 T0" -k "_3" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j ">5 u" -k "_3" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -k ">5" -j "_3" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -k ">5 T0" -j "_3" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/common-num(3+).txt" "${dict_path}/name(4+).txt" -k ">5 u" -j "_3" $optimization_parameter
	#	#1-3字母(含首字母大写和全大写) + 常见数字组合 [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k ">7" --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k "_6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k "_5" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/common-num(3+).txt" $mask -j ">7" --increment $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/common-num(3+).txt" $mask -j "_6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/common-num(3+).txt" $mask -j "_5" $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k ">6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k "_5" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/common-num(3+).txt" $mask -j ">6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/common-num(3+).txt" $mask -j "_5" $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 年 [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j "u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/name(4+).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/name(4+).txt" -k "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyy_1960-2030(4).txt" "${dict_path}/name(4+).txt" -k "u" $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 日月 [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j "u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/name(4+).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/name(4+).txt" -k "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/mmdd(4).txt" "${dict_path}/name(4+).txt" -k "u" $optimization_parameter
	#	#姓/姓名名(含首字母大写和全大写) + 8位年月日(yyyymmdd) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" -j "u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" -k "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" -k "u" $optimization_parameter
	#	#1-3位字母(含首字母大写和全大写) + 8位年月日(yyyymmdd) [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymmdd_1960-2030(8).txt" --increment $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" $mask --increment $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymmdd_1960-2030(8).txt" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" $mask --increment --increment-min 2 $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 6位年月日(yymmdd) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" -k "x26" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" -j "T0" -k "x26" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymmdd_1960-2030(8).txt" -j "u" -k "x26" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" -j "x26" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" -k "T0" -j "x26" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" "${dict_path}/name(4+).txt" -k "u" -j "x26" $optimization_parameter
	#	#2-3位字母(含首字母大写) + 6位年月日(yymmdd) [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymmdd_1960-2030(8).txt" --increment --increment-min 2 -k "x26" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" $mask --increment --increment-min 2 -j "x26" $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymmdd_1960-2030(8).txt" --increment --increment-min 2 -k "x26" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" $mask --increment --increment-min 2 -j "x26" $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 6-7位年月日(yyyymd)(日月去0) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" -j "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" -j "u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" -k "T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" -k "u" $optimization_parameter
	#	#1-3位字母(含首字母大写和全大写) + 6-7位年月日(yyyymd)(日月去0) [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymd_1960-2030(6-7).txt" -k "_6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymd_1960-2030(6-7).txt" -k "_7" --increment $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" $mask -j "_6" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" $mask -j "_7" --increment $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymd_1960-2030(6-7).txt" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" $mask --increment --increment-min 2 $optimization_parameter
	#	#姓/姓名(含首字母大写和全大写) + 4-5位年月日(yymd)(日月去0) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" -j "T0" -k "O02" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyymd_1960-2030(6-7).txt" -j "u" -k "O02" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" -k "T0" -j "O02" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" "${dict_path}/name(4+).txt" -k "u" -j "O02" $optimization_parameter
	#	#3位字母(含首字母大写和全大写) + 5位年月日(yymd)(日月去0) [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymd_1960-2030(6-7).txt" -k "_7 O02" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" $mask -j "_7 O02" $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/yyyymd_1960-2030(6-7).txt" -k "_7 O02" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyymd_1960-2030(6-7).txt" $mask -j "_7 O02" $optimization_parameter
	#	#1字母(含大写) + 6/8位年月日(yyyymmdd/yymmdd) + 1字母(含大写)
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" -r "${dict_path}/Prefix-Suffix-a-zA-z.rule" $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/yyyymmdd_1960-2030(8).txt" -j "x26" -r "${dict_path}/Prefix-Suffix-a-zA-z.rule" $optimization_parameter
	#	#2-3位字母(含首字母大写和全大写) + 6位121212/123123/112233格式数字(ababab/abcabc) [含反组合]
	#	mask="-1 ?l?u ?1?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/00-99.txt" -k "p2" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/000-999.txt" -k "p1" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/000-999.txt" -k "q" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 "${dict_path}/00-99.txt" $hash $mask -j "p2" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 "${dict_path}/000-999.txt" $hash $mask -j "p1" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 "${dict_path}/000-999.txt" $hash $mask -j "q" --increment --increment-min 2 $optimization_parameter
	#	mask="?u?u?u"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/00-99.txt" -k "p2" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/000-999.txt" -k "p1" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/000-999.txt" -k "q" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/00-99.txt" $mask -j "p2" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/000-999.txt" $mask -j "p1" --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/000-999.txt" $mask -j "q" --increment --increment-min 2 $optimization_parameter
	#	#拼音(含首字母大写和全大写) + 6位121212格式数字(ababab) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/00-99.txt" -k "p2" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/00-99.txt" -k "p2" -j ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/00-99.txt" -k "p2" -j ">4 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/00-99.txt" "${dict_path}/pinyin(2+).txt" -j "p2" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/00-99.txt" "${dict_path}/pinyin(2+).txt" -j "p2" -k ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/00-99.txt" "${dict_path}/pinyin(2+).txt" -j "p2" -k ">4 u" $optimization_parameter
	#	#拼音(含首字母大写和全大写) + 6位123123/112233格式数字(abcabc) [含反组合]
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "p1" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "p1" -j ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "p1" -j ">4 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "q" -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "q" -j ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/000-999.txt" -k "q" -j ">4 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "p1" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "p1" -k ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "p1" -k ">4 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "q" -k ">4" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "q" -k ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/000-999.txt" "${dict_path}/pinyin(2+).txt" -j "q" -k ">4 u" $optimization_parameter
	#	#拼音(含首字母大写和全大写)/年份 + .com
	#	mask=.com
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/pinyin(2+).txt" $mask -j ">4" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/pinyin(2+).txt" $mask -j ">4 T0" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/pinyin(2+).txt" $mask -j ">4 u" $optimization_parameter
	#	hashcat -m 22000 -a 6 $hash "${dict_path}/yyyy_1960-2030(4).txt" $mask $optimization_parameter
	#	#拼音(含首字母大写) + 6位邮编
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/zipcode(6).txt" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/zipcode(6).txt" -j "T0" $optimization_parameter
	#	#纯姓名拼音(含首字母大写和全大写)
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j ">8" $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j ">8 T0" $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j ">8 u" $optimization_parameter
	#	#姓/姓名拼音(含首字母大写和全大写) + 符号(.@!#*?+-)
	#	#mask='-1 '\''.@!#*??+-'\'' ?1'
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -j ">7" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -j ">7 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -j ">7 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p1" -j ">6" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p1" -j ">6 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p1" -j ">6 u" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p2" -j ">5" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p2" -j ">5 T0" $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-special-char(1).txt" -k "p2" -j ">5 u" $optimization_parameter
	#	#mask=''\''!@#'\'''
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '>5 $! $@ $#' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '>5 T0 $! $@ $#' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '>5 u $! $@ $#' $optimization_parameter
	#	#拼音(含首字母大写和全大写)/2-3字母 + 年份/月日/常见数字组合 + 符号(.@)
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -k '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -k '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -k '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -k '$@@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -k '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -k '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -k '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -k '$@@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -k '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -k '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -k '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -k '$@@' $optimization_parameter
	#	mask="?l?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 $.' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 $..' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 $@' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 $@@' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 $.' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 $..' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 $@' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 $@@' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_3 $..' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_3 $@@' --increment $optimization_parameter
	#	#拼音(含首字母大写和全大写)//2-3字母 + 符号(.@!#*?+) + 年份/月日/常见数字组合
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/common-num(3+).txt" -j '$@@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/yyyy_1960-2030(4).txt" -j '$@@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j '$.' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j '$..' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j '$@' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/name(4+).txt" "${dict_path}/mmdd(4).txt" -j '$@@' $optimization_parameter
	#	mask="?l?l?l"
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 ^.' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 ^..' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '>5 ^@' --increment --increment-min 2 $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 ^.' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 ^..' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_4 ^@' --increment $optimization_parameter
	#	hashcat -m 22000 -a 7 $hash $mask "${dict_path}/common-num(3+).txt" -k '_3 ^..' --increment $optimization_parameter
	#	#拼音(首字母大写) + 拼音(首字母大写) + .
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j 'T0' -k 'T0 $.' $optimization_parameter
	#	#拼音(含首字母大写) + & + 拼音(含首字母大写)
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '$&' -k '>5' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>3 $&' -k '_4' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>4 $&' -k '_3' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>5 $&' -k '_2' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '$& T0' -k '>5 T0' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>3 $& T0' -k '_4 T0' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>4 $& T0' -k '_3 T0' $optimization_parameter
	#	hashcat -m 22000 -a 1 $hash "${dict_path}/pinyin(2+).txt" "${dict_path}/pinyin(2+).txt" -j '>5 $& T0' -k '_2 T0' $optimization_parameter
	#	#姓/姓名拼音 + .@ + 姓/姓名拼音(如lihua@lihua)
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_4 $. d D9' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_5 $. d D11' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_6 $. d D13' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_4 $@ d D9' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_5 $@ d D11' $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/name(4+).txt" -j '_6 $@ d D13' $optimization_parameter
	#	#拼音(含全大写)穿插数字(如x1i2n3g4、m1i9n9g8)
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/pinyin(2+).txt" -r "${dict_path}/Interval-Insert-4Num.rule" -j ">4 <5" $optimization_parameter
	#	hashcat -m 22000 -a 0 $hash "${dict_path}/pinyin(2+).txt" -r "${dict_path}/Interval-Insert-4Num.rule" -j ">4 <5 u" $optimization_parameter
	#	#符号(.@!#*?+) + 拼音(含首字母大写和全大写)/2-3字母 + 年份/月日/常见数字组合
	#	#概率较小，暂不编写
	#	
	#	#符号(.@!#*?+) + 年份/月日/常见数字组合 + 拼音(含首字母大写和全大写)/2-3字母
	#	#概率较小，暂不编写
	#	
	#	#年份/月日/常见数字组合 + 拼音(含首字母大写和全大写)/2-3字母 + 符号(.@!#*?+)
	#	#概率较小，暂不编写
	#	
	#	#年份/月日/常见数字组合 + 符号(.@!#*?+) + 拼音(含首字母大写和全大写)/2-3字母
	#	#概率较小，暂不编写
	#	
	#	#6位年月日(yymmdd) + 符号(.@!#*?+) + 拼音(含首字母大写和全大写)/2-3字母
	#	#概率较小，暂不编写
	#	
	#	#符号(.@!#*?+) + 2-3字母 + 年份/月日/常见数字组合 + 符号(.@!#*?+)
	#	#概率较小，暂不编写
	#	
	#	#年份/月日/常见数字组合 + 拼音(含首字母大写和全大写)/2-3字母 + 年份/月日/常见数字组合
	#	#概率较小，暂不编写
	#	
	#	#拼音(含首字母大写和全大写)/2-3字母 + 符号(.@!#*?+) + 年份/月日/常见数字组合 + 符号(.@!#*?+)
	#	#概率较小，暂不编写
	#	#概率较小，暂不编写
	#	
	#	#拼音 + 年份/月日/常见数字组合 + 拼音
	#	#概率较小，暂不编写
	#	
	#	#拼音(含首字母大写) + ./@ + 拼音(含首字母大写) + ./@ ( + 拼音(含首字母大写) ( + ./@))
	#	#概率较小，暂不编写
	#	
	#	;;
esac
read -p "输入回车键退出..."