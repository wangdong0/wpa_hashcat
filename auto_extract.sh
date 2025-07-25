#!/bin/bash

# 自动解压函数
auto_extract() {
    local file="$1"
    local target_dir="${file%.*}"  # 解压到与压缩包同名的目录
    
    # 检查文件是否存在
    if [[ ! -f "$file" ]]; then
        echo "错误: 文件 '$file' 不存在"
        return 1
    fi

    # 创建目标目录
    mkdir -p "$target_dir" || {
        echo "错误: 无法创建目录 '$target_dir'"
        return 1
    }

    # 根据文件后缀选择解压方式
    case "$file" in
        *.7z|*.7Z)
            if command -v 7z &>/dev/null; then
                7z x "$file" -o"$target_dir" -y >/dev/null
            elif command -v 7za &>/dev/null; then
                7za x "$file" -o"$target_dir" -y >/dev/null
            else
                echo "错误: 需要安装p7zip工具(7z或7za命令)"
                return 1
            fi
            ;;
        *.zip|*.ZIP)
            if command -v unzip &>/dev/null; then
                unzip -q -o "$file" -d "$target_dir"
            else
                echo "错误: 需要安装unzip工具"
                return 1
            fi
            ;;
        *.rar|*.RAR)
            if command -v unrar &>/dev/null; then
                unrar x -y "$file" "$target_dir" >/dev/null
            elif command -v rar &>/dev/null; then
                rar x -y "$file" "$target_dir" >/dev/null
            else
                echo "错误: 需要安装unrar或rar工具"
                return 1
            fi
            ;;
        *.tar.gz|*.tgz)
            tar -xzf "$file" -C "$target_dir" --overwrite
            ;;
        *.tar.bz2)
            tar -xjf "$file" -C "$target_dir" --overwrite
            ;;
        *.tar.xz)
            tar -xJf "$file" -C "$target_dir" --overwrite
            ;;
        *)
            echo "错误: 不支持的压缩格式 '$file'"
            return 1
            ;;
    esac

    if [[ $? -eq 0 ]]; then
        echo "解压成功: $file → $target_dir"
    else
        echo "解压失败: $file"
        return 1
    fi
}

# 批量解压当前目录下所有支持的压缩文件
batch_extract() {
    local formats=("*.7z" "*.zip" "*.rar" "*.tar.gz" "*.tgz" "*.tar.bz2" "*.tar.xz")
    local extracted=0
    
    for format in "${formats[@]}"; do
        for file in $format; do
            [[ -f "$file" ]] || continue
            auto_extract "$file" && ((extracted++))
        done
    done
    
    if (( extracted == 0 )); then
        echo "未找到可解压的文件"
    fi
}

# 使用示例:
# 解压单个文件: auto_extract "archive.7z"
# 解压当前目录所有文件: batch_extract

export -f auto_extract