#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import struct
import argparse
from datetime import datetime

def hccapx_to_hc22000(input_file, output_file=None, verbose=False):
    """
    将 hccapx 文件转换为 hc22000 格式
    :param input_file: 输入的 .hccapx 文件路径
    :param output_file: 输出的 .hc22000 文件路径（可选）
    :param verbose: 是否显示详细处理信息
    :return: 转换后的文件路径
    """
    # 检查输入文件是否存在
    if not os.path.isfile(input_file):
        print(f"错误：输入文件 '{input_file}' 不存在！")
        sys.exit(1)
    
    if verbose:
        print(f"开始处理: {input_file}")
        print(f"目标格式: hc22000")

    # 读取文件内容
    with open(input_file, "rb") as f:
        data = f.read()

    # 验证文件签名 (HCPX)
    signature = struct.unpack("4s", data[0:4])[0]
    if signature != b"HCPX":
        print(f"错误：无效的 hccapx 文件签名，应为 'HCPX'，实际为 {signature}")
        sys.exit(1)

    # 解析文件结构
    version = struct.unpack("I", data[4:8])[0]
    message_pair = struct.unpack("B", data[8:9])[0]
    essid_len = struct.unpack("B", data[9:10])[0]
    essid = struct.unpack(f"{essid_len}s", data[10:10+essid_len])[0]
    keyver = struct.unpack("B", data[42:43])[0]
    keymic = struct.unpack("16s", data[43:59])[0]
    mac_ap = struct.unpack("6s", data[59:65])[0]
    nonce_ap = struct.unpack("32s", data[65:97])[0]
    mac_sta = struct.unpack("6s", data[97:103])[0]
    nonce_sta = struct.unpack("32s", data[103:135])[0]
    eapol_len = struct.unpack("H", data[135:137])[0]
    eapol = struct.unpack(f"{eapol_len}s", data[137:137+eapol_len])[0]

    # 构建 hc22000 格式字符串
    protocol = "WPA"
    pmkid_mic = keymic.hex()
    type_val = "02"
    mac_ap_hex = mac_ap.hex()
    mac_client_hex = mac_sta.hex()
    essid_hex = essid.hex()
    nonce_ap_hex = nonce_ap.hex()
    eapol_hex = eapol.hex()
    message_pair_hex = f"{message_pair:02x}"

    hc22000_str = (
        f"{protocol}*{type_val}*{pmkid_mic}*{mac_ap_hex}*{mac_client_hex}"
        f"*{essid_hex}*{nonce_ap_hex}*{eapol_hex}*{message_pair_hex}"
    )

    # 处理输出文件名
    if not output_file:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{base_name}_{timestamp}.hc22000"
    elif not output_file.endswith('.hc22000'):
        output_file += '.hc22000'

    # 写入转换结果
    with open(output_file, "w") as f:
        f.write(hc22000_str)
    
    if verbose:
        print(f"转换成功！输出文件: {output_file}")
        print(f"ESSID: {essid.decode('utf-8', 'ignore')}")
        print(f"AP MAC: {':'.join(f'{b:02x}' for b in mac_ap)}")
    
    return output_file

if __name__ == "__main__":
    # 参数解析器配置 [2,5,6](@ref)
    parser = argparse.ArgumentParser(
        description="将 hccapx 文件转换为 Hashcat hc22000 格式",
        epilog="示例: python3 hccapx_to_hc22000.py capture.hccapx --output result.hc22000 -v"
    )
    parser.add_argument("input", help="输入的 .hccapx 文件路径")
    parser.add_argument("-o", "--output", help="输出的 .hc22000 文件路径（可选）")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细处理信息")
    args = parser.parse_args()

    # 执行转换
    hccapx_to_hc22000(
        input_file=args.input,
        output_file=args.output,
        verbose=args.verbose
    )