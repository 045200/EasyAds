#!/usr/bin/env python3
# AdGuard Home 规则下载与合并脚本
# 功能：从多个来源下载拦截规则和白名单规则，合并处理
# 改进：特别处理 rssv.cn 的下载问题，增加重试机制和自定义请求头

import os
import shutil
import requests
import time
from urllib.parse import urlparse

# ============== 配置参数 ==============
MAX_RETRIES = 3  # 最大重试次数
TIMEOUT = 60     # 请求超时时间(秒)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# ============== 目录清理 ==============
def clean_directory(directory):
    """清理目录"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            print(f"已清理目录: {directory}")
        else:
            print(f"目录不存在，无需清理: {directory}")
    except Exception as e:
        print(f"目录清理失败: {directory}, 错误: {e}")
        raise

# ============== 初始化工作目录 ==============
def init_directories():
    """初始化工作目录"""
    directories = ["./tmp/", "./data/rules/"]
    for dir_path in directories:
        try:
            os.makedirs(dir_path, exist_ok=True)
            print(f"目录初始化完成: {dir_path}")
        except PermissionError:
            print(f"错误：目录 {dir_path} 创建权限不足")
            raise
        except Exception as e:
            print(f"目录 {dir_path} 创建失败: {e}")
            raise

# ============== 本地规则处理 ==============
def copy_local_rules():
    """复制本地规则到临时目录"""
    try:
        if os.path.exists("./data/mod/adblock.txt"):
            shutil.copy("./data/mod/adblock.txt", "./tmp/adblock01.txt")
            print("本地拦截规则拷贝完成")
        else:
            print("警告：本地拦截规则文件不存在")
            
        if os.path.exists("./data/mod/whitelist.txt"):
            shutil.copy("./data/mod/whitelist.txt", "./tmp/allow01.txt")
            print("本地白名单规则拷贝完成")
        else:
            print("警告：本地白名单规则文件不存在")
    except Exception as e:
        print(f"本地规则拷贝失败: {e}")
        raise

# ============== 下载核心函数 ==============
def download_file(url, save_path):
    """下载文件并保存到本地"""
    headers = {"User-Agent": USER_AGENT}
    
    # 特殊处理 rssv.cn 的请求
    if "rssv.cn" in url:
        headers["Referer"] = "http://rssv.cn/"
        headers["Accept"] = "text/plain"
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"正在下载({attempt+1}/{MAX_RETRIES}): {url}")
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            response.raise_for_status()
            
            # 检查内容是否有效
            if not response.text.strip():
                raise ValueError("下载内容为空")
                
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"下载完成: {save_path}")
            return True
            
        except requests.exceptions.SSLError:
            # 如果SSL验证失败，尝试不验证
            try:
                response = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
                response.raise_for_status()
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"下载完成(跳过SSL验证): {save_path}")
                return True
            except Exception as e:
                print(f"下载失败(跳过SSL验证): {url} | 错误: {e}")
                
        except Exception as e:
            print(f"下载失败: {url} | 错误: {e}")
            if attempt < MAX_RETRIES - 1:
                wait_time = (attempt + 1) * 5
                print(f"等待 {wait_time}秒后重试...")
                time.sleep(wait_time)
    
    print(f"下载失败: 已达到最大重试次数 {MAX_RETRIES}")
    return False

# ============== 规则源列表 ===============
adblock = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",  # 大萌主-接口广告
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",    # DD-AD规则
    "https://raw.hellogithub.com/hosts",                                   # GitHub加速hosts
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt", # cat
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt", # 测试hosts
    "https://lingeringsound.github.io/10007_auto/adb.txt",                 # 10007自动规则
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",  # 秋风补充
    "http://hgzspj.51vip.biz/hg1.txt",                                    # 海哥规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",            # FCM Hosts
    "http://rssv.cn/adguard/api.php?type=black",                          # 晴雅黑名单(特殊处理)
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",  # 秋风主规则
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",    # 下一个ID见
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt",  # 茯苓拦截
]

allow = [
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",  # 测试白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",  # 通用白名单
    "https: