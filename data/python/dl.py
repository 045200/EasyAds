# AdGuard Home 规则下载与合并脚本
# 功能：从多个来源下载拦截规则和白名单规则，合并处理

import os
import shutil
import requests
from urllib.parse import quote

# ============== 目录清理 ==============
# 删除旧规则目录（如果存在）
directory = "./data/rules/"
try:
    shutil.rmtree(directory)
    print(f"已清理目录: {directory}")
except FileNotFoundError:
    print(f"目录不存在，无需清理: {directory}")
except Exception as e:
    print(f"目录清理失败: {directory}, 错误: {e}")
    raise

# ============== 初始化工作目录 ==============
# 创建临时文件夹（用于存储下载的规则）
try:
    os.makedirs("./tmp/", exist_ok=True)
    print("临时目录初始化完成")
except PermissionError:
    print("错误：临时目录创建权限不足")
    raise
except Exception as e:
    print(f"临时目录创建失败: {e}")
    raise

# ============== 本地规则处理 ==============
# 复制本地规则到临时目录
try:
    shutil.copy("./data/mod/adblock.txt", "./tmp/adblock01.txt")  # 主拦截规则
    shutil.copy("./data/mod/whitelist.txt", "./tmp/allow01.txt")  # 主白名单
    print("本地规则拷贝完成")
except Exception as e:
    print(f"本地规则拷贝失败: {e}")
    raise

# 广告拦截规则源
adblock = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",  # 大萌主-接口广告

#-"https://cdn.jsdelivr.net/gh/privacy-protection-tools/anti-AD/anti-ad-easylist.txt", # anti-ad
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",  # DD-AD规则
    "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt",  # AdRules DNS过滤
    
"https://raw.hellogithub.com/hosts",  # GitHub加速hosts

"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",  # cat
    
"https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",  # 测试hosts
    "https://lingeringsound.github.io/10007_auto/adb.txt",  # 10007自动规则
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",  # 秋风补充
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",  # 海哥规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",  # FCM Hosts
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt",  # 晴雅黑名单
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",  # 秋风主规则
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",  # 下一个ID见
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt",  # 茯苓拦截
    "https://raw.githubusercontent.com/twoone-3/AdGuardHomeForRoot/refs/heads/main/src/bin/data/filters/1732747955.txt"  # twoone-3
]

# 白名单规则
allow = [
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",  # 测试白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",  # 通用白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",  # 冷漠域名白名单
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",  # jhsvip白名单
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",  # liwenjie119
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",  # 喵二白名单
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",  # 茯苓白名单

"https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/script/allowlist.txt", # cat白名单
 
"https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/refs/heads/main/rule/mylist.txt", # hululu1068
   "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",  # 酷安cocieto
    "https://anti-ad.net/easylist.txt"  # anti-AD白名单
]

# ============== 下载核心函数 ==============
def download_file(url, save_path):
    """下载文件并保存到本地"""
    try:
        print(f"正在下载: {url}")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        print(f"下载完成: {save_path}")
        
    except Exception as e:
        print(f"下载失败: {url} | 错误: {e}")
        raise

# ============== 执行下载任务 ==============
print("\n开始下载拦截规则...")
for i, url in enumerate(adblock, start=2):  # 从02开始编号
    save_path = f"./tmp/adblock{i:02d}.txt"
    download_file(url, save_path)

print("\n开始下载白名单规则...")
for j, url in enumerate(allow, start=2):  # 从02开始编号
    save_path = f"./tmp/allow{j:02d}.txt"
    download_file(url, save_path)

# ============== 完成统计 ==============
total_ad = len(adblock) + 1  # 包含本地规则
total_allow = len(allow) + 1  # 包含本地规则
print(f"\n任务完成！共处理: {total_ad}条拦截规则, {total_allow}条白名单规则")
print("所有文件已保存到 ./tmp/ 目录")