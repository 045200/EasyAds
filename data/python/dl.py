import os
import shutil
import requests
from urllib.parse import quote

# 删除目录（如果存在）
directory = "./data/rules/"
try:
    shutil.rmtree(directory)
    print(f"成功删除目录 {directory}")
except FileNotFoundError:
    print(f"目录 {directory} 不存在，无需删除")
except Exception as e:
    print(f"无法删除目录 {directory}, 错误: {e}")
    raise

# 创建临时文件夹
try:
    os.makedirs("./tmp/", exist_ok=True)
except PermissionError:
    print("无法创建 ./tmp/ 目录，权限不足")
    raise

# 复制补充规则（跨平台兼容）
shutil.copy("./data/mod/adblock.txt", "./tmp/adblock01.txt")
shutil.copy("./data/mod/whitelist.txt", "./tmp/allow01.txt")

# 拦截规则
adblock = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt",
    "https://raw.hellogithub.com/hosts",
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",
    "https://lingeringsound.github.io/10007_auto/adb.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt",
    "https://raw.githubusercontent.com/twoone-3/AdGuardHomeForRoot/refs/heads/main/src/bin/data/filters/1732747955.txt"
]

# 白名单规则
allow = [
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    "https://file-git.trli.club/file-hosts/allow/Domains",
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",
    "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
    "https://anti-ad.net/easylist.txt"
]

def download_file(url, save_path):
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()  # 检查 HTTP 错误
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        print(f"下载成功: {url} -> {save_path}")
    except Exception as e:
        print(f"下载失败: {url}, 错误: {e}")
        raise

# 下载拦截规则
for i, url in enumerate(adblock, start=2):  # 从 adblock02.txt 开始
    download_file(url, f"./tmp/adblock{i:02d}.txt")

# 下载白名单规则
for j, url in enumerate(allow, start=2):  # 从 allow02.txt 开始
    download_file(url, f"./tmp/allow{j:02d}.txt")

print("所有规则下载完成")