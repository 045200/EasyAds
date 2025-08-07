import os
import shutil
import requests
import time
from pathlib import Path

# ===== 配置参数 =====
MAX_RETRIES = 3
TIMEOUT = 30
USER_AGENT = "AdGuardRulesDownloader/1.0"
TMP_DIR = Path("./tmp")
DATA_DIR = Path("./data")

def init_environment():
    """初始化工作目录"""
    try:
        TMP_DIR.mkdir(exist_ok=True, parents=True)
        (DATA_DIR / "rules").mkdir(exist_ok=True, parents=True)
        (DATA_DIR / "mod").mkdir(exist_ok=True, parents=True)
        print("✓ 目录初始化完成")
    except Exception as e:
        raise RuntimeError(f"目录初始化失败: {e}")

def handle_local_rules():
    """处理本地规则文件"""
    try:
        # 主拦截规则
        adblock_src = DATA_DIR / "mod" / "adblock.txt"
        adblock_dst = TMP_DIR / "adblock01.txt"
        if not adblock_src.exists():
            adblock_src.touch()
        shutil.copy(adblock_src, adblock_dst)

        # 主白名单
        whitelist_src = DATA_DIR / "mod" / "whitelist.txt"
        whitelist_dst = TMP_DIR / "allow01.txt"
        if not whitelist_src.exists():
            whitelist_src.touch()
        shutil.copy(whitelist_src, whitelist_dst)
        print("✓ 本地规则处理完成")
    except Exception as e:
        raise RuntimeError(f"本地规则处理失败: {e}")

def download_rule(url: str, save_path: Path) -> bool:
    """带重试机制的下载函数"""
    headers = {"User-Agent": USER_AGENT}
    if "rssv.cn" in url:
        headers.update({"Referer": "http://rssv.cn/"})

    for attempt in range(MAX_RETRIES):
        try:
            print(f"⇩ 下载 [{attempt+1}/{MAX_RETRIES}]: {url}")
            verify_ssl = not url.startswith('http://')
            response = requests.get(url, headers=headers, timeout=TIMEOUT, verify=verify_ssl)
            response.raise_for_status()
            
            content = response.text.strip()
            if not content:
                raise ValueError("空内容")
                
            save_path.write_text(content, encoding='utf-8')
            print(f"✓ 保存到: {save_path}")
            return True
        except Exception as e:
            print(f"✗ 错误: {type(e).__name__} - {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
    return False

# ===== 完整规则源（保留所有注释）=====
ADBLOCK_SOURCES = [
    # 主规则源
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",  # 大萌主-接口广告
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",    # DD-AD规则
    "https://raw.hellogithub.com/hosts",                                   # GitHub加速hosts

    # 补充规则
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt", # cat规则
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt", # 测试hosts
    "https://lingeringsound.github.io/10007_auto/adb.txt",                 # 10007自动规则

    # 特殊规则（需特殊处理）
    "http://rssv.cn/adguard/api.php?type=black",                           # 晴雅黑名单
    "http://hgzspj.51vip.biz/hg1.txt",                                    # 海哥规则

    # 其他规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",            # FCM Hosts
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",  # 秋风规则
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",     # SMAdHosts
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt"  # 茯苓拦截
]

ALLOW_SOURCES = [
    # 基础白名单
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",  # 测试白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",  # 通用白名单

    # 域名白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",                # 冷漠域名白名单
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",     # jhsvip白名单

    # 其他白名单
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",  # liwenjie119
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",  # 喵二白名单
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",  # 茯苓白名单
    "https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/script/allowlist.txt",  # cat白名单
    "https://anti-ad.net/easylist.txt"                                   # anti-AD白名单
]

def download_all_rules():
    """下载所有规则文件"""
    print("\n" + "="*40)
    print("下载拦截规则".center(40))
    print("="*40)
    for i, url in enumerate(ADBLOCK_SOURCES, 2):
        download_rule(url, TMP_DIR / f"adblock{i:02d}.txt")

    print("\n" + "="*40)
    print("下载白名单规则".center(40))
    print("="*40)
    for j, url in enumerate(ALLOW_SOURCES, 2):
        download_rule(url, TMP_DIR / f"allow{j:02d}.txt")

def main():
    try:
        init_environment()
        handle_local_rules()
        download_all_rules()
        print("\n✓ 所有规则下载完成")
    except Exception as e:
        print(f"\n✗ 脚本执行失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()