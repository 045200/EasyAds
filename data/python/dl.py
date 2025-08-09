import os
import shutil
import requests
import time
from pathlib import Path

# ============== 配置参数 ==============
MAX_RETRIES = 3
TIMEOUT = 60
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# ============== 目录初始化 ==============
def init_environment():
    """初始化工作目录"""
    try:
        os.makedirs("./tmp/", exist_ok=True)
        os.makedirs("./data/rules/", exist_ok=True)
        os.makedirs("./data/mod/", exist_ok=True)
        print("✓ 目录初始化完成")
    except Exception as e:
        print(f"✗ 目录初始化失败: {e}")
        raise

# ============== 本地规则处理 ==============
def handle_local_rules():
    """处理本地规则文件"""
    try:
        # 主拦截规则
        if not os.path.exists("./data/mod/adblock.txt"):
            open("./data/mod/adblock.txt", "w").close()
        shutil.copy("./data/mod/adblock.txt", "./tmp/adblock01.txt")

        # 主白名单
        if not os.path.exists("./data/mod/whitelist.txt"):
            open("./data/mod/whitelist.txt", "w").close()
        shutil.copy("./data/mod/whitelist.txt", "./tmp/allow01.txt")

        print("✓ 本地规则处理完成")
    except Exception as e:
        print(f"✗ 本地规则处理失败: {e}")
        raise

# ============== 增强下载函数 ==============
def download_with_retry(url, save_path):
    """带重试机制的下载函数（增强版）"""
    temp_path = f"{save_path}.tmp"  # 提前定义临时文件路径
    headers = {"User-Agent": USER_AGENT}

    # 动态特殊域名处理
    special_domains = {
        "rssv.cn": {
            "Referer": "http://rssv.cn/",
            "Accept": "text/plain",
            "Connection": "keep-alive"
        },
        "51vip.biz": {
            "Accept-Encoding": "gzip"
        },
        "anti-ad.net": {
            "Accept": "text/plain, */*"
        }
    }

    # 动态添加特殊头部
    for domain, extra_headers in special_domains.items():
        if domain in url:
            headers.update(extra_headers)
            break

    # 对于HTTP链接，禁用SSL验证
    verify_ssl = not url.startswith('http://')

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            print(f"⇩ 正在下载 [{attempt+1}/{MAX_RETRIES}]: {url}")

            # 确保临时文件不存在
            if os.path.exists(temp_path):
                os.remove(temp_path)

            response = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT,
                verify=verify_ssl,
                stream=True
            )
            response.raise_for_status()

            # 流式写入临时文件
            with open(temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # 过滤keep-alive空块
                        f.write(chunk)
            
            # 验证文件有效性
            if os.path.getsize(temp_path) == 0:
                raise ValueError("下载内容为空")
            
            # 原子操作：临时文件 -> 目标文件
            shutil.move(temp_path, save_path)
            file_size = os.path.getsize(save_path)/1024
            print(f"✓ 下载成功 -> {save_path} ({file_size:.1f}KB)")
            return True

        except Exception as e:
            last_error = e
            print(f"✗ 尝试 {attempt+1} 失败: {type(e).__name__}: {e}")
            
            # 清理临时文件
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            
            # 指数退避重试
            if attempt < MAX_RETRIES - 1:
                sleep_time = (attempt + 1) * 3
                print(f"⏳ 等待 {sleep_time}秒后重试...")
                time.sleep(sleep_time)

    print(f"! 无法下载: {url} (已达最大重试次数)")
    if last_error:
        print(f"最后错误: {type(last_error).__name__}: {last_error}")
    return False

# ============== 完整规则源列表 ==============
adblock = [
    # 主规则源
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",  # 大萌主-接口广告
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",    # DD-AD规则
    "https://raw.hellogithub.com/hosts",                                   # GitHub加速hosts
    "https://anti-ad.net/easylist.txt",                                    # anti-AD

    # 补充规则
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt", # cat规则
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt", # 测试hosts
    "https://lingeringsound.github.io/10007_auto/adb.txt",                 # 10007自动规则

    # 特殊规则（需特殊处理）
    "http://rssv.cn/adguard/api.php?type=black",                           # 晴雅黑名单（需特殊头）
    "http://hgzspj.51vip.biz/hg1.txt",                                    # 海哥规则（HTTP链接）

    # 其他规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",            # FCM Hosts
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",  # 秋风主规则
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",     # SMAdHosts
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt",  # 茯苓拦截
]

allow = [
    # 基础白名单
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",  # 测试白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",  # 通用白名单

    # 域名白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",                # 冷漠域名白名单
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",     # jhsvip白名单

    # 其他白名单
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",  # liwenjie119
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",  # 喵二白
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",  # 茯苓白名单
    "https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/script/allowlist.txt",  # cat白名单
    "https://anti-ad.net/easylist.txt"                                   # anti-AD白名单
]

# ============== 主下载流程 ==============
def download_rules():
    """主下载流程"""
    print("\n" + "="*40)
    print("开始下载拦截规则".center(40))
    print("="*40)
    for i, url in enumerate(adblock, 1):
        save_path = f"./tmp/adblock{i:02d}.txt"
        if not download_with_retry(url, save_path):
            # 如果下载失败，创建空文件占位
            open(save_path, "w").close()

    print("\n" + "="*40)
    print("开始下载白名单规则".center(40))
    print("="*40)
    for j, url in enumerate(allow, 1):
        save_path = f"./tmp/allow{j:02d}.txt"
        if not download_with_retry(url, save_path):
            # 如果下载失败，创建空文件占位
            open(save_path, "w").close()

# ============== 主函数 ==============
def main():
    try:
        # 初始化环境
        init_environment()
        handle_local_rules()

        # 下载规则
        download_rules()

        # 结果统计
        print("\n" + "="*40)
        print("下载结果统计".center(40))
        print("="*40)
        ad_files = [f for f in os.listdir("./tmp/") if f.startswith("adblock")]
        allow_files = [f for f in os.listdir("./tmp/") if f.startswith("allow")]
        
        print(f"拦截规则文件: {len(ad_files)}个")
        print(f"白名单规则文件: {len(allow_files)}个")
        print("\n文件详情:")
        
        total_size = 0
        for f in sorted(ad_files + allow_files):
            size = os.path.getsize(f"./tmp/{f}")/1024
            total_size += size
            status = "✓" if size > 0 else "✗ (空文件)"
            print(f"- {status} {f} ({size:.1f}KB)")
        
        print(f"\n总计: {len(ad_files + allow_files)}个文件, {total_size:.1f}KB")
        print(f"✓ 任务完成！文件保存在: {os.path.abspath('./tmp/')}")

    except Exception as e:
        print(f"\n✗ 脚本执行失败: {e}")
        raise

if __name__ == "__main__":
    main()