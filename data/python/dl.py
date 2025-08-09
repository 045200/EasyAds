import os
import shutil
import requests
import time
from pathlib import Path
from urllib.parse import urlparse

# ============== 配置参数 ==============
MAX_RETRIES = 3
TIMEOUT = 30  # 缩短超时时间
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
RETRY_DELAY = [3, 6, 9]  # 自定义重试延迟

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

# ============== 智能下载函数 ==============
def smart_download(url, save_path):
    """智能下载函数，自动处理各种特殊情况"""
    temp_path = f"{save_path}.tmp"
    headers = {"User-Agent": USER_AGENT}
    
    # 动态特殊域名处理
    domain_rules = {
        "rssv.cn": {
            "headers": {
                "Referer": "http://rssv.cn/",
                "Accept": "text/plain",
                "Connection": "keep-alive"
            },
            "timeout": 60,
            "retries": 5
        },
        "51vip.biz": {
            "headers": {
                "Accept-Encoding": "gzip"
            },
            "timeout": 45,
            "fallback": "https://mirror.example.com/51vip/hg1.txt"  # 备用镜像示例
        },
        "anti-ad.net": {
            "headers": {
                "Accept": "text/plain, */*"
            }
        }
    }

    # 应用特殊规则
    domain = urlparse(url).netloc
    rule = domain_rules.get(domain, {})
    current_timeout = rule.get("timeout", TIMEOUT)
    current_retries = rule.get("retries", MAX_RETRIES)
    headers.update(rule.get("headers", {}))

    # 对于HTTP链接，禁用SSL验证
    verify_ssl = not url.startswith('http://')

    last_error = None
    for attempt in range(current_retries):
        try:
            print(f"⇩ 正在下载 [{attempt+1}/{current_retries}]: {url}")

            # 确保临时文件不存在
            if os.path.exists(temp_path):
                os.remove(temp_path)

            # 使用会话保持连接
            with requests.Session() as session:
                response = session.get(
                    url,
                    headers=headers,
                    timeout=current_timeout,
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

        except requests.exceptions.SSLError:
            # SSL错误时重试并禁用验证
            verify_ssl = False
            last_error = "SSL验证错误，已禁用SSL验证"
            print(f"⚠ SSL验证失败，禁用验证重试...")
            continue
            
        except Exception as e:
            last_error = str(e)
            print(f"✗ 尝试 {attempt+1} 失败: {type(e).__name__}: {e}")
            
            # 清理临时文件
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            
            # 自定义延迟重试
            if attempt < current_retries - 1:
                delay = RETRY_DELAY[attempt] if attempt < len(RETRY_DELAY) else RETRY_DELAY[-1]
                print(f"⏳ 等待 {delay}秒后重试...")
                time.sleep(delay)

    # 尝试备用镜像（如果有）
    if 'fallback' in rule and rule['fallback']:
        print(f"⚠ 尝试备用镜像: {rule['fallback']}")
        return smart_download(rule['fallback'], save_path)

    print(f"! 无法下载: {url} (已达最大重试次数)")
    if last_error:
        print(f"最后错误: {last_error}")
    
    # 创建空文件保持编号连续性
    open(save_path, "w").close()
    return False

# ============== 规则源列表 ==============
adblock = [
    # 主规则源
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    "https://raw.hellogithub.com/hosts",
    "https://anti-ad.net/easylist.txt",

    # 补充规则
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",
    "https://lingeringsound.github.io/10007_auto/adb.txt",

    # 特殊规则
    "http://rssv.cn/adguard/api.php?type=black",
    "http://hgzspj.51vip.biz/hg1.txt",

    # 其他规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt"
]

allow = [
    # 白名单规则
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    "https://file-git.trli.club/file-hosts/allow/Domains",
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/refs/heads/script/script/allowlist.txt",
    "https://anti-ad.net/easylist.txt"
]

# ============== 主下载流程 ==============
def download_rules():
    """主下载流程"""
    print("\n" + "="*40)
    print("开始下载拦截规则".center(40))
    print("="*40)
    for i, url in enumerate(adblock, 1):
        save_path = f"./tmp/adblock{i:02d}.txt"
        smart_download(url, save_path)

    print("\n" + "="*40)
    print("开始下载白名单规则".center(40))
    print("="*40)
    for j, url in enumerate(allow, 1):
        save_path = f"./tmp/allow{j:02d}.txt"
        smart_download(url, save_path)

# ============== 主函数 ==============
def main():
    try:
        # 初始化环境
        init_environment()
        handle_local_rules()

        # 下载规则
        start_time = time.time()
        download_rules()
        elapsed = time.time() - start_time

        # 结果统计
        print("\n" + "="*40)
        print("下载结果统计".center(40))
        print("="*40)
        
        ad_files = sorted([f for f in os.listdir("./tmp/") if f.startswith("adblock")])
        allow_files = sorted([f for f in os.listdir("./tmp/") if f.startswith("allow")])
        
        # 统计信息
        success_count = 0
        fail_count = 0
        total_size = 0
        
        print("拦截规则文件:")
        for f in ad_files:
            size = os.path.getsize(f"./tmp/{f}")/1024
            total_size += size
            if size > 0:
                success_count += 1
                print(f"- ✓ {f} ({size:.1f}KB)")
            else:
                fail_count += 1
                print(f"- ✗ {f} (下载失败)")
        
        print("\n白名单规则文件:")
        for f in allow_files:
            size = os.path.getsize(f"./tmp/{f}")/1024
            total_size += size
            if size > 0:
                success_count += 1
                print(f"- ✓ {f} ({size:.1f}KB)")
            else:
                fail_count += 1
                print(f"- ✗ {f} (下载失败)")
        
        print(f"\n总计: {success_count}个成功, {fail_count}个失败")
        print(f"总大小: {total_size:.1f}KB")
        print(f"耗时: {elapsed:.2f}秒")
        print(f"✓ 任务完成！文件保存在: {os.path.abspath('./tmp/')}")

    except Exception as e:
        print(f"\n✗ 脚本执行失败: {e}")
        raise

if __name__ == "__main__":
    main()