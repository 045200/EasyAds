import os
import shutil
import requests
import time
from urllib.parse import urlparse

# ============== 配置参数 ==============
MAX_RETRIES = 3       # 最大重试次数
TIMEOUT = 15          # 请求超时时间(秒)
GITHUB_CDN = "https://cdn.jsdelivr.net/gh"  # GitHub CDN镜像地址

# ============== 目录初始化 ==============
def init_environment():
    """初始化工作目录结构"""
    try:
        os.makedirs("./tmp/", exist_ok=True)      # 临时下载目录
        os.makedirs("./data/mod/", exist_ok=True) # 规则存储目录
        print("✓ 目录初始化完成")
    except Exception as e:
        print(f"✗ 目录初始化失败: {e}")
        raise

# ============== 本地规则处理 ==============
def handle_local_rules():
    """处理本地已有规则文件"""
    try:
        # 主拦截规则 (本地自定义规则)
        if not os.path.exists("./data/mod/adblock.txt"):
            open("./data/mod/adblock.txt", "w").close()
        shutil.copy("./data/mod/adblock.txt", "./tmp/adblock01.txt")

        # 主白名单 (本地自定义白名单)
        if not os.path.exists("./data/mod/whitelist.txt"):
            open("./data/mod/whitelist.txt", "w").close()
        shutil.copy("./data/mod/whitelist.txt", "./tmp/allow01.txt")

        print("✓ 本地规则处理完成")
    except Exception as e:
        print(f"✗ 本地规则处理失败: {e}")
        raise

# ============== 优化的下载函数 ==============
def download_with_retry(url, save_path):
    """
    带CDN加速和智能回退的下载函数
    :param url: 下载地址
    :param save_path: 保存路径
    :return: 是否成功
    """
    original_url = url  # 保存原始URL用于回退
    
    # 自动转换GitHub原始URL为CDN加速URL
    if "raw.githubusercontent.com" in url:
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')
            user_repo = f"{path_parts[1]}/{path_parts[2]}"
            branch = path_parts[3]
            file_path = '/'.join(path_parts[4:])
            cdn_url = f"{GITHUB_CDN}/{user_repo}@{branch}/{file_path}"
            print(f"🔧 转换GitHub URL为CDN镜像: {cdn_url}")
            url = cdn_url
        except Exception as e:
            print(f"⚠ URL转换失败，使用原始URL: {str(e)}")

    session = requests.Session()
    temp_path = f"{save_path}.tmp"  # 临时下载路径
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"⇩ 正在尝试 [{attempt+1}/{MAX_RETRIES}]: {url}")
            
            response = session.get(
                url,
                timeout=TIMEOUT,
                stream=True,
                headers={
                    "Accept": "text/plain",
                    "Accept-Encoding": "identity"  # 禁用压缩编码
                }
            )
            
            response.raise_for_status()

            # 流式写入文件 (避免大文件内存占用)
            with open(temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # 验证文件有效性
            if os.path.getsize(temp_path) == 0:
                raise ValueError("下载内容为空")

            shutil.move(temp_path, save_path)
            print(f"✓ 下载成功 -> {save_path} ({os.path.getsize(save_path)/1024:.1f}KB)")
            return True

        except Exception as e:
            print(f"✗ 尝试 {attempt+1} 失败: {type(e).__name__}: {str(e)[:100]}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if attempt < MAX_RETRIES - 1:
                wait_time = 2 ** attempt  # 指数退避策略
                print(f"⏳ 等待 {wait_time}秒后重试...")
                time.sleep(wait_time)

    # CDN下载失败时回退到原始GitHub URL
    if url != original_url:
        print(f"🔄 CDN下载失败，尝试回退到原始URL: {original_url}")
        return download_with_retry(original_url, save_path)
        
    return False

# ============== 规则源列表 (带详细注释) ==============
adblock = [
    # 大萌主-接口广告规则
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    
    # DD-AD去广告规则
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    
    # GitHub加速hosts (HelloGitHub提供)
    "https://raw.hellogithub.com/hosts",
    
    # Anti-AD通用规则
    "https://anti-ad.net/easylist.txt",
    
    # Cats-Team广告规则
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
    
    # 挡广告hosts规则
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",
    
    # 10007自动规则
    "https://lingeringsound.github.io/10007_auto/adb.txt",
    
    # 晴雅去广告规则
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    
    # 海哥广告规则
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    
    # FCM hosts规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
    
    # 秋风广告规则
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    
    # SMAdHosts规则
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    
    # 茯苓拦截规则
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
]

allow = [
    # 挡广告白名单
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
    
    # AdGuardHome通用白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    
    # 冷漠域名白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",
    
    # jhsvip白名单
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
    
    # liwenjie119白名单
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    
    # 喵二白名单
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    
    # 茯苓白名单
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
    
    # Cats-Team白名单
    "https://raw.githubusercontent.com/Cats-Team/AdRules/script/allowlist.txt",
    
    # Anti-AD白名单
    "https://anti-ad.net/easylist.txt"
]

# ============== 主下载流程 ==============
def download_rules():
    """执行规则下载任务"""
    print("\n" + "="*40)
    print("开始下载拦截规则".center(40))
    print("="*40)
    for i, url in enumerate(adblock, 1):
        save_path = f"./tmp/adblock{i:02d}.txt"
        download_with_retry(url, save_path)

    print("\n" + "="*40)
    print("开始下载白名单规则".center(40))
    print("="*40)
    for j, url in enumerate(allow, 1):
        save_path = f"./tmp/allow{j:02d}.txt"
        download_with_retry(url, save_path)

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
        print("\n文件列表:")
        for f in sorted(ad_files + allow_files):
            size = os.path.getsize(f"./tmp/{f}")/1024
            print(f"- {f} ({size:.1f}KB)")
        
        print(f"\n✓ 任务完成！文件保存在: {os.path.abspath('./tmp/')}")
    except Exception as e:
        print(f"\n✗ 脚本执行失败: {e}")
        raise

if __name__ == "__main__":
    main()