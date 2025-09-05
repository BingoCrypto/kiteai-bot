# -*- coding: utf-8 -*-
import os
import random
import string
import time
import json
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
from fake_useragent import FakeUserAgent

# ==============================================================================
# 全局配置
# ==============================================================================
MAX_THREADS = 5  # 最大并发线程数
MAX_RETRIES = 3  # 大多数操作的默认最大重试次数
SLEEP_TIME_PER_ACCOUNT = 3  # 每个账户完成所有任务后的间隔秒数
lock = threading.Lock()  # 线程锁，用于安全写入日志

# CAPTCHA 服务配置 (用于领水)
CAPTCHA_API_URL = "https://api.yescaptcha.com"
CAPTCHA_KEY = "5fac7c0aa08f87cc8714ed5612a73644460de45e38849"  # 替换为你的 YesCaptcha API Key
SITE_KEY = "6Lc_VwgrAAAAALtx_UtYQnW-cFg8EPDgJ8QVqkaz"
SITE_URL = "https://testnet.gokite.ai"


# ==============================================================================
# 1. 通用模块 (代理, 加密, 登录)
# ==============================================================================

def load_proxies(filename="proxies.txt"):
    """从文件加载代理列表，支持两种格式"""
    proxies = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("http://") and not line.startswith("https://"):
                    line = "http://" + line
                proxies.append(line)
        print(f"✅ 成功从 {filename} 加载 {len(proxies)} 个代理。")
    except FileNotFoundError:
        print(f"⚠️ 警告: 未找到代理文件 '{filename}'。程序将尝试不使用代理运行。")
    return proxies


class AuthClient:
    """用于生成登录 gokite.ai 所需的授权 Token"""
    KEY_HEX = "6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a"

    @staticmethod
    def hex_to_bytes(hex_str):
        return bytes.fromhex(hex_str)

    def encrypt(self, address):
        key = self.hex_to_bytes(self.KEY_HEX)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(address.encode('utf-8')) + encryptor.finalize()
        return (iv + ciphertext + encryptor.tag).hex()

    def generate_auth_token(self, address):
        return self.encrypt(address)


def login(wallet_address, proxies=None):
    """使用钱包地址登录，返回 access_token"""
    client = AuthClient()
    auth_token = client.generate_auth_token(wallet_address)
    url = "https://neo.prod.gokite.ai/v2/signin"
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": FakeUserAgent().random
    }
    payload = {"eoa": wallet_address}

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=20)
            if resp.status_code == 200:
                access_token = resp.json().get("data", {}).get("access_token")
                if access_token:
                    print(f"✅ [{wallet_address}] 登录成功")
                    return access_token
            print(f"⚠️ [{wallet_address}] 登录失败({resp.status_code})，重试中 ({attempt + 1}/{MAX_RETRIES})")
        except Exception as e:
            print(f"❌ [{wallet_address}] 登录异常: {e}")
        time.sleep(3)
    return None


def get_aa_address(wallet_address, proxies=None):
    """获取与 EOA 关联的 AA 钱包地址"""
    eth_rpc_url = "https://rpc-testnet.gokite.ai/"
    contract_address = "0x948f52524Bdf595b439e7ca78620A8f843612df3"
    method_selector = "8cb84e18"
    suffix = "4b6f5b36bb7706150b17e2eecb6e602b1b90b94a4bf355df57466626a5cb897b"
    wallet_hex = wallet_address.lower().replace("0x", "").rjust(64, "0")
    call_data = "0x" + method_selector + wallet_hex + suffix
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": contract_address, "data": call_data}, "latest"]
    }
    try:
        resp = requests.post(eth_rpc_url, json=payload, proxies=proxies, timeout=10)
        result = resp.json().get("result", "")
        if result and result != "0x":
            aa_address = "0x" + result[-40:]
            print(f"✅ [{wallet_address}] 获取 AA 钱包地址成功: {aa_address}")
            return aa_address
    except Exception as e:
        print(f"❌ [{wallet_address}] 获取 AA 钱包地址失败: {e}")
    return None


# ==============================================================================
# 2. 任务模块
# ==============================================================================

# --- 任务 1: 每日领水 (Faucet) ---
def get_captcha_token(proxies):
    """通过 YesCaptcha 获取 reCAPTCHA token"""
    if CAPTCHA_KEY == "YOUR_YESCAPTCHA_API_KEY":
        print("❌ 未配置 CAPTCHA_KEY，无法进行领水操作。")
        return ""
    try:
        task_data = {
            "clientKey": CAPTCHA_KEY,
            "task": {"websiteURL": SITE_URL, "websiteKey": SITE_KEY, "type": "NoCaptchaTaskProxyless"}
        }
        resp = requests.post(f"{CAPTCHA_API_URL}/createTask", json=task_data, proxies=proxies, timeout=10).json()
        task_id = resp.get("taskId")
        if not task_id:
            print(f"❌ 无法创建验证码任务: {resp.get('errorDescription')}")
            return ""

        for _ in range(120):  # 等待最多 2 分钟
            time.sleep(2)
            check_data = {"clientKey": CAPTCHA_KEY, "taskId": task_id}
            check_resp = requests.post(f"{CAPTCHA_API_URL}/getTaskResult", json=check_data, proxies=proxies,
                                       timeout=10).json()
            if check_resp.get("status") == "ready":
                token = check_resp.get("solution", {}).get("gRecaptchaResponse", "")
                if token:
                    print("✅ 成功获取 reCAPTCHA token")
                    return token
        print("⏰ 验证码获取超时")
    except Exception as e:
        print(f"⚠️ 获取验证码时发生异常: {e}")
    return ""


def faucet_transfer(access_token, wallet_address, proxies):
    """请求 Faucet 领水"""
    print(f"[*] [{wallet_address}] 开始执行每日领水...")
    url = "https://ozone-point-system.prod.gokite.ai/blockchain/faucet-transfer"
    headers = {
        "accept": "application/json, text/plain, */*",
        "authorization": f"Bearer {access_token}",
        "content-type": "application/json",
        "User-Agent": FakeUserAgent().random
    }
    for attempt in range(MAX_RETRIES):
        try:
            token = get_captcha_token(proxies)
            if not token:
                continue  # 获取 token 失败则重试

            headers["x-recaptcha-token"] = token
            resp = requests.post(url, headers=headers, json={}, proxies=proxies, timeout=30)
            data = resp.json()
            error = data.get("error")

            with lock:
                with open("faucet_log.txt", "a", encoding="utf-8") as f:
                    if not error:
                        print(f"✅ [{wallet_address}] 领水成功")
                        f.write(f"{datetime.now()}: {wallet_address} - 领水成功\n")
                        return True
                    elif "Already claimed today" in error:
                        print(f"[*] [{wallet_address}] 今日已领取，跳过")
                        f.write(f"{datetime.now()}: {wallet_address} - 今日已领取\n")
                        return False
                    else:
                        print(f"❌ [{wallet_address}] 领水失败: {error} (尝试 {attempt + 1}/{MAX_RETRIES})")
                        f.write(f"{datetime.now()}: {wallet_address} - 领水失败: {error}\n")

        except Exception as e:
            print(f"⚠️ [{wallet_address}] 领水请求异常: {e} (尝试 {attempt + 1}/{MAX_RETRIES})")
        time.sleep(3)
    return False


# --- 任务 2: 每日问答 (Daily Quiz) ---
def daily_quiz(access_token, wallet_address, proxies):
    """执行每日答题"""
    print(f"[*] [{wallet_address}] 开始执行每日问答...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": FakeUserAgent().random
    }
    today = datetime.now().strftime("%Y-%m-%d")
    try:
        # 1. 创建 quiz
        create_payload = {"title": f"daily_quiz_{today}", "num": 1, "eoa": wallet_address}
        create_url = "https://neo.prod.gokite.ai/v2/quiz/create"
        quiz_resp = requests.post(create_url, json=create_payload, headers=headers, proxies=proxies, timeout=20).json()
        if "data" not in quiz_resp or "quiz_id" not in quiz_resp["data"]:
            # "quiz already created" or other errors
            error_msg = quiz_resp.get('error', '未知错误')
            if 'already created' in error_msg:
                print(f"[*] [{wallet_address}] 今日问答已完成")
            else:
                print(f"❌ [{wallet_address}] 创建问答失败: {error_msg}")
            return

        quiz_id = quiz_resp["data"]["quiz_id"]

        # 2. 获取问题
        get_url = f"https://neo.prod.gokite.ai/v2/quiz/get?id={quiz_id}&eoa={wallet_address}"
        question_data = requests.get(get_url, headers=headers, proxies=proxies, timeout=20).json()["data"]["question"][
            0]

        # 3. 提交答案
        submit_payload = {
            "quiz_id": quiz_id,
            "question_id": question_data["question_id"],
            "answer": question_data["answer"],  # 直接使用API返回的正确答案
            "finish": True,
            "eoa": wallet_address
        }
        requests.post("https://neo.prod.gokite.ai/v2/quiz/submit", json=submit_payload, headers=headers,
                      proxies=proxies, timeout=10)
        print(f"✅ [{wallet_address}] 每日问答成功")

    except Exception as e:
        print(f"❌ [{wallet_address}] 每日问答失败: {e}")


# --- 任务 3: AI 交互 ---
def run_kite_inference(access_token, aa_address, proxies, quest_data):
    """(最終融合版) 結合已知可用邏輯，運行 Kite AI 推理任務"""
    print(f"[*] [{aa_address}] 開始執行 Kite AI 交互 (10次)...")

    if not quest_data or not isinstance(quest_data, dict):
        print("    - ❌ quest.json 数据无效或为空，跳过 Kite AI 任务。")
        return

    for i in range(10):
        for attempt in range(1, 4):  # 最多重試3次
            try:
                available_roles = list(quest_data.keys())
                if not available_roles:
                    print("    - ❌ quest.json 中没有可用的角色，跳过。")
                    break

                role = random.choice(available_roles)
                role_data = quest_data.get(role, {})
                service_id = role_data.get("service_id")
                questions = role_data.get("questions")

                if not service_id or not questions:
                    print(f"    - ⚠️ 角色 '{role}' 的配置不完整，跳过此次提问。")
                    continue

                message = random.choice(questions)

                print(f"    - [{role}] 第 {i + 1:2d} 次提问 (尝试 {attempt}/3): {message[:30]}...")

                inference_url = "https://ozone-point-system.prod.gokite.ai/agent/inference"
                headers = {
                    "accept": "text/event-stream", "authorization": f"Bearer {access_token}",
                    "origin": "https://testnet.gokite.ai", "referer": "https://testnet.gokite.ai/",
                    "user-agent": "Mozilla/5.0",  # <-- 採用您版本中固定的 User-Agent
                }
                payload = {
                    "service_id": service_id, "subnet": "kite_ai_labs", "stream": True,
                    "body": {"stream": True, "message": message}
                }

                response = requests.post(inference_url, headers=headers, json=payload, stream=True, proxies=proxies,
                                         timeout=60)
                response.raise_for_status()

                # --- 核心修改：採用您版本中更具容錯性的解析邏輯 ---
                result = ""
                for line in response.iter_lines(decode_unicode=True):
                    if line and line.startswith("data:"):
                        if line.strip() == "data: [DONE]":
                            break
                        try:
                            clean_line = line[5:].strip()
                            if not clean_line:
                                continue
                            delta = json.loads(clean_line).get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content")
                            if content:
                                result += content
                        except:
                            # 如果單行解析失敗，靜默忽略，繼續處理下一行
                            continue

                if not result:
                    raise ValueError("推理結果為空，可能是數據流問題，觸發重試")

                print(f"    - ✅ 推理結果: {result[:50]}...")

                # --- 提交收据 ---
                receipt_url = "https://neo.prod.gokite.ai/v2/submit_receipt"
                receipt_headers = headers.copy()
                receipt_headers["content-type"] = "application/json"
                receipt_payload = {
                    "address": aa_address, "service_id": service_id,
                    "input": [{"type": "text/plain", "value": message}],
                    "output": [{"type": "text/plain", "value": result}]
                }
                r = requests.post(receipt_url, headers=receipt_headers, json=receipt_payload, proxies=proxies,
                                  timeout=30)
                r.raise_for_status()
                print(f"    - ✅ 收据提交成功 (状态码: {r.status_code})")

                time.sleep(random.uniform(2, 4))
                break  # 成功，跳出重試迴圈

            except Exception as e:
                print(f"    - ⚠️ 第 {i + 1} 次交互的第 {attempt} 次尝试失败: {e}")
                if attempt < 3:
                    print("    - ⏳ 准备重试...")
                    time.sleep(5)
                else:
                    print(f"    - ❌ 第 {i + 1} 次交互在3次尝试后徹底失敗。")


# --- 任务 4: 每日质押 (Staking) ---
def stake_random_pool(access_token, wallet_address, proxies):
    """随机向一个子网质押 1 个代币"""
    print(f"[*] [{wallet_address}] 开始执行每日质押...")
    url = "https://ozone-point-system.prod.gokite.ai/subnet/delegate"
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": FakeUserAgent().random}
    subnets = [
        "0xb132001567650917d6bd695d1fab55db7986e9a5",
        "0xca312b44a57cc9fd60f37e6c9a343a1ad92a3b6c",
        "0xc368ae279275f80125284d16d292b650ecbbff8d",
        "0x72ce733c9974b180bed20343bd1024a3f855ec0c"
    ]
    payload = {"subnet_address": random.choice(subnets), "amount": 1, "remark": "daily stake"}

    for _ in range(MAX_RETRIES):
        try:
            result = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=30).json()
            if not result.get("error"):
                tx_hash = result.get('data', {}).get('tx_hash', 'N/A')
                print(f"✅ [{wallet_address}] 质押成功, TX: {tx_hash}")
                return
            elif "No enough balance" in result.get("error", ""):
                print(f"⚠️ [{wallet_address}] 质押失败: 余额不足。请先领水。")
                return  # 余额不足，无需重试
            else:
                print(f"❌ [{wallet_address}] 质押失败: {result.get('error')}")
        except Exception as e:
            print(f"❌ [{wallet_address}] 质押请求异常: {e}")
        time.sleep(5)


# --- 任务 5: 领取子网奖励 (Claim Rewards) ---
def claim_rewards(access_token, wallet_address, proxies):
    """领取所有子网的质押奖励"""
    print(f"[*] [{wallet_address}] 开始领取所有子网奖励...")
    url = "https://ozone-point-system.prod.gokite.ai/subnet/claim-rewards"
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": FakeUserAgent().random}
    subnets = [
        "0xb132001567650917d6bd695d1fab55db7986e9a5",
        "0xca312b44a57cc9fd60f37e6c9a343a1ad92a3b6c",
        "0xc368ae279275f80125284d16d292b650ecbbff8d",
        "0x72ce733c9974b180bed20343bd1024a3f855ec0c"
    ]
    for subnet in subnets:
        try:
            payload = {"subnet_address": subnet}
            result = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=30).json()
            if not result.get("error"):
                tx_hash = result.get('data', {}).get('tx_hash', 'N/A')
                print(f"✅ [{wallet_address}] 成功领取子网 {subnet[-6:]} 奖励, TX: {tx_hash}")
            elif "claimable rewards is zero" in result.get("error", ""):
                print(f"[*] [{wallet_address}] 子网 {subnet[-6:]} 无可领取奖励")
            else:
                print(f"❌ [{wallet_address}] 子网 {subnet[-6:]} 领取失败: {result.get('error')}")
        except Exception as e:
            print(f"❌ [{wallet_address}] 领取子网 {subnet[-6:]} 奖励异常: {e}")
        time.sleep(1)
    print(f"[*] [{wallet_address}] 所有子网奖励领取尝试完成。")


# ==============================================================================
# 3. 主流程控制
# ==============================================================================

def process_wallet(wallet_address, proxy, quest_data):
    """为单个钱包执行所有任务"""
    print(f"\n{'=' * 30} ✨ 开始处理钱包: {wallet_address} {'=' * 30}")

    # 步骤 0: 初始化 (准备代理, 登录, 获取 AA 地址)
    proxies_dict = {"http": proxy, "https": proxy} if proxy else None
    if proxy:
        print(f"[*] [{wallet_address}] 使用代理: {proxy.split('@')[-1]}")
    else:
        print(f"[*] [{wallet_address}] 不使用代理")

    access_token = login(wallet_address, proxies_dict)
    if not access_token:
        print(f"❌ [{wallet_address}] 登录失败，跳过该钱包所有任务。")
        with lock:
            with open("failed_wallets.txt", "a", encoding="utf-8") as f:
                f.write(f"{wallet_address} - 登录失败\n")
        return

    aa_address = get_aa_address(wallet_address, proxies_dict)
    if not aa_address:
        print(f"❌ [{wallet_address}] 无法获取 AA 地址，部分任务可能失败。")
        # 即使获取失败，也继续执行，因为某些任务可能不需要 AA 地址

    # 按顺序执行任务
    # 任务 1: 每日领水
    faucet_transfer(access_token, wallet_address, proxies_dict)
    time.sleep(random.uniform(1, 3))

    # 任务 2: 每日问答
    daily_quiz(access_token, wallet_address, proxies_dict)
    time.sleep(random.uniform(1, 3))

    # 任务 3: AI 交互 (需要 AA 地址)
    if aa_address:
        run_kite_inference(access_token, aa_address, proxies_dict, quest_data)
        time.sleep(random.uniform(1, 3))
    else:
        print(f"[*] [{wallet_address}] 因缺少 AA 地址，跳过 AI 交互任务。")

    # 任务 4: 每日质押
    stake_random_pool(access_token, wallet_address, proxies_dict)
    time.sleep(random.uniform(1, 3))

    # 任务 5: 领取奖励
    claim_rewards(access_token, wallet_address, proxies_dict)

    print(f"🎉 钱包 {wallet_address} 所有任务执行完毕 {'=' * 30}")
    time.sleep(SLEEP_TIME_PER_ACCOUNT)


def main():
    # 读取钱包
    try:
        with open("wallets.txt", "r", encoding="utf-8") as f:
            wallets = [line.strip() for line in f if line.strip()]
        if not wallets:
            print("❌ mywallets.txt 文件为空，请添加钱包地址。")
            return
    except FileNotFoundError:
        print("❌ 未找到 mywallets.txt 文件，请创建并填入钱包地址。")
        return

    # 读取代理
    proxies = load_proxies()

    # 读取 AI 问题数据
    try:
        with open("quest.json", "r", encoding="utf-8") as f:
            quest_data = json.load(f)
    except FileNotFoundError:
        print("❌ 未找到 quest.json 文件，AI 交互任务将无法执行。")
        quest_data = {}
    except json.JSONDecodeError:
        print("❌ quest.json 文件格式错误，AI 交互任务将无法执行。")
        quest_data = {}

    # 使用线程池并发处理钱包
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for wallet in wallets:
            # 为每个钱包任务随机选择一个代理
            proxy = random.choice(proxies) if proxies else None
            futures.append(executor.submit(process_wallet, wallet, proxy, quest_data))

        for future in as_completed(futures):
            try:
                future.result()  # 等待线程完成，并捕获可能出现的异常
            except Exception as e:
                print(f"💥 [主线程捕获异常]: {e}")

    print("\n✅ 所有钱包均已处理完毕。")


if __name__ == "__main__":
    # 在运行前检查 CAPTCHA_KEY 是否已配置
    if CAPTCHA_KEY == "YOUR_YESCAPTCHA_API_KEY":
        print("*" * 60)
        print("⚠️  警告: CAPTCHA_KEY 未在脚本中配置,推荐使用https://yescaptcha.com/i/iVXk4u。")
        print("   领水 (Faucet) 功能将无法使用。")
        print("   请在脚本第 22 行替换 'YOUR_YESCAPTCHA_API_KEY'。")
        print("*" * 60)
    main()