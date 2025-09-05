# Gokite AI Testnet 自动化脚本 ✨

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

这是一个功能强大的 Python 脚本，旨在自动化与 [Gokite AI Testnet](https://testnet.gokite.ai/) 的日常交互任务。通过执行此脚本，您可以自动为多个钱包完成每日签到、领水、问答、AI 交互、质押和领取奖励等操作。

## ⚠️ 重要免责声明

* **仅供学习与教育用途**：本脚本旨在研究 Python 与 Web3 应用的交互，请勿用于商业或其他非法用途。
* **风险自负**：使用自动化脚本可能违反服务条款。所有因使用此脚本而导致的风险（包括但不限于资产损失、账户封禁）由用户自行承担。
* **非投资建议**：此项目不构成任何形式的投资建议。

---

## 🚀 主要功能

脚本将按照以下顺序为 `wallets.txt` 中的每一个钱包地址执行任务：

1.  💧 **每日领水 (Faucet)**：自动完成 Captcha 验证并领取测试网代币。 +50分
2.  🧠 **每日问答 (Daily Quiz)**：自动创建并回答每日测验以获取积分。 +50分
3.  🤖 **AI 互动 (AI Interaction)**：
    * 随机与 **Kite AI** 进行 10 次对话互动。 +100分
4.  🥩 **每日质押 (Staking)**：随机向一个验证人节点质押代币。 +50分
5.  🏆 **领取奖励 (Claim Rewards)**：自动领取所有子网的质押奖励。 +100分

---

## 🔧 环境准备

在开始之前，请确保您的系统已安装以下软件：

* [Python 3.8](https://www.python.org/downloads/) 或更高版本
* `pip` (Python 的包安装程序)

## 🛠️ 安装与设置指南

请按照以下步骤设置您的操作环境：

### 1. 克隆项目

将此项目克隆到您的本地计算机：
```bash
git clone https://github.com/BingoCrypto/kiteai-bot.git
cd kiteaibot
```

### 2. 安装依赖包

我们建议在虚拟环境中安装，以避免包冲突。
```bash
# 创建虚拟环境 (可选)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装必要的包
pip install -r requirements.txt
```

您需要手动创建 `requirements.txt` 文件，内容如下：
```txt
requests
cryptography
fake_useragent
```

### 3. 设置脚本与文件

这是最关键的一步。请在项目根目录下创建并设置以下文件：

#### A. 脚本内部设置 (`main.py`)

打开主脚本文件（例如 `main.py`），找到**全局配置**区域并修改以下参数：

* `MAX_THREADS`: 最大同时运行的线程数，建议根据您的网络和计算机性能设置（默认为 `5`）。
* `CAPTCHA_KEY`: **(必要)** 您的 [YesCaptcha](https://yescaptcha.com/i/iVXk4u) 服务的 API Key。领水功能依赖此密钥来处理 reCAPTCHA 验证。

#### B. 钱包文件 (`wallets.txt`)

创建 `wallets.txt` 文件，每行放入一个您的钱包地址。
```txt
0x1234567890abcdef1234567890abcdef12345678
0xabcdef1234567890abcdef1234567890abcdef12
...
```

#### C. 代理文件 (`proxies.txt`)

创建 `proxies.txt` 文件，每行放入一个代理。支持两种格式：
```
http://user:password@ip:port
user:password@ip:port
...
```
* `推荐代理`: **(非必要但建议使用)** 您的 [Nstproxy](https://app.nstproxy.com/register?i=O5qx52) 全世界轮换代理 流量低至0.8$/G。

如果此文件为空或不存在，脚本将尝试不使用代理运行。

#### D. AI 问题文件 (`quest.json`)

创建 `quest.json` 文件，用于 Kite AI 的互动。您可以自定义角色和问题。文件必须是有效的 JSON 格式。
```json
{
  "Crypto Analyst": {
    "service_id": "service_cIdUDSJwe77eT2gepWl5gM1j",
    "questions": [
      "What is the current trend of Bitcoin?",
      "Can you analyze the potential of Ethereum's next upgrade?",
      "Explain the concept of DeFi staking."
    ]
  },
  "Content Creator": {
    "service_id": "service_T2e2T2gepWl5gM1jcIdUDSJw",
    "questions": [
      "Give me five ideas for a YouTube video about AI.",
      "Write a short blog post about the future of remote work."
    ]
  }
}
```

## ▶️ 如何运行

完成所有设置后，在终端中执行以下命令即可启动脚本：

```bash
python main.py
```

脚本将开始逐一处理 `wallets.txt` 中的钱包，并在控制台中显示详细的执行日志。

## 📜 授权条款

本项目采用 [MIT License](LICENSE) 授权。