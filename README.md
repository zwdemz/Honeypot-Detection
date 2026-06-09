# 蜜罐检测工具 (Honeypot Detection)

自动化蜜罐识别工具，支持多线程扫描、智能速率限制、主流云厂商及开源蜜罐指纹检测。

## 功能特性

| 特性 | 说明 |
|---|---|
| **URL 去重** | 输入自动去重 + 结果增量过滤 |
| **多线程扫描** | 基于 `ThreadPoolExecutor`，线程数可调 |
| **速率限制** | 令牌桶算法，精细控制请求速率 |
| **蜜罐指纹库** | 40+ 检测规则 |
| **自动重试** | 指数退避重试，容忍临时网络故障 |
| **代理支持** | 支持 HTTP 代理扫描 |
| **双格式输出** | 文本 / JSON |

## 支持的蜜罐类型

### 云厂商蜜罐
| 厂商 | 检测项 |
|---|---|
| **阿里云** | 阿里云蜜罐、Cloud Shield WAF、Aliyun DDoS |
| **腾讯云** | 腾讯云蜜罐、T-Sec WAF |
| **华为云** | 华为云蜜罐、HWS WAF |
| **AWS** | AWS Honeypot、GuardDuty、Honey Token |
| **Azure** | Azure Deception、Defender for Cloud、Sentinel |
| **GCP** | Google Cloud Deception、Chronicle |

### 开源蜜罐
| 项目 | 类型 |
|---|---|
| **HFish** | 国产高交互蜜罐平台 |
| **T-Pot** | 德国电信多蜜罐平台 |
| **Cowrie / Kippo** | SSH 中交互蜜罐 |
| **Conpot** | ICS 工业控制蜜罐 |
| **Dionaea** | 服务漏洞模拟蜜罐 |
| **Glastopf** | Web 应用蜜罐 |
| **Honeyd** | 虚拟蜜罐守护进程 |
| **OpenCanary** | 开源金丝雀蜜罐 |
| **MHN** | Modern Honey Network |

### 通用检测规则
- Set-Cookie 堆叠（> 5 个）
- HTML 注释密度异常（> 500 行）
- 内容低熵（词汇唯一率 < 15%）
- Content-Length 声明与实际不匹配
- 缺失安全响应头
- 自定义蜜罐 Header（X-Honeypot / X-Canary / X-Decoy）
- 严格 CSP 策略

## 安装

```bash
pip install requests urllib3
```

## 快速开始

```bash
# 10 线程扫描
python detector.py -i urls.txt

# 20 线程 + 5 req/s 限速
python detector.py -i urls.txt -t 20 -r 5

# 通过代理 + JSON 报告输出
python detector.py -i urls.txt --proxy http://127.0.0.1:8080 --json -o report/
```

## 命令行参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `-i, --input` | ✔ | — | URL 列表文件（每行一个） |
| `-t, --threads` | | 10 | 并发线程数 |
| `-r, --rate` | | 不限 | 每秒请求数限制 |
| `-o, --output` | | `.` | 输出目录 |
| `--proxy` | | — | HTTP 代理地址 |
| `--json` | | — | 输出 JSON 格式报告 |

## 输出

```
==================================================
  Scan Complete
==================================================
  Total      : 1000
  Honeypot   : 23
  Normal     : 967
  Error      : 10
==================================================
```

- **honeypot.txt** — 疑似蜜罐 URL（含触发规则）
- **normal.txt** — 正常 URL
- **report.json** (--json) — 完整结构化报告

## 许可

MIT
