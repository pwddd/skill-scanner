# ClawHub 扫描功能

## 概述

Skill Scanner 支持直接从 ClawHub URL 扫描技能包，无需手动下载和上传。

## 配置

### 环境变量

在 `.env` 文件中配置 ClawHub 下载地址前缀：

```bash
CLAWHUB_DOWNLOAD_URL_PREFIX=https://wry-manatee-359.convex.site/api/v1/download
```

如果未设置，将使用默认值：`https://wry-manatee-359.convex.site/api/v1/download`

## API 使用

### 端点

```
POST /scan-clawhub
```

### 请求参数

```json
{
  "clawhub_url": "https://clawhub.ai/username/project-name",
  "policy": "strict",
  "use_llm": false,
  "llm_provider": "anthropic",
  "use_behavioral": false,
  "use_virustotal": false,
  "vt_upload_files": false,
  "use_aidefense": false,
  "use_trigger": false,
  "enable_meta": false,
  "llm_consensus_runs": 1
}
```

### 参数说明

- `clawhub_url` (必需): ClawHub 项目 URL，格式为 `https://clawhub.ai/username/project-name`
- `policy` (可选): 扫描策略，可以是预设名称（strict, balanced, permissive）或自定义 YAML 文件路径
- `custom_rules` (可选): 自定义 YARA 规则目录路径
- `use_llm` (可选): 是否启用 LLM 分析器
- `llm_provider` (可选): LLM 提供商（anthropic 或 openai）
- `use_behavioral` (可选): 是否启用行为分析器
- `use_virustotal` (可选): 是否启用 VirusTotal 二进制文件扫描
- `vt_upload_files` (可选): 是否上传未知文件到 VirusTotal
- `use_aidefense` (可选): 是否启用 AI Defense 分析器
- `aidefense_api_url` (可选): AI Defense API URL
- `use_trigger` (可选): 是否启用触发器特异性分析
- `enable_meta` (可选): 是否启用元分析以过滤误报
- `llm_consensus_runs` (可选): LLM 共识运行次数（多数投票）

### 响应示例

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "skill_name": "caldav-calendar",
  "is_safe": true,
  "max_severity": "INFO",
  "findings_count": 0,
  "scan_duration_seconds": 2.5,
  "timestamp": "2026-03-11T10:30:00Z",
  "findings": []
}
```

## 使用示例

### 使用 curl

```bash
curl -X POST "http://localhost:8000/scan-clawhub" \
  -H "Content-Type: application/json" \
  -d '{
    "clawhub_url": "https://clawhub.ai/Asleep123/caldav-calendar",
    "policy": "strict"
  }'
```

### 使用 Python

```python
import httpx

async def scan_clawhub_skill():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/scan-clawhub",
            json={
                "clawhub_url": "https://clawhub.ai/Asleep123/caldav-calendar",
                "policy": "strict",
                "use_llm": True,
                "llm_provider": "anthropic"
            }
        )
        return response.json()
```

## URL 格式

ClawHub URL 必须遵循以下格式：

```
https://clawhub.ai/<username>/<project-name>
```

例如：
- `https://clawhub.ai/Asleep123/caldav-calendar`
- `https://clawhub.ai/steipete/nano-pdf`

系统会自动从 URL 中提取项目名称（slug），并使用配置的下载地址前缀构建下载 URL：

```
{CLAWHUB_DOWNLOAD_URL_PREFIX}?slug=<project-name>
```

## 安全限制

为了防止滥用和资源耗尽，ClawHub 扫描功能实施了以下限制：

- 最大上传大小：50 MB
- 最大 ZIP 条目数：500 个文件
- 最大解压缩大小：200 MB
- 下载超时：60 秒
- 自动检测并拒绝路径遍历和符号链接

## 错误处理

### 常见错误

1. **400 Bad Request**: 无效的 ClawHub URL 格式
2. **404 Not Found**: ClawHub 上找不到项目
3. **413 Payload Too Large**: 包大小超过限制
4. **502 Bad Gateway**: 无法从 ClawHub 下载

### 错误响应示例

```json
{
  "detail": "Invalid ClawHub URL: expected clawhub.ai domain, got example.com"
}
```

## 工作流程

1. 客户端发送包含 ClawHub URL 的 POST 请求
2. 服务器从 URL 中提取项目 slug
3. 使用配置的下载地址前缀构建下载 URL
4. 下载 ZIP 包到临时目录
5. 验证 ZIP 包大小和内容
6. 解压缩并查找 SKILL.md 文件
7. 执行安全扫描
8. 返回扫描结果
9. 清理临时文件

## 注意事项

- 确保 `CLAWHUB_DOWNLOAD_URL_PREFIX` 环境变量正确配置
- 下载的包会在扫描完成后自动清理
- 如果下载失败，请检查网络连接和 ClawHub 服务状态
- 建议在生产环境中设置 `SKILL_SCANNER_ALLOWED_ROOTS` 以限制文件系统访问
