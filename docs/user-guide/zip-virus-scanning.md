# ZIP 病毒扫描功能

## 概述

ZIP 病毒扫描分析器使用 VirusTotal API 扫描完整的 ZIP 包文件，检测潜在的恶意软件包。这与现有的 VirusTotal 分析器（扫描单个二进制文件）互补，提供了额外的安全层。

## 功能特点

- 扫描完整的 ZIP 包文件（而不是解压后的单个文件）
- 使用 VirusTotal 的 SHA256 哈希查找
- 支持多种压缩格式：.zip, .tar, .gz, .tgz, .tar.gz
- 可选择上传未知文件到 VirusTotal 进行扫描
- 与其他分析器架构一致
- 独立的分析器，可单独启用或禁用

## 配置

### 环境变量

需要配置 VirusTotal API 密钥：

```bash
export VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

或在 `.env` 文件中：

```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

## API 使用

### 启用 ZIP 病毒扫描

在任何扫描请求中添加 `use_zip_virus: true` 参数：

```json
{
  "clawhub_url": "https://clawhub.ai/username/project-name",
  "policy": "strict",
  "use_zip_virus": true,
  "vt_upload_files": false
}
```

### 参数说明

- `use_zip_virus` (boolean): 是否启用 ZIP 病毒扫描，默认 `false`
- `vt_upload_files` (boolean): 是否上传未知文件到 VirusTotal，默认 `false`
  - `false`: 仅检查已存在的哈希（更注重隐私）
  - `true`: 如果哈希不存在，上传文件进行扫描

### 与 VirusTotal 分析器的区别

| 特性 | VirusTotal 分析器 | ZIP 病毒分析器 |
|------|------------------|---------------|
| 扫描对象 | 单个二进制文件 | 完整 ZIP 包 |
| 文件类型 | .exe, .dll, .pdf, .png 等 | .zip, .tar, .gz 等 |
| 启用参数 | `use_virustotal` | `use_zip_virus` |
| 可同时使用 | ✓ | ✓ |

## 使用示例

### 示例 1: 基本扫描

```bash
curl -X POST "http://localhost:8000/scan-clawhub" \
  -H "Content-Type: application/json" \
  -H "X-VirusTotal-Key: your_api_key" \
  -d '{
    "clawhub_url": "https://clawhub.ai/username/project",
    "use_zip_virus": true
  }'
```

### 示例 2: 同时启用两个 VirusTotal 分析器

```bash
curl -X POST "http://localhost:8000/scan-clawhub" \
  -H "Content-Type: application/json" \
  -H "X-VirusTotal-Key: your_api_key" \
  -d '{
    "clawhub_url": "https://clawhub.ai/username/project",
    "use_virustotal": true,
    "use_zip_virus": true,
    "vt_upload_files": false
  }'
```

### 示例 3: 使用 Python

```python
import asyncio
import httpx
import os

async def scan_with_zip_virus():
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/scan-clawhub",
            json={
                "clawhub_url": "https://clawhub.ai/username/project",
                "use_zip_virus": True,
                "vt_upload_files": False,
            },
            headers={"X-VirusTotal-Key": vt_api_key}
        )
        return response.json()

result = asyncio.run(scan_with_zip_virus())
print(result)
```

### 示例 4: 运行示例脚本

```bash
# 设置 API 密钥
export VIRUSTOTAL_API_KEY=your_key

# 运行示例
python examples/scan_with_zip_virus.py
```

## 扫描结果

### 成功响应示例

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "skill_name": "example-skill",
  "is_safe": false,
  "max_severity": "CRITICAL",
  "findings_count": 1,
  "scan_duration_seconds": 2.5,
  "timestamp": "2026-03-11T10:00:00Z",
  "findings": [
    {
      "id": "ZIP_VT_a1b2c3d4",
      "rule_id": "ZIP_VIRUSTOTAL_MALICIOUS",
      "category": "malware",
      "severity": "CRITICAL",
      "title": "Malicious ZIP package detected: skill.zip",
      "description": "VirusTotal detected this ZIP package as potentially malicious. 15/70 security vendors flagged this file as malicious. File size: 1.5 MB. SHA256: a1b2c3d4...",
      "file_path": "skill.zip",
      "analyzer": "zip_virus",
      "metadata": {
        "file_hash": "a1b2c3d4e5f6...",
        "file_size": 1572864,
        "malicious_count": 15,
        "suspicious_count": 3,
        "total_engines": 70,
        "detection_ratio": 0.214,
        "references": [
          "https://www.virustotal.com/gui/file/a1b2c3d4..."
        ]
      }
    }
  ]
}
```

### 严重程度判定

分析器根据检测率自动判定严重程度：

- **CRITICAL**: 30% 或以上的安全厂商标记为恶意
- **HIGH**: 10-30% 的安全厂商标记为恶意
- **MEDIUM**: 有可疑标记
- **LOW**: 其他情况

## 工作流程

1. 扫描器在技能包中查找 ZIP 文件（.zip, .tar, .gz 等）
2. 计算每个 ZIP 文件的 SHA256 哈希值
3. 查询 VirusTotal 数据库
4. 如果启用了 `vt_upload_files` 且哈希不存在，上传文件进行扫描
5. 分析检测结果并生成发现报告
6. 根据检测率判定严重程度

## 限制

- **文件大小**: VirusTotal 免费 API 限制为 32MB，高级 API 为 650MB
- **速率限制**: VirusTotal API 有速率限制，请参考其文档
- **上传时间**: 上传和扫描大文件可能需要较长时间
- **隐私**: 上传文件会将其发送到 VirusTotal（第三方服务）

## 最佳实践

1. **默认不上传**: 设置 `vt_upload_files: false` 以保护隐私
2. **组合使用**: 同时启用 `use_virustotal` 和 `use_zip_virus` 以获得全面保护
3. **CI/CD 集成**: 在 CI/CD 管道中自动扫描所有 ZIP 包
4. **定期扫描**: 定期重新扫描以检测新发现的威胁

## 故障排除

### 错误: "VirusTotal API key is missing"

确保设置了环境变量：
```bash
export VIRUSTOTAL_API_KEY=your_key
```

### 错误: "Rate limit exceeded"

VirusTotal API 有速率限制。等待一段时间后重试，或升级到高级 API。

### 错误: "File too large to upload"

ZIP 文件超过 32MB（免费 API）。考虑：
- 使用高级 API（650MB 限制）
- 设置 `vt_upload_files: false` 仅检查哈希
- 减小 ZIP 文件大小

## 安全注意事项

- ZIP 病毒扫描是额外的安全层，不能替代其他安全措施
- 即使 VirusTotal 未检测到威胁，文件仍可能包含恶意代码
- 建议结合多个分析器使用（静态分析、LLM 分析等）
- 上传文件到 VirusTotal 会将其发送到第三方服务

## 相关文档

- [VirusTotal 分析器文档](../architecture/analyzers/index.md)
- [API 端点参考](../reference/api-endpoint-reference.md)
- [ClawHub 扫描功能](clawhub-scanning.md)
