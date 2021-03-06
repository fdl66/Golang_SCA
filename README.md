## 功能
Golang 依赖库 安全风险分析, 协助你快速发现 Golang依赖库的安全风险。

原理：
    
    1. 从所有 go.mod 文件中解析出你依赖的所有库名和版本号。
    2. 对获取到的库名和版本号进行去重。
    3. 从缓存中查询（缓存72小时自动过期），是否已经有查询结果，有的话从缓存中取出。
    4. 缓存中没有的话，需要实时的从 https://deps.dev/ 查询获取。

> TODO: deps.dev 支持的语言不止Golang，所以，后面本项目会持续扩展对Rust、Java、Python、Node.js的支持


## 使用说明
```bash
# Input

# file: go.mod文件
# dir：包含任意go.mod文件的目录
# 你需要指定你的go.mod文件，或者把你的go.mod文件全部复制到一个文件夹里面，然后指定这个目录即可。

python3 golang_sca.py file/dir ...

eg:
    python .\golang_sca.py go.mod E:\code\py\Golang_SCA\input




# Output
output/res.json

```

## 结果样例
```json
{
    "github.com/BurntSushi/toml v0.3.1": {
        "name": "github.com/BurntSushi/toml",
        "version": "v0.3.1",
        "time": 1647013364.285942,
        "advisories": [] // 无漏洞风险
    },
    "github.com/gin-gonic/gin v1.6.0": {
        "name": "github.com/gin-gonic/gin",
        "version": "v1.6.0",
        "time": 1647013967.5933473,
        "advisories": [ // 安全风险列表
            {
                "source": "GHSA",
                "sourceID": "GHSA-h395-qcrw-5vmq",
                "sourceURL": "https://github.com/advisories/GHSA-h395-qcrw-5vmq",
                "title": "Inconsistent Interpretation of HTTP Requests in github.com/gin-gonic/gin",
                "description": "This affects all versions of package github.com/gin-gonic/gin under 1.7.0. When gin is exposed directly to the internet, a client's IP can be spoofed by setting the X-Forwarded-For header.",
                "referenceURLs": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-28483",
                    "https://github.com/gin-gonic/gin/pull/2474%23issuecomment-729696437",
                    "https://github.com/gin-gonic/gin/pull/2632",
                    "https://github.com/gin-gonic/gin/commit/bfc8ca285eb46dad60e037d57c545cd260636711",
                    "https://github.com/gin-gonic/gin/releases/tag/v1.7.0",
                    "https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMGINGONICGIN-1041736",
                    "https://github.com/advisories/GHSA-h395-qcrw-5vmq"
                ],
                "severity": "HIGH", // 高危风险
                "gitHubSeverity": "HIGH",
                "scoreV3": 7.1,
                "aliases": [
                    "CVE-2020-28483"
                ],
                "disclosedAt": 1624470801,
                "observedAt": 1639539014
            },
            {
                "source": "OSV",
                "sourceID": "GO-2021-0052",
                "sourceURL": "https://osv.dev/vulnerability/GO-2021-0052",
                "title": "GO-2021-0052",
                "description": "Due to improper HTTP header santization, a malicious user can spoof their\nsource IP address by setting the X-Forwarded-For header. This may allow\na user to bypass IP based restrictions, or obfuscate their true source.\n",
                "referenceURLs": [
                    "https://github.com/gin-gonic/gin/commit/bfc8ca285eb46dad60e037d57c545cd260636711",
                    "https://github.com/gin-gonic/gin/pull/2474",
                    "https://github.com/gin-gonic/gin/pull/2632",
                    "https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0052.yaml",
                    "https://storage.googleapis.com/go-vulndb/byID/GO-2021-0052.json"
                ],
                "severity": "UNKNOWN",
                "gitHubSeverity": "UNKNOWN",
                "aliases": [
                    "CVE-2020-28483"
                ],
                "disclosedAt": 1618401600,
                "observedAt": 1639517407
            }
        ]
    },
    "github.com/influxdata/influx-cli/v2 v2.2.1-0.20211129214229-4c0fae3a4c0d": {
        "name": "github.com/influxdata/influx-cli/v2",
        "version": "v2.2.1-0.20211129214229-4c0fae3a4c0d",
        "time": 1647013967.5923712,
        "advisories": []
    },
    "gopkg.in/square/go-jose.v2 v2.3.1": {
        "name": "gopkg.in/square/go-jose.v2",
        "version": "v2.3.1",
        "time": 1647013967.5923712,
        "advisories": []
    },
    "github.com/burntsushi/toml v0.3.1": {
        "name": "github.com/burntsushi/toml",
        "version": "v0.3.1",
        "time": 1647013967.5913942,
        "advisories": []
    }
}
```




## 依赖
1. `requests(python3)`
2. 致谢：`https://deps.dev/`







## 如果这个项目对你有用的话，麻烦点颗小星星 ^_^  

