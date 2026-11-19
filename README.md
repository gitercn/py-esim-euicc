# 凤凰读卡器 / eSIM eUICC 工具

凤凰读卡器是一种便宜的读取SIM卡的工具， USB 转串口读卡器（PL2303）上的一套小工具。**所有脚本共用同一个 T=0 传输层**：
`euicc_lpa.py` 里的 `Phoenix` 类（过程字节握手、NULL 字节跳过、`Le=0`→256、
`61xx` 链）。新增脚本请直接 `from euicc_lpa import Phoenix`，不要再自己写一份。

## 驱动

drivers文件夹包含一些驱动，推荐用 PL2303_3.3.11.152_x86_x64_2010 这个版本的驱动，不要用新的新的会报错。

## 脚本

| 脚本 | 用途 |
|---|---|
| `euicc_lpa.py` | **传输层 + eUICC 信息**：ATR、EID、Info2、Profile 列表 |
| `sim_dump.py` | **普通 SIM/USIM 信息**：ICCID、IMSI、SPN、FPLMN、SMSP、MSISDN |
| `euicc_download.py` | **LPA 原型**：ES9+ / ES10b 全流程，可只跑到某个阶段不写卡 |
| `sim_chunk_write.py` | 分块 STORE DATA 测试，用来观察 `0x60` NULL 字节行为 |
| `start-smdpp.bat` | 启动本地 osmo-smdpp（测试用 SM-DP+） |

## 常用命令

```powershell
# 普通 SIM
python sim_dump.py COM4 19200

# eUICC 基本信息
python euicc_lpa.py COM4 19200

# LPA 全流程：默认停在拿到 profile 包之后，不写卡
python euicc_download.py "LPA:1$host$MATCHING-ID" COM4
# 真的写进卡
python euicc_download.py "LPA:1$host$MATCHING-ID" COM4 --load
# 只跑到 AuthenticateClient
python euicc_download.py "LPA:1$host$MATCHING-ID" COM4 --stop=authclient
```

## 硬件前提

- 读卡器开关拨到 **19200** 一侧（靠 USB 口那端）
- 卡没插好会表现为"无 ATR"；卡被错误 APDU 弄死后只能**拔插读卡器**恢复
- 串口被别的程序占用时报 `PermissionError`，先关掉那个程序

## 卡类型怎么区分

| | 普通 SIM | eUICC |
|---|---|---|
| ATR | `3B 9F 95 80 …`（TD1=0x80，只支持 T=0） | `3B 9F 96 80 …` |
| `SELECT ISD-R` | 无响应（没有这个 applet） | `9000` |
| `GET DATA EID` | 无响应 | 返回 32 字节 EID |
| `sim_dump.py` | 能读全部字段 | 只能读 ICCID 部分 |

## 依赖

只有两个，用 [uv](https://docs.astral.sh/uv/) 一条命令装好：

```powershell
uv sync
uv run python sim_dump.py COM4 19200
```

`pyserial` 负责串口，`requests` 负责 ES9+ HTTP。**不需要 pysim**——`euicc_download.py` 原本只用 pysim 解两个 ASN.1 响应，现在换成了本文件里的 `decode_choice_response()`（30 行 DER 读取，已用真实响应验证）。

### 可选：本地测试 SM-DP+

`start-smdpp.bat` 需要 osmocom 的 pysim，但它**没有发布到 PyPI**（PyPI 上的 `pysim` 是另一个项目）。按需两步（缺一不可）：

```powershell
git clone https://github.com/osmocom/pysim.git    # 要的是 osmo-smdpp.py 和测试数据
uv sync --extra smdp                              # 装它的 Python 依赖
```

第二条会从 GitHub 装 `pySim @ git+https://github.com/osmocom/pysim` 并带上一大串依赖
（asn1tools / twisted / pyscard …）。**四个工具都用不到它**，只有你想跑
`osmo-smdpp.py` 时才需要——而且它用的是 SGP.26 测试证书，生产根的 eUICC 会拒绝。

注意 osmo-smdpp.py 在 Windows 上有个路径转义问题：Twisted 把 endpoint 字符串当
`":"` 分隔、`"\"` 转义的描述来解析，所以证书路径里的反斜杠要换成 `/`。
修复在 `patches/osmo-smdpp-windows.patch`，`start-smdpp.bat` 会自动应用。

补丁基于 pysim 提交 `39c2f6f3f647d3acc8728eb4b3c8fe6769f2b03e`。若要精确复现：

```powershell
git clone https://github.com/osmocom/pysim.git
cd pysim
git checkout 39c2f6f3f647d3acc8728eb4b3c8fe6769f2b03e
git apply ..\patches\osmo-smdpp-windows.patch
```
