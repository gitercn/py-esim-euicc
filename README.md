# 凤凰读卡器 / eSIM eUICC 工具

PL2303 USB 转串口读卡器上的一套 SIM / eUICC 小工具。**所有脚本共用 `euicc_lpa.py` 里的
`Phoenix` 类**（过程字节握手、`0x60` NULL 跳过、`Le=0`→256、`61xx` 链）。新脚本直接
`from euicc_lpa import Phoenix`，不要再写一份。

## 驱动

用 `drivers/PL2303_3.3.11.152_x86_x64_2010`，新版驱动会报错。

## 脚本

| 脚本 | 用途 |
|---|---|
| `euicc_lpa.py` | 传输层 + eUICC 信息：ATR、EID、Info2、Profile 列表 |
| `sim_dump.py` | 普通 SIM/USIM：ICCID、IMSI、ACC、SPN、FPLMN、PLMNSEL、R1-R5、SMSP、MSISDN（`--auth` 跑一次 GSM 算法往返）|
| `euicc_download.py` | LPA 原型：ES9+ / ES10b 全流程，可停在任意阶段；带 `--enable` / `--verify-ff03` |
| `enable_profile.py` | 只做 ES10c：列 profile、启用、复位、报 AID。不重新下载、不要新激活码 |
| `probe_after_install.py` | 装完后看三件事：哪张在启用、`EF.DIR(2F00)` 登记了哪些 AID、卡对哪些 AID 回 `9000` |
| `read_ff03.py` | 单独读 `EF_FF03`（R1-R5），不碰 ISD-R |
| `verify_profile_der.py` | 离线解 DER（要 pysim）：列 PE / FID / 内容，查字节串，数 BPP 里的 `0x86` 条数 |
| `mk_cmcc_ff03.py` | 从 pristine GSMA 测试 UPP 生成 CMCC 形状的包（要 pysim），`--imsi/--iccid` 必填 |
| `diff_card.py` | 把包和卡里的同名 EF 逐字段对比，尾部填充不算差异 |
| `sim_chunk_write.py` | 分块 STORE DATA 测试，观察 `0x60` NULL 行为 |
| `start-smdpp.bat` | 启动本地 osmo-smdpp（测试用 SM-DP+）|

## 常用命令

```powershell
python sim_dump.py COM4 19200            # 普通 SIM / USIM
python euicc_lpa.py COM4 19200           # eUICC 基本信息

# LPA：默认停在拿到 profile 包之后不写卡，加 --load 才写
python euicc_download.py 'LPA:1$host$MATCHING-ID' COM4 [--load] [--stop=authclient]
# 一条跑完：写卡 + 启用 + 复位 + 读回 FF03（卡里有多张时加 --iccid=…）
python euicc_download.py 'LPA:1$host$MATCHING-ID' COM4 --load --enable --verify-ff03
```

> **Windows 引号**：激活码里有两个 `$`。PowerShell 双引号会展开 `$rsp` / `$XXXXX`，
> 结果变成 `LPA:1.example.com-XXXXX-...`，脚本报 `bad activation code`。**一律用单引号**，
> cmd.exe 和 bash 也一样安全。

## 写卡

### 装完还有两步：enable 和 verify

`--load` 只是把 profile **装进去**，装完是 disabled，卡上还看不到它的文件系统。要读私有
文件（比如 `EF_FF03` / R1-R5）必须：

1. **ES10c EnableProfile**（`--enable`）——`BF31 { A0 { 5A 0A <iccid> } 81 01 FF }`，
   `refreshFlag=TRUE`。不指定 `--iccid` 时自动挑最后一张 disabled 的。
2. **REFRESH**——在凤凰读卡器上就是拉一次 RTS（`ph.reset()`）。复位后逻辑通道全关，
   ISD-R 要重选，但 USIM 应用这时候才存在。
3. **读 FF03**（`--verify-ff03`）——先试 `3F00/FF03`，再试 `3F00/7FF0/FF03`。

也可以单独跑 `python read_ff03.py COM4`（前提是已经 enable 过）。注意 `--enable` 之后
必须真的复位，否则读到的还是旧状态；部分 eUICC 需要拔插读卡器。

`Phoenix.reset()` 会自己重试：这个 PL2303 在 19200 8E2 下经常第一次复位只回一串 `0x00`，
同一个句柄重复拉 RTS 也清不掉，必须关掉串口重开。所以失败时它 close/open 再打一次脉冲，
最多 4 次。连续 4 次拿不到 `3B/3F` 开头的 ATR，就是卡真死了（或者没插好）。

### 装不进去时（`6A88` / `6A80` / `6D00` …）

```powershell
python euicc_lpa.py COM4                                            # 先看卡里现在有什么
python euicc_download.py 'LPA:1$x$y' COM4 --load --mode=stream --trace
```

- **`--mode=tlv`（默认，唯一能用的）**：按 **TLV 边界**把 BPP 切成一条条完整的 DER 片段，
  每条一个 STORE DATA。关键点：**eUICC 对每条 ES10b 命令是独立解析的**，一条命令里必须是
  语法完整的 TLV，绝不能按偏移切（第二段从 TLV 中间开始，卡在最后一块回 `6A88`）。
  切法和 NekokoLPA 的 `_decomposeBpp` 一致（来源 lpac）：

  ```
  段 0   : BF36 头 + BF23 InitialiseSecureChannelRequest
  A0/A2  : 序列头 + 第 1 个元素，然后剩下每个元素各一段
  A1/A3  : 序列头单独一段，然后每个元素各一段
  其它   : 整个元素一段
  ```

  12 KB 的包会变成 17 段、最大 1020 B，全部落在卡的 4 KB 单命令窗口内。本卡上已完整装成功。
- **`--mode=stream`**：把 `BF36 + 整个 body` 当一条命令发。只有单命令窗口装得下时才行；
  配 `--segment` 硬切会把 TLV 切断，不推荐。
- **`--mode=elements`**：拆掉 `BF36`、把每个顶层 TLV 当独立命令发。只有老 ISD-R 认。
- **`--chunk=255`** 单条命令内的分块大小（255 = 一条短命令装完，最省事）；
  **`--trace`** 逐条打印 APDU 头和 SW。
- **`--bpp=` 在这张卡上不行**：没走 PrepareDownload 时 ISD-R 直接回 `6D00`（INS not
  supported）。每次都得走完整 ES9+。

### 这张卡的两个怪癖（已实测）

1. **单条 ES10b 命令上限 4096 字节**，与块数无关（16×255、24×170、32×128 都能过，
   4112 B 就 `6A84`）。所以只能靠 `--mode=tlv` 分段。
2. **`refreshFlag` 必须显式编码，即使它是 FALSE**。`81 01 00` → `enableResult=0`；
   省掉这个字段（严格 DER 的做法）→ `127 (undefinedError)`；`81 01 FF` → `7`（这张卡
   不肯自己做 REFRESH）。`enable_profile()` 已自动处理：先发 TRUE，被拒改发显式 FALSE，
   再由我们 RTS 复位。

## 离线检查（不用读卡器）

```powershell
python mk_cmcc_ff03.py --imsi=460009876543210 --iccid=89860012345678901234
python verify_profile_der.py cmcc_ff03.der   # 列 PE / FID，确认 FF03 = 20132F495B
```

`verify_profile_der.py` 打印每个 PE 的类型和每个文件的 FID + 内容，末尾直接说目标字节串在
不在；遇到重复的 PE-MF / PE-Header / PE-End 会报 `ILLEGAL`（SGP.22 只允许一个）。拿到 BPP
后还能 `--bpp=FILE` 数 `0x86` 命令条数，它必须等于 DER 里的 PE 个数。

### DER 能决定什么，不能决定什么

拿 `cmcc_ff03.der` 打 opencode 的 `/validate-der-file`，回显就是它从包里读出来的东西。
实测这个 DP 基本**照抄 DER**：

| 字段 | 来自 DER？ | 实测 |
|---|---|---|
| `imsi` | **是** | 改 `EF.IMSI` → 回显跟着变（`460001234567890` → `460009876543210`）|
| `spn` | **是** | 改 `EF.SPN` → 回显 `China Mobile` |
| `ki` / `opc` | **是** | 来自 `A4 akaParameter`，不是 `EF.KEYS` |
| `iccid` | **是**，但 DP 解错半字节 | 包里 `89860012345678901234` → 回显 `98680021436587092143` |
| 文件布局 / `EF_FF03` | **是** | GFM 里加什么，卡上就有什么 |

`ki`/`opc` 最容易看错。回显的 `ki=000102…0F` / `opc=00…00` **正好就是**测试 UPP 里
`A4 akaParameter` 的两个字段：

```text
A4 35 A0 05 80 00 81 01 0B A1 2C A1 2A
      80 01 03                       <- algorithmID = 3
      81 01 02                       <- algorithmOptions
      82 10 000102030405060708090A0B0C0D0E0F   <- K
      83 10 00000000000000000000000000000000   <- OPc
```

所以 **Ki/OPc 在 profile 包里**，位置是 `A4 akaParameter`，不是 `EF.KEYS`。`EF.KEYS`（6F08）
永远是 `07 FF*32`，那是给卡内个人化代理填的占位符，改它没用；改 `A4` 才有用。

`iccid` 的"红叉"是 DP 自己的 bug：`89860012345678901234` 按 GSM 11.11 低半字节在前打包是
`98 68 00 21 43 65 87 09 21 43`，DP 按高半字节在前解回去得到 `98680021436587092143`——
同一串字节、相反方向，一个数字都不差。**包没问题，是它解错了**。

所以：`--ki/--opc` 能换掉包里的密钥（不带则保留测试向量，`verify_profile_der.py` 会警告
`placeholder test key`），但**改不出真网能用的卡**——鉴权要运营商为该 IMSI 签发的 Ki/OPc，
只在 HLR/HSS 和原卡安全存储里。DER 只决定"卡里长什么样"：IMSI / SPN / 文件布局 / FF03 / AID。

### ICCID 必须"三处一致"

大多数 eUICC 会把 `storeMetadata` 声明的 ICCID 和 profile 内部 ICCID 交叉校验。profile 里
有**两个** ICCID：

| 位置 | 谁读 |
|---|---|
| `PE-Header` (A0) 的 `iccid` 字段 | DP / 卡，这是**权威**值 |
| `EF.ICCID` (2FE2) 的内容 | 卡的文件系统 |

只改 `EF.ICCID` 不改 `PE-Header`，比两个都不改更糟——直接
`installFailedDueToDataMismatch`。`mk_cmcc_ff03.py` 两处一起改。三处要相等：
**DP 声明的 = PE-Header.iccid = EF.ICCID**。DP 声明的那个值装失败时会写在 `load_result.bin`。

### 装失败怎么知道原因（不用再猜 6985）

`LoadBoundProfilePackage` 失败时，卡可能**直接在段响应里**返回 `ProfileInstallationResult`，
而不是留一条通知——丢掉它就只能看到后面那句莫名其妙的 `6985`。`load_bpp` 现在会自动存成
`load_result.bin` 并当场解码：

```powershell
python euicc_download.py --decode-result=load_result.bin
```

```
[result] ProfileInstallationResult: ERROR
[result]   transactionId = 0102030405060708090A0B0C0D0E0F10
[result]   bppCommandId  = 5 (loadProfileElements)
[result]   errorReason   = 13 (installFailedDueToDataMismatch)
[result]   storeMetadata ICCID = 98680021436587092143
```

完整取值见 `ERR_REASON_NAMES`（照 SGP.22）。注意这张卡实际发的是
`BF37 { BF27 …, A2 { A1 … } }`，不是规范文字里的 `A0/A3`，解码器两种都认。

## 装上了、读得到 FF03，但手机没信号

装成功 ≠ 能用。先跑一遍对比，别直接插手机：

```powershell
python sim_dump.py COM4
```

五个曾经把卡做成"能装能读但不能用"的坑：

1. **`EF.DIR` 里的 AID 决定手机能不能选到 USIM。** eUICC 按 `EF.DIR` 注册 AID。测试 UPP
   记录 1 写的是 `A0000000871002FF49FFXXXX`（12 字节），实测选它 `9000`，选标准
   `A0000000871002FF33FFXXXX` 是 `6A82`——手机永远问标准 AID，所以看着有卡、实际没有
   USIM。`mk_cmcc_ff03.py` 会把记录 1 换成标准 AID。
2. **IMSI 用占位值会静默失败。** 装得上、读得回、就是注不上网。`--imsi/--iccid` 现在必填。
3. **`A4 akaParameter` 里带的是测试密钥。** 装得上、读得回、IMSI 也对，但网络鉴权必然
   失败（`000102…0F` / `00…00` 是公开测试向量）。用 `--ki/--opc` 改。
4. **`EF.AD` 第一个字节是 `0x80` 而不是 `0x00`。** 这是 `ms_operation_mode`：`00` = normal，
   `80` = type approval（产测/型号认证）。测试 UPP 自带 `80000002`，真卡是 `00000002`。
   名字像内部字段，实际是告诉手机按什么模式工作，属于功能差异。
5. **`EF.UST` 声明支持哪些 USIM 服务。** 这一项**故意不跟着真卡改**，原因见下。

### 怎么和一张能用的卡逐字段对齐

```powershell
python diff_card.py cmcc_ff03.der COM4
```

把卡上（`7F20` / `7F10`）和包里同名的 EF 逐条对比，尾部填充不算差异（250 字节的
`PLMNwAcT` 和 60 字节的都只表示"没有优选 PLMN"）。当前实测 12 项里 11 项一致：

| 字段 | 真卡 | 包里 | |
|---|---|---|---|
| `EF.IMSI` | `084906008967452301` | 同 | ✓ |
| `EF.ACC` | `0080` | 同 | ✓ |
| `EF.AD` | `00000002` | 同 | ✓ |
| `EF.SPN` | `00 "CMCC"` | 同 | ✓ |
| `EF.FPLMN` | `45008 45012 45030 45005` | 同 | ✓ |
| `EF.PLMNwAcT` | 空 | 空 | ✓ |
| `EF.OPLMNwAcT` | 46000 ×3（E-UTRAN/UTRAN/GSM）| 同 | ✓ |
| `EF.HPLMNwAcT` | 同上 | 同 | ✓ |
| `EF.HPPLMN` | `50` | 同 | ✓ |
| `EF.MSISDN` | 空 | 空 | ✓ |
| `EF.SMSP` | SMSC `+8613800200500` | 同 | ✓ |
| `EF.UST` | 12 字节 | 15 字节 | **故意不同** |

```powershell
python mk_cmcc_ff03.py --imsi=460009876543210 --iccid=89860012345678901234 `
  --spn=CMCC --spn-flag=00 --acc=0080 --ad=00000002 --hpplmn=50 `
  --fplmn=45008,45012,45030,45005 --smsc=+8613800200500 `
  --oplmn=46000:4000,46000:8000,46000:0080 `
  --hplmn=46000:4000,46000:8000,46000:0080 --out=cmcc_ff03.der
```

`AcT` 是 16 位访问技术位（TS 31.102 §4.2.5）：**`0x8000` UTRAN、`0x4000` E-UTRAN、
`0x0080` GSM**。E-UTRAN 占 bit 14-12 三位，`0x4000` = WB-S1 + NB-S1 都支持，`0x6000` 只 WB，
`0x5000` 只 NB。所以上面三条是"46000 三网都允许"；只写 `46000:4000` 就只有 E-UTRAN。

### 为什么 `EF.UST` 不跟着改

1. 那张真卡**没有 ADF.USIM**（`7FD0` 和所有 AID 都回 `6A82`），读到的 `6F38` 是 `DF.GSM`
   里的文件，按 TS 51.011 那里并没有 EF.UST，所以它未必是 USIM 服务表。
2. 内容自相矛盾：服务 12（SMS）没置位却有 SMSC，服务 42/43 没置位却有 `OPLMNwAcT`/
   `HPLMNwAcT`。照抄没意义。
3. 包里的 UST 是 SAIP 标准值，和包里实际带哪些文件对得上（42/43 置位正好对应刚填的两个
   PLMN 列表）。而且它 15 字节、真卡 12 字节，改就得连文件尺寸一起改。

顺带：`sim_dump.py --auth` 只说明 USIM applet 活着且有一把密钥，**不能**说明密钥是对的。
Ki/OPc 既不能用 `READ BINARY` 读，也不能靠"选得上 USIM"证明；唯一证明是拿真网下发的
RAND/AUTN 跑一次鉴权，或者直接插手机看能不能注册。

## 硬件前提

- 读卡器开关拨到 **19200** 一侧（靠 USB 口那端）
- 卡没插好表现为"无 ATR"；卡被错误 APDU 弄死后只能**拔插读卡器**恢复
- 串口被别的程序占用时报 `PermissionError`，先关掉那个程序

## 卡类型怎么区分

| | 普通 SIM | eUICC |
|---|---|---|
| ATR | `3B 9F 95 XX …`（TD1=0x80，只支持 T=0）| `3B 9F 96 XX …` |
| `SELECT ISD-R` | 无响应（没有这个 applet）| `9000` |
| `GET DATA EID` | 无响应 | 返回 32 字节 EID |
| `sim_dump.py` | 能读全部字段 | 只能读 ICCID 部分 |

## 依赖

```powershell
uv sync
uv run python sim_dump.py COM4 19200
```

`pyserial` 管串口，`requests` 管 ES9+ HTTP，**读写卡都不需要 pysim**——
`euicc_download.py` 原本只用 pysim 解两个 ASN.1 响应，现在换成了自带的
`decode_choice_response()`（30 行 DER 读取，已用真实响应验证）。`verify_profile_der.py` /
`mk_cmcc_ff03.py` 是例外，它们纯离线、要 pysim。

### 可选：本地测试 SM-DP+

`start-smdpp.bat` 需要 osmocom 的 pysim（**没发布到 PyPI**，PyPI 上的 `pysim` 是另一个项目）：

```powershell
git clone https://github.com/osmocom/pysim.git
cd pysim && git checkout 39c2f6f3f647d3acc8728eb4b3c8fe6769f2b03e   # 补丁基于这个提交
uv sync --extra smdp
```

`--extra smdp` 会从 GitHub 装 `pySim @ git+...` 并带一大串依赖（asn1tools / twisted /
pyscard …）。**读写卡的四个工具都用不到**，只有跑 `osmo-smdpp.py` 才需要；而且它用 SGP.26
测试证书，生产根的 eUICC 会拒绝。

Windows 上还有个路径转义问题：Twisted 把 endpoint 字符串当 `":"` 分隔、`"\"` 转义的描述
解析，所以证书路径里的反斜杠要换成 `/`。修复在 `patches/osmo-smdpp-windows.patch`，
`start-smdpp.bat` 会自动应用。
