# CRUX

CRUX 是一个在本地运行的 ZIP 密码恢复命令行工具，支持传统 PKZIP 和 WinZip AES 加密档案。`recover` 使用 Python 在 CPU 上搜索密码，找到后解压；`hashcat` 导出兼容哈希，并可调用单独安装的 hashcat 执行搜索。

当前版本：`0.2.0`。请仅用于自己拥有或已获授权恢复的档案。

## 环境初始化

需要 [uv](https://docs.astral.sh/uv/getting-started/installation/) 和 Python 3.11 或更新版本。项目通过 `.python-version` 默认选择 Python 3.11；uv 可在需要时下载对应解释器。以下命令在项目根目录执行，PowerShell、Linux 和 macOS 均可使用。

```text
uv sync
uv run crux --help
```

`uv sync` 根据随仓库提供的 `uv.lock` 创建本地 `.venv`，安装 CRUX、运行依赖及默认开发依赖。无需复制他人的虚拟环境，也无需手动设置 `PYTHONPATH`。需要严格检查锁文件时执行 `uv sync --locked`；仅安装运行依赖时执行 `uv sync --no-dev`。

克隆或下载 GitHub 仓库后，进入包含 `pyproject.toml` 的目录执行以上命令即可。Python 密码恢复和哈希导出不需要 hashcat；实际调用 hashcat 还需要它的可执行程序和对应设备运行环境。

## 目录结构与发布副本

本地开发目录的结构如下：

```text
CRUX/
├── src/crux/          # CLI、候选密码生成、恢复流程和 ZIP 处理
├── tests/             # 自行生成测试档案的回归测试
├── pyproject.toml     # 依赖、构建配置和 crux 命令入口
├── uv.lock            # 锁定的依赖版本
├── .python-version   # 默认 Python 3.11
├── .gitignore
├── LICENSE            # Apache-2.0
├── README.md
├── codes.zip          # 随项目公开发布的示例档案
├── kernels/           # 本地预留目录，不参与当前 Python 功能
└── sync/CRUX/         # 可独立上传 GitHub 的发布副本
```

上传 `sync/CRUX` 内的源码、测试、配置、文档和 `codes.zip`，使 `pyproject.toml` 位于 GitHub 仓库根目录。发布仓库不包含上层目录、`kernels` 或嵌套的 `sync`。`.git` 是本地 Git 元数据，通过 Git 提交和推送管理，不作为普通项目文件上传。

发布副本可在自己的目录内独立执行 `uv sync` 和 `uv run crux ...`，不需要原始开发目录。两份代码是独立副本；开发目录更新后，需要将变更再次复制到发布目录。

虚拟环境、缓存、构建产物、其他 ZIP、默认命名的词典、导出的哈希、密码结果和默认解压目录由 `.gitignore` 排除。`codes.zip` 是允许提交的例外。使用自定义词典或输出名称时，按需补充忽略规则。

## 快速验证

示例档案 `codes.zip` 的已知密码是 `20050808`。下面用固定候选密码验证恢复和解压，不进行大范围枚举：

```text
uv run crux recover codes.zip --mask "20050808" --workers 1 --progress-every 0
```

成功时输出：

```text
FOUND password: 20050808
Extracted to: <实际输出路径>
```

默认解压到档案旁的 `codes_extracted`；若目录已存在，则选择 `codes_extracted_2` 等新名称。也可以通过 `--output-dir` 指定输出目录。

只验证 hashcat 哈希导出：

```text
uv run crux hashcat codes.zip --no-run
```

这会写入 `codes.hash`，示例档案对应模式 `17230`（PKZIP checksum-only），不会启动 hashcat，也不会解压。

## Python 密码恢复

```text
uv run crux recover "path/to/archive.zip" --charset digits --min-length 1 --max-length 6
uv run crux recover "path/to/archive.zip" --mask "CRUX?d?d"
uv run crux recover "path/to/archive.zip" --wordlist passwords.txt
uv run crux recover "path/to/archive.zip" --charset all --min-length 1 --max-length 6 --workers 8 --batch-size 20000
```

档案参数可省略，默认查找当前工作目录中的 `lock.zip`。仓库不提供该文件；省略参数前需要自行准备，否则会报告 `Archive not found`。相对档案路径和词典路径均相对于执行命令时的工作目录。

候选密码依次来自词典、掩码和字符集枚举。`--wordlist` 或 `--mask` 会优先尝试对应候选，但不会关闭随后默认的字符集搜索。词典使用 UTF-8，每行一个密码，忽略空行并去重。

Python 掩码支持 `?l`（小写字母）、`?u`（大写字母）、`?d`（数字）、`?s`（符号）和 `??`（字面量问号），其余字符作为固定前缀或后缀。例如 `CRUX?d?d` 表示 `CRUX00` 至 `CRUX99`。

| 字符集 | 内容 |
| --- | --- |
| `lower` | `a-z` |
| `upper` | `A-Z` |
| `digits` | `0-9` |
| `alpha` | 小写及大写字母 |
| `alnum` | 小写、大写字母及数字 |
| `symbols` | `!@#$%^&*()-_=+[]{};:,.<>/` |
| `all` | `alnum` 加上述符号 |

| 选项 | 默认值与用途 |
| --- | --- |
| `--charset` | `alnum` |
| `--min-length` / `--max-length` | `1` / `5`，包含两个边界 |
| `--workers` | CPU 数量与 `4` 中的较小值，至少为 `1` |
| `--batch-size` | `10000`，每次分配给工作进程的候选数量 |
| `--progress-every` | 每 `10000` 次尝试刷新进度；`0` 关闭周期刷新 |
| `--output-dir` | 档案旁的 `<档案名>_extracted` |

`--workers 1` 使用单进程；更大的值使用进程池。较大的批量可以减少调度开销，较小的批量可以缩短找到密码后的停机响应时间。工作进程复用已打开的 ZIP；WinZip AES 会先验证密码校验值，再进行完整验证。纯字符集搜索按互不重叠的索引范围分配任务。

交互终端显示进度、尝试次数、速率、耗时和状态。Python 恢复的预计剩余时间使用 `YYYY:MM:DD:HH:MM:SS` 格式；无法估算时显示 `----:--:--:--:--:--`。请根据已知前缀、长度、数字模式或词典限制候选范围，避免一开始使用过大的全字符搜索空间。

## 可选 hashcat 后端

hashcat 是独立的开源工具，`uv sync` 不会安装它。可从 [hashcat 官方网站](https://hashcat.net/hashcat/) 获取发行包，或按 [官方源码构建说明](https://github.com/hashcat/hashcat/blob/master/BUILD.md) 编译，并配置对应设备所需的驱动或运行环境。保留发行包或构建产物的完整资源目录，尤其是 `OpenCL` 和 `modules` 等运行资源。

本机的 hashcat **源码库**位置已迁移到：

```text
F:\ATLAS\CRATE\Password\hashcat
```

整理项目时，该目录尚未发现 `hashcat.exe` 或其他 hashcat 可执行程序。源码目录本身不能作为 `--hashcat-path` 的值；编译或安装后，将参数指向实际的可执行文件。其他机器使用自己的安装位置，CRUX 不依赖这个本机路径。

例如，在 PowerShell 中设置已安装的 Windows 可执行程序路径，再检查文件确实存在：

```powershell
# 将此示例路径替换为实际安装或编译生成的可执行文件。
$HASHCAT = "C:\Tools\hashcat\hashcat.exe"
Test-Path -LiteralPath $HASHCAT

uv run crux hashcat codes.zip --hashcat-path $HASHCAT --mask "20050808"
```

若已编译到上述本机源码目录，实际文件可能是 `F:\ATLAS\CRATE\Password\hashcat\hashcat.exe`；先检查是否存在再使用。Linux/macOS 指向实际 `hashcat` 可执行文件。如果 hashcat 已加入系统 `PATH`，可以省略 `--hashcat-path`，默认命令名为 `hashcat`。

hashcat 掩码交由 hashcat 解析，支持它自己的掩码语法。以下为 PowerShell 示例：

```powershell
# 8 位数字掩码
uv run crux hashcat codes.zip --hashcat-path $HASHCAT --mask "?d?d?d?d?d?d?d?d"

# 8 至 12 位数字；转换为 hashcat 的增量掩码
uv run crux hashcat "path/to/archive.zip" --hashcat-path $HASHCAT --charset digits --min-length 8 --max-length 12

# 字典攻击
uv run crux hashcat "path/to/archive.zip" --hashcat-path $HASHCAT --wordlist passwords.txt

# 选择设备，并禁用 potfile 以执行新的搜索
uv run crux hashcat codes.zip --hashcat-path $HASHCAT --device 1 --mask "20050808" --extra-arg=--potfile-disable

# 显示 hashcat 原始输出，便于诊断
uv run crux hashcat codes.zip --hashcat-path $HASHCAT --mask "20050808" --raw-output
```

`--mask`、`--wordlist`、`--charset` 在 hashcat 子命令中互斥。没有提供这三个选项，或指定 `--no-run` 时，仅导出哈希。hashcat 子命令找到密码后打印密码，不执行解压；需要解压时，可以将找到的密码作为 `recover --mask` 的固定候选使用。

| hashcat 选项 | 用途 |
| --- | --- |
| `--member NAME` | 指定用于导出的 ZIP 成员；默认从加密成员中选择 |
| `--hash-file PATH` | 哈希输出路径；默认 `<档案名>.hash` |
| `--hashcat-path PATH` | 可执行文件路径或命令名；默认 `hashcat` |
| `--no-run` | 只导出哈希 |
| `-w` / `--workload-profile` | hashcat 工作负载配置，`1` 至 `4`，默认 `3` |
| `--device LIST` | 传给 hashcat 的设备列表，如 `1` 或 `1,2` |
| `--extra-arg ARG` | 附加 hashcat 参数，可重复；以 `-` 开头的值使用 `--extra-arg=值` |
| `--raw-output` | 显示 hashcat 原始输出 |

CRUX 从可执行文件所在目录启动 hashcat，以便找到运行资源；传给它的哈希和词典路径会转为绝对路径。默认使用紧凑进度显示，并在搜索前后检查 potfile；已找到的哈希可能直接显示 `already cracked (potfile)`。`--extra-arg=--potfile-disable` 可禁用这一复用。

支持的导出模式包括 WinZip AES `13600`、传统 PKZIP 压缩成员 `17200`、未压缩成员 `17210`，以及多成员校验模式 `17230`。具体模式由档案结构决定，并非所有 ZIP 都是 `17230`。WinZip AES 哈希包含所选成员的加密数据；传统 PKZIP 单成员模式最多内嵌 `320 KiB` 数据。具有至少三个加密传统 PKZIP 成员的档案可使用多成员校验模式，避免内嵌整个大文件。

## 输出与常见问题

- `Archive not found`：检查档案路径；省略参数时，需要当前工作目录中存在 `lock.zip`。
- `hashcat executable not found`：安装或编译 hashcat，并提供实际可执行文件路径，或加入系统 `PATH`。只需要导出时使用 `--no-run`。
- `Exhausted` 或密码未找到：所选候选范围已经尝试完毕，调整长度、字符集、掩码或词典。`Recovered: 0/1` 表示尚未恢复，`1/1` 表示已恢复。
- 哈希导出提示成员过大：存在模式数据限制，选择合适成员或使用支持的多成员档案；不要将其视为密码搜索已经开始。
- 已有输出目录：CRUX 选择新的编号目录，不覆盖原目录。解压过程中使用临时目录，并检查 ZIP 成员路径，阻止写到目标目录之外。
- hashcat 导出会生成 `.hash`；紧凑模式运行时可能生成 `.hash.found`。hashcat 自身的 potfile 和恢复文件按它的配置存放，可能位于外部安装目录。

## 开发与测试

```text
uv sync --locked
uv run python -m pytest
uv run crux recover --help
uv run crux hashcat --help
```

现有测试自行生成 ZIP 和词典，并模拟 hashcat 调用，不依赖本机 hashcat、GPU 或 `codes.zip`。覆盖候选生成、单进程与多进程恢复、进度显示、解压目录策略、路径检查、哈希导出和 hashcat 参数传递。

在 `sync/CRUX` 中可以执行相同命令。提交前确认 `git status` 中只包含需要发布的文件，虚拟环境和运行结果未被纳入。项目使用 Apache-2.0 许可证，见 [LICENSE](LICENSE)；外部 hashcat 的许可证以其自身项目为准。
