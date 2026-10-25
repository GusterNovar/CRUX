# CRUX

CRUX `0.3.0` 是一个使用 **hashcat** 在本地恢复 ZIP 密码的命令行工具，支持传统 PKZIP 和 WinZip AES。命令直接接收 ZIP 路径，只有普通字符集搜索和字典搜索两种模式。

## 安装与使用

需要 [uv](https://docs.astral.sh/uv/getting-started/installation/)、Python 3.11 或更新版本，以及完整的 [hashcat 发行包](https://hashcat.net/hashcat/)和对应设备运行环境。

在包含 `pyproject.toml` 的项目目录执行：

```text
uv sync
uv run crux --version
uv run crux --help
```

普通模式：按照字符集和长度范围搜索。

```text
uv run crux path/to/archive.zip --charset digits --min 8 --max 12
```

字典模式：只尝试词典中长度符合条件的密码。

```text
uv run crux path/to/archive.zip --wordlist passwords.txt --min 8 --max 12
```

`--min` 和 `--max` 均包含边界。`--charset` 与 `--wordlist` 互斥，字典模式会先按长度过滤词典，然后交给 hashcat 执行；它不会再追加字符集搜索。词典使用 UTF-8，每行一个密码，支持 BOM 和 Windows 换行，保留密码前后的空格。长度按字符计数，空行会被忽略；过滤结果为空时直接报错。过滤过程逐行读写临时文件，运行结束后清理，不修改原词典，也不需要将整个词典读入内存。

未提供 `--wordlist` 时默认进入普通模式，字符集为 `alnum`，长度为 `1–5`；字典模式默认最小长度为 `1`，省略 `--max` 时不设长度上限。

找到密码后输出 `FOUND password: ...`，退出码为 `0`。搜索耗尽和执行失败均返回非零退出码，并区分显示 `exhausted` 和 `failed`。

## 自动查找与自定义 hashcat

通常无需指定 hashcat 路径。查找顺序为：

1. `--hashcat PATH`，也接受原来的 `--hashcat-path PATH`。
2. 环境变量 `HASHCAT`。
3. 系统 `PATH` 中的 hashcat。
4. 当前工作目录的 `hashcat`、项目内的 `hashcat`、`.tools` 及 `.tools/hashcat-*` 发行包目录。
5. 本机的 `F:\ATLAS\CRATE\Password\hashcat`、其下的 `hashcat-*`，以及 `cache/crux/hashcat-*`。

显式指定的路径或环境变量配置无效时会报错，以便及时发现配置问题。参数支持实际可执行文件、可执行命令名，或直接包含可执行文件的目录。Linux/macOS 查找 `hashcat`、`hashcat.bin`，Windows 查找 `hashcat.exe`。其他机器可以通过 `PATH`、环境变量或项目工具目录使用自己的安装位置。

自定义路径：

```text
uv run crux path/to/archive.zip --charset digits --min 8 --max 12 --hashcat "C:/Tools/hashcat/hashcat.exe"
```

PowerShell 中也可以设置会话环境变量，让后续命令自动使用它：

```powershell
$env:HASHCAT = "C:\Tools\hashcat\hashcat.exe"
uv run crux path/to/archive.zip --wordlist passwords.txt --min 8 --max 12
```

如果使用普通 PowerShell 变量 `$HASHCAT`，通过参数传入：

```powershell
$HASHCAT = "C:\Tools\hashcat\hashcat.exe"
uv run crux path/to/archive.zip --charset digits --min 8 --max 12 --hashcat $HASHCAT
```

CRUX 从可执行文件所在目录启动 hashcat，并传入绝对路径，以便正确加载 `OpenCL`、`modules` 等资源。请保留完整发行包；单独的源码目录无法执行密码搜索，`uv sync` 也不会安装 hashcat 或显卡驱动。

本机的修改版 hashcat 程序位于：

```text
F:\ATLAS\CRATE\Password\hashcat\hashcat.exe
```

开发目录和 `sync/CRUX` 发布副本均可自动找到它。官方 `7.1.2` 发行包仍保留在同目录的 `cache/crux/hashcat-7.1.2` 中，可通过自定义路径选用；大型单成员 PKZIP 需要修改版中的流式扩展。发布 CRUX 时无需携带此机器上的运行目录。

## 字符集

| 名称 | 内容 |
| --- | --- |
| `lower` | `a-z` |
| `upper` | `A-Z` |
| `digits` | `0-9` |
| `alpha` | 小写和大写字母 |
| `alnum` | 小写、大写字母和数字，默认值 |
| `symbols` | `!@#$%^&*()-_=+[]{};:,.<>/` |
| `all` | `alnum` 加上述符号 |

## 诊断与高级选项

日常使用只需要档案路径、搜索模式和长度；以下选项用于导出、设备选择或诊断。

| 选项 | 用途 |
| --- | --- |
| `--no-run` | 只导出哈希，不启动 hashcat，也不要求已安装 hashcat |
| `--hash-file PATH` | 哈希输出路径；默认 ZIP 旁的 `<档案名>.hash` |
| `--member NAME` | 指定用于导出的 ZIP 成员 |
| `-w` / `--workload-profile` | 工作负载 `1–4`，默认 `2`；资源不足时可用 `-w 1` |
| `--device LIST` | 指定 hashcat 设备，如 `1` 或 `1,2` |
| `--raw-output` | 显示 hashcat 原始输出 |
| `--extra-arg ARG` | 附加 hashcat 参数，可重复；以 `-` 开头的值写为 `--extra-arg=值` |
| `--version` | 显示 CRUX 版本 |

例如，导出示例档案的哈希：

```text
uv run crux codes.zip --no-run
```

`codes.zip` 的已知密码为 `20050808`。在 UTF-8 词典 `passwords.txt` 中加入这一行，即可用少量候选验证联动：

```text
uv run crux codes.zip --wordlist passwords.txt --min 8 --max 8
```

CRUX 自动选择 WinZip AES `13600`、PKZIP 压缩成员 `17200`、未压缩成员 `17210`、多成员校验模式 `17230`，或扩展的流式模式 `17240`。小型传统 PKZIP 成员继续使用原有模式；单成员数据超过原生模式的 `320 KiB` 缓冲区时，自动改用流式模式，不需要调整命令。未指定成员且只有一到两个传统 PKZIP 成员时，优先选择较小的成员。

流式模式需要本项目配套修改版 hashcat，官方 `7.1.2` 发行包没有此扩展。本机编译后的程序是 `F:\ATLAS\CRATE\Password\hashcat\hashcat.exe`，CRUX 会自动优先找到它。如果显式设置了 `HASHCAT` 或 `--hashcat`，请指向这个修改版；使用缺少扩展的版本时，CRUX 会给出明确提示。

流式哈希只保存最多 `256` 字节的加密样本、长度、CRC 和原档案的路径。GPU 筛选候选密码，hashcat 的主机端代码分块解密并校验完整数据，通过 CRC 和解压长度验证后才报告找到密码。原档案需要在搜索期间保持原位且不被修改。工作内存随缓冲区和线程数分配，不再随整个成员大小增长；具体速度仍取决于初筛命中率、CPU 和磁盘性能。该扩展针对传统 PKZIP 的未压缩与 DEFLATE 成员，WinZip AES 仍使用原有模式。

默认显示紧凑进度，执行失败时保留 hashcat 的诊断信息。默认会复用 hashcat 的 potfile；已有结果时显示 `already cracked (potfile)` 并打印密码。需要重新执行搜索时，追加 `--extra-arg=--potfile-disable`。每次搜索会写入 `.hash`，找到结果时写入 `.hash.found`；hashcat 自己的缓存和 potfile 按其配置保存。

## 从 0.2.0 升级

`0.3.0` 将 CLI 收敛为 hashcat 后端的两种搜索方式：删除 `recover`、`hashcat` 子命令以及独立的 `--mask` 入口，档案路径改为必填，长度选项改为 `--min`、`--max`。原来 `crux hashcat archive.zip --charset digits --min-length 8 --max-length 12` 对应的新命令是 `crux archive.zip --charset digits --min 8 --max 12`。

## 开发与发布

源码位于 `src/crux`，测试位于 `tests`，`sync/CRUX` 是可独立使用的发布副本。两处源码、测试、文档和锁文件需要保持一致，虚拟环境和本地工具目录不参与发布。

```text
uv sync --locked
uv run python -m pytest
```

单元测试自行生成 ZIP 和词典，并模拟 hashcat 调用，不要求 GPU 或 hashcat。覆盖两种 CLI 搜索、路径自动发现与覆盖、字典长度过滤和清理、状态码、结果读取、失败诊断、哈希导出和 ZIP 处理。真实设备联动测试应另外运行实际恢复命令，检查退出码及输出密码。

项目使用 Apache-2.0 许可证，见 [LICENSE](LICENSE)。hashcat 的许可证见其自身发行包。
