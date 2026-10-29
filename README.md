# Kartrider-lpk-unpacker

《跑跑卡丁车》P3563 客户端 **LPK 版本 4** 的 Python 拆包器。支持查看文件列表、完整性校验、提取单个资源或整个分包目录。

当前提供源码，**没有可执行文件或 GitHub Release**。不需要启动游戏、管理员权限、IDA、Frida、Unicorn 或内存 dump。

## 安装

需要 Python 3.10+。在源码目录运行：

```powershell
python -m pip install -r requirements.txt
```

本地验证环境：Windows、Python 3.14、cryptography 50.0.2。其他系统未实机验收。

## 使用

查看分包内容：

```powershell
python lpk_unpacker.py "D:/Kart/Data/DataPack9_00040.lpk" --list
```

完整拆出一个分包，保留包内目录和文件原始字节：

```powershell
python lpk_unpacker.py "D:/Kart/Data/DataPack9_00040.lpk" -o "D:/unpacked"
```

只拆出一个文件，`--path` 为包内的完整路径，区分大小写：

```powershell
python lpk_unpacker.py "D:/Kart/Data/DataPack9_00040.lpk" --path "stage/tuning/paramGraphLine.png" -o "D:/sample"
```

文件会写入 `D:/sample/stage/tuning/paramGraphLine.png`。不指定 `-o` 时使用输入旁的 `<名称>.unpacked` 目录。已存在的文件不会被覆盖；包内重复输出路径也会拒绝。

批量拆出目录中的所有 `.lpk`：

```powershell
python lpk_unpacker.py "D:/Kart/Data" -o "D:/unpacked-all"
```

仅解密、解压并检查完整内容，不写出资源：

```powershell
python lpk_unpacker.py "D:/Kart/Data" --verify
```

任一文件失败会输出错误并以非零状态退出；成功文件仍计入统计。提取前校验长度和 MD5，校验失败的文件不会写出。完整参数见 `python lpk_unpacker.py --help`。

## 支持范围与验证

- 已验证本机 P3563 的 **344 个分包、138,118 个文件**，解密、解压后的长度和 MD5 全部通过，原文总量 **5,201,195,182 字节**。
- 仅支持已观察到的版本 4、flags `6/7`、零分段列表。其他布局直接报错，不尝试旧格式回退。
- 内置格式字符串 `NhucnUGGZIHvxdga` 来自该批客户端的原生头解析。`--mixing` 可显式指定其他字符串，但不代表其他版本已经验证，也不提供任意归档头的自动恢复。
- `headerChecksum` 已读取，但其公式尚未完整解释；部分扩展字段语义也未完整解释。文件表记录校验和、每个输出的完整长度和 MD5 均实际校验。
- PNG、OGG 等保持普通资源格式；部分 XML/KML 为 UTF-16；`.1s` 等仍需专用解析器。这些是游戏资源，不是客户端 C++ 源码。
- 仓库不包含游戏文件、dump、提取样本、原始资源索引或历史扫描日志。

## 测试

无需原始资源的测试：

```powershell
python -m unittest -v
```

可选本地原始资源检查（原文件不随仓库提供）：

```powershell
$env:LPK_DATA_DIR = "D:/Kart/Data"
python -m unittest -v
python -O -m unittest -v
```

覆盖读取缓冲的计数器边界、截断输入、输出路径越界、实际样本提取、损坏载荷拒绝与禁止覆盖。正式校验使用显式异常，即使 Python 开启 `-O` 也不会跳过完整性检查。
