# metallib-air-check

读出 iOS 系统 Metal 库（`.metallib`）的 AIR 版本，并找出其中带 `agx` 的名称（苹果 GPU 专用内建函数的标志）。
用来判断非苹果的着色器翻译器（例如 metal2vulkan）能否处理 iOS 27 的系统着色器，比如 QuartzCore 的 `default.metallib`。

仓库里没有任何苹果二进制。固件在 Actions runner 上从 Apple CDN 获取并解密，产物只有名称、版本和计数。

## 运行

Actions → **metallib AIR check** → Run workflow。默认取 iPhone17,3 27.0（24A437）的 OS cryptex（`sys`，约 2.2 GiB），其中有 QuartzCore 和 CoreImage 的系统库。

步骤：`ipsw extract --remote --dmg` 取镜像，`ipsw fw aea` 解密，7-Zip 26.04 从 APFS 里只解出 `*.metallib*`，最后由 `tools/metallib_info.py` 分析。

## 报告

`metallib-report` artifact 和运行页 Summary：

- 每个库的文件格式版本、目标系统、函数数，函数列表 `VERS` 标签里的 AIR 和 Metal 语言版本，以及 bitcode 里的目标三元组（如 `air64_v29-apple-ios27.0.0`）
- 含 `agx` 的名称和用到它们的函数
- AIR 名称按前缀归类的统计，以及解出的文件清单 `files.tsv`

## 本地运行

```bash
python3 tools/metallib_info.py path/to/metallibs --out out/report
```
