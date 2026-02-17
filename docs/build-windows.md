# Windows 下编译说明

## 方式一：完整编译（含 ATIS 语音 / Opus）

需要 CGO 和 libopus，按以下步骤操作。

### 1. 安装 MSYS2 与依赖

1. 安装 [MSYS2](https://www.msys2.org/)。
2. 打开 **MSYS2 UCRT64** 或 **MSYS2 MINGW64**，执行：
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-pkg-config mingw-w64-ucrt-x86_64-opus
   ```
   若为 32 位或其它架构，将 `x86_64` 换成对应前缀（如 `i686`）。

### 2. 使用 MSYS2 环境编译

在 **MSYS2 UCRT64** 或 **MINGW64** 终端中进入项目目录：

```bash
cd /d/WorkSpace/go/SimpleFSD-main   # 按你的实际路径
export CGO_ENABLED=1
go run build.go
```

生成的可执行文件在项目根目录，名称形如 `fsd-windows-amd64-xxxxxxx.exe`。

### 3. 在 PowerShell/CMD 中编译（已配置好 MinGW + pkg-config）

若已把 MSYS2 的 `ucrt64\bin`（或 `mingw64\bin`）加入系统 PATH，可在普通 PowerShell 中：

```powershell
cd d:\WorkSpace\go\SimpleFSD-main
$env:CGO_ENABLED = "1"
go run build.go
```

或直接编译主程序（不跑 build 脚本）：

```powershell
go build -o fsd.exe ./cmd/fsd
```

---

## 方式二：不依赖 libopus 的编译（无 ATIS 语音编码）

若暂时不需要 ATIS 语音，或本机未安装 libopus，可关闭 CGO 编译（项目已提供 Opus 存根，默认不启用 opus 标签）：

```powershell
cd d:\WorkSpace\go\SimpleFSD-main
$env:CGO_ENABLED = "0"
go run build.go
```

或直接编译（与上述等价，不传 `-tags opus` 即使用存根）：

```powershell
go build -o fsd.exe ./cmd/fsd
```

此时不会链接 libopus，ATIS 语音编码不可用（调用时返回错误）。

---

## 启用 ATIS 语音时用 build 脚本

若已按方式一安装好 **libopus** 与 pkg-config（无需 libopusfile），希望打出的包带 Opus 编码，可在执行 build 时打开 opus 标签（脚本会使用 `-tags opus nolibopusfile`，仅依赖 libopus）：

```powershell
$env:CGO_ENABLED = "1"
$env:BUILD_OPUS = "1"
go run build.go
```

---

## 常见问题

| 现象 | 处理 |
|------|------|
| `pkg-config: executable file not found` | 未安装 pkg-config 或未加入 PATH，在 MSYS2 中安装并确保使用 MSYS2 终端编译。 |
| `undefined: Stream`（hraban/opus） | CGO 或 libopus 未正确配置，改用 **方式二** 或按 **方式一** 在 MSYS2 下完整安装依赖后再编译。 |
| 希望用 vcpkg 的 opus | 安装 opus 后设置 `PKG_CONFIG_PATH` 指向 vcpkg 的 pkgconfig 目录，或设置 `CGO_CFLAGS` / `CGO_LDFLAGS` 指向 opus 头文件和库。 |
| `Package opusfile was not found` | 本仓库通过 `-tags nolibopusfile` 只链接 libopus，不依赖 libopusfile。若手动执行 `go build`，请使用 `-tags "opus nolibopusfile"`。 |
