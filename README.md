# 天翼校园认证客户端（湖南适配版）

一个用 C 写的第三方天翼校园网（中国电信）认证客户端。**在广东版的基础上增加了湖南省的协议适配**，
自带网页界面、零运行时依赖、可编译成单个 exe。

本项目是 [BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)
（Apache-2.0）的**改造版**。改造了哪些、第三方组件是什么许可证，见
[`NOTICE`](NOTICE) 与下面的「来源与许可」。

> **免责声明**：本项目与电信、任何高校均无关联，为个人学习与自用而写。协议参数由抓包分析得出。
> 使用前请确认不违反你所在学校的网络使用规定。

---

## 它做什么

校园网在未认证时会拦截明文 HTTP，把请求重定向到一个门户。本程序负责：

1. 探测是否处于「需要认证」状态；
2. 从接入设备下发的重定向里**取出门户地址**（所以不需要你填）；
3. 读真实网卡的 IP / MAC / 网关作为身份；
4. 按湖南的报文格式加密请求、取票据、登录；
5. 定期发心跳保活；掉线后自动重新认证；
6. 全程提供一个网页界面，账号密码在网页上填，**不用手改配置文件**。

## 湖南和广东的区别

| | 广东 | 湖南 |
|---|---|---|
| 算法协商 | 向服务端 POST Algo-ID，回 ZSM 块 | **不协商**，Algo-ID 固定 |
| 密钥 | 从服务端下发的块里取 | **本地内置**（`src/cipher/algo/hunan/`） |
| 端点 | 从门户页的 `campus.js` 注释块里挖 | **固定的一组 `.cgi` 名** |
| 身份 | 主要靠门户页里的查询串 | **真实网卡**的 IP / MAC / 网关 |
| 查询串 | `wlanuserip` / `wlanacip` | `wlanuserip` / `mscgip` / `wlanusermac` |
| 补零规则 | `ceil(L/16)*16` | `ceil((L+1)/16)*16`（多一个 NUL 结尾字节） |

这几处差异是踩坑踩出来的，展开写在 `../esurfing/文档/路线B-进展.md` 里。

## 网页界面

程序启动后监听 `http://127.0.0.1:8888`（端口可在配置里改）。界面为 **WinUI 3 / Fluent 风格**，
**零外部资源** —— 不引用任何 CDN、字体或图标库：客户端跑在校园网里，外网随时可能不通。

- **仪表盘**：认证状态、出网状态、运行时长
- **设置**：手机号、密码、省份、回退门户地址；改完点「保存并应用」即时生效
- **日志**：直接在线看运行日志
- **关于**：版本、接口、实际使用的门户地址

几个设计决定，都是被实际问题逼出来的：

- **设置页那两栏叫「回退门户地址」**，不是「门户地址」。未认证时门户由接入设备下发，
  优先用它；配置里那份只在下发失败时兜底。页面上另有一行只读的「当前实际使用」，
  如实区分 `接入设备下发` / `配置回退` / `尚未判定` 三种来源。
- **首次运行不需要配置文件**。以前是先读配置、配置不合法就退出，而唯一能填账号的网页
  又是在配置加载成功之后才起来 —— 死锁。现在配置缺失/账号为空/被停用都不再退出，
  网页照常提供，只是不发起认证。
- **「重新认证」在未认证时也能用**。主循环只在探测到 302 时才创建认证线程，而接入设备
  在客户端已在线时不会注入 302；此时若网络通、但程序没有会话，用户会卡在无路可走的状态。
  现在这个按钮会强制发起一次认证。

## 编译

需要 **CMake ≥ 3.16**、**Ninja**、**C 编译器**（MSVC 或 MinGW-w64 gcc），以及
**libcurl**（本工程用 `find_package(CURL REQUIRED)`；Windows 上链静态库）。

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

产物是 `build/ESurfingClient.exe`（Windows）或 `build/ESurfingClient`。

如果 libcurl 不在默认搜索路径，额外给两个变量：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCURL_LIBRARY=/path/to/libcurl.a \
      -DCURL_INCLUDE_DIR=/path/to/curl/include
cmake --build build
```

还支持 `-D__OPENWRT__=1`（路由器的 OpenWrt 目标）与 Android 交叉编译，
分支写在 `CMakeLists.txt` 里。

### 离线自检

不联网，校验两件事：门户地址解析、以及抓包样本的加解密是否逐字节吻合。

这个目标**默认不构建**，要显式打开：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_HUNAN_SELFTEST=ON
cmake --build build
./build/hunan_selftest              # 默认在 re-artifacts/extracted 找样本
./build/hunan_selftest <样本目录>    # 也可以指定目录
```

> **本仓库不含抓包样本。** 「抓包逐字节」那部分需要作者本地的证据目录
> （32 个 `req_*.bin`）。没有样本时门户解析部分照常跑并给出结论，
> 样本缺失会明确打印「找不到样本」，不会假装通过。

### 如果是整包发行（含脚本与工具链）

按目录结构分发的整包里另有一层 `scripts\`，把常用操作包好了：

```bat
scripts\build-app.bat        :: 编译到 ..\build
scripts\restart-client.bat   :: 停掉运行中的客户端，把 build 装到 run 并启动
scripts\build-selftest.bat   :: 编译离线自检
scripts\run-selftest.bat     :: 跑离线自检
```

`build\` 与 `run\` 分开是有原因的：运行中的 exe 被 Windows 锁定，直接链接进去会
`Permission denied`。所以编译进 `build\`，再由 `restart-client.bat` 搬到 `run\`。
用上面的 cmake 命令自己编则不受影响。

### 三个已经踩过的坑（照抄结论就行）

这三个都只在 **MinGW-w64 + 中文路径 + Windows** 的组合下出现：

1. **要用 Ninja，别用 `MinGW Makefiles`。** 工程路径含中文时，CMake 生成的
   makefile 是 UTF-8，而 GNU Make 按 ANSI 码页读 —— 编译器路径变成乱码，
   报 `CreateProcess(NULL, D:\<乱码>\gcc.exe) failed`。Ninja 用宽字符 API，没这问题。
2. **MinGW 的 `bin` 目录必须在 PATH 上。** gcc 会去起 `cc1.exe`，而 `cc1.exe`
   需要同目录的 `libwinpthread-1.dll` / `libgcc_s_seh-1.dll`。只用绝对路径调 gcc 不够，
   子进程会以 `0xC0000135`（DLL 找不到）静默死掉，gcc 什么都不报。
3. **`.bat` 一律纯 ASCII + CRLF。** cmd.exe 按活动码页逐字节解析 `.bat`，中文字面量
   会被啃坏（`setlocal` 曾变成 `tlocal`）；LF 行尾会让 `if (...)` 块和变量展开错乱。

## 配置文件

`ESurfingClient.json` 与 exe 同目录。下面是首次运行自动生成的模板，**字段名以它为准**：

```json
{
  "enabled": true,
  "web_external_acc": false,
  "log_lv": 5,
  "log_dir": "./",
  "conn_timeout": 7,
  "op_timeout": 10,
  "web_port": 8888,
  "accounts": [{
    "username": "",
    "password": "",
    "channel": 3,
    "mark": "",
    "province": "hunan",
    "portal": "175.12.104.1",
    "portal_port": 10001,
    "mscgip": "",
    "time_windows": []
  }]
}
```

- `province` 只有 `hunan`（湖南）和 `guangdong`（广东）两个有效值，**选错会认证失败**。
- `portal` / `portal_port` / `mscgip` 是**回退值**，留空也可以 —— 未认证时接入设备会下发。
- `channel` 是数字：1=Windows、2=Linux、3=Android、4=iOS、5=macOS。
  它决定 User-Agent 与主机名，进而影响服务端下发什么算法；湖南用不上这套（UA 固定），
  但字段要留着。
- `log_lv`：0=NONE … 5=DEBUG、6=VERBOSE。
- **不需要手工创建这个文件** —— 首次运行会自动生成模板，然后在网页上填。

> ⚠️ 配置文件里是**明文账号密码**，不要外传、不要提交到版本库。

## 命令行

```
ESurfingClient.exe                    正常启动（前台模式，含网页界面）
ESurfingClient.exe --help             全部参数
ESurfingClient.exe --account N        指定用第几个账号（配合 --role auth）
ESurfingClient.exe --list-accounts    列出可用账号序号后退出（供 init 脚本用）
ESurfingClient.exe --print-log-dir    打印实际使用的日志目录后退出
ESurfingClient.exe --control-port N   拆分进程模式下的控制通道端口
ESurfingClient.exe --install / -u     安装 / 卸载为系统服务（需管理员权限）
```

服务模式、拆分进程模式（`--role supervisor|auth|web`）用于开机自启与多账号，
普通使用直接双击 exe 即可。**网页端口不在命令行上** —— 它由配置文件的
`web_port` 决定（默认 8888）。

## 来源与许可

### 上游

[BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)，
**Apache License 2.0**。本仓库抽取其 `esurfingclient/app/` 子树作为基线
（本地提交 `00f1b5b`），该子树 129 个文件里 **121 个逐字节一致**。
上游的 LuCI 插件、OpenWrt 打包、`docs/`、CI 都**没有**带过来。

被排除的另一个 fork：`Rsplwe/ESurfingClient-CVersion` —— 逐字节比对只有 5 个文件对得上，
96 个文件在那边根本不存在，所以来源不是它。

### 仓库内第三方组件

| 目录 | 是什么 | 许可证 |
|---|---|---|
| `third_party/7z` | LZMA SDK（Igor Pavlov） | 公有领域 |
| `third_party/cJSON` | cJSON | MIT |
| `third_party/minihttp` | 最小 HTTP/1.1 服务器，**本项目自写** | Apache-2.0 |

**mongoose 已被删除。** 上游用它做网页服务器，而 mongoose 是 GPL-2.0-only 或商业授权 ——
一旦随二进制分发就会触发 GPL 传染。现用自写的 `minihttp` 替代（约 500 行，
接口与 mongoose 同名同形，所以 5 个 webserver 源文件只改了 include）。
删掉之后许可证构成变成 **Apache-2.0 + MIT + 公有领域**，发行桌面版无额外义务。

### 本仓库的许可

**Apache License 2.0**，全文见 [`LICENSE`](LICENSE)。
本仓库是修改版，改了什么逐条列在 [`NOTICE`](NOTICE) 里（§4(b) 要求标注修改）。

### 关于协议参数

湖南的算法档与报文格式来自对**官方闭源客户端**的抓包分析。这部分是互操作性研究，
不是复制第三方源码；相应的抓包与逆向脚本**不在本仓库里**。

### 未合并的上游改动

基线取自上游 HEAD 之前的一个快照。上游后来改过若干文件（含一处看门狗时间处理），
本仓库尚未合并。这是已知差距，不是疏漏。
