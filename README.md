# SimpleFSD

[![ReleaseCard]][Release]![ReleaseDataCard]![LastCommitCard]  
![BuildStateCard]![ProjectLanguageCard]![ProjectLicense]

![](./docs/image/show.png)

> ### *本项目正在快速迭代中, API接口可能不稳定, 请及时查阅最新的API文档*

## 简介

本项目是一个用Go语言编写, 主要用于模拟飞行的联机服务器  
支持 Swift, Euroscope 或其他自定义的客户端  
Echo未经过测试, 理论上任何实现了 FSD Version 3.000 Draft 9 协议的客户端均可链接   

## 特点  

- 支持计划同步：自动同步管制员对飞行计划的修改
- 支持计划锁定：自动锁定被管制员修改过的飞行计划，直到用户下线或者提交起落机场不同的计划
- 支持更加详细的管制员信息获取：例如可以获取到 Logoff time和管制员是否处于Break状态
- 支持 FSD Version 3.000 Draft 9 协议
- 支持 VATSIM 协议
- 支持高并发：golang原生支持
- 支持VisualPosition：可以做到0.2s上传一次位置
- 支持语音调频：本功能需要额外的软件
- 全功能HTTP服务器：不仅仅是FSD，还是飞控后端
- 支持Websocket连接：可以通过Websocket连接到FSD进行双向文字交互

如果您觉得这个FSD功能太多, 过于庞大  
我们还有专门精简过功能的[lite版本][Lite], 仅保留了核心的fsd功能  
当然我们还是建议您使用全功能版本以获得更好的体验  

想提交PR？想自己对服务器进行二次开发？请查阅我们的[文档][WIKI]

## 开源协议

MIT License

Copyright © 2025-2026 Half_nothing

无附加条款。

## 行为准则

在[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)中查阅

[ReleaseCard]: https://img.shields.io/github/v/release/Flyleague-Collection/SimpleFSD?style=for-the-badge&logo=github

[ReleaseDataCard]: https://img.shields.io/github/release-date/Flyleague-Collection/SimpleFSD?display_date=published_at&style=for-the-badge&logo=github

[LastCommitCard]: https://img.shields.io/github/last-commit/Flyleague-Collection/SimpleFSD?display_timestamp=committer&style=for-the-badge&logo=github

[BuildStateCard]: https://img.shields.io/github/actions/workflow/status/Flyleague-Collection/SimpleFSD/go-build.yml?style=for-the-badge&logo=github&label=Full-Build

[Lite]: https://github.com/Flyleague-Collection/SimpleFSD-Lite

[ProjectLanguageCard]: https://img.shields.io/github/languages/top/Flyleague-Collection/SimpleFSD?style=for-the-badge&logo=github

[ProjectLicense]: https://img.shields.io/badge/License-MIT-blue?style=for-the-badge&logo=github

[Release]: https://www.github.com/Flyleague-Collection/SimpleFSD/releases/latest

[WIKI]: https://docs.half-nothing.cn/
