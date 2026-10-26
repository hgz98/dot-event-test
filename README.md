# Render 临时合成事件测试（本地准备，尚未部署）

只发一个随机标记，不连接 QQ、不读文件、不执行命令。不需要 pip、框架或数据库。
复用已测试的 `trial_server.py` 协议模块；入口为 `render_server.py`。
**No authentication 模式能否被 ChatGPT 订阅事件尚未验证**；部署成功不代表事件端到端成功。

## 手动部署

1. 自己选择一个公开代码仓库，仅上传本文件夹内这些合成测试文件到仓库根目录；不要上传其他目录、日志、令牌、私钥或真实数据。本包不指定或创建仓库。
2. 登录 Render Dashboard，选择 New → Web Service，使用你选择的公开仓库。需要登录由你完成；遇到银行卡、支付或付费升级立即停下。
3. 选择 Python、**Free**。Build Command：`python -m unittest discover -v`；Start Command：`python render_server.py`；Health Check Path：`/health`。关闭自动部署。若界面名称变化，以对应设置为准，不选择付费方案。也可使用根目录 `render.yaml` Blueprint。
4. 首次部署可不设置 `TRIAL_EXPIRES_AT`，服务仅健康检查可用，MCP 测试关闭。准备添加插件时，把此环境变量设置为「当前 UTC 时间 + 最多 15 分钟」，格式 `YYYY-MM-DDTHH:MM:SSZ`，然后应用设置/手动重新部署。它不是秘密，不能设置为遥远未来。部署耗时计入窗口，过期需由你明确更新此时间重新测试。
5. 使用 Render 实际分配的 HTTPS 服务地址加 `/mcp` 添加自定义插件，认证选 No authentication。`/health` 只返回存活状态；`/status` 只提供不含凭据的简短状态。
6. 告诉 dot：订阅 `synthetic.marker_created`，收到后用收到的 `eventId` 调用 `synthetic_reply`。订阅成功约 10 秒后发一个合成事件。回调 2xx 只表示接收；公开工具收到 ACK 也不是身份保证，应与当前 dot 实际回复交叉确认。
7. 测试后移除插件并在 Render 停止/删除该测试服务。不要把它用于正式消息接收。

## 边界与寿命

- 监听 `0.0.0.0:$PORT`（默认 10000）；仅 `/mcp` 接受 POST，健康与状态路径只读。
- 回调 URL/签名密钥仅在进程内存中，最长到本次窗口结束（最多 15 分钟），不写入文件或应用日志。Python 无法保证内存物理擦除；平台自身日志/内存策略由 Render 管理。
- 到期清除订阅并拒绝 MCP 操作，但进程继续健康响应，避免健康检查导致循环重启。固定 UTC 截止时间不随自动重启延后；启动时超过未来 15 分钟的截止时间也会关闭测试，需改正后明确重启。重启不会恢复任何旧订阅或密钥。不要用自动生成未来截止时间的启动脚本。
- 无 OAuth、无真实数据、无持久化；公开匿名端点可能被别人抢先订阅，不能证明调用者身份。只作一次短期互通性实验。
- 本地验证：`python -m unittest discover -v`，只用模拟回调和 loopback，不访问公网。本包没有执行部署、注册、授权或实际 ChatGPT 事件测试。
