# DN42 Automatic Peering Telegram Bot

### DN42 ~~贴贴~~ Autopeer Bot

----------

## bot 要求

- 禁用 Privacy Mode
- 示例 Command List 如下：
```
peer - New peering
ping - Ping an address
ping4 - Ping an IPv4 address
ping6 - Ping an IPv6 address
trace - Traceroute an address
traceroute - Traceroute an address
traceroute4 - Traceroute an IPv4 address
traceroute6 - Traceroute an IPv6 address
delete - Delete existing peering
cancel - Cancel current operation
```

## 食用方法：

- 默认 peer 的目录位于 `/etc/wireguard/` 和 `/etc/bird/peers/` 两个目录下
- 不用说，肯定是 `pip install -r requirements.txt` 啦
- 将 `config_sample.py` 重命名为 `config.py`
- 修改 `config.py` 中的配置
- 使用具有控制 Wireguard 和 Bird 的权限的用户启动 `main.py`
- 在 Telegram 中输入 `/start` ，开始~~贴贴~~

## 关于

Sora 版权所有 https://www.sorasky.in/

欢迎访问 https://dn42.mol.moe/ 了解更多和我~~贴贴~~ Peer 的详情。
