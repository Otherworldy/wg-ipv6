# scripts

`proxy-sticky.service`（项目根）可直接复制/软链到 `/etc/systemd/system/`：

```bash
sudo cp proxy-sticky.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-sticky
```

注意：`config.yaml` 里 `listen: 0.0.0.0:26184` 时，把 sing-box 的 socks5-in（26183）停用或改端口，避免端口冲突。socks5 客户端改用 26184。
