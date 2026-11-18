# GSB Bugfix Task
## 题面
单点登录回调跳转接口在处理重定向url时可被劫持：未校验host白名单、允许javascript伪协议、未归一化url、忽略端口绕过、未区分内部/外部域名；oauth/redirect.py 是核心，tests/test_sso_redirect.py 15个红。要修的是：校验目标域名白名单、拦截javascript等危险协议、标准化url后再校验、校验端口、禁止跳转至内网地址。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
