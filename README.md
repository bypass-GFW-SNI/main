 # bypass-GFW-SNI

代理方式请参考 [bypass-GFW-SNI/proxy](https://github.com/bypass-GFW-SNI/proxy)。

此“半” POC 程序可以在不自行架设境外服务器的情况下，直接访问符合特定条件的被中国防火长城（“GFW”）屏蔽的站点。TL;DR，是通过类似域前置的方式突破了 GFW 的 SNI 封锁。

## 特定条件

存在可以访问的上游无污染 DNS ，使其解析被封锁域名，且返回的 IP 可以正常进行 TLS 握手。

#### 其中：

1. 访问境外 DNS 皆存在 DNS 污染。但目前 GFW 仅污染 53 端口，并没有屏蔽使用 *DNS over TLS* 或者 *DNS over HTTPS* 技术的 DNS 服务商及相应端口，例如 `1.1.1.1` 或 `8.8.8.8`。

2. 大型境外被封禁网站多为直接封禁 IP。但目前 GFW 仅有 IPv4 黑名单，还未封禁 IPv6 地址，而国内大型运营商，例如中国联通，已开始分配 IPv6 地址，并可以通过其连接互联网。

3. 某些被封禁域名使用了非独立 IP 的 CDN，例如 Cloudflare 免费版，因此强制需要 SNI，否则无法成功握手。或者因为配置了多证书，导致返回的默认证书并非欲访问域名。

### 样例

<dl>
  <dt>有 IPv4 接口</dt>
  <dd>Amazon、Reddit、Steam、Wikipedia、Yahoo、Twitch 等。</dd>
  <dt>有 IPv6 接口</dt>
  <dd>Google、Youtube、Facebook 等。</dd>
  <dt>依然无法访问</dt>
  <dd>Twitter（因 IPv4 地址黑名单，且没有配置 IPv6）等，未使用 HTTPS 技术的网站，以及符合 <b>其中.3</b> 条件的域名。</dd>
</dl>

# 实现

### 定义

<dl>
  <dt>自定域名列表</dt>
  <dd>可自行设置的被封禁域名列表。</dd>
  <dt>上游默认 DNS</dt>
  <dd>解析不存在于自定域名列表里的域名时会转发请求的上游 DNS。</dd>
  <dt>上游无污染 DNS</dt>
  <dd>解析存在于自定域名列表里的域名时会请求的上游 DNS。  </dd>
  <dt>自签发 CA 证书</dt>
  <dd>为本地中间人攻击而自签的 CA 证书。 </dd>
  <dt>原网站证书</dt>
  <dd>原网站的正常证书。</dd>
  <dt>本地 XX</dt>
  <dd>程序内所运行的相应 XX 服务。</dd>
</dl>

### 准备

1. 系统信任自签发 CA 证书。
2. 配置好自定域名列表。
3. 启动程序，程序会监听 `localhost` 上的 443（TCP）、53（UDP）和 80（TCP）端口，从而实现本地 DNS 和本地网络服务器。
4. 配置系统 DNS 为 `localhost`。

## 流程

假设要请求的是 `example.com`，且其存在于自定域名列表内。

浏览器请求 `https://example.com`，系统使用本地 DNS 解析 `example.com`。此时若域名不在自定域名列表内，本地 DNS 将会把 DNS 请求转发给上游默认 DNS，接着就如普通网络请求那样。如不在，也就是域名为 `example.com`，本地 DNS 则会返回一个 loopback 地址。

此时浏览器将会和本地服务器进行 TLS 握手，而本地服务器将会根据握手中的 SNI 使用自签发 CA 证书签发 SSL 证书。此时 TLS 握手成功，并且浏览器将传送数据。

本地服务器将会通过上游无污染 DNS 解析 `example.com`，并尝试和解析出的 IP 逐一进行 TLS 握手，且握手信息中的 Server Name 将被替换为 IP 地址本身，这可以使远程网络服务器返回默认的 TLS 证书。若握手失败，则表明连接超时，或者 IP 地址已被 GFW 列为黑名单，或者出现 <b>其中.3</b> 的情况；若握手成功，则程序将会使用原本的域名，即 `example.com`，校验原网站证书的有效性。若校验失败，则表明要么原网站被中间人攻击，要么出现 <b>其中.3</b> 的情况。

若一切成功，则表明已成功访问被封锁网站，并且本地服务器将开始转发远端数据。

# 运行

基于 Go Debug 信息以及目前程序完整度，将暂时不考虑分发已编译二进制。

运行此程序，你需要在电脑上安装 [Go 运行环境](https://golang.org/dl)，同时 `go get` 下列包：

<dl>
  <dt><a href="https://github.com/Sirupsen/logrus">github.com/Sirupsen/logrus</a></dt>
  <dd>程序所使用的日志包。</dd>
  <dt><a href="https://github.com/miekg/dns">github.com/miekg/dns</a></dt>
  <dd>本地 DNS 以及 DNS 请求核心包。</dd>
  <dt><a href="https://godoc.org/golang.org/x/net/publicsuffix">golang.org/x/net/publicsuffix</a></dt>
  <dd>域名匹配以及证书签发所需的 Public Suffix 列表。</dd>
</dl>

最后，`go run main.go` 便可启动程序。详细流程参考 **实现—准备**。

## 配置

### 常量

`const` 中有 10 个可配置参数，分别为：

<dl>
  <dt>caCert</dt>
  <dd>自签发 CA 证书路径。</dd>
  <dt>caKey</dt>
  <dd>自签发 CA 证书所对应的私钥路径。</dd>
  <dt>defDNS</dt>
  <dd>上游默认 DNS 地址（需要为 IP:端口 格式）。</dd>
  <dt>gfwDNS</dt>
  <dd>上游无污染 DNS 地址（需要为 IP:端口 格式）。</dd>
  <dt>certExpire</dt>
  <dd>证书签发过期时间。</dd>
  <dt>dialTimeout</dt>
  <dd>TCP 握手超时时间。</dd>
  <dt>pollInterval</dt>
  <dd>配置文件更改检测间隔。</dd>
  <dt>cacheAddrTtl</dt>
  <dd>可用解析 IP 缓存时长（TTL）。</dd>
  <dt>logLevel</dt>
  <dd>日志详细度，参见<a href="https://godoc.org/github.com/sirupsen/logrus#Level">日志包文档</a>。</dd>
  <dt>configFile</dt>
  <dd>自定域名列表文件路径。</dd>
</dl>

#### 其中：

`caCert` 和 `caKey` 需要你的证书及私钥格式为 PEM。同时，`caKey` 默认你的私钥算法为 RSA。如果你的私钥算法不是 RSA，请自行修改 `var` 中 `caPriKey` 的变量类型，和 `init()` 函数中的相关调用。

与 DNS 有关的两个参数 `defDNS` 和 `gfwDNS` 在更改时可能需要与 `var` 中的 `defDnsCli`和 `gfwDnsCli` 中的 `New` 函数所对应地同时进行更改。更详细地说，需要更改其中新建 `dns.Client` 的 `Net` 参数，其与 DNS 所须的请求方式有关。参见 [DNS 包文档](https://godoc.org/github.com/miekg/dns#Client)。

`configFile` 的格式为纯文本格式，一行一个合法的域名，如此[样例文件](https://github.com/bypass-GFW-SNI/main/blob/master/domain.conf)。在匹配时将会匹配所有这些域名的子域名。[gfwlist-to-domain](https://github.com/bypass-GFW-SNI/gfwlist-to-domain) 可以将 GFW List 转换成符合此程序要求的文件。同时，程序将会轮询并检测配置文件是否有变化并实时更新，所以增减域名列表不需要重启程序。

---

同时，程序监听的 53 和 80 端口是可选的，在 `main()` 函数的两个 Goroutine（`go func() {...}()`）的函数注释或开头加入 `return` 便可。详细对应位置可通过阅读注释找到。

若不监听 53 端口，则程序将无法自动将域名解析至回环地址，用户也无法将 DNS 设置为 `localhost`。若此时依然想使用此程序，需手动配置 Hosts 文件，并将需要的域名，包括子域名，映射为本地回环地址。

若不监听 80 端口，则在不小心访问被封锁域名的 80 端口时将会出现无法访问的情况；或者若未配置 DNS 也未配置 Hosts 的话，将会被 GFW 所阻拦。

# TODO

- [ ] 外部配置文件
- [ ] 外部可用 IP 缓存文件
- [ ] 多上游无污染 DNS
- [ ] 待 ESNI 普及后尝试实现
- [ ] 待 QUIC 普及后尝试实现