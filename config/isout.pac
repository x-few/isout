var proxy = "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT;";

function FindProxyForURL(url, host) {
	return proxy;
}
