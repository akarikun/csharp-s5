### --socks5无用户名密码
```
1	client:0x05, 0x01, 0x00
2	server:0x05, 0x00
3	client:0x05, 0x01, 0x00, 0x03,	[1(byte):urlLen],  [urlLen(byte)]...,	[2(byte):port]
4	server:0x05, 0x00, 0x00, 0x03,  [1(byte):urlLen],  [urlLen(byte)]...,	[2(byte):port]

...之后服务端只管接收转发数据

说明

3:假设请求的是https://bing.com,则客户端发送的数据是
	05 01 00 03 [08] [62 69 6e 67 2e 63 6f 6d] [01 bb]
	08是指URL的长度(bing.com)
	62 69 6e 67 2e 63 6f 6d是指bing.com
	01 bb是指访问端口号443(处理的时候注意大小尾字节)
4:只是第二个字节变成0,其他数据与3一致
```
![img.gif](https://raw.githubusercontent.com/akarikun/csharp-s5/main/img.gif)