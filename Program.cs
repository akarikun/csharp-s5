using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace gogogo
{
    class Program
    {
        static int PortDefault(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                int port;
                if (int.TryParse(args[0], out port))
                    return port;
            }
            return 52222;
        }
        static void Main(string[] args)
        {
#if DEBUG
            args = new string[] { "52222"
                //, "admin", "123456" 
            };
#endif
            ///gogogo [52222] [?username] [?password]
            var port = PortDefault(args);
            Console.Title = port.ToString();
            Console.WriteLine("gogogo Listen {0}", port);
            var s = new S5Server();
            s.BlacklistFilter = (url) =>
            {
                var list = new List<string>();
                list.Add("google");
                foreach (var i in list)
                {
                    if (url.Contains(i))
                    {
                        return false;
                    }
                }
                return true;
            };
            s.Message = (msg) =>
            {
                Console.WriteLine(msg);
            };
            s.Traffic = (upload, download, uploadTotal, downloadTotal) =>
            {
                var u = uploadTotal / 1024.0 / 1024;//MB
                var d = downloadTotal / 1024.0 / 1024;//MB               
                Console.Title = string.Format("{0} | ↑:{1}MB  ↓:{2}MB", port,
                    string.Format("{0:N2}", u), string.Format("{0:N2}", d));
            };
            var name = "";
            var pwd = "";
            if (args.Length >= 2) { name = args[1]; }
            if (args.Length >= 3) { pwd = args[2]; }
            if (!string.IsNullOrEmpty(name) || !string.IsNullOrEmpty(pwd))
            {
                s.SetAuthor(name, pwd);
                Console.WriteLine("{0}/{1}", name, pwd);
            }
            s.Start("0.0.0.0", port);
            Console.ReadLine();
        }
    }

    public static class Extensions
    {
        public static bool StartWith(this byte[] b1, byte[] b2)
        {
            if (b2.Length > b1.Length) return false;
            for (var i = 0; i < b2.Length; i++)
            {
                if (b1[i] != b2[i])
                    return false;
            }
            return true;
        }
        public static byte[] SubBytes(this byte[] b1, int start, int len)
        {
            List<byte> list = new List<byte>();
            len = b1.Length < start + len ? b1.Length : len + start;
            for (var i = start; i < len; i++)
            {
                list.Add(b1[i]);
            }
            return list.ToArray();
        }
    }
    public partial class S5Server
    {
        public class S5Data
        {
            static int TIMEOUT = -1;
            internal Socket clientSocket;
            internal Socket proxySocket;
            internal byte[] clientBuffer = new byte[65535];
            internal byte[] proxyBuffer = new byte[65535];

            private int _clientBufferSize;
            public int clientBufferSize
            {
                get { return _clientBufferSize; }
                set
                {
                    _clientBufferSize = value;
                    clientBufferTotal += value;
                    Traffic?.Invoke(clientBufferTotal, proxyBufferSize);
                }
            }
            private int _proxyBufferSize;
            public int proxyBufferSize
            {
                get { return _proxyBufferSize; }
                set
                {
                    _proxyBufferSize = value;
                    proxyBufferTotal += value;
                    Traffic?.Invoke(clientBufferTotal, proxyBufferSize);
                }
            }
            public Action<string> Message;
            public Action<long, long> Traffic;
            internal static long clientBufferTotal = 0;
            internal static long proxyBufferTotal = 0;
            public void TCPProxyConn(IPEndPoint ip, string url)
            {
                try
                {
                    this.proxySocket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    this.proxySocket.BeginConnect(ip, _OnProxyConnect, url);
                }
                catch (Exception ex)
                {
                    this.ProxyDispose();
                    this.ClientDispose();
                }
            }
            private void _OnProxyConnect(IAsyncResult ir)
            {
                var url = ir.AsyncState as string;
                try
                {
                    proxySocket.EndConnect(ir);
                    if (this.proxySocket.Connected)
                    {
                        proxyBuffer = new byte[proxyBuffer.Length];
                        clientBuffer = new byte[clientBuffer.Length];
                        this.clientSocket.BeginReceive(clientBuffer, 0, clientBuffer.Length, SocketFlags.None, this._OnClientReceive, null);
                        this.proxySocket.BeginReceive(proxyBuffer, 0, proxyBuffer.Length, SocketFlags.None, this._OnProxyReceive, null);
                    }
                    else
                    {
                        this.ProxyDispose();
                        this.ClientDispose();
                    }
                }
                catch (Exception ex)
                {
                    Message?.Invoke(string.Format("{0} <===> {1}", url, ex.Message));
                    this.ProxyDispose();
                    this.ClientDispose();
                }
            }
            public void UdpProxy(IPEndPoint ip)
            {
                try
                {
                    this.proxySocket = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    this.proxySocket.Bind(ip);
                    proxyBuffer = new byte[proxyBuffer.Length];
                    clientBuffer = new byte[clientBuffer.Length];
                    var _IP = ip as EndPoint;
                    proxyBuffer = new byte[proxyBuffer.Length];
                    this.proxySocket.BeginReceiveFrom(proxyBuffer, 0, proxyBuffer.Length, SocketFlags.None, ref _IP, _OnProxyReceiveFrom, _IP);
                }
                catch (Exception ex)
                {
                    this.ClientDispose();
                }
            }
            private void _OnProxyReceiveFrom(IAsyncResult ir)
            {
                try
                {
                    var ip = ir.AsyncState as EndPoint;
                    var size = this.proxySocket.EndReceiveFrom(ir, ref ip);
                    if (size > 0)
                    {
                        this.proxyBufferSize = size;
                        this.proxySocket.SendTo(proxyBuffer, 0, proxyBuffer.Length, SocketFlags.None, ip);
                    }
                    this.proxySocket.BeginReceiveFrom(proxyBuffer, 0, proxyBuffer.Length, SocketFlags.None, ref ip, _OnProxyReceiveFrom, ip);
                }
                catch (Exception ex)
                {
                    this.ProxyDispose();
                    ClientDispose();
                }
            }
            private void _OnClientReceive(IAsyncResult ir)
            {
                try
                {
                    if (this.clientSocket.Connected)
                    {
                        var size = this.clientSocket.EndReceive(ir);
                        if (size > 0)
                        {
                            this.clientBufferSize = size;
                            this.ProxySendToClient(clientBuffer);
                            this.clientSocket.BeginReceive(clientBuffer, 0, clientBuffer.Length, SocketFlags.None, this._OnClientReceive, null);
                        }
                        else
                        {
                            this.ProxyDispose();
                            ClientDispose();
                        }
                    }
                }
                catch (Exception ex)
                {
                    this.ProxyDispose();
                    ClientDispose();
                }
            }
            private void _OnProxyReceive(IAsyncResult ir)
            {
                try
                {
                    if (this.proxySocket.Connected)
                    {
                        var size = this.proxySocket.EndReceive(ir);
                        if (size > 0)
                        {
                            this.proxyBufferSize = size;
                            ClientSendToProxy(proxyBuffer);
                            this.proxySocket.BeginReceive(proxyBuffer, 0, proxyBuffer.Length, SocketFlags.None, this._OnProxyReceive, null);
                        }
                        else
                        {
                            ProxyDispose();
                            ClientDispose();
                        }
                    }
                }
                catch (Exception ex)
                {
                    ProxyDispose();
                    ClientDispose();
                }
            }
            private void ClientSendToProxy(byte[] buffer)
            {
                try
                {
                    if (clientSocket.Poll(TIMEOUT, SelectMode.SelectWrite))
                    {
                        clientSocket.Send(buffer, 0, proxyBufferSize, SocketFlags.None);
                    }
                }
                catch (Exception ex)
                {
                    ProxyDispose();
                    ClientDispose();
                }
            }

            private void ProxySendToClient(byte[] buffer)
            {
                try
                {
                    if (proxySocket.Poll(TIMEOUT, SelectMode.SelectWrite))
                    {
                        proxySocket.Send(buffer, 0, clientBufferSize, SocketFlags.None);
                    }
                }
                catch (Exception ex)
                {
                    ProxyDispose();
                    ClientDispose();
                }
            }
            public void ProxyDispose()
            {
                Traffic?.Invoke(clientBufferTotal, proxyBufferSize);
                try { proxySocket.Disconnect(false); } catch (Exception ex) { }
                try { proxySocket.Shutdown(SocketShutdown.Both); } catch (Exception ex) { }
                try { proxySocket.Close(); } catch (Exception ex) { }
            }
            public void ClientDispose()
            {
                Traffic?.Invoke(clientBufferTotal, proxyBufferSize);
                try { clientSocket.Disconnect(false); } catch (Exception ex) { }
                try { clientSocket.Shutdown(SocketShutdown.Both); } catch (Exception ex) { }
                try { clientSocket.Close(); } catch (Exception ex) { }
            }
        }
    }
    public partial class S5Server : IDisposable
    {
        Socket socket;
        public Func<string, bool> BlacklistFilter;
        public Action<string> Message;
        public Action<long, long, long, long> Traffic;
        public string username;
        public string password;
        public void SetAuthor(string username, string password)
        {
            this.username = username;
            this.password = password;
        }
        public void Start(string ip, int port)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Parse(ip), port));
            socket.Listen(3);
            socket.BeginAccept(AcceptSocket, socket);
        }
        void AcceptSocket(IAsyncResult result)
        {
            var socket = result.AsyncState as Socket;
            var s = socket.EndAccept(result);
            var s5 = new S5Data() { clientSocket = s };
            s5.Message = (msg) => { this.Message?.Invoke(msg); };
            s5.Traffic = (clientBufferTotal, proxyBufferSize) => { this.Traffic?.Invoke(clientBufferTotal, proxyBufferSize, S5Data.clientBufferTotal, S5Data.proxyBufferTotal); };
            s5.clientBufferSize = s5.clientSocket.Receive(s5.clientBuffer);
            DoShakeHands(s5);
            socket.BeginAccept(AcceptSocket, socket);
        }
        bool ClientRecv(S5Data s5)
        {
            try
            {
                if (s5.clientSocket.Connected)
                {
                    s5.clientBuffer = new byte[s5.clientBuffer.Length];
                    s5.clientBufferSize = s5.clientSocket.Receive(s5.clientBuffer);
                    return s5.clientBufferSize > 0;
                }
                s5.ClientDispose();
                return false;
            }
            catch (Exception ex)
            {
                s5.ClientDispose();
                return false;
            }
        }
        bool ClientSend(S5Data s5, byte[] buffer)
        {
            try
            {
                if (s5.clientSocket.Connected)
                {
                    s5.clientSocket.Send(buffer);
                    return true;
                }
                s5.ClientDispose();
                return false;
            }
            catch (Exception ex)
            {
                s5.ClientDispose();
                return false;
            }
        }
        /// <summary>
        /// 握手处理
        /// </summary>
        /// <param name="s5"></param>
        void DoShakeHands(S5Data s5)
        {
            var size = s5.clientBufferSize;
            byte[] buffer = s5.clientBuffer;
            Socket cs = s5.clientSocket;
            #region 验证部分

            if (size == 3 && buffer.StartWith(new byte[] { 0x05, 0x01, 0x00 }))//无需验证
            {
                if (string.IsNullOrEmpty(this.username) && string.IsNullOrEmpty(this.password))
                {
                    ClientSend(s5, new byte[] { 0x05, 0x00 });
                    if (ClientRecv(s5))
                    {
                        DoShakeHands(s5);
                    }
                    return;
                }
                ClientSend(s5, new byte[] { 0x05, 0xFF });
                s5.ClientDispose();
                return;
            }
            if (size == 3 && buffer.StartWith(new byte[] { 0x05, 0x01, 0x02 })) //用户名或密码
            {
                ClientSend(s5, new byte[] { 0x05, 0x02 });//需要验证
                if (ClientRecv(s5))
                {
                    var nameLen = s5.clientBuffer[1];
                    var name = Encoding.UTF8.GetString(s5.clientBuffer.SubBytes(2, nameLen));
                    var pwdLen = s5.clientBuffer[2 + nameLen];
                    var pwd = Encoding.UTF8.GetString(s5.clientBuffer.SubBytes(3 + nameLen, pwdLen));
                    if (name == this.username && pwd == this.password)
                    {
                        ClientSend(s5, new byte[] { 0x01, 0x00 });//验证成功
                        if (ClientRecv(s5))
                        {
                            DoShakeHands(s5);
                            return;
                        }
                    }
                }
                ClientSend(s5, new byte[] { 0x05, 0xFF });
                s5.ClientDispose();
                return;
            }
            #endregion
            #region 解析部分
            if (buffer.StartWith(new byte[] { 0x05, 0x01, 0x00, 0x03 }))//域名解析
            {
                var len = buffer[4];//长度
                var urlByte = buffer.SubBytes(5, len);
                var url = Encoding.UTF8.GetString(urlByte);
                var pList = buffer.SubBytes(5 + len, 2);
                var port = (pList[0] << 8) + pList[1];
                if (BlacklistFilter?.Invoke(url) == false)
                {
                    s5.ClientDispose();
                    return;
                }
                try
                {
                    var addr = Dns.GetHostAddresses(url).FirstOrDefault();
                    Message?.Invoke(string.Format("{0} ===> {2}:{3}【{1}】", cs.RemoteEndPoint.ToString(), addr, url, port));
                    List<byte> list = new List<byte>();
                    buffer[1] = 0x00;
                    ClientSend(s5, buffer.SubBytes(0, size));
                    s5.TCPProxyConn(new IPEndPoint(addr, port), url);
                }
                catch (Exception ex)
                {
                    s5.ClientDispose();
                }
                return;
            }
            else if (buffer.StartWith(new byte[] { 0x05, 0x03, 0x00, 0x01 }))//udp ipv4 暂未测试这里的代码
            {
                //buffer.SubBytes(4, 4);//0x00 0x00 0x00 0x00
                var pList = buffer.SubBytes(8, 2);//
                var port = (pList[0] << 8) + pList[1];
                List<byte> list = new List<byte>();
                list.AddRange(new byte[] { 0x05, 0x00, 0x00, 0x01 });
                var ipv4 = Dns.GetHostAddresses(Dns.GetHostName()).LastOrDefault().MapToIPv4();//本设备有2个IPV4,但是只有一个是可以正常内网通讯
                list.AddRange(ipv4.GetAddressBytes());
                //list.AddRange(new byte[] { 0xC3, 0x53 });//50003
                list.AddRange(pList);
                //未找到具体文档,这里不清楚具体要返回什么IP跟端口
                //使用QQ客户端测试接收到的IP是0x00 0x00 0x00 0x00,端口正常,SSTAP则只有0x05, 0x03, 0x00, 0x01这四个字节数据
                var _IP = new IPEndPoint(ipv4, port);
                cs.SendTo(list.ToArray(), _IP);
                if (ClientRecv(s5))
                {

                }
                s5.UdpProxy(_IP);
                return;
            }
            else if (buffer.StartWith(new byte[] { 0x05, 0x00, 0x00, 0x01 }))
            {

            }
            else if (buffer.StartWith(new byte[] { 0x05, 0x01, 0x00, 0x01 }))
            {

            }
            else
            {

            }
            #endregion
        }
        public void Dispose()
        {
            try { socket.Disconnect(false); } catch (Exception ex) { }
            try { socket.Shutdown(SocketShutdown.Both); } catch (Exception ex) { }
            try { socket.Dispose(); } catch (Exception ex) { }
        }
    }
}
