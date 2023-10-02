using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.StreamExtended.Network;

namespace Sharp.Proxy
{
    public class ProxyController : IDisposable
    {
        private readonly ProxyServer proxyServer;

        private readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        private readonly ConcurrentQueue<Tuple<ConsoleColor?, string>> consoleMessageQueue
            = new ConcurrentQueue<Tuple<ConsoleColor?, string>>();

        private ExplicitProxyEndPoint explicitEndPointHttps, explicitEndPointHttp;

        public ProxyController()
        {
            Task.Run(() => ListenToConsole());

            proxyServer = new ProxyServer();

            //proxyServer.EnableHttp2 = true;

            // generate root certificate without storing it in file system
            proxyServer.CertificateManager.CreateRootCertificate(false);
            proxyServer.CertificateManager.TrustRootCertificate();
            //proxyServer.CertificateManager.TrustRootCertificateAsAdmin();

            proxyServer.ExceptionFunc = async exception =>
            {
                if (exception is ProxyHttpException phex)
                    WriteToConsole(exception.Message + ": " + phex.InnerException?.Message, ConsoleColor.Red);
                else
                    WriteToConsole(exception.Message, ConsoleColor.Red);
            };

            proxyServer.TcpTimeWaitSeconds = 10;
            proxyServer.ConnectionTimeOutSeconds = 15;
            proxyServer.ReuseSocket = false;
            proxyServer.EnableConnectionPool = false;
            proxyServer.ForwardToUpstreamGateway = true;
            proxyServer.CertificateManager.SaveFakeCertificates = true;
            //proxyServer.ProxyBasicAuthenticateFunc = async (args, userName, password) =>
            //{
            //    return true;
            //};

        }

        private CancellationToken CancellationToken => cancellationTokenSource.Token;

        public void Dispose()
        {
            cancellationTokenSource.Dispose();
            proxyServer.Dispose();
        }

        public void StartProxy()
        {
            proxyServer.BeforeRequest += OnRequest;
            proxyServer.BeforeResponse += OnResponse;
            proxyServer.AfterResponse += OnAfterResponse;

            proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

            //proxyServer.EnableWinAuth = true;

            // EndPoint for HTTPS protocol
            explicitEndPointHttps = new ExplicitProxyEndPoint(IPAddress.Any, sharp_proxy.Properties.Settings.Default.HttpsPort);

            // Fired when a CONNECT request is received
            explicitEndPointHttps.BeforeTunnelConnectRequest += OnBeforeTunnelConnectRequest;
            explicitEndPointHttps.BeforeTunnelConnectResponse += OnBeforeTunnelConnectResponse;

            // An explicit endpoint is where the client knows about the existence of a proxy
            // So client sends request in a proxy friendly manner
            proxyServer.AddEndPoint(explicitEndPointHttps);

            // EndPoint for HTTP protocol
            explicitEndPointHttp = new ExplicitProxyEndPoint(IPAddress.Any, sharp_proxy.Properties.Settings.Default.HttpPort);

            // Fired when a CONNECT request is received
            explicitEndPointHttp.BeforeTunnelConnectRequest += OnBeforeTunnelConnectRequest;
            explicitEndPointHttp.BeforeTunnelConnectResponse += OnBeforeTunnelConnectResponse;

            // An explicit endpoint is where the client knows about the existence of a proxy
            // So client sends request in a proxy friendly manner
            proxyServer.AddEndPoint(explicitEndPointHttp);

            // EndPoint for SOCKS protocol
            if (sharp_proxy.Properties.Settings.Default.UseSocks)
            {
                var socksEndPoint = new SocksProxyEndPoint(IPAddress.Any, sharp_proxy.Properties.Settings.Default.Socks5Port, true)
                {
                    // Generic Certificate hostname to use
                    // When SNI is disabled by client
                    GenericCertificateName = "google.com"
                };
                proxyServer.AddEndPoint(socksEndPoint);
            }

            proxyServer.Start();

            foreach (var endPoint in proxyServer.ProxyEndPoints)
                Console.WriteLine("Listening on '{0}' endpoint at Ip {1} and port: {2} ", endPoint.GetType().Name,
                    endPoint.IpAddress, endPoint.Port);
        }

        public void Stop()
        {
            explicitEndPointHttps.BeforeTunnelConnectRequest -= OnBeforeTunnelConnectRequest;
            explicitEndPointHttps.BeforeTunnelConnectResponse -= OnBeforeTunnelConnectResponse;

            explicitEndPointHttp.BeforeTunnelConnectRequest -= OnBeforeTunnelConnectRequest;
            explicitEndPointHttp.BeforeTunnelConnectResponse -= OnBeforeTunnelConnectResponse;

            proxyServer.BeforeRequest -= OnRequest;
            proxyServer.BeforeResponse -= OnResponse;
            proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;

            proxyServer.Stop();

            // remove the generated certificates
            //proxyServer.CertificateManager.RemoveTrustedRootCertificate();
        }

    
        private async Task OnBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            var hostname = e.HttpClient.Request.RequestUri.Host;
            e.GetState().PipelineInfo.AppendLine(nameof(OnBeforeTunnelConnectRequest) + ":" + hostname);
            WriteToConsole("Tunnel to: " + hostname);

            var clientLocalIp = e.ClientLocalEndPoint.Address;
            if (!clientLocalIp.Equals(IPAddress.Loopback) && !clientLocalIp.Equals(IPAddress.IPv6Loopback))
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(clientLocalIp, 0);
        }

        private void WebSocket_DataSent(object sender, DataEventArgs e)
        {
            var args = (SessionEventArgs)sender;
            WebSocketDataSentReceived(args, e, true);
        }

        private void WebSocket_DataReceived(object sender, DataEventArgs e)
        {
            var args = (SessionEventArgs)sender;
            WebSocketDataSentReceived(args, e, false);
        }

        private void WebSocketDataSentReceived(SessionEventArgs args, DataEventArgs e, bool sent)
        {
            if (sharp_proxy.Properties.Settings.Default.CaptureData)
            {
                var color = sent ? ConsoleColor.Green : ConsoleColor.Blue;

                foreach (var frame in args.WebSocketDecoder.Decode(e.Buffer, e.Offset, e.Count))
                {
                    if (frame.OpCode == WebsocketOpCode.Binary)
                    {
                        var data = frame.Data.ToArray();
                        var str = string.Join(",", data.ToArray().Select(x => x.ToString("X2")));
                        WriteToConsole(str, color);
                    }

                    if (frame.OpCode == WebsocketOpCode.Text) WriteToConsole(frame.GetText(), color);
                }
            }
        }

        private Task OnBeforeTunnelConnectResponse(object sender, TunnelConnectSessionEventArgs e)
        {
            e.GetState().PipelineInfo
                .AppendLine(nameof(OnBeforeTunnelConnectResponse) + ":" + e.HttpClient.Request.RequestUri);

            return Task.CompletedTask;
        }

        // intercept & cancel redirect or update requests
        private async Task OnRequest(object sender, SessionEventArgs e)
        {
            e.GetState().PipelineInfo.AppendLine(nameof(OnRequest) + ":" + e.HttpClient.Request.RequestUri);

            var clientLocalIp = e.ClientLocalEndPoint.Address;
            if (!clientLocalIp.Equals(IPAddress.Loopback) && !clientLocalIp.Equals(IPAddress.IPv6Loopback))
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(clientLocalIp, 0);

            if (sharp_proxy.Properties.Settings.Default.CaptureData)
            {
                WriteToConsole("Active Client Connections:" + ((ProxyServer)sender).ClientConnectionCount);
                WriteToConsole(e.HttpClient.Request.Url);
            }
        }

       
        private async Task OnResponse(object sender, SessionEventArgs e)
        {
            if (sharp_proxy.Properties.Settings.Default.CaptureData)
            {
                e.GetState().PipelineInfo.AppendLine(nameof(OnResponse));
            }

            if (e.HttpClient.ConnectRequest?.TunnelType == TunnelType.Websocket)
            {
                e.DataSent += WebSocket_DataSent;
                e.DataReceived += WebSocket_DataReceived;
            }

            WriteToConsole("Active Server Connections:" + ((ProxyServer)sender).ServerConnectionCount);
        }

        private async Task OnAfterResponse(object sender, SessionEventArgs e)
        {
            if (sharp_proxy.Properties.Settings.Default.CaptureData)
            {
                WriteToConsole($"Pipelineinfo: {e.GetState().PipelineInfo}", ConsoleColor.Yellow);
            }
        }

        /// <summary>
        ///     Allows overriding default certificate validation logic
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            e.GetState().PipelineInfo.AppendLine(nameof(OnCertificateValidation));

            // set IsValid to true/false based on Certificate Errors
            if (e.SslPolicyErrors == SslPolicyErrors.None) e.IsValid = true;

            return Task.CompletedTask;
        }

        /// <summary>
        ///     Allows overriding default client certificate selection logic during mutual authentication
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
        {
            e.GetState().PipelineInfo.AppendLine(nameof(OnCertificateSelection));

            // set e.clientCertificate to override

            return Task.CompletedTask;
        }

        private void WriteToConsole(string message, ConsoleColor? consoleColor = null)
        {
            consoleMessageQueue.Enqueue(new Tuple<ConsoleColor?, string>(consoleColor, message));
        }

        private async Task ListenToConsole()
        {
            while (!CancellationToken.IsCancellationRequested)
            {
                while (consoleMessageQueue.TryDequeue(out var item))
                {
                    var consoleColor = item.Item1;
                    var message = item.Item2;

                    if (consoleColor.HasValue)
                    {
                        var existing = Console.ForegroundColor;
                        Console.ForegroundColor = consoleColor.Value;
                        Console.WriteLine(message);
                        Console.ForegroundColor = existing;
                    }
                    else
                    {
                        Console.WriteLine(message);
                    }
                }

                // Reduce CPU usage
                await Task.Delay(50);
            }
        }
    }
}