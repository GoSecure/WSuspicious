using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace WSuspicious.Utility
{
    public static class WindowsUpdateLauncher
    {
        private static readonly string userPath = Environment.GetEnvironmentVariable("PATH");

        private static readonly string win10Executable = "usoclient.exe";
        private static readonly string pathWin10 = userPath.Split(';')
                                                        .Where(s => File.Exists(Path.Combine(s, win10Executable)))
                                                        .FirstOrDefault();

        public static void StartUpdates()
        {
            if (pathWin10 != null && !String.IsNullOrWhiteSpace(pathWin10))
            {
                Process process = new Process();
                process.StartInfo.FileName = Path.Combine(pathWin10, win10Executable);
                process.StartInfo.Arguments = "StartInteractiveScan";
                process.Start();
                process.WaitForExit();
            }
            else
            {
                //TODO: Make this work for older windows versions with wuauclt.exe
            }
        }
    }
}
