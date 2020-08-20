using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace WSuspicious.Utility
{
    class InternetExplorerProxyManager
    {
        [DllImport("wininet.dll")]
        public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
        public const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        public const int INTERNET_OPTION_REFRESH = 37;

        private int proxyEnabled = 0;
        private string originalProxyUrl = "";

        private const string keyName = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        public void setProxy(string proxyhost, int port, bool setHTTPS)
        {
            this.proxyEnabled = Convert.ToInt32(Registry.GetValue(keyName, "ProxyEnable", 0));
            this.originalProxyUrl = (string)Registry.GetValue(keyName, "ProxyServer", "");

            string currentValue = this.originalProxyUrl;

            if (Regex.IsMatch(currentValue, "^[^:|=]{1,}:[0-9]{1,}$"))
            {
                // This is a global proxy, we have to split it
                if (setHTTPS)
                {
                    currentValue = String.Format("http={0}:{1};https={0}:{1};ftp={2};socks={3}", proxyhost, port, currentValue, currentValue);
                }
                else
                {
                    currentValue = String.Format("http={0}:{1};https={2};ftp={3};socks={4}", proxyhost, port, currentValue, currentValue, currentValue);
                }
            }
            else if (String.IsNullOrWhiteSpace(currentValue))
            {
                if (setHTTPS)
                {
                    currentValue = String.Format("http={0}:{1};https={0}:{1}", proxyhost, port);
                }
                else
                {
                    currentValue = String.Format("http={0}:{1}", proxyhost, port);
                }
            }
            else
            {
                currentValue = Regex.Replace(currentValue, "http=[^:]{1,}:[0-9]{1,}", String.Format("http={0}:{1}", proxyhost, port));

                if (setHTTPS)
                {
                    currentValue = Regex.Replace(currentValue, "https=[^:]{1,}:[0-9]{1,}", String.Format("https={0}:{1}", proxyhost, port));
                }
            }

            Registry.SetValue(keyName, "ProxyServer", currentValue);
            Registry.SetValue(keyName, "ProxyEnable", 1);

            // These lines implement the Interface in the beginning of program 
            // They cause the OS to refresh the settings, causing IP to realy update
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }

        public void revert()
        {
            Registry.SetValue(keyName, "ProxyServer", this.originalProxyUrl);
            Registry.SetValue(keyName, "ProxyEnable", this.proxyEnabled);

            // These lines implement the Interface in the beginning of program 
            // They cause the OS to refresh the settings, causing IP to realy update
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
    }
}
