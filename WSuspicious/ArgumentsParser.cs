using System;
using System.Collections.Generic;
using System.IO;

namespace WSuspicious
{
    class ArgumentsParser
    {
        public static Dictionary<string, string> parse(string[] args)
        {
            Dictionary<string, string> arguments = new Dictionary<string, string>();

            foreach (string argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                else
                    arguments[argument] = string.Empty;
            }
            
            if (arguments.ContainsKey("/exe"))
            {
                if (String.IsNullOrEmpty(arguments["/exe"]))
                {
                    throw new ArgumentException("The provided executable is invalid.");
                }

                if (!File.Exists(arguments["/exe"]))
                {
                    throw new ArgumentException("The provided executable was not found.");
                }
            }
            else
            {
                arguments["/exe"] = @".\PsExec64.exe";
            }
            
            if (arguments.ContainsKey("/command"))
            {
                if (String.IsNullOrEmpty(arguments["/command"]))
                {
                    throw new ArgumentException("The provided command is invalid.");
                }
            }
            else
            {
                arguments["/command"] = "-accepteula -s -d cmd /c \"echo 1 > C:\\wsuspicious.was.here\"";
            }

            return arguments;
        }
    }
}
