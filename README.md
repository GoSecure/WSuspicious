# WSuspicious

## Summary
This is a proof of concept program to escalate privileges on a Windows host using non-SSL WSUS traffic.
It was inspired from the WSuspect proxy project: https://github.com/ctxis/wsuspect-proxy

## Usage
The tool was tested on a Windows 10 machine (10.0.18363).

```
Usage: WSuspicious [OPTION]...
    Ex. WSuspicious.exe /command:" -accepteula -s -d cmd /c ""echo 1 > C:\\wsuspicious.txt""" /autoinstall
    
Creates a local proxy to intercept WSUS requests and try to escalate privileges.
If launched without any arguments, the script will simply create the file C:\\wsuspicious.was.here

    /exe                The full path to the executable to run
                        Known payloads are bginfo and PsExec. (Default: .\PsExec64.exe)
    /command            The command to execute (Default: -accepteula -s -d cmd /c "echo 1 > C:\\wsuspicious.was.here")
    /debug              Increase the verbosity of the tool
    /autoinstall        Start Windows updates automatically after the proxy is started.
    /help               Display this help and exit
```

### Examples
![WSuspicious Privesc Example](https://raw.githubusercontent.com/GoSecure/WSuspicious/master/docs/privesc.gif)

## Compilation
The ILMerge dependency can be used to compile the application into a standalone .exe file.
To compile and compile the application, simply use the following command:
```
dotnet msbuild /t:Restore /t:Clean /t:Build /p:Configuration=Release /p:DebugSymbols=false /p:DebugType=None /t:ILMerge /p:TrimUnusedDependencies=true
```
