# WSuspicious

## Summary
This is a proof of concept program to escalate privileges on a Windows host using non-SSL WSUS traffic.
It was inspired from the WSuspect proxy project: https://github.com/ctxis/wsuspect-proxy

## Usage
### Compilation

The ILMerge dependency can be used to compile the application into a standalone .exe file.
To compile and compile the application, simply use the following command:
```
dotnet msbuild /t:Restore /t:Build /p:Configuration=Release /p:DebugSymbols=false /p:DebugType=None /t:ILMerge /p:TrimUnusedDependencies=true
```
