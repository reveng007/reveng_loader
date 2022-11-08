@ECHO OFF

csc.exe /target:exe /platform:x64 /out:reveng_loader.exe  .\dotnetLoader.cs .\PELoader.cs /unsafe