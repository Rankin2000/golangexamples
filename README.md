# golang malware examples
For a presentation on basic malware, some basic examples of functionality had to be made. 
 
Examples include:
- Basic Shellcode Runner
- Remote Thread Injection
- IPv4 Obfuscation
- Shellcode Payload stored on Web
- Command Line spoofing


Proof of concept of calc.exe was used. 

`msfvenom -p windows/x64/exec cmd=calc.exe -f hex`


All Golang examples are purely PoC and not recommended code.
