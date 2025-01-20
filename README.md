# biscuit
A simple reverse shell PoC with API hashing


### API concealing
Windows API hashing is obtained with a custom hashing algorithm. By performing this task we can clean-up our IAT so the executable is less likely to get flagged by early analisys tools.

### Shellcode injection (long story short)
After the initial stage of resolving API, the sample simply locates the process which is going to be injected (in the example Notepad.exe), then proceeds to obtain an handle to it. 
Afterwards it reserves the proper amount of memory and writes the shellcode in the victim process opened just before.

The shellcode is redacted for security reasons. You can learn about shellcode generation by reading, for example, Metasploit documentation.