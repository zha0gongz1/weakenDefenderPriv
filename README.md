# weakenDefenderPriv

Without closing windows defender, to make defender (and probably other AV/EDRs) useless by removing its token privileges and lowering the token integrity.

The process of technology:

    Enable the SeDubgPrivilege in our process security token.
    Get a handle to Defender using PROCESS_QUERY_LIMITED_INFORMATION.
    Get a handle to the Defender token using TOKEN_ALL_ACCESS.
    Disable all privileges in the token using SetPrivilege
    Set the Defender token Integrity level to Untrusted.


Demo code of Golang, [here](https://github.com/pwn1sher/KillDefender) is the C++ version

![alt](https://github.com/zha0gongz1/weakenDefenderPriv/blob/main/result.jpg?raw=true)

*Please refer to [the principle explanation](https://www.cnblogs.com/H4ck3R-XiX/p/15872255.html).*
