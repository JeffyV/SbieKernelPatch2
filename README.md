driver from:
https://www.loldrivers.io/drivers/afb8bb46-1d13-407d-9866-1daa7c82ca63/

the poc:
https://github.com/kite03/echoac-poc/tree/main

the wp:
https://ioctl.fail/echo-ac-writeup/


# Study

IRP (I/O request packets)

The IRP Structure
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp

The IRP Major Function Codes
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes

# windows bcrypt

https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/

# ref

https://bbs.kanxue.com/thread-287189.htm

https://bbs.kanxue.com/thread-288315-1.htm
https://github.com/EEEEhex/SbieKernelPatch/tree/main

# other

```
SIGNATURE:<b64dec>  // this item not hash

DATE:KphParseDate()
DAYS:int
TYPE:str split by '-' // TYPE-LEVEL? 和下方合并的
LEVEL:str
OPTIONS:str
UPDATEKEY:str
-AMOUNT:int
-SOFTWARE:Sandboxie-Plus
HWID:uuid InitFwUuid()
```

// hash 上述项后进行签名校验 KphVerifySignature()
UPDATEKEY 可以不需要
LEVEL 可以不需要
DAYS 可以不需要

//
TYPE 强制,DEVELOPER or ETERNAL 不需要 level
OPTIONS 可选，NoSR,SBOX,EBOX,NETI,DESK,NoCR
HWID 需要为本机 hwid
SIGNATURE


// BCRYPT_ECDSA_P256_ALGORITHM
// KphVerifySignature(item hash, SIGNATURE)
