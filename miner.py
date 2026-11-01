
import os, sys
# GitHub Actions worker — env START END NEED
import sha3
W=bytes.fromhex("ac45ab246f50eb16670f61ccdadfce2b8682a7b8")
need=int(os.environ.get("NEED","33"))
start=int(os.environ.get("START","0"))
end=int(os.environ.get("END","500000000"))
k=sha3.keccak_256()
nbytes=need//8; rem=need%8
thresh=(0x100>>rem)-1 if rem else None
for n in range(start,end):
    k2=k.copy(); k2.update(W+n.to_bytes(32,'big'))
    d=k2.digest()
    if d[:nbytes]==b"\0"*nbytes and (thresh is None or d[nbytes]<=thresh):
        print("FOUND", n); open("nonce.txt","w").write(str(n)); sys.exit(0)
print("NOTFOUND")
