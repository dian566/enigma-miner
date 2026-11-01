import os
W=bytes.fromhex("ac45ab246f50eb16670f61ccdadfce2b8682a7b8")
need=int(os.environ.get("NEED","33"))
start=int(os.environ.get("START","0"))
end=int(os.environ.get("END","500000000"))
import sha3
from multiprocessing import Pool
N=2
def work(t):
    a,b=t
    k=sha3.keccak_256()
    nbytes=need//8; rem=need%8
    thresh=(0x100>>rem)-1 if rem else None
    for n in range(a,b):
        k2=k.copy(); k2.update(W+n.to_bytes(32,'big'))
        d=k2.digest()
        if d[:nbytes]==b"\\0"*nbytes and (thresh is None or d[nbytes]<=thresh):
            open("nonce.txt","w").write(str(n)); return n
    return None
chunk=(end-start)//N
ranges=[(start+i*chunk, start+(i+1)*chunk) for i in range(N-1)]+[(start+(N-1)*chunk,end)]
with Pool(N) as p:
    res=p.map(work,ranges)
print("FOUND" if any(res) else "NOTFOUND", [r for r in res if r])
