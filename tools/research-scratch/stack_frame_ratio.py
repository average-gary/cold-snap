import subprocess,re,sys,statistics
OBJ='/opt/homebrew/opt/llvm/bin/llvm-objdump'
rs=re.compile(r'^[0-9a-f]+ <(.+)>:')
def scan(args, pat):
    m={}; sym=None
    p=subprocess.Popen([OBJ,'-d','--no-show-raw-insn']+args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    rf=re.compile(pat)
    for line in p.stdout:
        g=rs.match(line)
        if g: sym=g.group(1); continue
        g=rf.search(line)
        if g and sym:
            v=int(g.group(1),16) if g.group(1).startswith('0x') else int(g.group(1))
            k=norm(sym)
            if v>m.get(k,0): m[k]=v
    p.wait()
    return m
def norm(s):
    s=s.lstrip('_')
    s=re.sub(r'17h[0-9a-f]{16}E$','',s)
    return s
import glob
tgt=scan(sorted(glob.glob('/Users/garykrause/repos/cold-snap/target/thumbv7em-none-eabihf/release/deps/*.rlib')), r'\bsub(?:\.w)?\s+sp,\s*(?:sp,\s*)?#(0x[0-9a-fA-F]+|[0-9]+)')
hst=scan(['/Users/garykrause/repos/cold-snap/target/aarch64-apple-darwin/release/examples/heap_profile'], r'\bsub\s+sp,\s*sp,\s*#(0x[0-9a-fA-F]+|[0-9]+)')
common=[k for k in tgt if k in hst and hst[k]>=64 and tgt[k]>=64]
r=[tgt[k]/hst[k] for k in common]
print('target_fns=',len(tgt),'host_fns=',len(hst),'common>=64B=',len(common))
print('ratio target/host: median=%.3f mean=%.3f p90=%.3f max=%.3f'%(statistics.median(r),statistics.mean(r),sorted(r)[int(.9*len(r))],max(r)))
print('weighted (sum tgt / sum host over common) = %.3f'%(sum(tgt[k] for k in common)/sum(hst[k] for k in common)))
top=sorted(common,key=lambda k:-hst[k])[:12]
for k in top: print('  host=%5d tgt=%5d %.2f  %s'%(hst[k],tgt[k],tgt[k]/hst[k],k[:96]))
