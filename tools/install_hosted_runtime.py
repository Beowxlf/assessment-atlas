"""Install Atlas's Linux user-space runtimes without root or trust/TLS changes.

Run using Ubuntu's system Python, under the pre-provisioned service account.
Official HTTPS metadata/checksums are verified; downloads and versions are recorded.
An administrator separately provisions HTTPS/systemd and browser OS dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request

NODE_VERSION='22.23.3'
NODE_SHA256='df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de'
PLAYWRIGHT_VERSION='1.62.1'


def download(url,path,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'Assessment-Atlas-runtime-installer','Accept':'application/json'})
    with urllib.request.urlopen(request,timeout=45) as response:
        with path.open('xb') as output:
            total=0
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>limit:raise RuntimeError('Runtime download exceeded its size limit.')
                output.write(chunk)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(archive,destination):
    # Runtime archives come from verified official assets. Check every path/link
    # before extracting; do not depend on Python 3.12's tar extraction filter.
    with tarfile.open(archive) as tar:
        root=destination.resolve()
        for entry in tar.getmembers():
            target=(root/entry.name).resolve()
            if not target.is_relative_to(root) or entry.isdev():raise RuntimeError('Unsafe runtime archive member.')
            if entry.issym() or entry.islnk():
                link=(target.parent/entry.linkname if entry.issym() else root/entry.linkname).resolve()
                if not link.is_relative_to(root):raise RuntimeError('Unsafe runtime archive link.')
        tar.extractall(destination)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    if not sys.platform.startswith('linux') or os.geteuid()==0 or platform.machine()!='x86_64':raise SystemExit('Use the unprivileged Linux x86_64 service account.')
    root=args.root.resolve();runtime=root/'runtime';runtime.mkdir(mode=0o700,exist_ok=True)
    if (runtime/'runtime-receipt.json').exists():raise SystemExit('Runtime already installed; prepare a separate versioned upgrade.')
    stage=runtime/'downloads';stage.mkdir(mode=0o700,exist_ok=False)
    metadata=stage/'uv-release.json';download('https://api.github.com/repos/astral-sh/uv/releases/latest',metadata,2*1024*1024)
    release=json.loads(metadata.read_text());asset=next(a for a in release['assets'] if a['name']=='uv-x86_64-unknown-linux-gnu.tar.gz')
    if not asset['browser_download_url'].startswith('https://github.com/astral-sh/uv/releases/download/') or not str(asset.get('digest','')).startswith('sha256:'):raise RuntimeError('Official uv asset digest unavailable; refusing unverified download.')
    uv_archive=stage/'uv.tar.gz';uv_digest=download(asset['browser_download_url'],uv_archive,40*1024*1024)
    if 'sha256:'+uv_digest!=asset['digest']:raise RuntimeError('uv digest mismatch.')
    unpack(uv_archive,stage);uv=stage/'uv-x86_64-unknown-linux-gnu/uv'
    environment={**os.environ,'UV_PYTHON_INSTALL_DIR':str(runtime/'python'),'UV_NO_MODIFY_PATH':'1','PLAYWRIGHT_BROWSERS_PATH':str(root/'browser-cache')}
    subprocess.run([str(uv),'python','install','3.12'],env=environment,check=True,timeout=300)
    subprocess.run([str(uv),'venv','--python','3.12',str(runtime/'venv')],env=environment,check=True,timeout=60)
    python=runtime/'venv/bin/python'
    source=Path(__file__).resolve().parent.parent
    subprocess.run([str(uv),'pip','install','--python',str(python),'-r',str(source/'requirements-web.txt'),'-r',str(source/'requirements-protocols.txt')],env=environment,check=True,timeout=300)
    node_archive=stage/'node.tar.xz';node_digest=download('https://nodejs.org/download/release/v'+NODE_VERSION+'/node-v'+NODE_VERSION+'-linux-x64.tar.xz',node_archive,50*1024*1024)
    if node_digest!=NODE_SHA256:raise RuntimeError('Node.js digest mismatch.')
    unpack(node_archive,stage);(stage/('node-v'+NODE_VERSION+'-linux-x64')).rename(runtime/'node')
    environment['PATH']=str(runtime/'node/bin')+':'+environment.get('PATH','/usr/bin:/bin')
    browser=runtime/'browser';browser.mkdir(mode=0o700,exist_ok=False)
    subprocess.run([str(runtime/'node/bin/npm'),'install','--ignore-scripts','--no-audit','--no-fund','playwright@'+PLAYWRIGHT_VERSION],cwd=browser,env=environment,check=True,timeout=180)
    subprocess.run([str(runtime/'node/bin/node'),str(browser/'node_modules/playwright/cli.js'),'install','chromium'],env=environment,check=True,timeout=300)
    receipt={'node':NODE_VERSION,'node_sha256':node_digest,'uv':release['tag_name'],'uv_sha256':uv_digest,'python':subprocess.check_output([str(python),'--version'],text=True).strip(),'playwright':PLAYWRIGHT_VERSION,'uid':os.geteuid(),'chromium_sandbox_required':True,'browser_cache':str(root/'browser-cache'),'tls_verification_disabled':False}
    (runtime/'runtime-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


if __name__=='__main__':main()
