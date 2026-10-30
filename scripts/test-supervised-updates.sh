#!/usr/bin/env bash
# Linux integration qualification for the same-binary SpamGate supervisor.
# No GitHub credentials, MTA mutations, Docker socket or outside network required.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
command -v go >/dev/null || { echo 'go required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }
BASE_VERSION="$(sed -n 's/^const Version = "\([^"]*\)"$/\1/p' "$ROOT/internal/core/types.go")"
[[ "$BASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || { echo 'unsupported development version' >&2; exit 1; }
cd "$ROOT"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TMP/spamgate-base" ./cmd/spamgate
for VARIANT in healthy broken; do
  mkdir -p "$TMP/$VARIANT-source"
  cp -a cmd internal go.mod "$TMP/$VARIANT-source/"
  RELEASE="$(python3 - "$BASE_VERSION" "$VARIANT" <<'PY'
import sys
parts=sys.argv[1].split('.')
parts[-1]=str(int(parts[-1])+({'healthy':1,'broken':2}[sys.argv[2]]))
print('.'.join(parts))
PY
)"
  sed -i "s/const Version = \"$BASE_VERSION\"/const Version = \"$RELEASE\"/" "$TMP/$VARIANT-source/internal/core/types.go"
  if [[ "$VARIANT" == broken ]]; then
    python3 - "$TMP/$VARIANT-source/cmd/spamgate/main.go" <<'PY'
import sys
path=sys.argv[1]
s=open(path).read()
pattern='func runApp(ctx context.Context, opts options) error {'
assert s.count(pattern)==1
s=s.replace(pattern,pattern+'\nreturn fmt.Errorf("intentional supervisor rollback test: worker refused to start")\n')
open(path,'w').write(s)
PY
  fi
  (cd "$TMP/$VARIANT-source" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TMP/spamgate-$VARIANT" ./cmd/spamgate)
  [[ "$("$TMP/spamgate-$VARIANT" -version)" == "$RELEASE" ]]
done

python3 - "$TMP" "$BASE_VERSION" <<'PY'
import os, sys, json, subprocess, tempfile, shutil, hashlib, urllib.request, urllib.error, http.cookiejar, socket, re, time, signal
root,base_version=sys.argv[1:]
def port():
    sock=socket.socket();sock.bind(('127.0.0.1',0));v=sock.getsockname()[1];sock.close();return v

def scenario(kind,increment,inplace=False):
    label=kind+('-inplace' if inplace else '')
    dirname=os.path.join(root,'test-'+label);os.mkdir(dirname)
    data=os.path.join(dirname,'data');address=port();log=os.path.join(dirname,'worker.log')
    handle=open(log,'w+')
    env=os.environ.copy(); env['SPAMGATE_INPLACE_UPDATES']='1' if inplace else '0'
    parent=subprocess.Popen([os.path.join(root,'spamgate-base'),'-internal-supervise','-data',data,'-listen',f'127.0.0.1:{address}'],stdout=handle,stderr=handle,env=env)
    base=f'http://127.0.0.1:{address}'
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def api(path,method='GET',payload=None,headers=None):
        body=json.dumps(payload).encode() if payload is not None else None
        request=urllib.request.Request(base+path,data=body,method=method,headers={'Content-Type':'application/json',**(headers or {})})
        with opener.open(request,timeout=2) as response:return response.status,json.loads(response.read())
    def until(predicate,seconds):
        for _ in range(int(seconds*8)):
            try:
                result=predicate()
                if result:return result
            except (OSError,ValueError,KeyError,urllib.error.URLError):pass
            time.sleep(.125)
        raise AssertionError(f'{kind}: timed out waiting for observed state')
    try:
        until(lambda:api('/healthz')[1]['version']==base_version,12)
        def claim():
            with open(log) as f:text=f.read()
            match=re.search(r'setup_key=([\w-]+)',text)
            return match.group(1) if match else None
        key=until(claim,8)
        status,_=api('/api/v1/setup','POST',{'username':'admin','password':'a long and unique test password','setup_key':key})
        assert status==201
        _,identity=api('/api/v1/me');token=identity['csrf']
        binary=os.path.join(root,'spamgate-'+kind)
        with open(binary,'rb') as f:source=f.read()
        folder=os.path.join(data,'updates');os.makedirs(folder,exist_ok=True)
        target=os.path.join(folder,'pending');open(target,'wb').write(source);os.chmod(target,0o700)
        version='.'.join(base_version.split('.')[:-1]+[str(int(base_version.split('.')[-1])+increment)])
        with open(os.path.join(folder,'pending.json'),'w') as f:json.dump({'Version':'v'+version,'Filename':'spamgate-linux-amd64','SHA256':hashlib.sha256(source).hexdigest()},f)
        status,response=api('/api/v1/update/install','POST',headers={'X-CSRF-Token':token,'X-Confirm-Update':'install verified update'})
        assert status==202,response
        def state():
            with open(os.path.join(folder,'last-update.json')) as f:return json.load(f)
        result=until(lambda:(s if (s:=state())['state'] in ('healthy','rolled_back') else None),22)
        expected='healthy' if kind=='healthy' else 'rolled_back'
        assert result['state']==expected,(kind,result)
        wanted=version if kind=='healthy' else base_version
        until(lambda:api('/healthz')[1]['version']==wanted,12)
        assert parent.poll() is None,(kind,'supervisor process died')
        if inplace:
            installed=os.path.join(data,'bin','spamgate')
            assert os.path.isfile(installed),(kind,'missing in-place installed executable')
            actual=subprocess.check_output([installed,'-version'],timeout=3,text=True).strip()
            assert actual==wanted,(kind,'installed executable on disk is not the running version',actual,wanted)
        _,me=api('/api/v1/me');assert me['name']=='admin',(kind,'admin session did not survive')
        print(f'PASS {kind}: parent PID {parent.pid} alive; version {wanted}; audit={expected}; authenticated session retained')
    finally:
        parent.terminate()
        try:parent.wait(timeout=10)
        except subprocess.TimeoutExpired:parent.kill();parent.wait(timeout=3)
        handle.close()
scenario('healthy',1)
scenario('broken',2)
scenario('healthy',1,True)
scenario('broken',2,True)
PY
