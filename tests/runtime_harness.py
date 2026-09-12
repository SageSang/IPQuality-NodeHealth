"""Local-only process/handshake fixture for the actual OpenWrt controller."""
import copy
import json
import os
import shutil
import socket
import subprocess
import sys
import time

from test_port_mapping import CONVERTER, ROOT, mapping_case, proxy

APPLY = ROOT / "integrations/openwrt/apply-ranking.sh"
CHECK = ROOT / "integrations/openwrt/check-ranking.sh"

CORE_SOURCE = r'''
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
static volatile sig_atomic_t running=1;
static void stop(int sig) { (void)sig; running=0; }
int main(int argc,char **argv) {
  const char *file=NULL; int validate=0;
  for(int i=1;i<argc;i++) {
    if(!strcmp(argv[i],"-f") && i+1<argc) file=argv[++i];
    else if(!strcmp(argv[i],"-t")) validate=1;
  }
  if(!file) return 2;
  if(validate) return getenv("TEST_REJECT_CANDIDATE") && strstr(file,"generations/") ? 2 : 0;
  FILE *input=fopen(file,"r"); if(!input) return 2;
  char *text=calloc(1048577,1); fread(text,1,1048576,input); fclose(input);
  char *cursor=strstr(text,"\"listeners\""); if(!cursor) return 2;
  int fds[256], count=0, missing=strstr(text,"bad.example")!=NULL;
  while((cursor=strstr(cursor,"\"port\"")) && count<256) {
    cursor=strchr(cursor,':')+1; int port=(int)strtol(cursor,&cursor,10);
    if(missing) { missing=0; continue; }
    int fd=socket(AF_INET,SOCK_STREAM,0), reuse=1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    struct sockaddr_in address={0}; address.sin_family=AF_INET;
    address.sin_port=htons(port); inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    if(bind(fd,(struct sockaddr*)&address,sizeof(address)) || listen(fd,32)) return 3;
    fds[count++]=fd;
  }
  free(text); signal(SIGTERM,stop); signal(SIGINT,stop); signal(SIGPIPE,SIG_IGN);
  while(running) {
    fd_set set; FD_ZERO(&set); int maximum=-1;
    for(int i=0;i<count;i++) { FD_SET(fds[i],&set); if(fds[i]>maximum) maximum=fds[i]; }
    struct timeval timeout={0,100000};
    if(select(maximum+1,&set,NULL,NULL,&timeout)<=0) continue;
    for(int i=0;i<count;i++) if(FD_ISSET(fds[i],&set)) {
      int client=accept(fds[i],NULL,NULL); if(client<0) continue;
      struct timeval limit={0,200000}; setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
      unsigned char data[4]; if(recv(client,data,sizeof(data),0)>0) {
        unsigned char reply[2]={5,0}; send(client,reply,2,0);
      }
      close(client);
    }
  }
  for(int i=0;i<count;i++) close(fds[i]); return 0;
}
'''

SERVICE_SOURCE = r'''import os,signal,subprocess,sys,time
from pathlib import Path
pidfile=Path(os.environ['SERVICE_PID_FILE'])
log=Path(os.environ['TEST_SERVICE_LOG'])
def alive(pid):
    try:
        value=Path(f'/proc/{pid}/stat').read_text()
        return value[value.rfind(')')+2:].split()[0] != 'Z'
    except OSError: return False
def stop():
    if pidfile.exists():
        pid=int(pidfile.read_text())
        try: os.kill(pid,signal.SIGTERM)
        except ProcessLookupError: pass
        for _ in range(100):
            if not alive(pid): break
            time.sleep(.01)
        pidfile.unlink(missing_ok=True)
action=sys.argv[1]
with log.open('a') as stream:stream.write(action+'\n')
if action=='stop':stop();sys.exit(0)
if action=='status':sys.exit(0 if pidfile.exists() and alive(int(pidfile.read_text())) else 1)
if action!='restart':sys.exit(2)
text=Path(os.environ['CONFIG_PATH']).read_text()
if os.environ.get('TEST_IGNORE_NEW_RESTART') and 'new.example' in text:sys.exit(0)
stop()
process=subprocess.Popen([os.environ['MIHOMO_BIN'],'-d',os.environ['WORK_DIR'],'-f',os.environ['CONFIG_PATH']],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
pidfile.write_text(str(process.pid))
if os.environ.get('TEST_INTERRUPT_NEW') and 'new.example' in text:os.kill(os.getppid(),signal.SIGTERM)
'''

FAULT_SOURCE = r'''
if (process.argv[1]?.endsWith('runtime-controller.mjs')) {
  const fs=require('fs'), path=require('path'), original=fs.renameSync;
  const phase=process.env.TEST_CRASH_PHASE;
  const pending=path.join(process.env.CACHE_DIR,'pending.json');
  fs.renameSync=function(source,destination) {
    const active=fs.existsSync(pending);
    let label='';
    if(destination===pending) label='pending';
    if(active && destination===process.env.CONFIG_PATH) label='config';
    if(active && destination===process.env.EXPORT_DIR && source.startsWith(process.env.EXPORT_DIR+'.new.')) label='exports';
    if(active && destination===path.join(process.env.CACHE_DIR,'applied.json')) label='receipt';
    if(process.env.TEST_EXPORT_FAILURE && label==='exports') throw new Error('synthetic export failure');
    if(phase===`before-${label}` && label) process.kill(process.pid,'SIGKILL');
    const result=original.apply(this,arguments);
    if(phase===`after-${label}` && label) process.kill(process.pid,'SIGKILL');
    return result;
  };
}
'''


class Runtime:
    def __init__(self, directory, compiled):
        self.directory=directory
        self.work=directory / "work"
        self.cache=self.work / "cache"
        self.export=directory / "exports"
        self.work.mkdir(); self.cache.mkdir(); self.export.mkdir()
        self.config=self.work / "config.yaml"
        self.core=self.work / "core"
        shutil.copy2(compiled,self.core)
        self.proxies=[proxy("Hong Kong A")]
        self.profile={"ipv6":False,"allow-lan":False,"mode":"rule","dns":{"enable":False,"ipv6":False},
                      "rules":["MATCH,DIRECT"],"proxies":self.proxies,
                      "listeners":[{"name":"old-listener","type":"mixed","listen":"127.0.0.1","port":62000,"proxy":"Hong Kong A"}]}
        self.config.write_text(json.dumps(self.profile))
        self.config.chmod(0o640)
        self.profile_path=directory / "profile.json"
        self.profile_path.write_text(json.dumps(self.profile))
        self.source=directory / "inventory.json"
        self.map_path=directory / "map.json"
        self.pid=directory / "core.pid"
        self.log=directory / "service.log"
        self.service=directory / "service"
        self.service.write_text(f"#!{sys.executable}\n"+SERVICE_SOURCE)
        self.service.chmod(0o755)
        self.yaml=directory / "yaml.cjs"
        self.yaml.write_text("exports.load=JSON.parse; exports.dump=x=>JSON.stringify(x);\n")
        self.fault=directory / "fault.cjs"
        self.fault.write_text(FAULT_SOURCE)
        self.mapping=mapping_case(self.proxies)[3]
        self.env=dict(os.environ, WORK_DIR=str(self.work),CACHE_DIR=str(self.cache),CONFIG_PATH=str(self.config),
            EXPORT_DIR=str(self.export),MIHOMO_BIN=str(self.core),SERVICE_SCRIPT=str(self.service),
            SERVICE_PID_FILE=str(self.pid),TEST_SERVICE_LOG=str(self.log),STABLE_CONVERTER=str(CONVERTER),
            JS_YAML_PATH=str(self.yaml),NODE_BIN=shutil.which("node"),NODE_PATH="",ADVERTISE_HOST="192.0.2.4",
            APPROVED_NAMESPACE=self.mapping["namespace"],APPROVED_SERVER_INSTANCE_ID=self.mapping["server_instance_id"],
            APPROVED_PORT_PLAN_VERSION=self.mapping["port_plan_version"],RUNTIME_PROFILE_PATH=str(self.profile_path),
            READINESS_ATTEMPTS="5",READINESS_DELAY_SECONDS="0.03",LISTENER_CONNECT_TIMEOUT_MS="150",
            LISTENER_CHECK_CONCURRENCY="64",CONFIG_MODE="0640",RANKING_URL="http://127.0.0.1:1/map.json",
            SOURCE_URL="http://127.0.0.1:1/download/collection/inventory?target=ClashMeta&noCache=true")
        self.env.pop("NODE_OPTIONS",None)
        profile_hash=subprocess.run(["node","-e", "const c=require(process.argv[1]); console.log(c.runtimeProfileHash(JSON.parse(process.argv[2])));",
                                     str(CONVERTER),json.dumps(self.profile)],text=True,capture_output=True,check=True).stdout.strip()
        self.env["APPROVED_RUNTIME_PROFILE_HASH"]=profile_hash
        envfile=directory / "env"
        envfile.write_text("# This isolated test passes explicit environment values.\n")
        self.env["NODE_HEALTH_ENV_FILE"]=str(envfile)
        (self.export / "sentinel.txt").write_text("old-export\n")
        self.set_target(self.proxies)
        subprocess.run([str(self.service),"restart"],env=self.env,check=True)
        self.wait_socket(62000)
        self.log.write_text("")

    def wait_socket(self, port):
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.1) as client:
                    client.sendall(bytes([5,2,0,2]))
                    if client.recv(2)==bytes([5,0]):return
            except OSError:pass
            time.sleep(.01)
        raise AssertionError("isolated core listener did not become ready")

    def set_target(self, proxies, mapping=None):
        self.proxies=copy.deepcopy(proxies)
        self.mapping=mapping or mapping_case(proxies)[3]
        self.source.write_text(json.dumps({"proxies":proxies}))
        self.map_path.write_text(json.dumps(self.mapping))

    def run(self, apply=True, **extra):
        environment=dict(self.env,**extra)
        if any(name in extra for name in ("TEST_CRASH_PHASE","TEST_EXPORT_FAILURE")):
            environment["NODE_OPTIONS"]=f"--require={self.fault}"
        args=["sh",str(APPLY),str(self.source),str(self.map_path),self.mapping["mapping_version"]] if apply else ["sh",str(CHECK)]
        return subprocess.run(args,env=environment,capture_output=True,text=True,timeout=15)

    def backoff(self):
        (self.cache / "backoff.json").write_text(json.dumps({"attempts":2,"retry_after":int(time.time()*1000)+3600000}))

    def receipt(self):
        return json.loads((self.cache / "applied.json").read_text())

    def close(self):
        subprocess.run([str(self.service),"stop"],env=self.env,capture_output=True,timeout=5)
