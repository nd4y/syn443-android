"""Ephemeral loopback TLS issuer/API for actual cross-process Android acceptance.

OpenSSL generates all secrets at runtime. No real issuer, user, key or endpoint is used.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from policy_fixture import Publisher, b64

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return b64(hashlib.sha256(value).digest())
def decode(value):return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
def integer(value):
    raw=value.lstrip(b'\0') or b'\0'
    if raw[0]&128:raw=b'\0'+raw
    return bytes([2,len(raw)])+raw

class Fixture:
    def __init__(self,config):
        self.publisher=Publisher();self.root=Path(self.publisher.temp.name)
        self.rsa=self.root/'issuer.pem';self.cert=self.root/'tls.pem';self.tls_key=self.root/'tls-key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(self.rsa)],check=True,capture_output=True)
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
                        '-keyout',str(self.tls_key),'-out',str(self.cert),'-days','1','-subj','/CN=127.0.0.1',
                        '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
        modulus=subprocess.check_output(['openssl','rsa','-in',str(self.rsa),'-noout','-modulus']).decode().strip().split('=',1)[1]
        self.jwk={'kid':'test-issuer','kty':'RSA','use':'sig','alg':'RS256','n':b64(bytes.fromhex(modulus)),'e':'AQAB'}
        self.ca=base64.b64encode(subprocess.check_output(['openssl','x509','-in',str(self.cert),'-outform','DER'])).decode()
        self.server=HTTPServer(('127.0.0.1',0),Handler);self.server.fixture=self
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(self.cert),str(self.tls_key))
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.origin='https://127.0.0.1:'+str(self.server.server_port);self.issuer=self.origin+'/realms/test'
        self.authorization={};self.codes={};self.tokens={};self.sessions={};self.receipts={};self.refresh_receipts={};self.proofs=set()
        self.config=config;self.revision=1;self.policy_status=200;self.envelopes={};self.policy_requests=0;self.registrations=0
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3);self.publisher.close()
    def bootstrap(self):return {'serviceId':'emulator','issuer':self.issuer,'clientId':'test','apiOrigin':self.origin,
        'roots':{'test-root':self.publisher.spki},'tlsCaDer':self.ca}
    def jwt(self,thumb,nonce=None):
        now=int(time.time());claims={'iss':self.issuer,'sub':'synthetic-owner','aud':'test' if nonce else 'syn443-api','azp':'test','iat':now,'exp':now+300}
        if nonce:claims['nonce']=nonce
        else:claims['cnf']={'jkt':thumb}
        raw=b64(canonical({'alg':'RS256','kid':'test-issuer','typ':'JWT'}))+'.'+b64(canonical(claims))
        return raw+'.'+b64(subprocess.check_output(['openssl','dgst','-sha256','-sign',str(self.rsa)],input=raw.encode()))
    def proof(self,method,path,headers,body):
        parts=headers['DPoP'].split('.');assert len(parts)==3 and all(len(v)<8192 for v in parts)
        header=json.loads(decode(parts[0]));claims=json.loads(decode(parts[1]));jwk=header['jwk']
        assert header['alg']=='ES256' and header['typ']=='dpop+jwt'
        assert set(jwk)=={'kty','crv','x','y'} and jwk['kty']=='EC' and jwk['crv']=='P-256'
        x,y=decode(jwk['x']),decode(jwk['y']);signature=decode(parts[2]);assert len(x)==len(y)==32 and len(signature)==64
        public=self.root/'request-public.der';sig=self.root/'request-signature.der'
        public.write_bytes(bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')+x+y)
        pair=integer(signature[:32])+integer(signature[32:]);sig.write_bytes(bytes([48,len(pair)])+pair)
        result=subprocess.run(['openssl','dgst','-sha256','-verify',str(public),'-keyform','DER','-signature',str(sig)],input=(parts[0]+'.'+parts[1]).encode(),capture_output=True)
        assert result.returncode==0 and claims['htm']==method and claims['htu']==self.origin+path
        assert abs(int(time.time())-claims['iat'])<=60 and claims['jti'] not in self.proofs and len(self.proofs)<1024
        self.proofs.add(claims['jti'])
        thumb=digest(canonical(jwk));authorization=headers.get('Authorization')
        if authorization:
            assert authorization.startswith('DPoP ') and claims['ath']==digest(authorization[5:].encode())
            if body is not None:assert claims['req_hash']==digest(body)
            else:assert 'req_hash' not in claims
        return thumb,claims
    def request(self,method,path,headers,body):
        parsed=urlsplit(path);oidc='/realms/test/protocol/openid-connect'
        if method=='GET' and parsed.path.endswith('/.well-known/openid-configuration'):
            return 200,{'issuer':self.issuer,'authorization_endpoint':self.origin+oidc+'/auth',
                'token_endpoint':self.origin+oidc+'/token','jwks_uri':self.origin+oidc+'/certs',
                'id_token_signing_alg_values_supported':['RS256'],'dpop_signing_alg_values_supported':['ES256'],'code_challenge_methods_supported':['S256']},{}
        if method=='GET' and parsed.path==oidc+'/certs':return 200,{'keys':[self.jwk]},{}
        if method=='GET' and parsed.path==oidc+'/auth':
            query={k:v[0] for k,v in parse_qs(parsed.query,strict_parsing=True).items()}
            assert query['client_id']=='test' and query['redirect_uri']=='syn443://oauth/callback' and query['code_challenge_method']=='S256'
            code=secrets.token_urlsafe(32);self.codes[code]=query
            return 302,None,{'Location':'syn443://oauth/callback?'+urlencode({'state':query['state'],'iss':self.issuer,'code':code})}
        thumb,claims=self.proof(method,parsed.path,headers,body)
        if method=='POST' and parsed.path==oidc+'/token':
            form={k:v[0] for k,v in parse_qs(body.decode(),strict_parsing=True).items()};query=self.codes.pop(form['code'])
            assert form['client_id']=='test' and form['redirect_uri']=='syn443://oauth/callback'
            assert digest(form['code_verifier'].encode())==query['code_challenge'] and thumb==query['dpop_jkt']
            token=self.jwt(thumb);self.tokens[token]=thumb
            return 200,{'token_type':'DPoP','expires_in':300,'access_token':token,'id_token':self.jwt(thumb,query['nonce'])},{}
        token=headers['Authorization'][5:]
        if parsed.path=='/v1/devices/enroll':
            assert self.tokens[token]==thumb;value=json.loads(body);assert digest(canonical(value['key']))==thumb
            if body not in self.receipts:
                now=int(time.time()*1000);self.registrations+=1
                session={'deviceId':secrets.token_urlsafe(32),'accessToken':secrets.token_urlsafe(32),'refreshToken':secrets.token_urlsafe(32),
                    'accessUntilMs':now+590000,'refreshUntilMs':now+86000000,'generation':0,'nonce':secrets.token_urlsafe(32)}
                self.sessions[thumb]=session;self.receipts[body]=session.copy()
            return 200,self.receipts[body],{}
        if parsed.path=='/v1/identity/devices/revoke':
            assert self.tokens[token]==thumb
            for key in json.loads(body)['thumbprints']:self.sessions.pop(key,None)
            return 204,None,{}
        session=self.sessions[thumb]
        assert claims['nonce']==session['nonce']
        if parsed.path=='/v1/device/session/refresh':
            assert token==session['refreshToken']
            session.update(accessToken=secrets.token_urlsafe(32),refreshToken=secrets.token_urlsafe(32),
                accessUntilMs=int(time.time()*1000)+590000,generation=session['generation']+1,nonce=secrets.token_urlsafe(32))
            return 200,session,{}
        assert token==session['accessToken']
        if parsed.path=='/v1/device/revoke':self.sessions.pop(thumb);return 204,None,{}
        assert method=='GET' and parsed.path=='/v1/device/policy';self.policy_requests+=1
        if self.policy_requests<=getattr(self,'pending_policy_requests',0):return 202,{'code':'provisioning_pending'},{}
        if self.policy_status!=200:return self.policy_status,{'code':'fixture_unavailable'},{}
        key=(thumb,self.revision)
        if key not in self.envelopes:
            self.publisher.device=session['deviceId'];self.envelopes[key]=self.publisher.sign(self.config,revision=self.revision,key_thumbprint=thumb)
        return 200,self.envelopes[key],{'Content-Type':'application/jose'}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def setup(self):super().setup();self.connection.settimeout(5)
    def do_GET(self):self.respond()
    def do_POST(self):self.respond()
    def respond(self):
        try:
            count=int(self.headers.get('Content-Length','0'));assert 0<=count<=16384
            body=self.rfile.read(count) if self.command=='POST' else None
            status,value,headers=self.server.fixture.request(self.command,self.path,self.headers,body)
        except Exception:status,value,headers=400,{'code':'fixture_request_rejected'},{}
        payload=b'' if value is None else value.encode() if isinstance(value,str) else canonical(value)
        self.send_response(status);self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(payload)))
        for key,value in headers.items():self.send_header(key,value)
        if 'Content-Type' not in headers:self.send_header('Content-Type','application/json')
        self.end_headers();self.wfile.write(payload)
