import base64
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import build_opener, HTTPSHandler, ProxyHandler
from enrollment_fixture import Fixture, canonical, decode, digest
from policy_fixture import Publisher, b64

class EnrollmentFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=Fixture({'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct'}})
        cls.client=Publisher();point=base64.b64decode(cls.client.spki)[-64:]
        cls.jwk={'kty':'EC','crv':'P-256','x':b64(point[:32]),'y':b64(point[32:])};cls.thumb=digest(canonical(cls.jwk))
    @classmethod
    def tearDownClass(cls):cls.fixture.close();cls.client.close()
    def proof(self,method,path,body=None,token=None,nonce=None):
        claims={'htm':method,'htu':self.fixture.origin+path,'iat':int(time.time()),'jti':secrets.token_urlsafe(24)}
        if token:
            claims['ath']=digest(token.encode())
            if body is not None:claims['req_hash']=digest(body)
        if nonce:claims['nonce']=nonce
        content=b64(canonical({'alg':'ES256','typ':'dpop+jwt','jwk':self.jwk}))+'.'+b64(canonical(claims))
        der=subprocess.check_output(['openssl','dgst','-sha256','-sign',str(self.client.key)],input=content.encode())
        size=der[3];r=int.from_bytes(der[4:4+size],'big');tail=4+size;s=int.from_bytes(der[tail+2:],'big')
        headers={'DPoP':content+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))}
        if token:headers['Authorization']='DPoP '+token
        return headers
    def test_loopback_tls_discovery_uses_the_generated_ca(self):
        f=self.fixture;context=ssl.create_default_context(cafile=str(f.cert))
        opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context))
        with opener.open(f.issuer+'/.well-known/openid-configuration',timeout=5) as response:
            value=json.loads(response.read(16384));self.assertTrue(response.status==200 and value['issuer']==f.issuer)
        with self.assertRaises(Exception):
            build_opener(ProxyHandler({}),HTTPSHandler()).open(f.issuer+'/.well-known/openid-configuration',timeout=5)
    def test_proof_signature_method_and_replay_are_enforced(self):
        f=self.fixture;headers=self.proof('GET','/v1/device/policy')
        with self.assertRaises(AssertionError):f.proof('POST','/v1/device/policy',headers,None)
        self.assertTrue(f.proof('GET','/v1/device/policy',headers,None)[0]==self.thumb)
        with self.assertRaises(AssertionError):f.proof('GET','/v1/device/policy',headers,None)
        other=self.proof('GET','/v1/device/policy');parts=other['DPoP'].split('.')
        other['DPoP']=parts[0]+'.'+parts[1]+'.'+b64(b'\0'*64)
        with self.assertRaises(AssertionError):f.proof('GET','/v1/device/policy',other,None)
    def test_pkce_enrollment_policy_key_binding_and_revocation(self):
        f=self.fixture;verifier=secrets.token_urlsafe(32)
        query={'client_id':'test','redirect_uri':'syn443://oauth/callback','code_challenge_method':'S256',
               'code_challenge':digest(verifier.encode()),'dpop_jkt':self.thumb,'state':secrets.token_urlsafe(32),'nonce':secrets.token_urlsafe(32)}
        status,_,headers=f.request('GET','/realms/test/protocol/openid-connect/auth?'+urlencode(query),{},None)
        self.assertTrue(status==302);code=parse_qs(urlsplit(headers['Location']).query)['code'][0]
        form=urlencode({'client_id':'test','redirect_uri':'syn443://oauth/callback','code_verifier':verifier,'code':code}).encode()
        path='/realms/test/protocol/openid-connect/token'
        status,tokens,_=f.request('POST',path,self.proof('POST',path,form),form);self.assertTrue(status==200)
        with self.assertRaises(KeyError):f.request('POST',path,self.proof('POST',path,form),form)
        path='/v1/devices/enroll';body=canonical({'key':self.jwk,'requestId':secrets.token_urlsafe(32)})
        status,session,_=f.request('POST',path,self.proof('POST',path,body,tokens['access_token']),body)
        self.assertTrue(status==200 and session['generation']==0)
        path='/v1/device/policy';status,envelope,headers=f.request('GET',path,self.proof('GET',path,token=session['accessToken'],nonce=session['nonce']),None)
        value=json.loads(decode(envelope.split('.')[1]))
        self.assertTrue(status==200 and value['schemaVersion']==2 and value['keyThumbprint']==self.thumb and value['targetDevice']==session['deviceId'])
        path='/v1/device/revoke';body=canonical({'requestId':secrets.token_urlsafe(32)})
        status,_,_=f.request('POST',path,self.proof('POST',path,body,session['accessToken'],session['nonce']),body)
        self.assertTrue(status==204 and self.thumb not in f.sessions)

if __name__=='__main__':unittest.main()
