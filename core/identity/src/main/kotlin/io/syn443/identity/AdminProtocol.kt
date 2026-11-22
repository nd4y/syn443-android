package io.syn443.identity

import io.syn443.identity.AdminIdentity.Companion.integer
import io.syn443.identity.AdminIdentity.Companion.text
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*

/** Synchronous administrative OAuth worker. Android persistence/UI and API actions are separate layers. */
class AdminProtocol internal constructor(private val identity:AdminIdentity,private val key:ProofKey,private val exchange:IdentityExchange,
    private val boot:()->Int,private val elapsed:()->Long,private val admission:AdminDiscoveryGuard?=null) {
    val authority:String get()=identity.authority
    val thumbprint:String=Identity.thumbprint(key.publicKey)
    private val oidc=identity.metadata.issuer+"/protocol/openid-connect"
    private data class Started(val boot:Int,val elapsed:Long)
    private fun start()=Started(boot(),elapsed()).also {require(it.boot>=0 && it.elapsed>=0)}
    private fun observed(reply:Reply,started:Started,floor:TrustedTime?=null):TrustedTime {
        val ended=elapsed();require(boot()==started.boot)
        return TrustedTime.observe(requireNotNull(reply.single("date")),started.boot,started.elapsed,ended,floor)
    }
    private fun request(scope:IdentityScope,method:String,url:String,body:ByteArray?=null,
        proof:String?=null,anonymous:Boolean=false,beforeDispatch:()->Unit={}):Reply=scope.request {
        val headers=linkedMapOf("Cache-Control" to "no-store")
        if(body!=null)headers["Content-Type"]="application/x-www-form-urlencoded"
        if(proof!=null)headers["DPoP"]=proof
        admission?.check(requireDiscovered=!anonymous,anonymous=anonymous)
        beforeDispatch()
        exchange.request(method,url,headers.toMap(),body?.copyOf(),it,65_536).also {
            admission?.check(requireDiscovered=!anonymous,anonymous=anonymous)
        }
    }
    private fun json(reply:Reply):JsonObject {
        require(reply.body.size in 1..65_536 &&
            reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
        return Identity.objectJSON(Policy.utf8(reply.body))
    }
    private fun status(reply:Reply) {
        if(reply.status!=200)throw AdminException(when(reply.status) {
            400,401->AdminFailure.REAUTHENTICATE
            403->forbidden(reply)
            else->AdminFailure.INVALID_REPLY
        })
    }
    private fun catalogCode(reply:Reply):String? = runCatching {
            require(reply.body.size in 1..128 &&
                reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
            val challenge=Identity.objectJSON(Policy.utf8(reply.body))
            require(challenge.keys==setOf("code"))
            challenge.getValue("code").text().also { require(it.matches(Regex("[a-z_]{1,64}"))) }
        }.getOrNull()
    /** This finite catalog denial is not a nonce challenge or permission grant. */
    private fun forbidden(reply:Reply):AdminFailure =
        if(catalogCode(reply)=="catalog_reauthentication_required")AdminFailure.REAUTHENTICATE else AdminFailure.ACCESS_DENIED
    private inline fun <T> checked(block:()->T):T=try {block()}
        catch(e:AdminException){throw e}
        catch(e:DeliveryException){throw AdminException(if(e.reason==DeliveryFailure.CANCELLED)AdminFailure.CANCELLED else AdminFailure.TRANSPORT)}
        catch(_:Exception){throw AdminException(AdminFailure.INVALID_REPLY)}

    fun newPending(generation:Long):AdminPending=checked {
        admission?.check()
        identity.pending(generation,thumbprint,boot(),elapsed())
    }
    fun authorization(pending:AdminPending,generation:Long):String=checked {
        admission?.check(requireDiscovered=true)
        identity.authorization(pending,generation,thumbprint,boot(),elapsed()).also {admission?.check(requireDiscovered=true)}
    }
    /** Discovery is anchored only to the signed administrative issuer. No browser/device-origin fallback. */
    fun discover(scope:IdentityScope,floor:TrustedTime?=null):AdminIssuerState=checked {
        floor?.window(boot(),elapsed())
        admission?.check(anonymous=true)
        val prior=admission?.priorTime()
        val effectiveFloor=if(prior==null)floor else if(floor==null)prior else this.floor(floor,prior)
        val started=start()
        val reply=request(scope,"GET",identity.metadata.issuer+"/.well-known/openid-configuration",anonymous=true)
        status(reply);val data=json(reply)
        require(data.getValue("issuer").text()==identity.metadata.issuer &&
            data.getValue("authorization_endpoint").text()==oidc+"/auth" &&
            data.getValue("token_endpoint").text()==oidc+"/token" && data.getValue("jwks_uri").text()==oidc+"/certs")
        fun supports(name:String,value:String) {
            val values=data.getValue(name).jsonArray.map {it.text()}
            require(values.size in 1..32 && values.distinct().size==values.size && value in values)
        }
        supports("id_token_signing_alg_values_supported","RS256")
        supports("dpop_signing_alg_values_supported","ES256")
        supports("code_challenge_methods_supported","S256")
        val initial=observed(reply,started,effectiveFloor)
        val keysStarted=start()
        val jwks=request(scope,"GET",oidc+"/certs",anonymous=true)
        status(jwks);json(jwks)
        val state=scope.request {
            val keys=Identity.rsaKeys(Policy.utf8(jwks.body))
            val time=observed(jwks,keysStarted,initial)
            admission?.check(time=time,anonymous=true)
            AdminIssuerState(keys,time,authority,thumbprint)
        }
        val accepted=admission?.record(state.time)
        if(accepted==null)state else AdminIssuerState(state.keys,accepted,authority,thumbprint)
    }
    private fun validateIssuer(issuer:AdminIssuerState) {
        admission?.check(time=issuer.time,requireDiscovered=true)
        require(issuer.authority==authority && issuer.keyThumbprint==thumbprint)
        issuer.time.window(boot(),elapsed())
    }
    private data class Delivered(val data:JsonObject,val time:TrustedTime) {
        override fun toString()="AdminDelivered([redacted])"
    }
    private fun token(body:ByteArray,initialFloor:TrustedTime,scope:IdentityScope,
        guard:()->Unit={},beforeFirstDispatch:()->Unit={}):Delivered {
        require(body.size in 1..8192)
        var nonce="";var floor=initialFloor
        for(attempt in 0..1) {
            val started=start()
            require(Identity.thumbprint(key.publicKey)==thumbprint)
            val proof=Identity.proof(key.publicKey,key::sign,"POST",oidc+"/token",
                floor.proofSecond(started.boot,started.elapsed),nonce=nonce)
            val reply=request(scope,"POST",oidc+"/token",body,proof) {
                val now=elapsed()
                require(boot()==started.boot && now>=started.elapsed && now-started.elapsed<=20_000 &&
                    Identity.thumbprint(key.publicKey)==thumbprint)
                floor.window(started.boot,now)
                guard()
                if(attempt==0)beforeFirstDispatch()
            }
            if(reply.status in setOf(400,401) && attempt==0 && json(reply)["error"]?.text()=="use_dpop_nonce") {
                nonce=requireNotNull(reply.single("dpop-nonce")).also {
                    require(it.length in 1..256 && it.all {c->c.code in 33..126})
                }
                floor=observed(reply,started,floor)
                continue
            }
            status(reply)
            // A successful response is never retried, even if its body, Date or token is invalid.
            return Delivered(json(reply),observed(reply,started,floor))
        }
        throw AdminException(AdminFailure.REAUTHENTICATE)
    }
    fun exchangeCallback(raw:String,pending:AdminPending,generation:Long,issuer:AdminIssuerState,scope:IdentityScope):AdminSession=checked {
        validateIssuer(issuer)
        val code=identity.callback(raw,pending,generation,thumbprint,boot(),elapsed())
        val body=Identity.form(linkedMapOf("grant_type" to "authorization_code","client_id" to AdminBootstrap.CLIENT_ID,
            "redirect_uri" to AdminBootstrap.CALLBACK,"code_verifier" to pending.verifier,"code" to code)).toByteArray(Charsets.UTF_8)
        val result=token(body,issuer.time,scope,guard={
            identity.binding(pending,generation,thumbprint,boot(),elapsed())
            require(pending.consumed.get())
        })
        scope.request {session(result,issuer,pending.nonce,null).also {admission?.check(time=result.time,requireDiscovered=true)}}
    }
    private fun validateSession(session:AdminSession,unused:Boolean=true,admit:Boolean=true) {
        if(admit)admission?.check(time=session.time,requireDiscovered=true)
        require(session.authority==authority && session.keyThumbprint==thumbprint && session.bootCount==boot())
        session.time.window(boot(),elapsed())
        if(session.family.isClosed() || unused && !session.available())throw AdminException(AdminFailure.REAUTHENTICATE)
        if(elapsed()>=session.sessionUntilElapsedMs)throw AdminException(AdminFailure.SESSION_EXPIRED)
    }
    private fun floor(first:TrustedTime,second:TrustedTime):TrustedTime {
        val now=elapsed();val currentBoot=boot()
        val a=first.window(currentBoot,now);val b=second.window(currentBoot,now)
        require(a.lowerMs<=Math.addExact(b.upperMs,30_000) && b.lowerMs<=Math.addExact(a.upperMs,30_000))
        return TrustedTime(currentBoot,now,maxOf(a.lowerMs,b.lowerMs),maxOf(a.upperMs,b.upperMs))
    }
    /** Only a nonce challenge can repeat the same refresh inside one operation. Uncertain dispatch retires it. */
    fun refresh(previous:AdminSession,issuer:AdminIssuerState,scope:IdentityScope):AdminSession {
        var dispatched=false
        try {
            return checked {
                validateSession(previous);validateIssuer(issuer)
                val trusted=floor(previous.time,issuer.time)
                val body=refreshBody(previous.refreshToken)
                val result=token(body,trusted,scope,guard={validateSession(previous,false);validateIssuer(issuer)}) {
                    if(!previous.consume())throw AdminException(AdminFailure.REAUTHENTICATE)
                    dispatched=true
                }
                scope.request {session(result,issuer,previous.originalNonce,previous).also {
                    admission?.check(time=result.time,requireDiscovered=true)
                }}
            }
        } catch(e:AdminException) {
            // The transport cannot prove whether a dispatched rotating refresh was committed.
            // A new operation must never replay it; cancellation before dispatch remains cancellation.
            if(dispatched)throw AdminException(AdminFailure.REAUTHENTICATE)
            throw e
        }
    }
    private fun session(delivered:Delivered,issuer:AdminIssuerState,nonce:String,previous:AdminSession?):AdminSession {
        if(previous?.family?.isClosed()==true)throw AdminException(AdminFailure.REAUTHENTICATE)
        val data=delivered.data;require(data.getValue("token_type").text()=="DPoP")
        val access=data.getValue("access_token").text();val refresh=data.getValue("refresh_token").text()
        require(access.length in 24..16_384 && refresh.length in 24..16_384 && access!=refresh &&
            access.all {it.code in 33..126} && refresh.all {it.code in 33..126})
        require(refreshBody(refresh).size<=8192)
        require(previous==null || access!=previous.accessToken && refresh!=previous.refreshToken)
        val expires=data.getValue("expires_in").integer();val refreshExpires=data.getValue("refresh_expires_in").integer()
        require(expires in 1..600 && refreshExpires in 1..86_400)
        val id=data["id_token"]?.text()
        val now=elapsed();val currentBoot=boot();val window=delivered.time.window(currentBoot,now)
        val principal=identity.tokens(id,access,issuer.keys,thumbprint,nonce,window,previous==null,previous?.subject)
        val expiry=Math.multiplyExact(principal.accessExpiresSeconds,1000)
        // expires_in and signed exp must describe the same expiry within HTTPS Date precision/RTT.
        require(expiry>=Math.addExact(delivered.time.lowerMs,(expires-1)*1000) &&
            expiry<=Math.addExact(delivered.time.upperMs,(expires+1)*1000))
        data["scope"]?.let {
            val scopes=AdminIdentity.scope(it.text())
            val accessClaims=Identity.objectJSON(Policy.utf8(Policy.decode64(access.split('.')[1])))
            require(scopes==AdminIdentity.scope(accessClaims.getValue("scope").text()))
        }
        val accessDeadline=Math.addExact(now,expiry-window.upperMs)
        val serverRefreshDeadline=Math.addExact(delivered.time.elapsedMs,
            Math.addExact(delivered.time.lowerMs,refreshExpires*1000)-delivered.time.upperMs)
        val deadline=minOf(serverRefreshDeadline,previous?.sessionUntilElapsedMs ?:
            Math.addExact(delivered.time.elapsedMs,28_800_000-(delivered.time.upperMs-delivered.time.lowerMs)))
        require(accessDeadline>now && deadline>now)
        return AdminSession(access,refresh,principal.subject,thumbprint,authority,currentBoot,
            minOf(accessDeadline,deadline),deadline,delivered.time,nonce,previous?.family?:AdminSessionFamily()).also {
            if(!it.available())throw AdminException(AdminFailure.REAUTHENTICATE)
        }
    }
    private fun refreshBody(refresh:String)=Identity.form(linkedMapOf("grant_type" to "refresh_token",
        "client_id" to AdminBootstrap.CLIENT_ID,"refresh_token" to refresh)).toByteArray(Charsets.UTF_8)
    private fun controlAccess(session:AdminSession,time:TrustedTime?=null,admit:Boolean=true) {
        if(admission==null)throw AdminException(AdminFailure.REAUTHENTICATE)
        validateSession(session,admit=admit)
        require(Identity.thumbprint(key.publicKey)==thumbprint)
        if(elapsed()>=session.accessUntilElapsedMs)throw AdminException(AdminFailure.REAUTHENTICATE)
        val expiry=Math.addExact(session.time.upperMs,session.accessUntilElapsedMs-session.time.elapsedMs)
        admission.priorTime()?.let {
            if(it.window(boot(),elapsed()).upperMs>=expiry)throw AdminException(AdminFailure.REAUTHENTICATE)
        }
        time?.let {
            if(admit)admission.check(time=it,requireDiscovered=true)
            // A newly observed server clock can reject an access token; it can never extend its lease.
            if(it.window(boot(),elapsed()).upperMs>=expiry)throw AdminException(AdminFailure.REAUTHENTICATE)
        }
    }
    private fun <T> controlRead(read:AdminControl.Read,target:String,current:AdminSession,scope:IdentityScope,prefix:String="",
        parse:(JsonObject,TimeWindow,String)->T):T=checked {
        controlAccess(current)
        val guard=checkNotNull(admission)
        val body=AdminControl.request(read,target,prefix)
        val prior=guard.priorTime()
        val trusted=if(prior==null)current.time else floor(current.time,prior)
        val started=start();val url=identity.metadata.apiOrigin+AdminControl.PATH
        val proof=scope.request {
            controlAccess(current)
            Identity.proof(key.publicKey,key::sign,"POST",url,trusted.proofSecond(started.boot,started.elapsed),
                token=current.accessToken,body=body)
        }
        val reply=scope.request {
            val now=elapsed()
            require(boot()==started.boot && now>=started.elapsed && now-started.elapsed<=20_000)
            controlAccess(current)
            exchange.request("POST",url,mapOf("Content-Type" to "application/json","Cache-Control" to "no-store",
                "Authorization" to "DPoP ${current.accessToken}","DPoP" to proof),body.copyOf(),it,read.maxReply).also {
                controlAccess(current)
            }
        }
        if(reply.status!=200)throw AdminException(when(reply.status) {
            401->AdminFailure.REAUTHENTICATE
            403->forbidden(reply)
            in 500..599->AdminFailure.TRANSPORT
            else->AdminFailure.INVALID_REPLY
        })
        val time=observed(reply,started,trusted)
        val result=scope.request {
            require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
            require(reply.body.size in 1..read.maxReply)
            val wire=Policy.utf8(reply.body)
            val document=AdminControl.objectReply(wire,read)
            controlAccess(current,time)
            parse(document,time.window(boot(),elapsed()),wire).also {controlAccess(current,time)}
        }
        val accepted=guard.record(time)
        controlAccess(current,accepted,admit=false)
        result
    }
    fun listDevices(after:String,session:AdminSession,scope:IdentityScope,prefix:String=""):AdminDevicePage =
        controlRead(AdminControl.Read.DEVICES,after,session,scope,prefix) {document,time,wire->
            AdminControl.devices(document,after,time,wire,prefix)
        }
    fun deviceConfiguration(id:String,session:AdminSession,scope:IdentityScope):AdminDeviceConfiguration =
        controlRead(AdminControl.Read.CONFIGURATION,id,session,scope) {document,time,wire->AdminControl.configuration(document,id,time,wire)}
    fun deviceRuntime(id:String,session:AdminSession,scope:IdentityScope):AdminDeviceRuntime =
        controlRead(AdminControl.Read.RUNTIME,id,session,scope) {document,time,wire->AdminControl.runtime(document,id,time,wire)}
    /** Stable actor binding for private drafts. This value is not a role or MFA grant. */
    fun layerActor(current:AdminSession):String=checked {
        controlAccess(current)
        Identity.hash((identity.metadata.issuer+"\u0000"+current.subject).toByteArray(Charsets.UTF_8))
    }
    /** Offline editing may outlive the short access token, never the original
     * session, current signed discovery, BOOT or verified account. Value only. */
    fun layerOwnership(current:AdminSession):AdminLayerOwnership=checked {
        require(admission!=null)
        validateSession(current)
        val prior=admission.priorTime()
        val trusted=if(prior==null)current.time else floor(current.time,prior)
        val now=elapsed()
        val window=trusted.window(boot(),now)
        validateSession(current)
        AdminLayerOwnership(identity.editorServiceHash,
            Identity.hash((identity.metadata.issuer+"\u0000"+current.subject).toByteArray(Charsets.UTF_8)),
            identity.metadata.apiOrigin,window,boot(),now,current.sessionUntilElapsedMs,identity.serviceBinding)
    }
    /** Compute once on the controller worker after a checked response. UI clocks
     * cannot renew the review ticket by reopening a dialog or receiving it late. */
    fun layerReviewDeadline(preview:AdminLayerPreview,current:AdminSession):Long=checked {
        val owned=layerOwnership(current)
        require(!preview.replayOnly && preview.context.actor==owned.actor && preview.context.origin==owned.apiOrigin)
        val reviewUntil=minOf(preview.expiresAtMs,Math.addExact(preview.issuedAtMs,90_000))
        val remaining=reviewUntil-owned.time.upperMs
        require(remaining in 1..90_000)
        minOf(Math.addExact(owned.observedElapsedMs,remaining),owned.sessionUntilElapsedMs)
    }
    /** Exactly one explicit layer operation. Caller journals mutation bytes before
     * invoking this method and owns reconciliation of an uncertain response. */
    fun layerAction(action:AdminLayerRequest,current:AdminSession,scope:IdentityScope):AdminLayerReply=checked {
        controlAccess(current)
        val expected=action.expected
        require(expected.actor.isEmpty() || expected.actor==layerActor(current))
        require(expected.origin.isEmpty() || expected.origin==identity.metadata.apiOrigin)
        val guard=checkNotNull(admission)
        val body=action.bodyBytes()
        try {
            require(body.size in 1..262_144)
            val prior=guard.priorTime()
            val trusted=if(prior==null)current.time else floor(current.time,prior)
            val started=start();val url=identity.metadata.apiOrigin+AdminControl.PATH
            val proof=scope.request {
                controlAccess(current)
                Identity.proof(key.publicKey,key::sign,"POST",url,trusted.proofSecond(started.boot,started.elapsed),
                    token=current.accessToken,body=body,maxBody=262_144)
            }
            val reply=scope.request {
                val now=elapsed()
                require(boot()==started.boot && now>=started.elapsed && now-started.elapsed<=20_000)
                controlAccess(current)
                exchange.request("POST",url,mapOf("Content-Type" to "application/json","Cache-Control" to "no-store",
                    "Authorization" to "DPoP ${current.accessToken}","DPoP" to proof),body.copyOf(),it,action.maxReplyBytes)
                    .also {controlAccess(current)}
            }
            if(reply.status!=200) {
                val code=catalogCode(reply)
                throw AdminException(when {
                    reply.status==401->AdminFailure.REAUTHENTICATE
                    reply.status==403->forbidden(reply)
                    reply.status==409 && code=="catalog_revision_conflict"->AdminFailure.CONFLICT
                    reply.status==400 && code=="catalog_invalid"->AdminFailure.INVALID_CONFIGURATION
                    reply.status==429 && code=="catalog_quota"->AdminFailure.LIMITED
                    reply.status in 500..599->AdminFailure.TRANSPORT
                    else->AdminFailure.INVALID_REPLY
                })
            }
            val time=observed(reply,started,trusted)
            val result=scope.request {
                require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
                require(reply.body.size in 1..action.maxReplyBytes)
                controlAccess(current,time)
                AdminLayerControl.parseReply(action,Policy.utf8(reply.body),time.window(boot(),elapsed()))
                    .also {controlAccess(current,time)}
            }
            val accepted=guard.record(time)
            controlAccess(current,accepted,admit=false)
            result
        }finally {body.fill(0)}
    }
    /** Read-only eligibility for a NEW mutation only. No cached feature grant,
     * session/MFA renewal or reinterpretation of a retained operation. */
    fun configurationRequestVersion(current:AdminSession,scope:IdentityScope):Int=checked {
        controlAccess(current)
        val guard=checkNotNull(admission)
        val body=Canonical.encode(buildJsonObject {
            put("version",1);put("action","configuration.protocol.get")
            put("requestId",Identity.random());put("payload",buildJsonObject {})
        }).toByteArray(Charsets.UTF_8)
        try {
            require(body.size in 1..8192)
            val prior=guard.priorTime()
            val trusted=if(prior==null)current.time else floor(current.time,prior)
            val started=start();val url=identity.metadata.apiOrigin+AdminControl.PATH
            val proof=scope.request {
                controlAccess(current)
                Identity.proof(key.publicKey,key::sign,"POST",url,trusted.proofSecond(started.boot,started.elapsed),
                    token=current.accessToken,body=body)
            }
            val reply=scope.request {
                val now=elapsed()
                require(boot()==started.boot && now>=started.elapsed && now-started.elapsed<=20_000)
                controlAccess(current)
                exchange.request("POST",url,mapOf("Content-Type" to "application/json","Cache-Control" to "no-store",
                    "Authorization" to "DPoP ${current.accessToken}","DPoP" to proof),body.copyOf(),it,4096)
                    .also {controlAccess(current)}
            }
            require(reply.body.size<=4096 && reply.headers.keys.none {it.equals("dpop-nonce",true)})
            if(reply.status==404 || reply.status==405 || reply.status==400 && catalogCode(reply)=="catalog_invalid") {
                // An unsupported read provides no trusted clock or new authority.
                return@checked scope.request {controlAccess(current);1}
            }
            if(reply.status!=200) {
                val code=catalogCode(reply)
                throw AdminException(when {
                    reply.status==401->AdminFailure.REAUTHENTICATE
                    reply.status==403->forbidden(reply)
                    reply.status==409 && code=="catalog_revision_conflict"->AdminFailure.CONFLICT
                    reply.status==429 && code=="catalog_quota"->AdminFailure.LIMITED
                    reply.status in 500..599->AdminFailure.TRANSPORT
                    else->AdminFailure.INVALID_REPLY
                })
            }
            val time=observed(reply,started,trusted)
            val version=scope.request {
                require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json" && reply.body.isNotEmpty())
                controlAccess(current,time)
                val value=Identity.objectJSON(Policy.utf8(reply.body))
                require(value.keys==setOf("version","configurationRequestVersion"))
                val schema=value.getValue("version").jsonPrimitive
                val selected=value.getValue("configurationRequestVersion").jsonPrimitive
                require(!schema.isString && schema.content=="1" && !selected.isString && selected.content in setOf("1","2"))
                selected.content.toInt().also {controlAccess(current,time)}
            }
            val accepted=guard.record(time)
            controlAccess(current,accepted,admit=false)
            version
        }finally {body.fill(0)}
    }
    /** An explicit lookup/seal of exact retained bytes. The result is a value
     * receipt, never a fresh preview, publication or device activation grant. */
    fun operationReconcile(action:AdminOperationRequest,current:AdminSession,scope:IdentityScope):AdminOperationReceipt=checked {
        controlAccess(current)
        require(action.actor==layerActor(current) && action.origin==identity.metadata.apiOrigin)
        val url=identity.metadata.apiOrigin+"/v1/control/configuration/reconcile"
        require(action.uri==url && action.maxReplyBytes==1_048_576)
        val guard=checkNotNull(admission);val body=action.bodyBytes()
        try {
            // Canonical four-field framing of a full256KiB original remains
            // below350000 bytes, so existing proof admission needs no widening.
            require(body.size in 1..360_448)
            val prior=guard.priorTime()
            val trusted=if(prior==null)current.time else floor(current.time,prior)
            val started=start()
            val proof=scope.request {
                controlAccess(current)
                Identity.proof(key.publicKey,key::sign,"POST",url,trusted.proofSecond(started.boot,started.elapsed),
                    token=current.accessToken,body=body,maxBody=360_448)
            }
            val reply=scope.request {
                val now=elapsed()
                require(boot()==started.boot && now>=started.elapsed && now-started.elapsed<=20_000)
                controlAccess(current)
                exchange.request("POST",url,mapOf("Content-Type" to "application/json","Cache-Control" to "no-store",
                    "Authorization" to "DPoP ${current.accessToken}","DPoP" to proof),body.copyOf(),it,action.maxReplyBytes)
                    .also {controlAccess(current)}
            }
            if(reply.status!=200) {
                val code=catalogCode(reply)
                throw AdminException(when {
                    reply.status==401->AdminFailure.REAUTHENTICATE
                    reply.status==403->forbidden(reply)
                    reply.status==409 && code=="catalog_revision_conflict"->AdminFailure.CONFLICT
                    reply.status==400 && code=="catalog_invalid"->AdminFailure.INVALID_CONFIGURATION
                    reply.status==429 && code=="catalog_quota"->AdminFailure.LIMITED
                    reply.status in setOf(404,405) || reply.status in 500..599->AdminFailure.TRANSPORT
                    else->AdminFailure.INVALID_REPLY
                })
            }
            val time=observed(reply,started,trusted)
            val result=scope.request {
                require(reply.single("content-type")?.substringBefore(';')?.trim()?.lowercase()=="application/json")
                require(reply.body.size in 1..action.maxReplyBytes)
                controlAccess(current,time)
                AdminOperationReconcile.parseReply(action,Policy.utf8(reply.body),time.window(boot(),elapsed()))
                    .also {controlAccess(current,time)}
            }
            val accepted=guard.record(time)
            controlAccess(current,accepted,admit=false)
            result
        }finally {body.fill(0)}
    }
    /** No transport call and no device identity mutation, including after BOOT or expiry. */
    fun logout(session:AdminSession):AdminLogout=checked {
        require(session.authority==authority && session.keyThumbprint==thumbprint)
        session.retire();AdminLogout(authority,thumbprint)
    }
    companion object {
        /** Source must return one atomically verified current trust snapshot, on a background worker. */
        fun fromDiscovery(source:()->AdminDiscovery?,key:ProofKey,exchange:IdentityExchange,
            boot:()->Int,elapsed:()->Long):AdminProtocol {
            val initial=try {source()} catch(_:Exception) {null}
                ?:throw AdminException(AdminFailure.REAUTHENTICATE)
            return AdminProtocol(initial.identity(),key,exchange,boot,elapsed,AdminDiscoveryGuard(initial,source,boot,elapsed))
        }
    }
}
