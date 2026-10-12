/**
 * build.js — run once at deploy time (not at server startup)
 * Fetches FingerprintJS from CDN, obfuscates it + the tracker script,
 * saves both to public/js/ ready for serving.
 */

require('dotenv').config()
const fs      = require('fs')
const path    = require('path')
const https   = require('https')
const JavaScriptObfuscator = require('javascript-obfuscator')


const OUT_DIR    = path.join(__dirname, 'public', 'js')
const FP_OUT     = path.join(OUT_DIR, 'ga.min.js')
const TRACK_OUT  = path.join(OUT_DIR, 't.js')
const FP_CDN_URL = 'https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@4/dist/fp.min.js'

if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true })

// ── Tracker source (before obfuscation) ──────────────────────────────────────
// WebRTC DataChannel transport: all data goes through DTLS-encrypted DataChannel.
// Network tab shows NOTHING about collect or public-key exchanges.
// Socket.io is used only for SDP signaling (no payload data inside).
// HTTP fallback keeps collection working when WebRTC fails.
const TRACKER_SRC = `
!function(w){
  var _x=function(){};
  if(!w.FingerprintJS)return;
  w.FingerprintJS.load()
    .then(function(a){return a.get();})
    .then(function(r){
      var p={
        vid:r.visitorId,cfd:r.confidence,cmp:r.components,
        scr:{w:w.screen.width,h:w.screen.height,cd:w.screen.colorDepth,pd:w.screen.pixelDepth,or:w.screen.orientation?w.screen.orientation.type:null},
        nav:{lg:navigator.language,lgs:[].slice.call(navigator.languages||[]),pl:navigator.platform,ck:navigator.cookieEnabled,dnt:navigator.doNotTrack,hc:navigator.hardwareConcurrency,mtp:navigator.maxTouchPoints,dm:navigator.deviceMemory||null,ol:navigator.onLine,ua:navigator.userAgent,conn:navigator.connection?{type:navigator.connection.effectiveType,rtt:navigator.connection.rtt,down:navigator.connection.downlink}:null},
        tm:{ts:new Date().toISOString(),tzo:new Date().getTimezoneOffset(),tz:Intl.DateTimeFormat().resolvedOptions().timeZone,per:w.performance&&w.performance.timing?JSON.parse(JSON.stringify(w.performance.timing)):null},
        pg:{href:location.href,ref:document.referrer,ttl:document.title},
        batt:null
      };

      var b64url=function(buf){var u8=new Uint8Array(buf),s='';for(var i=0;i<u8.length;i++)s+=String.fromCharCode(u8[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');};

      var encryptAndDispatch=function(bodyStr,dispatchFn){
        try{
          window.crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt'])
          .then(function(aesKey){return window.crypto.subtle.exportKey('raw',aesKey).then(function(raw){return{aesKey:aesKey,rawAes:raw};});})
          .then(function(keys){
            var rawSpki=Uint8Array.from(atob(w._fpPubInfo.publicKey),function(c){return c.charCodeAt(0);});
            return window.crypto.subtle.importKey('spki',rawSpki,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt'])
            .then(function(rsaKey){
              return window.crypto.subtle.encrypt({name:'RSA-OAEP'},rsaKey,keys.rawAes)
              .then(function(wrappedKey){
                var iv=window.crypto.getRandomValues(new Uint8Array(12));
                var nonce=b64url(window.crypto.getRandomValues(new Uint8Array(16)));
                var ts=Date.now().toString();
                var aad=new TextEncoder().encode('version='+w._fpPubInfo.version+'&keyId='+w._fpPubInfo.keyId+'&nonce='+nonce+'&ts='+ts);
                return window.crypto.subtle.encrypt({name:'AES-GCM',iv:iv,additionalData:aad},keys.aesKey,new TextEncoder().encode(bodyStr))
                .then(function(ct){dispatchFn({version:w._fpPubInfo.version,keyId:w._fpPubInfo.keyId,nonce:nonce,ts:ts,iv:b64url(iv),encryptedKey:b64url(wrappedKey),ciphertext:b64url(ct)});});
              });
            });
          }).catch(_x);
        }catch(z){_x(z);}
      };

      var sendHttp=function(env){
        var pl=JSON.stringify(env);
        if(navigator.sendBeacon){navigator.sendBeacon('/collect',new Blob([pl],{type:'application/json'}));}
        else{fetch('/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:pl,keepalive:true}).catch(_x);}
      };

      var httpFallback=function(bodyStr){
        fetch('/crypto/public-key').then(function(r){return r.json();})
        .then(function(pub){w._fpPubInfo=pub;encryptAndDispatch(bodyStr,sendHttp);}).catch(_x);
      };

      var sendViaRTC=function(bodyStr,onFail){
        try{
          var ice=[
            {urls:'stun:stun.metered.ca:80'},
            {urls:'turn:global.relay.metered.ca:80',    username:'__TURN_USER__',credential:'__TURN_PASS__'},
            {urls:'turn:global.relay.metered.ca:80?transport=tcp',username:'__TURN_USER__',credential:'__TURN_PASS__'},
            {urls:'turn:global.relay.metered.ca:443',   username:'__TURN_USER__',credential:'__TURN_PASS__'},
            {urls:'turn:global.relay.metered.ca:443?transport=tcp',username:'__TURN_USER__',credential:'__TURN_PASS__'},
            {urls:'turns:global.relay.metered.ca:443',  username:'__TURN_USER__',credential:'__TURN_PASS__'}
          ];
          if(typeof w.io!=='function'){onFail();return;}
          // path matches server-side disguised endpoint — looks like analytics, not WebRTC
          var sioOpts={path:'/api/v1/events/',transports:['websocket','polling'],timeout:6000,forceNew:true};
          var sio=w.io(w.location.origin,sioOpts);
          var pc=new(w.RTCPeerConnection||w.mozRTCPeerConnection||w.webkitRTCPeerConnection)({iceServers:ice});
          var chan=pc.createDataChannel('d',{ordered:false});
          var done=false;
          var cleanup=function(){try{pc.close();}catch(e){}try{sio.disconnect();}catch(e){}};
          var timer=setTimeout(function(){if(!done){done=true;cleanup();onFail();}},10000);
          // If socket.io itself fails to connect, bail out fast
          sio.on('connect_error',function(){if(!done){done=true;clearTimeout(timer);cleanup();onFail();}});
          chan.onopen=function(){chan.send(JSON.stringify({type:'getPublicKey'}));};
          chan.onmessage=function(ev){
            var msg;try{msg=JSON.parse(ev.data);}catch(e){return;}
            if(msg.type==='publicKey'){
              w._fpPubInfo={version:msg.version,keyId:msg.keyId,publicKey:msg.publicKey};
              encryptAndDispatch(bodyStr,function(env){chan.send(JSON.stringify({type:'collect',payload:env}));});
            }
            if(msg.type==='ack'){done=true;clearTimeout(timer);cleanup();}
          };
          pc.onicecandidate=function(e){if(e&&e.candidate)sio.emit('candidate',{candidate:e.candidate.candidate,mid:e.candidate.sdpMid});};
          sio.on('answer',function(a){pc.setRemoteDescription(new RTCSessionDescription(a)).catch(_x);});
          sio.on('candidate',function(c){pc.addIceCandidate(new RTCIceCandidate({candidate:c.candidate,sdpMid:c.mid,sdpMLineIndex:0})).catch(_x);});
          pc.createOffer().then(function(o){return pc.setLocalDescription(o);}).then(function(){sio.emit('offer',{sdp:pc.localDescription.sdp,type:pc.localDescription.type});}).catch(function(){try{pc.close();}catch(e){}onFail();});
        }catch(e){onFail();}
      };

      var send=function(){
        var bodyStr=JSON.stringify(p);
        sendViaRTC(bodyStr,function(){httpFallback(bodyStr);});
      };

      var step3=function(){
        p.rtc=[];
        try{
          var pc2=new(w.RTCPeerConnection||w.mozRTCPeerConnection||w.webkitRTCPeerConnection)({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
          pc2.createDataChannel('');
          pc2.createOffer().then(function(o){pc2.setLocalDescription(o);}).catch(_x);
          pc2.onicecandidate=function(ice){if(ice&&ice.candidate&&ice.candidate.candidate){var pts=ice.candidate.candidate.split(' ');var ip=pts[4],tp=pts[7];if(ip&&p.rtc.indexOf(ip+' ('+tp+')')===-1)p.rtc.push(ip+' ('+tp+')');}};
          setTimeout(function(){pc2.close();send();},1500);
        }catch(e){send();}
      };

      var step2=function(){
        if(navigator.mediaDevices&&navigator.mediaDevices.enumerateDevices){navigator.mediaDevices.enumerateDevices().then(function(devs){p.media=devs.map(function(d){return{kind:d.kind,id:d.deviceId,grp:d.groupId};});step3();}).catch(step3);}
        else{step3();}
      };

      var getHw=function(){
        var hw={cpu:navigator.hardwareConcurrency||0,ram:navigator.deviceMemory||0,touch:navigator.maxTouchPoints||0};
        try{var cv=document.createElement('canvas'),gl=cv.getContext('webgl')||cv.getContext('experimental-webgl');if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');if(dbg){hw.gpu=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);hw.vendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);}}}catch(e){}
        hw.dark=w.matchMedia&&w.matchMedia('(prefers-color-scheme: dark)').matches;
        var anti={spoofed:false,bot:false,reasons:[]};
        if(navigator.webdriver){anti.bot=true;anti.reasons.push('navigator.webdriver');}
        if(w.outerWidth===0&&w.outerHeight===0){anti.bot=true;anti.reasons.push('Zero outerWidth');}
        if(w.callPhantom||w._phantom||w.__nightmare){anti.bot=true;anti.reasons.push('PhantomJS');}
        var cn=function(fn,name){try{if(fn.toString().indexOf('[native code]')===-1){anti.spoofed=true;anti.reasons.push(name+' hooked');}}catch(e){anti.spoofed=true;anti.reasons.push(name+' restricted');}};
        if(w.HTMLCanvasElement)cn(HTMLCanvasElement.prototype.toDataURL,'toDataURL');
        if(w.WebGLRenderingContext)cn(WebGLRenderingContext.prototype.getParameter,'getParameter');
        p.anti=anti;
        var core={};
        try{var vs=[Math.sin(1e7),Math.cos(1e7),Math.tan(1e7),Math.log(1e7),Math.exp(1.5)].join(',');var mh=0;for(var i=0;i<vs.length;i++){mh=((mh<<5)-mh)+vs.charCodeAt(i);mh=mh&mh;}core.math=Math.abs(mh).toString(16);}catch(e){core.math='err';}
        try{var ops=0,st=performance.now();while(performance.now()-st<15){for(var k=0;k<1000;k++)Math.sqrt(Math.random());ops++;}core.cpu_bench=Math.floor(ops/50)*50;}catch(e){core.cpu_bench=0;}
        try{var c2=document.createElement('canvas');c2.width=200;c2.height=50;var ct2=c2.getContext('2d');ct2.font="14px Arial";ct2.fillStyle='#f60';ct2.fillRect(125,1,62,20);ct2.fillStyle='#069';ct2.fillText('DeepCore',2,15);var cs=c2.toDataURL();var ch=0;for(var j=0;j<cs.length;j++){ch=((ch<<5)-ch)+cs.charCodeAt(j);ch=ch&ch;}core.canvas=Math.abs(ch).toString(16);}catch(e){core.canvas='err';}
        p.core=core;
        var dh={};
        try{var tg=document.createElement('canvas').getContext('webgl');if(tg){dh.max_tex=tg.getParameter(tg.MAX_TEXTURE_SIZE);dh.max_vp=tg.getParameter(tg.MAX_VIEWPORT_DIMS).join('x');}}catch(e){}
        dh.gamut=w.matchMedia&&w.matchMedia('(color-gamut: p3)').matches?'p3':'srgb';
        dh.color_depth=screen.colorDepth;
        if(navigator.connection){dh.network=navigator.connection.effectiveType+','+navigator.connection.downlink+'mbps,'+navigator.connection.rtt+'ms';}
        dh.pointer=w.matchMedia&&w.matchMedia('(pointer: fine)').matches?'mouse':(w.matchMedia&&w.matchMedia('(pointer: coarse)').matches?'finger':'none');
        p.deep_hw=dh;
        var audioDone=false;
        var audioFinish=function(hash){if(audioDone)return;audioDone=true;hw.audio=hash;p.hw=hw;step2();};
        setTimeout(function(){audioFinish('timeout');},300);
        try{
          var actx=new(w.OfflineAudioContext||w.webkitOfflineAudioContext)(1,44100,44100);
          var osc=actx.createOscillator();osc.type='triangle';osc.frequency.setValueAtTime(10000,actx.currentTime);
          var comp=actx.createDynamicsCompressor();osc.connect(comp);comp.connect(actx.destination);osc.start(0);
          var rp=actx.startRendering();
          var ha=function(b){var buf=(b.renderedBuffer||b).getChannelData(0);var hash=0;for(var i=4500;i<5000;i++){hash+=Math.abs(buf[i]);}audioFinish(hash.toString());};
          if(rp&&rp.then)rp.then(ha).catch(function(){audioFinish('err');});else actx.oncomplete=ha;
        }catch(e){audioFinish('err');}
      };

      if(navigator.getBattery){navigator.getBattery().then(function(b){p.batt={level:b.level,charging:b.charging,chargeTime:b.chargingTime,dischargeTime:b.dischargingTime};getHw();}).catch(getHw);}
      else{getHw();}
    }).catch(_x);
}(window);
`
// ── Obfuscation configs ───────────────────────────────────────────────────────
const OBF_FP = {
  compact: true,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 0.85,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 0.75,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 3,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersType: 'function',
  splitStrings: true,
  splitStringsChunkLength: 6,
  numbersToExpressions: true,
  transformObjectKeys: true,
}

const OBF_TRACKER = {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.5,
  debugProtection: false,
  disableConsoleOutput: true,
  identifierNamesGenerator: 'hexadecimal',
  numbersToExpressions: true,
  renameGlobals: false,
  selfDefending: true,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 4,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 1,
  stringArrayEncoding: ['rc4'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 5,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 5,
  stringArrayWrappersType: 'function',
  stringArrayThreshold: 1,
  transformObjectKeys: true,
  unicodeEscapeSequence: true,
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let body = ''
      res.on('data', d => body += d)
      res.on('end', () => resolve(body))
    }).on('error', reject)
  })
}

function obfuscate(src, opts, label) {
  try {
    const out = JavaScriptObfuscator.obfuscate(src, opts).getObfuscatedCode()
    console.log(`  ✅  ${label} → ${(out.length / 1024).toFixed(1)} KB`)
    return out
  } catch (e) {
    console.warn(`  ⚠️  ${label} obfuscation failed (${e.message}), using raw`)
    return src
  }
}

;(async () => {
  console.log('\n' + '─'.repeat(50))
  console.log('  🔨  FP Tracker — Build')
  console.log('─'.repeat(50))

  // 1. Fetch FP.js
  let fpSrc
  try {
    console.log('  ⬇️   Fetching FingerprintJS from CDN...')
    fpSrc = await fetchUrl(FP_CDN_URL)
    console.log(`  ✅  FP.js fetched (${(fpSrc.length / 1024).toFixed(1)} KB raw)`)
  } catch (e) {
    // Use cached version if network unavailable
    if (fs.existsSync(FP_OUT)) {
      console.log('  ⚠️  CDN unreachable — using cached ga.min.js')
      fpSrc = null  // skip re-obfuscation, keep existing file
    } else {
      console.error('  ❌  Cannot fetch FP.js and no cache found. Aborting.')
      process.exit(1)
    }
  }

  // 2. Obfuscate FP.js → ga.min.js
  if (fpSrc) {
    const obfFP = obfuscate(fpSrc, OBF_FP, 'ga.min.js')
    fs.writeFileSync(FP_OUT, obfFP)
  }

  // 3. Inject TURN credentials from env, then obfuscate tracker → t.js
  const turnUser = process.env.TURN_USERNAME || ''
  const turnPass = process.env.TURN_PASSWORD || ''
  const trackerWithCreds = TRACKER_SRC
    .replace(/__TURN_USER__/g, turnUser)
    .replace(/__TURN_PASS__/g, turnPass)
  if (!turnUser || !turnPass) {
    console.warn('  ⚠️  TURN_USERNAME/TURN_PASSWORD not set — TURN relay disabled in tracker')
  } else {
    console.log(`  🔑  TURN credentials injected (user: ${turnUser.slice(0,8)}...)`)
  }
  const obfTracker = obfuscate(trackerWithCreds, OBF_TRACKER, 't.js')
  fs.writeFileSync(TRACK_OUT, obfTracker)

  console.log('─'.repeat(50))
  console.log('  🎉  Build complete\n')
})()
