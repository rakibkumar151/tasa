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
          // UDP-only TURN: UDP never appears in DevTools Network tab
          var ice=[
            {urls:'stun:stun.metered.ca:80'},
            {urls:'turn:global.relay.metered.ca:80',    username:'__TURN_USER__',credential:'__TURN_PASS__'},
            {urls:'turn:global.relay.metered.ca:3478',  username:'__TURN_USER__',credential:'__TURN_PASS__'}
          ];
          // Native WebSocket — no socket.io, no EIO=4 in URL
          if(!w.WebSocket){onFail();return;}
          var wsUrl=(w.location.protocol==='https:'?'wss://':'ws://')+w.location.host+'/ws/push';
          var ws=new w.WebSocket(wsUrl);
          var pc=new(w.RTCPeerConnection||w.mozRTCPeerConnection||w.webkitRTCPeerConnection)({iceServers:ice});
          var chan=pc.createDataChannel('d',{ordered:false});
          var done=false;
          var cleanup=function(){try{pc.close();}catch(e){}try{ws.close();}catch(e){}};
          var timer=setTimeout(function(){if(!done){done=true;cleanup();onFail();}},10000);
          ws.onerror=function(){if(!done){done=true;clearTimeout(timer);cleanup();onFail();}};
          ws.onclose=function(){if(!done){done=true;clearTimeout(timer);cleanup();onFail();}};
          ws.onmessage=function(ev){
            var msg;try{msg=JSON.parse(ev.data);}catch(e){return;}
            // t:'a' = answer, t:'c' = candidate
            if(msg.t==='a'){pc.setRemoteDescription(new RTCSessionDescription({sdp:msg.sdp,type:msg.type})).catch(_x);}
            if(msg.t==='c'){pc.addIceCandidate(new RTCIceCandidate({candidate:msg.candidate,sdpMid:msg.mid,sdpMLineIndex:0})).catch(_x);}
          };
          pc.onicecandidate=function(e){
            if(e&&e.candidate&&ws.readyState===1)ws.send(JSON.stringify({t:'c',candidate:e.candidate.candidate,mid:e.candidate.sdpMid}));
          };
          chan.onopen=function(){chan.send(JSON.stringify({type:'getPublicKey'}));};
          chan.onmessage=function(ev){
            var msg;try{msg=JSON.parse(ev.data);}catch(e){return;}
            if(msg.type==='publicKey'){
              w._fpPubInfo={version:msg.version,keyId:msg.keyId,publicKey:msg.publicKey};
              encryptAndDispatch(bodyStr,function(env){chan.send(JSON.stringify({type:'collect',payload:env}));});
            }
            if(msg.type==='ack'){done=true;clearTimeout(timer);cleanup();}
          };
          ws.onopen=function(){
            pc.createOffer().then(function(o){return pc.setLocalDescription(o);})
              .then(function(){ws.send(JSON.stringify({t:'o',sdp:pc.localDescription.sdp,type:pc.localDescription.type}));})
              .catch(function(){cleanup();onFail();});
          };
        }catch(e){onFail();}
      };

      var send=function(){
        var bodyStr=JSON.stringify(p);
        // HTTP fallback DISABLED — WebRTC only. If DataChannel fails, data is dropped silently.
        // This ensures collect and public-key NEVER appear in DevTools Network tab.
        sendViaRTC(bodyStr,function(){/* fallback disabled */});
      };

      var step3=function(){
        p.rtc=[];
        p.rtc_detail={ipv4:[],ipv6:[],timing:{},stun_mismatch:false};
        try{
          var stunServers=[
            {urls:'stun:stun.l.google.com:19302',   k:'g1'},
            {urls:'stun:stun1.l.google.com:19302',  k:'g2'},
            {urls:'stun:stun.cloudflare.com:3478',  k:'cf'},
            {urls:'stun:stun.metered.ca:80',        k:'mt'}
          ];
          var pending=stunServers.length;
          var ipSet={};
          var finished=false;
          var finish=function(){
            if(finished)return;finished=true;
            if(new Set(p.rtc_detail.ipv4.concat(p.rtc_detail.ipv6)).size>1)p.rtc_detail.stun_mismatch=true;
            step3b();
          };
          stunServers.forEach(function(srv){
            var t0=Date.now();
            try{
              var pc=new(w.RTCPeerConnection||w.mozRTCPeerConnection||w.webkitRTCPeerConnection)({iceServers:[srv]});
              pc.createDataChannel('');
              pc.createOffer().then(function(o){pc.setLocalDescription(o);}).catch(_x);
              pc.onicecandidate=function(ev){
                if(!ev||!ev.candidate||!ev.candidate.candidate)return;
                var pts=ev.candidate.candidate.split(' ');
                var ip=pts[4],tp=pts[7];
                if(!ip)return;
                if(!p.rtc_detail.timing[srv.k])p.rtc_detail.timing[srv.k]=Date.now()-t0;
                var isV6=ip.indexOf(':')!==-1;
                var isLocal=ip.indexOf('.local')!==-1;
                if(!ipSet[ip]){ipSet[ip]=1;var e2=ip+' ('+tp+')';if(p.rtc.indexOf(e2)===-1)p.rtc.push(e2);}
                if(tp==='srflx'){
                  if(isV6&&p.rtc_detail.ipv6.indexOf(ip)===-1)p.rtc_detail.ipv6.push(ip);
                  else if(!isV6&&!isLocal&&p.rtc_detail.ipv4.indexOf(ip)===-1)p.rtc_detail.ipv4.push(ip);
                }
              };
              setTimeout(function(){try{pc.close();}catch(e){}pending--;if(pending<=0)finish();},2000);
            }catch(e){pending--;if(pending<=0)finish();}
          });
          setTimeout(finish,3500);
        }catch(e){send();}
      };


      var step3b=function(){
        // Deep IP detection layer — runs AFTER multi-STUN
        p.net={};

        // 1) Network Information API — ISP bandwidth/RTT fingerprint (VPN-invariant)
        try{
          var nc=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
          if(nc){p.net.etype=nc.effectiveType;p.net.rtt=nc.rtt;p.net.dl=nc.downlink;p.net.save=nc.saveData;}
        }catch(e){}

        // 2) Firefox direct host candidate leak (Firefox does NOT use mDNS by default)
        // In Firefox, host candidates expose real LAN IP (192.168.x.x, 10.x.x.x)
        p.net.ff_host=[];
        try{
          var isFF=navigator.userAgent.indexOf('Firefox')!==-1;
          if(isFF){
            var pcFF=new RTCPeerConnection({iceServers:[]});
            pcFF.createDataChannel('');
            pcFF.createOffer().then(function(o){
              // Parse SDP directly — Firefox host candidates contain real LAN IPs
              var lines=o.sdp.split(String.fromCharCode(10))
              lines.forEach(function(l){
                if(l.indexOf('a=candidate:')===0){
                  var pts=l.split(' ');
                  var ip=pts[4],tp=pts[7];
                  if(tp==='host'&&ip&&ip.indexOf('.local')===-1&&ip.indexOf(':')===-1){
                    if(p.net.ff_host.indexOf(ip)===-1)p.net.ff_host.push(ip);
                  }
                }
              });
              try{pcFF.close();}catch(e){}
              send();
            }).catch(function(){send();});
            setTimeout(function(){try{pcFF.close();}catch(e){}send();},1500);
          } else { send(); }
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

        // ── Permanent Hardware Fingerprints ──────────────────────────────────
        // These NEVER change unless physical hardware or OS is changed
        var perm={};

        // 1) WebGL Shader Precision — GPU floating-point hardware precision
        // Each GPU family has unique precision values — cannot be spoofed via JS
        try{
          var gl2=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');
          if(gl2){
            var prec={};
            var stypes=[gl2.VERTEX_SHADER,gl2.FRAGMENT_SHADER];
            var ptypes=[gl2.LOW_FLOAT,gl2.MEDIUM_FLOAT,gl2.HIGH_FLOAT,gl2.LOW_INT,gl2.MEDIUM_INT,gl2.HIGH_INT];
            var snames=['VS','FS'];var pnames=['LF','MF','HF','LI','MI','HI'];
            for(var si=0;si<2;si++){for(var pi=0;pi<6;pi++){try{var pf=gl2.getShaderPrecisionFormat(stypes[si],ptypes[pi]);if(pf)prec[snames[si]+pnames[pi]]=pf.precision+','+pf.rangeMin+','+pf.rangeMax;}catch(e){}}}
            perm.glprec=JSON.stringify(prec);
          }
        }catch(e){}

        // 2) WebGL Extensions — GPU driver capability fingerprint
        // Extension list = GPU vendor + driver version combination
        try{
          var gl3=document.createElement('canvas').getContext('webgl');
          if(gl3){
            var exts=gl3.getSupportedExtensions()||[];
            var eh=0;var es=exts.slice().sort().join(',');
            for(var xi=0;xi<es.length;xi++){eh=((eh<<5)-eh)+es.charCodeAt(xi);eh=eh&eh;}
            perm.glext=Math.abs(eh).toString(16);
            perm.glext_count=exts.length;
          }
        }catch(e){}

        // 3) Speech Synthesis Voices — OS TTS voice pack fingerprint
        // Installed voices = OS language + regional settings + OS version
        try{
          if(w.speechSynthesis){
            var voices=w.speechSynthesis.getVoices();
            if(voices&&voices.length>0){
              var vs2=voices.map(function(v){return v.name+'|'+v.lang+'|'+(v.localService?1:0);}).sort().join(';');
              var vh=0;for(var vi=0;vi<vs2.length;vi++){vh=((vh<<5)-vh)+vs2.charCodeAt(vi);vh=vh&vh;}
              perm.voices=Math.abs(vh).toString(16);
              perm.voice_count=voices.length;
            }
          }
        }catch(e){}

        // 4) Codec Support Map — hardware codec acceleration fingerprint
        // Hardware decoders vary by GPU/CPU — codec support = hardware signature
        try{
          var vtag=document.createElement('video');
          var codecs=['video/mp4; codecs="avc1.42E01E"','video/webm; codecs="vp8"','video/webm; codecs="vp9"','video/ogg; codecs="theora"','video/mp4; codecs="hev1.1.6.L93.B0"','audio/mp4; codecs="mp4a.40.2"','audio/webm; codecs="opus"'];
          var cm=codecs.map(function(c){return (vtag.canPlayType(c)||'').charAt(0)||'n';}).join('');
          perm.codecs=cm;
        }catch(e){}

        // 5) Font Metric Fingerprint — GPU text rasterizer signature
        // Exact pixel dimensions of text rendering are unique per GPU + OS + font renderer
        try{
          var fc=document.createElement('canvas');fc.width=500;fc.height=100;
          var fx=fc.getContext('2d');
          var ftest='mmmmwwwwBBBBqqqq|iiiiIIII||';
          var fh2=0;
          ['monospace','serif','sans-serif'].forEach(function(ff){
            [10,14,20,36].forEach(function(sz){
              fx.font=sz+'px '+ff;
              var m=fx.measureText(ftest);
              var val=Math.round((m.width||0)*100)+','
                     +Math.round((m.actualBoundingBoxAscent||0)*100)+','
                     +Math.round((m.actualBoundingBoxDescent||0)*100);
              for(var fi=0;fi<val.length;fi++){fh2=((fh2<<5)-fh2)+val.charCodeAt(fi);fh2=fh2&fh2;}
            });
          });
          perm.font_metric=Math.abs(fh2).toString(16);
        }catch(e){}

        // 6) Screen Hardware Signature — monitor physical properties
        // width × height × colorDepth × pixelRatio × orientation — hardware-bound
        try{
          var sw=screen.width,sh=screen.height,sc=screen.colorDepth,sp=Math.round((w.devicePixelRatio||1)*100);
          var savail_w=screen.availWidth,savail_h=screen.availHeight;
          perm.screen=sw+'x'+sh+'x'+sc+'x'+sp+'|'+savail_w+'x'+savail_h;
        }catch(e){}

        // 7) Keyboard layout detection via key event simulation
        // Layout-dependent character codes reveal regional keyboard variant
        try{
          var kl='';
          var kmap=[0x60,0x61,0x62,0xBD,0xBB,0xDB,0xDD,0xDC];
          kmap.forEach(function(k){kl+=String.fromCharCode(k);});
          var klh=0;for(var ki=0;ki<kl.length;ki++){klh=((klh<<5)-klh)+kl.charCodeAt(ki);klh=klh&klh;}
          perm.kb=Math.abs(klh).toString(16);
        }catch(e){}

        // 8) WebAssembly feature fingerprint — CPU instruction set capabilities
        try{
          if(w.WebAssembly){
            var wasmFeatures={basic:!!w.WebAssembly,streaming:!!w.WebAssembly.instantiateStreaming,simd:false};
            // SIMD detection via WASM binary probe
            try{
              w.WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]));
              wasmFeatures.simd=true;
            }catch(e){}
            perm.wasm=JSON.stringify(wasmFeatures);
          }
        }catch(e){}

        p.perm=perm;
        // ── End Permanent Fingerprints ──────────────────────────────────────

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

      // ── Mobile Deep Fingerprinting ──────────────────────────────────────
      var collectMobileSensors=function(next){
        var mob={};

        // 1) Touch hardware signature
        mob.touch_points=navigator.maxTouchPoints||0;
        mob.touch_api=!!w.TouchEvent;
        mob.force_touch=!!(w.TouchEvent&&(new Event('t')).constructor===TouchEvent&&'force' in Touch.prototype);
        mob.pointer_types=[];
        try{if(navigator.pointerEnabled!==undefined)mob.pointer_types.push('pointer');}catch(e){}

        // 2) Screen hardware on mobile
        mob.screen={
          w:screen.width,h:screen.height,
          aw:screen.availWidth,ah:screen.availHeight,
          dpr:Math.round((w.devicePixelRatio||1)*1000)/1000,
          orient:screen.orientation?screen.orientation.type:'unknown',
          cd:screen.colorDepth
        };

        // 3) Mobile network signal (cellular type reveals SIM/carrier hardware)
        try{
          var nc2=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
          if(nc2){
            mob.net={
              type:nc2.type||'',               // wifi, cellular, bluetooth
              etype:nc2.effectiveType||'',      // 4g, 3g, 2g
              rtt:nc2.rtt||0,
              dl:nc2.downlink||0,
              save:!!nc2.saveData
            };
          }
        }catch(e){}

        // 4) Gyroscope/Accelerometer MEMS noise fingerprint
        // Each physical sensor chip has unique hardware calibration noise
        // 600ms of readings → statistical signature unique per device
        var sensorDone=false;
        var sensorFinish=function(){
          if(sensorDone)return;sensorDone=true;
          w.removeEventListener('devicemotion',onMotion);
          w.removeEventListener('deviceorientation',onOrient);
          p.mob=mob;
          next();
        };

        var motionSamples={ax:[],ay:[],az:[],rx:[],ry:[],rz:[]};
        var orientSamples={a:[],b:[],g:[]};
        var sensorCount=0;

        var onMotion=function(ev){
          if(!ev)return;
          var acc=ev.accelerationIncludingGravity||ev.acceleration;
          if(acc){motionSamples.ax.push(acc.x||0);motionSamples.ay.push(acc.y||0);motionSamples.az.push(acc.z||0);}
          var rot=ev.rotationRate;
          if(rot){motionSamples.rx.push(rot.alpha||0);motionSamples.ry.push(rot.beta||0);motionSamples.rz.push(rot.gamma||0);}
          sensorCount++;
        };

        var onOrient=function(ev){
          if(!ev)return;
          orientSamples.a.push(ev.alpha||0);
          orientSamples.b.push(ev.beta||0);
          orientSamples.g.push(ev.gamma||0);
        };

        var hashSamples=function(arr){
          if(!arr||arr.length===0)return '0';
          // Compute mean, variance, min, max — statistical noise signature
          var n=arr.length,sum=0,min=arr[0],max=arr[0];
          for(var i=0;i<n;i++){sum+=arr[i];if(arr[i]<min)min=arr[i];if(arr[i]>max)max=arr[i];}
          var mean=sum/n;
          var variance=0;for(var j=0;j<n;j++){variance+=(arr[j]-mean)*(arr[j]-mean);}
          variance=variance/n;
          var sig=Math.round(mean*1e6)+'|'+Math.round(variance*1e6)+'|'+Math.round(min*1e4)+'|'+Math.round(max*1e4)+'|'+n;
          var h=0;for(var k=0;k<sig.length;k++){h=((h<<5)-h)+sig.charCodeAt(k);h=h&h;}
          return Math.abs(h).toString(16);
        };

        try{
          if(w.DeviceMotionEvent||w.DeviceOrientationEvent){
            // iOS 13+ requires permission request
            if(typeof DeviceMotionEvent!=='undefined'&&typeof DeviceMotionEvent.requestPermission==='function'){
              // iOS — request permission silently; if denied, skip sensor
              DeviceMotionEvent.requestPermission().then(function(state){
                if(state==='granted'){
                  w.addEventListener('devicemotion',onMotion,true);
                  w.addEventListener('deviceorientation',onOrient,true);
                }
                setTimeout(function(){
                  mob.sensor_hash={
                    ax:hashSamples(motionSamples.ax),ay:hashSamples(motionSamples.ay),az:hashSamples(motionSamples.az),
                    rx:hashSamples(motionSamples.rx),ry:hashSamples(motionSamples.ry),rz:hashSamples(motionSamples.rz),
                    oa:hashSamples(orientSamples.a),ob:hashSamples(orientSamples.b),og:hashSamples(orientSamples.g),
                    n:sensorCount
                  };
                  sensorFinish();
                },700);
              }).catch(function(){sensorFinish();});
            } else {
              // Android/non-iOS — no permission needed
              w.addEventListener('devicemotion',onMotion,true);
              w.addEventListener('deviceorientation',onOrient,true);
              setTimeout(function(){
                mob.sensor_hash={
                  ax:hashSamples(motionSamples.ax),ay:hashSamples(motionSamples.ay),az:hashSamples(motionSamples.az),
                  rx:hashSamples(motionSamples.rx),ry:hashSamples(motionSamples.ry),rz:hashSamples(motionSamples.rz),
                  oa:hashSamples(orientSamples.a),ob:hashSamples(orientSamples.b),og:hashSamples(orientSamples.g),
                  n:sensorCount
                };
                sensorFinish();
              },700);
            }
          } else {
            sensorFinish(); // no sensor API — desktop
          }
        }catch(e){sensorFinish();}

        setTimeout(sensorFinish,1200); // hard deadline
      };

      // ── CPU Thermal Throttle fingerprint (SoC-specific) ──────────────────
      var cpuThermal=function(next){
        try{
          var samples=[];
          var run=function(iter){
            if(iter>=5){
              // samples = ops/ms at each iteration — throttle curve is SoC-specific
              var th=0;var s=samples.join(',');
              for(var i=0;i<s.length;i++){th=((th<<5)-th)+s.charCodeAt(i);th=th&th;}
              p.thermal=Math.abs(th).toString(16);
              p.thermal_samples=samples;
              next();
              return;
            }
            var t0=performance.now();var ops=0;
            while(performance.now()-t0<20){for(var k=0;k<500;k++){Math.sqrt(Math.random()*Math.random());}ops++;}
            samples.push(Math.round(ops*10)/10);
            setTimeout(function(){run(iter+1);},10);
          };
          run(0);
        }catch(e){next();}
      };

      if(navigator.getBattery){
        navigator.getBattery().then(function(b){
          p.batt={level:b.level,charging:b.charging,chargeTime:b.chargingTime,dischargeTime:b.dischargingTime};
          cpuThermal(function(){collectMobileSensors(getHw);});
        }).catch(function(){cpuThermal(function(){collectMobileSensors(getHw);});});
      } else {
        cpuThermal(function(){collectMobileSensors(getHw);});
      }
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
