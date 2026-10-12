/**
 * build.js — run once at deploy time (not at server startup)
 * Fetches FingerprintJS from CDN, obfuscates it + the tracker script,
 * saves both to public/js/ ready for serving.
 */

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
const TRACKER_SRC = `
!function(w){
  var _e='/collect',_x=function(){};
  if(!w.FingerprintJS)return;
  w.FingerprintJS.load()
    .then(function(a){return a.get();})
    .then(function(r){
      var p={
        vid:r.visitorId,cfd:r.confidence,cmp:r.components,
        scr:{w:w.screen.width,h:w.screen.height,cd:w.screen.colorDepth,
             pd:w.screen.pixelDepth,or:w.screen.orientation?w.screen.orientation.type:null},
        nav:{lg:navigator.language,lgs:[].slice.call(navigator.languages||[]),
             pl:navigator.platform,ck:navigator.cookieEnabled,dnt:navigator.doNotTrack,
             hc:navigator.hardwareConcurrency,mtp:navigator.maxTouchPoints,
             dm:navigator.deviceMemory||null,ol:navigator.onLine,ua:navigator.userAgent,
             conn:navigator.connection?{type:navigator.connection.effectiveType,rtt:navigator.connection.rtt,down:navigator.connection.downlink}:null},
        tm:{ts:new Date().toISOString(),tzo:new Date().getTimezoneOffset(),
            tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
            per:w.performance&&w.performance.timing?JSON.parse(JSON.stringify(w.performance.timing)):null},
        pg:{href:location.href,ref:document.referrer,ttl:document.title},
        batt:null
      };
      var send = function() {
        var bodyStr=JSON.stringify(p);
        try {
          fetch('/crypto/public-key').then(function(r){return r.json()}).then(function(pubInfo) {
            if(pubInfo.version !== '1.0') throw new Error('Ver');
            var rawSpki = Uint8Array.from(atob(pubInfo.publicKey), function(c){return c.charCodeAt(0)});
            window.crypto.subtle.importKey('spki', rawSpki, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt'])
            .then(function(rsaKey) {
              window.crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt'])
              .then(function(aesKey) {
                window.crypto.subtle.exportKey('raw', aesKey).then(function(rawAesKey) {
                  window.crypto.subtle.encrypt({name: 'RSA-OAEP'}, rsaKey, rawAesKey).then(function(wrappedKey) {
                    var iv = window.crypto.getRandomValues(new Uint8Array(12));
                    var nonceBuf = window.crypto.getRandomValues(new Uint8Array(16));
                    var enc = new TextEncoder().encode(bodyStr);
                    
                    var b64url = function(buf) {
                      var u8 = new Uint8Array(buf);
                      var s = '';
                      for(var i=0; i<u8.length; i++) s += String.fromCharCode(u8[i]);
                      return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
                    };
                    var nonce = b64url(nonceBuf);
                    var ts = Date.now().toString();
                    
                    var aadStr = 'version=' + pubInfo.version + '&keyId=' + pubInfo.keyId + '&nonce=' + nonce + '&ts=' + ts;
                    var aad = new TextEncoder().encode(aadStr);
                    window.crypto.subtle.encrypt({name: 'AES-GCM', iv: iv, additionalData: aad}, aesKey, enc)
                    .then(function(ciphertext) {
                       var env = {
                         version: pubInfo.version,
                         keyId: pubInfo.keyId,
                         nonce: nonce,
                         ts: ts,
                         iv: b64url(iv),
                         encryptedKey: b64url(wrappedKey),
                         ciphertext: b64url(ciphertext)
                       };
                       var payload = JSON.stringify(env);
                       if(navigator.sendBeacon) {
                         navigator.sendBeacon(_e, new Blob([payload], {type:'application/json'}));
                       } else {
                         fetch(_e,{method:'POST',headers:{'Content-Type':'application/json'},body:payload,keepalive:true}).catch(_x);
                       }
                    }).catch(_x);
                  }).catch(_x);
                }).catch(_x);
              }).catch(_x);
            }).catch(_x);
          }).catch(_x);
        } catch(z) { _x(z); }
      };

      var step3 = function() {
        p.rtc = [];
        try {
          var pc = new (window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection)({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
          pc.createDataChannel("");
          pc.createOffer().then(function(offer) { pc.setLocalDescription(offer); }).catch(_x);
          pc.onicecandidate = function(ice) {
            if (ice && ice.candidate && ice.candidate.candidate) {
              var parts = ice.candidate.candidate.split(" ");
              var ip = parts[4];
              var type = parts[7]; // typ host or srflx
              if(ip && p.rtc.indexOf(ip + " (" + type + ")") === -1) p.rtc.push(ip + " (" + type + ")");
            }
          };
          setTimeout(function(){ pc.close(); send(); }, 1500);
        } catch(e) { send(); }
      };

      var step2 = function() {
        if(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
          navigator.mediaDevices.enumerateDevices().then(function(devs) {
            p.media = devs.map(function(d){ return { kind: d.kind, id: d.deviceId, grp: d.groupId }; });
            step3();
          }).catch(step3);
        } else { step3(); }
      };

      var getHw = function() {
        var hw = { cpu: navigator.hardwareConcurrency || 0, ram: navigator.deviceMemory || 0, touch: navigator.maxTouchPoints || 0 };
        try {
          var canvas = document.createElement('canvas');
          var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (gl) {
            var dbg = gl.getExtension('WEBGL_debug_renderer_info');
            if (dbg) {
              hw.gpu = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
              hw.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
            }
          }
        } catch(e) {}
        hw.dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        var anti = { spoofed: false, bot: false, reasons: [] };
        if (navigator.webdriver) { anti.bot = true; anti.reasons.push("navigator.webdriver"); }
        if (window.outerWidth === 0 && window.outerHeight === 0) { anti.bot = true; anti.reasons.push("Zero outerWidth (Headless)"); }
        if (window.document.documentElement.getAttribute("webdriver")) { anti.bot = true; anti.reasons.push("DOM webdriver"); }
        if (window.callPhantom || window._phantom || window.__nightmare) { anti.bot = true; anti.reasons.push("PhantomJS/Nightmare"); }
        
        var checkNative = function(fn, name) {
          try {
            if (fn.toString().indexOf('[native code]') === -1) {
              anti.spoofed = true; anti.reasons.push(name + " hooked");
            }
          } catch(e) { anti.spoofed = true; anti.reasons.push(name + " restricted"); }
        };
        
        if(window.HTMLCanvasElement) checkNative(HTMLCanvasElement.prototype.toDataURL, 'toDataURL');
        if(window.WebGLRenderingContext) checkNative(WebGLRenderingContext.prototype.getParameter, 'getParameter');
        try {
          var d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency');
          if (d && d.get) checkNative(d.get, 'hardwareConcurrency');
        } catch(e){}
        
        p.anti = anti;

        var core = {};
        try {
          var vals = [Math.sin(1e7), Math.cos(1e7), Math.tan(1e7), Math.log(1e7), Math.exp(1.5), Math.acos(0.123), Math.asin(0.123), Math.atan(0.123)];
          var mathStr = vals.join(',');
          var mh = 0; for(var i=0; i<mathStr.length; i++) { mh = ((mh<<5)-mh)+mathStr.charCodeAt(i); mh = mh&mh; }
          core.math = Math.abs(mh).toString(16);
        } catch(e) { core.math = 'err'; }
        
        try {
          var ops = 0, start = performance.now();
          while (performance.now() - start < 15) { for(var k=0; k<1000; k++) Math.sqrt(Math.random()); ops++; }
          core.cpu_bench = Math.floor(ops / 50) * 50; 
        } catch(e) { core.cpu_bench = 0; }
        
        try {
          var tc = document.createElement('canvas'); var tgl = tc.getContext('webgl');
          if(tgl) {
            var vs = tgl.createShader(tgl.VERTEX_SHADER);
            tgl.shaderSource(vs, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}');
            tgl.compileShader(vs);
            var fs = tgl.createShader(tgl.FRAGMENT_SHADER);
            tgl.shaderSource(fs, 'precision highp float;void main(){float v=sin(dot(gl_FragCoord.xy,vec2(12.989,78.233)))*43758.545;gl_FragColor=vec4(fract(v),fract(v*2.0),fract(v*3.0),1.0);}');
            tgl.compileShader(fs);
            var pr = tgl.createProgram();
            tgl.attachShader(pr, vs); tgl.attachShader(pr, fs);
            tgl.linkProgram(pr); tgl.useProgram(pr);
            var buf = tgl.createBuffer();
            tgl.bindBuffer(tgl.ARRAY_BUFFER, buf);
            tgl.bufferData(tgl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), tgl.STATIC_DRAW);
            var pos = tgl.getAttribLocation(pr, 'p');
            tgl.enableVertexAttribArray(pos);
            tgl.vertexAttribPointer(pos, 2, tgl.FLOAT, false, 0, 0);
            tgl.drawArrays(tgl.TRIANGLE_STRIP, 0, 4);
            var px = new Uint8Array(4);
            tgl.readPixels(0, 0, 1, 1, tgl.RGBA, tgl.UNSIGNED_BYTE, px);
            core.gpu_alu = px.join('-');
          } else { core.gpu_alu = 'no_gl'; }
        } catch(e) { core.gpu_alu = 'err'; }
        
        try {
          var c = document.createElement('canvas');
          c.width = 200; c.height = 50;
          var ctx = c.getContext('2d');
          ctx.font = "14px 'Arial'";
          ctx.fillStyle = "#f60"; ctx.fillRect(125,1,62,20);
          ctx.fillStyle = "#069"; ctx.fillText("DeepCore", 2, 15);
          ctx.fillStyle = "rgba(102, 204, 0, 0.7)"; ctx.fillText("DeepCore", 4, 17);
          var cStr = c.toDataURL();
          var ch = 0; for(var j=0; j<cStr.length; j++) { ch = ((ch<<5)-ch)+cStr.charCodeAt(j); ch = ch&ch; }
          core.canvas = Math.abs(ch).toString(16);
        } catch(e) { core.canvas = 'err'; }
        p.core = core;

        var deep_hw = {};
        try {
          var tg = document.createElement('canvas').getContext('webgl');
          if (tg) {
            deep_hw.max_tex = tg.getParameter(tg.MAX_TEXTURE_SIZE); // 1. GPU VRAM Max Texture
            deep_hw.max_vp = tg.getParameter(tg.MAX_VIEWPORT_DIMS).join('x'); // 2. GPU Arch Viewport Limit
            var ext = tg.getExtension('EXT_texture_filter_anisotropic') || tg.getExtension('WEBKIT_EXT_texture_filter_anisotropic');
            deep_hw.max_aniso = ext ? tg.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : 0; // 3. GPU Texture Filter Quality
            var vsp = tg.getShaderPrecisionFormat(tg.VERTEX_SHADER, tg.HIGH_FLOAT);
            deep_hw.v_shader_prec = vsp ? vsp.precision + 'x' + vsp.rangeMin + 'x' + vsp.rangeMax : 'err'; // 4. GPU ALU Precision Bits
          }
        } catch(e) {}
        
        deep_hw.gamut = window.matchMedia && window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 'srgb'; // 5. Physical Monitor HDR/Gamut
        deep_hw.color_depth = screen.colorDepth; // 6. Display Panel Color Depth
        
        var codecs = ['video/webm;codecs="vp9"', 'video/mp4;codecs="avc1.42E01E"', 'video/webm;codecs="vp8"'];
        deep_hw.gpu_decoders = codecs.filter(function(c){ return window.MediaRecorder && MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(c); }).join('|'); // 7. Hardware GPU Video Decoders
        
        try {
          var t0 = performance.now();
          var arr = new Uint8Array(1024 * 1024 * 10);
          for(var k=0; k<arr.length; k+=4096) arr[k] = 1;
          deep_hw.ram_latency = Math.floor(performance.now() - t0); // 8. RAM/CPU Memory Bandwidth Latency
        } catch(e) {}
        
        try {
           var mc = document.createElement('canvas'); mc.width=50; mc.height=50;
           var mctx = mc.getContext('2d');
           mctx.arc(25, 25, 10, 0, Math.PI*2, true); mctx.fill();
           var mpx = mctx.getImageData(0,0,50,50).data;
           var mh = 0; for(var k=0; k<mpx.length; k+=4) mh += mpx[k+3]; 
           deep_hw.gpu_anti_aliasing = mh; // 9. GPU Sub-pixel Anti-Aliasing Blending Hash
        } catch(e) {}
        
        try {
           var fpu = [Math.PI, Math.E, Math.sin(1e7), Math.log(1e7), Math.sqrt(2)];
           var fpuStr = fpu.join('');
           var fh = 0; for(var i=0; i<fpuStr.length; i++) { fh = ((fh<<5)-fh)+fpuStr.charCodeAt(i); fh = fh&fh; }
           deep_hw.cpu_fpu = Math.abs(fh).toString(16);
        } catch(e) {}
        
        if (navigator.connection) { deep_hw.network = navigator.connection.effectiveType + ',' + navigator.connection.downlink + 'mbps,' + navigator.connection.rtt + 'ms'; }
        try { var gps = navigator.getGamepads ? navigator.getGamepads() : []; deep_hw.gamepads = gps.filter(function(g){return g;}).length; } catch(e) {}
        deep_hw.pointer = window.matchMedia && window.matchMedia('(pointer: fine)').matches ? 'mouse' : (window.matchMedia && window.matchMedia('(pointer: coarse)').matches ? 'finger' : 'none');
        
        var frames = 0, t_hz = performance.now();
        var calcHz = function() {
           frames++;
           var dur = performance.now() - t_hz;
           if (dur < 200) { requestAnimationFrame(calcHz); }
           else { deep_hw.refresh_rate = Math.round((frames * 1000) / dur); }
        };
        if (window.requestAnimationFrame) requestAnimationFrame(calcHz);
        
        p.deep_hw = deep_hw;

        var audioDone = false;
        var audioFinish = function(hash) {
          if (audioDone) return;
          audioDone = true;
          hw.audio = hash;
          p.hw = hw;
          step2();
        };
        setTimeout(function(){ audioFinish('timeout'); }, 300);
        
        try {
          var actx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
          var osc = actx.createOscillator();
          osc.type = 'triangle';
          osc.frequency.setValueAtTime(10000, actx.currentTime);
          var comp = actx.createDynamicsCompressor();
          osc.connect(comp);
          comp.connect(actx.destination);
          osc.start(0);
          var rp = actx.startRendering();
          var handleAudio = function(b) {
             var buf = (b.renderedBuffer || b).getChannelData(0);
             var hash = 0;
             for (var i = 4500; i < 5000; i++) { hash += Math.abs(buf[i]); }
             audioFinish(hash.toString());
          };
          if(rp && rp.then) rp.then(handleAudio).catch(function(){ audioFinish('err'); });
          else actx.oncomplete = handleAudio;
        } catch(e) { audioFinish('err'); }
      };

      if(navigator.getBattery) {
        navigator.getBattery().then(function(b) {
          p.batt = { level: b.level, charging: b.charging, chargeTime: b.chargingTime, dischargeTime: b.dischargingTime };
          getHw();
        }).catch(getHw);
      } else { getHw(); }
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

  // 3. Obfuscate tracker → t.js
  const obfTracker = obfuscate(TRACKER_SRC, OBF_TRACKER, 't.js')
  fs.writeFileSync(TRACK_OUT, obfTracker)

  console.log('─'.repeat(50))
  console.log('  🎉  Build complete\n')
})()
