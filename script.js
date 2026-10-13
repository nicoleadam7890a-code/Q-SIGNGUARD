(function(){
  var $ = function(id){return document.getElementById(id)};
  var STEPS = ["Upload signed document","Cryptographic verification","AI threat analysis","Risk assessment","Audit log"];
  var STEP_DESC = ["PDF or supported document","Hash, signature, certificate","Signing behavior","Score from 0 to 100","Save and anchor the hash"];
  var SIGNALS = [
    {id:"replay", name:"Replayed nonce",      hint:"Same signing request was seen before",  w:26},
    {id:"key",    name:"Key used abnormally", hint:"Key active from an unusual location",   w:22},
    {id:"burst",  name:"Signing burst",       hint:"Many signatures in a short window",     w:14},
    {id:"ip",     name:"IP mismatch",         hint:"Differs from the signer's usual range", w:12},
    {id:"device", name:"New device",          hint:"Never seen for this signer",            w:10},
    {id:"hours",  name:"Odd hours",           hint:"Signed outside normal working time",    w:7}
  ];
  var SCENES = {normal:{}, key:{key:1,device:1,ip:1,hours:1,burst:1}, replay:{replay:1,burst:1,device:1}};
  var OUTCOME_W = {valid:0, hash:45, invalid:50, expired:20};
  var OUTCOME_NAME = {hash:"Hash does not match the signed digest", invalid:"Signature is invalid", expired:"Certificate has expired"};
  var NOSIG_W = 30;
  var SAMPLE = "SIGNED AGREEMENT #4821\n\nPayer:     Meridian Traders Pvt Ltd\nPayee:     Asha Logistics\nAmount:    INR 2,50,000\nApproved:  Finance Controller\nDate:      13 Oct 2026\n";

  var st = {step:0, reached:0, file:null, outcome:"valid", sig:{}, logCount:0};
  var last = null;

  function hex(buf){return Array.prototype.map.call(new Uint8Array(buf),function(b){return ("0"+b.toString(16)).slice(-2)}).join("")}
  async function sha(buf){
    try{ return hex(await crypto.subtle.digest("SHA-256", buf)); }
    catch(e){ var a=new Uint8Array(buf),h=0; for(var i=0;i<a.length;i++){h=(h*31+a[i])|0} return ("fallback"+(h>>>0).toString(16)).padEnd(64,"0"); }
  }
  function short(h){return h.slice(0,16)+"…"+h.slice(-8)}
  function fmtSize(n){return n<1024?n+" bytes":(n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB")}

  /* ---------- stepper ---------- */
  var stepsEl = $("steps");
  STEPS.forEach(function(name,i){
    var li = document.createElement("li");
    li.innerHTML = '<button type="button" data-i="'+i+'"><span class="n">'+(i+1)+'</span><span class="t">'+name+'<span class="d">'+STEP_DESC[i]+'</span></span></button>';
    stepsEl.appendChild(li);
    li.firstChild.addEventListener("click", function(){ if(i<=st.reached) go(i); });
  });

  function go(i){
    st.step = i;
    for(var k=0;k<5;k++){ $("pane"+k).hidden = (k!==i); }
    var btns = stepsEl.querySelectorAll("button");
    btns.forEach(function(b,k){
      b.classList.toggle("done", k<st.reached && k!==i);
      b.disabled = k>st.reached;
      if(k===i) b.setAttribute("aria-current","step"); else b.removeAttribute("aria-current");
    });
    $("back").disabled = i===0;
    if(window.matchMedia && matchMedia("(max-width:700px)").matches){
      var cur = btns[i].parentNode; stepsEl.scrollLeft = cur.offsetLeft - (stepsEl.clientWidth - cur.offsetWidth)/2;
    }
    $("next").hidden = i===4;
    $("next").disabled = (i===0 && !st.file);
    $("next").textContent = i===2 ? "See risk score" : "Continue";
    $("hint").textContent = (i===0 && !st.file) ? "Add a document to continue" : "";
    if(i===1) renderChecks();
    renderChrome();
    if(i===3) renderVerdict();
    var top = $("app").getBoundingClientRect().top;
    if(top < 0) $("app").scrollIntoView({behavior:"smooth", block:"start"});
  }
  $("next").addEventListener("click", function(){ var n = Math.min(4, st.step+1); st.reached = Math.max(st.reached, n); go(n); });
  $("back").addEventListener("click", function(){ go(Math.max(0, st.step-1)); });

  /* ---------- phone progress bar + desktop live summary ---------- */
  function renderChrome(){
    var f = st.file, r = compute();
    $("mLbl").textContent = "Step "+(st.step+1)+" of 5";
    $("mTtl").textContent = STEPS[st.step];
    $("mProg").style.width = ((st.step+1)*20)+"%";
    var rk = $("mRk"); rk.hidden = !f; rk.textContent = "Risk "+r.score;
    $("sFile").textContent = f ? f.name : "No file yet";
    $("sHash").textContent = f ? short(f.hash) : "–";
    var vt = {valid:"Valid", hash:"Hash mismatch", invalid:"Invalid signature", expired:"Certificate expired"};
    $("sVer").textContent = (f && st.reached>=1) ? vt[st.outcome] : "Not checked yet";
    $("sScore").textContent = f ? r.score : "–";
    if(window.__qsgPane) window.__qsgPane(st, r);
    var c = $("sChip"); c.hidden = !f; c.className = "chip "+r.level;
    c.textContent = r.level==="ok" ? "Allow" : (r.level==="warn" ? "Send to review" : "Block");
  }

  /* ---------- step 1: upload ---------- */
  var TYPES={pdf:"PDF document",docx:"Word document (.docx)",txt:"Plain text",xml:"XML (XAdES candidate)",p7s:"PKCS#7 detached signature",json:"JSON"};
  function ferr(m){var e=$("fileErr");e.textContent=m;e.hidden=!m}
  async function loadFile(name, buf, isSample){
    var ext = (name.split(".").pop() || "").toLowerCase();
    if(!TYPES[ext]){ ferr("." + ext + " files are not supported. Use PDF, DOCX, TXT, XML, P7S or JSON."); return; }
    if(!buf.byteLength){ ferr("This file is empty."); return; }
    ferr("");
    var bytes = new Uint8Array(buf);
    var isPdf = bytes.length>4 && bytes[0]===0x25 && bytes[1]===0x50 && bytes[2]===0x44 && bytes[3]===0x46;
    var hasSig = null;
    if(isPdf && bytes.length < 30*1048576){
      var txt = new TextDecoder("latin1").decode(bytes);
      hasSig = /\/ByteRange\s*\[/.test(txt) || /\/Type\s*\/Sig\b/.test(txt);
    }
    var pages = null, sigs = null;
    if(isPdf && bytes.length < 30*1048576){ var t2 = new TextDecoder("latin1").decode(bytes); pages = (t2.match(/\/Type\s*\/Page(?![s\w])/g)||[]).length; sigs = (t2.match(/\/ByteRange\s*\[/g)||[]).length; }
    var docxSig = null;
    if(ext==="docx"){ docxSig = /_xmlsignatures\//.test(new TextDecoder("latin1").decode(bytes)); }
    st.file = {name:name, ext:ext, docxSig:docxSig, size:bytes.length, hash:await sha(buf), isPdf:isPdf, hasSig:hasSig, sample:!!isSample};
    st.reached = Math.max(st.reached, 0);
    var fc = $("filecard"); fc.hidden = false;
    fc.innerHTML = "";
    [["File", name + (isSample ? " (sample)" : "")],["Size", fmtSize(bytes.length)],["Type", TYPES[ext]],["Signature marker", isPdf ? (hasSig ? "Found (PDF signature field)" : "Not found") : (ext==="docx" ? (docxSig ? "Found (XML signature part)" : "Not found") : "Not checked for this format")],["SHA-256", st.file.hash]].concat(isPdf ? [["Pages", String(pages)],["Signature fields", String(sigs)]] : []).forEach(function(p){
      var dt = document.createElement("dt"); dt.textContent = p[0];
      var dd = document.createElement("dd"); dd.textContent = p[1]; if(p[0]==="SHA-256") dd.className = "mono";
      fc.appendChild(dt); fc.appendChild(dd);
    });
    $("next").disabled = false; $("hint").textContent = ""; renderChrome();
  }
  $("file").addEventListener("change", async function(e){
    var f = e.target.files[0]; if(!f) return;
    if(f.size > 60*1048576){ ferr("Please choose a file under 60 MB."); return; }
    await loadFile(f.name, await f.arrayBuffer(), false);
  });
  var drop = $("drop");
  ["dragenter","dragover"].forEach(function(ev){ drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.add("over"); }); });
  ["dragleave","drop"].forEach(function(ev){ drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.remove("over"); }); });
  drop.addEventListener("drop", async function(e){
    var f = e.dataTransfer.files[0]; if(!f) return;
    if(f.size > 60*1048576){ ferr("Please choose a file under 60 MB."); return; }
    await loadFile(f.name, await f.arrayBuffer(), false);
  });
  $("sample").addEventListener("click", async function(){
    var buf = new TextEncoder().encode(SAMPLE).buffer;
    await loadFile("agreement-4821.txt", buf, true);
  });

  /* ---------- step 2: verification ---------- */
  function renderChecks(){
    var f = st.file, ul = $("checks"); ul.innerHTML = "";
    var rows = [];
    rows.push({cls:"ok", ic:"✓", t:"Document hash", d:"SHA-256 computed: "+short(f.hash), mono:true});
    if(f.isPdf && f.hasSig === true) rows.push({cls:"ok", ic:"✓", t:"Embedded signature", d:"A signature field was found in the PDF."});
    else if(f.isPdf) rows.push({cls:"bad", ic:"!", t:"Embedded signature", d:"No signature field was found in this PDF."});
    else rows.push({cls:"na", ic:"–", t:"Embedded signature", d:"Not a PDF, so the demo skips signature detection."});
    var o = st.outcome;
    if(o==="valid") rows.push({cls:"ok", ic:"✓", t:"Signature and certificate", d:"Signature is valid and the certificate is current. (Simulated result)"});
    else if(o==="hash") rows.push({cls:"bad", ic:"!", t:"Signature and certificate", d:"The hash does not match the digest that was signed. (Simulated result)"});
    else if(o==="invalid") rows.push({cls:"bad", ic:"!", t:"Signature and certificate", d:"The signature does not verify against the signer's public key. (Simulated result)"});
    else rows.push({cls:"warn", ic:"!", t:"Signature and certificate", d:"The signature is valid but the certificate has expired. (Simulated result)"});
    rows.forEach(function(r){
      var li = document.createElement("li"); li.className = "check "+r.cls;
      li.innerHTML = '<div class="ic"></div><div><b></b><span></span></div>';
      li.querySelector(".ic").textContent = r.ic;
      li.querySelector("b").textContent = r.t;
      var sp = li.querySelector("span"); sp.textContent = r.d; if(r.mono) sp.className = "mono";
      ul.appendChild(li);
    });
  }
  $("outcome").addEventListener("click", function(e){
    var b = e.target.closest("button"); if(!b) return;
    st.outcome = b.getAttribute("data-o");
    $("outcome").querySelectorAll("button").forEach(function(x){ x.setAttribute("aria-pressed", x===b ? "true":"false"); });
    renderChecks(); renderChrome();
  });

  /* ---------- step 3: signals ---------- */
  var box = $("signals");
  SIGNALS.forEach(function(s){
    var l = document.createElement("label"); l.className = "pill"; l.id = "pill_"+s.id;
    l.innerHTML = '<input type="checkbox" id="s_'+s.id+'"><span class="box" aria-hidden="true"></span><b>'+s.name+'</b><span class="pts">+'+s.w+'</span><small>'+s.hint+'</small>';
    box.appendChild(l);
    st.sig[s.id] = false;
    l.querySelector("input").addEventListener("change", function(e){
      st.sig[s.id] = e.target.checked; l.classList.toggle("on", e.target.checked); markScene(null); renderChrome();
    });
  });
  function markScene(name){ $("scenes").querySelectorAll("button").forEach(function(b){ b.setAttribute("aria-pressed", b.getAttribute("data-s")===name ? "true":"false"); }); }
  $("scenes").addEventListener("click", function(e){
    var b = e.target.closest("button"); if(!b) return;
    var map = SCENES[b.getAttribute("data-s")];
    SIGNALS.forEach(function(s){ var on = !!map[s.id]; st.sig[s.id]=on; $("s_"+s.id).checked = on; $("pill_"+s.id).classList.toggle("on", on); });
    markScene(b.getAttribute("data-s")); renderChrome();
  });

  /* ---------- step 4: score ---------- */
  function compute(){
    var items = [], f = st.file;
    if(st.outcome !== "valid") items.push({name:OUTCOME_NAME[st.outcome], w:OUTCOME_W[st.outcome]});
    if(f && f.isPdf && f.hasSig === false) items.push({name:"No signature found in the file", w:NOSIG_W});
    SIGNALS.forEach(function(s){ if(st.sig[s.id]) items.push({name:s.name, w:s.w}); });
    var raw = items.reduce(function(a,b){return a+b.w},0);
    var score = Math.round(100 * (1 - Math.exp(-raw/42)));
    var level = score < 30 ? "ok" : (score < 65 ? "warn" : "bad");
    return {items:items, raw:raw, score:score, level:level};
  }
  function renderVerdict(){
    var r = compute(); last = r;
    var col = "var(--v"+r.level+")";
    var arc = $("arc"); arc.style.stroke = col;
    requestAnimationFrame(function(){ arc.style.strokeDashoffset = String(100 - r.score); });
    $("score").textContent = r.score;
    var chip = $("chip"); chip.className = "chip "+r.level;
    chip.textContent = r.level==="ok" ? "Allow" : (r.level==="warn" ? "Send to review" : "Block");
    $("vtext").textContent = r.level==="ok" ? "Nothing unusual found." : (r.level==="warn" ? "A person should check this signing." : "Stop this signing and alert the owner.");
    var ul = $("why"); ul.innerHTML = "";
    if(!r.items.length){
      var li = document.createElement("li"); li.innerHTML = '<span class="empty">No issues detected. Go back to try a different result or scenario.</span>'; ul.appendChild(li);
    } else {
      r.items.slice().sort(function(a,b){return b.w-a.w}).forEach(function(it){
        var li = document.createElement("li");
        li.innerHTML = '<span></span><span class="val">+'+it.w+' pts</span><div class="bar"><i style="width:'+Math.round(it.w/r.raw*100)+'%;--vc:'+col+'"></i></div>';
        li.firstChild.textContent = it.name;
        ul.appendChild(li);
      });
    }
  }

  /* ---------- step 5: audit ---------- */
  $("logBtn").addEventListener("click", async function(){
    var r = last || compute(), f = st.file;
    var ts = new Date().toISOString();
    var level = r.level==="ok" ? "ALLOW" : (r.level==="warn" ? "REVIEW" : "BLOCK");
    var li = document.createElement("li");
    var t = document.createElement("span"); t.className = "tag"; t.textContent = level+" "+r.score+"/100";
    var txt = " · "+f.name+" · "+short(f.hash)+" · "+ts.replace("T"," ").slice(0,19)+" UTC";
    if($("anchorBox").checked){
      var tx = "0x"+await sha(new TextEncoder().encode(f.hash+"|"+r.score+"|"+ts+"|"+(++st.logCount)));
      txt += " · anchored on testnet (simulated tx "+tx.slice(0,18)+"…"+tx.slice(-6)+")";
    } else txt += " · saved to audit log";
    li.appendChild(t); li.appendChild(document.createTextNode(txt));
    var logEl = $("log"); logEl.insertBefore(li, logEl.firstChild);
    document.dispatchEvent(new CustomEvent("qsg:saved",{detail:{level:level,score:r.score,name:f.name,hash:f.hash,ts:ts,tx:tx||null,anchored:$("anchorBox").checked}}));
  });
  $("restart").addEventListener("click", function(){
    st.file = null; st.reached = 0; st.outcome = "valid";
    $("file").value = ""; $("filecard").hidden = true;
    $("outcome").querySelectorAll("button").forEach(function(b){ b.setAttribute("aria-pressed", b.getAttribute("data-o")==="valid" ? "true":"false"); });
    SIGNALS.forEach(function(s){ st.sig[s.id]=false; $("s_"+s.id).checked=false; $("pill_"+s.id).classList.remove("on"); });
    markScene("normal");
    $("arc").style.strokeDashoffset = "100";
    go(0);
  });

  /* theme */
  $("theme").addEventListener("click", function(e){
    if(window.__themeSwitch){ window.__themeSwitch(e); return; }
    var root = document.documentElement;
    var cur = root.getAttribute("data-theme") || (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    root.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
  });

  go(0);
})();

(function(){
  var root = document.documentElement;
  var reduce = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
  var boot = document.getElementById("boot");
  var h1 = document.querySelector(".hero h1");
  var H1TEXT = h1 ? h1.textContent : "";

  /* ---------- mark elements that animate in on scroll ---------- */
  function mark(sel, soft, mod, step){
    var list = document.querySelectorAll(sel);
    for(var i=0;i<list.length;i++){
      var el = list[i];
      el.classList.add("rv");
      if(soft) el.classList.add("soft");
      if(mod) el.style.setProperty("--d", ((i % mod) * step) + "ms");
    }
  }
  function splitWords(el){
    var text = el.textContent.replace(/\s+/g, " ").trim();
    var words = text.split(" "), frag = document.createDocumentFragment();
    words.forEach(function(w, i){
      var o = document.createElement("i"); o.className = "w";
      var inn = document.createElement("i"); inn.className = "wi";
      inn.style.setProperty("--i", Math.min(i, 16));
      inn.textContent = w;
      o.appendChild(inn); frag.appendChild(o);
      if(i < words.length - 1) frag.appendChild(document.createTextNode(" "));
    });
    el.textContent = ""; el.appendChild(frag);
  }
  function markText(sel){
    var list = document.querySelectorAll(sel);
    for(var i=0;i<list.length;i++){ splitWords(list[i]); list[i].classList.add("rv", "txt"); }
  }
  function splitInside(sel){
    var list = document.querySelectorAll(sel);
    for(var i=0;i<list.length;i++) splitWords(list[i]);
  }
  if(!reduce){
    mark(".hero h1");
    markText(".hero .lead");
    var lead = document.querySelector(".hero .lead"); if(lead) lead.style.setProperty("--d", "300ms");
    mark("#app", true);
    markText("section.block > h2"); markText("section.block > p.intro");
    mark(".flow li", false, 5, 110);
    mark(".threat", false, 2, 120);
    mark(".stack .col", false, 3, 120);
    splitInside(".flow li b, .flow li span, .threat h3, .threat p, .stack .col h3");
    mark("footer .frow", true);
  }

  var started = false;
  function startReveal(){
    if(started) return; started = true;
    var targets = document.querySelectorAll(".rv");
    function show(el){
      clearTimeout(el._t);
      el.classList.add("in");
      var d = parseInt(el.style.getPropertyValue("--d"), 10) || 0;
      el._t = setTimeout(function(){ el.classList.add("done"); }, 1300 + d);
    }
    function hide(el, e){
      clearTimeout(el._t);
      el.classList.remove("in", "done");
      el.classList.toggle("from-top", e.boundingClientRect.bottom <= 0);
    }
    if(!("IntersectionObserver" in window)){ for(var i=0;i<targets.length;i++) show(targets[i]); return; }
    var io = new IntersectionObserver(function(es){
      es.forEach(function(e){
        var el = e.target, on = el.classList.contains("in");
        if(e.intersectionRatio >= 0.12){ if(!on) show(el); }
        else if(e.intersectionRatio === 0 && on){ hide(el, e); }
      });
    }, {threshold:[0, 0.12], rootMargin:"0px"});
    for(var j=0;j<targets.length;j++) io.observe(targets[j]);
  }

  /* ---------- headline decode effect ---------- */
  function scramble(){
    if(reduce || !h1) return;
    var chars = "01ABCDEF#$%&/<>[]{}";
    var n = H1TEXT.length, t0 = performance.now(), dur = 1300;
    h1.setAttribute("aria-label", H1TEXT);
    h1.style.minHeight = h1.offsetHeight + "px";
    function step(now){
      var p = Math.min(1, (now - t0) / dur), fixed = Math.floor(p * n), out = "";
      for(var i=0;i<n;i++){
        var c = H1TEXT.charAt(i);
        out += (i < fixed || c === " ") ? c : chars.charAt(Math.floor(Math.random() * chars.length));
      }
      h1.textContent = out;
      if(p < 1) requestAnimationFrame(step);
      else {
        h1.textContent = H1TEXT; h1.style.minHeight = "";
        h1.classList.add("glitch");
        setTimeout(function(){ h1.classList.remove("glitch"); }, 700);
      }
    }
    requestAnimationFrame(step);
  }

  /* ---------- loading screen ---------- */
  function finishBoot(){
    if(boot){ boot.classList.add("out"); setTimeout(function(){ boot.style.display = "none"; }, 800); }
    root.style.overflow = "";
    startReveal(); scramble();
  }
  if(reduce || !boot){
    if(boot) boot.style.display = "none";
    startReveal();
  } else {
    root.style.overflow = "hidden";
    setTimeout(finishBoot, 2500);
  }

  /* ---------- background colour shift + scroll progress ---------- */
  var secs = [
    {el: document.querySelector(".hero"), p: [228,262,200]},
    {el: document.getElementById("app"), p: [250,200,290]},
    {el: document.getElementById("how"), p: [272,318,215]},
    {el: document.getElementById("threats"), p: [350,18,295]},
    {el: document.getElementById("stack"), p: [190,165,222]},
    {el: document.querySelector("footer"), p: [228,262,200]}
  ].filter(function(s){ return s.el; });
  var prog = document.getElementById("prog");
  var aur = document.getElementById("aurora"), floorEl = document.getElementById("floor");
  var hs = secs.length ? secs[0].p.slice() : [228,262,200], sp = 0, lastSet = "";

  function targetPal(){
    var mid = window.innerHeight * 0.5, i = 0, tops = [], last = secs.length - 1;
    for(var k=0;k<secs.length;k++){ tops.push(secs[k].el.getBoundingClientRect().top - mid); if(tops[k] <= 0) i = k; }
    if(i >= last) return secs[last].p.slice();
    var t = (0 - tops[i]) / (tops[i+1] - tops[i]);
    t = Math.max(0, Math.min(1, t)); t = t * t * (3 - 2 * t);
    return secs[i].p.map(function(v, j){ return v + (secs[i+1].p[j] - v) * t; });
  }
  function update(smooth){
    var tgt = targetPal();
    hs = hs.map(function(v, j){ return smooth ? v + (tgt[j] - v) * 0.06 : tgt[j]; });
    var max = root.scrollHeight - window.innerHeight;
    var p = max > 0 ? Math.min(1, Math.max(0, (window.pageYOffset || 0) / max)) : 0;
    sp = smooth ? sp + (p - sp) * 0.08 : p;
    var s = hs[0].toFixed(1) + "," + hs[1].toFixed(1) + "," + hs[2].toFixed(1) + "," + sp.toFixed(3);
    if(s !== lastSet && aur){
      aur.style.setProperty("--h1", hs[0].toFixed(1)); aur.style.setProperty("--h2", hs[1].toFixed(1));
      aur.style.setProperty("--h3", hs[2].toFixed(1)); aur.style.setProperty("--sp", sp.toFixed(3));
      lastSet = s;
    }
    if(prog) prog.style.transform = "scaleX(" + p.toFixed(4) + ")";
  }
  update(false);

  /* ---------- cyber rain canvas ---------- */
  var rain = document.getElementById("rain");
  var ctx = rain && rain.getContext ? rain.getContext("2d") : null;
  var W = 0, H = 0, fs = 16, colW = 22, cols = [], rgb = "124,144,255", dark = false;
  var CH = "01ABCDEF0123456789<>/#$%{}[]";

  function readTheme(){
    var c = getComputedStyle(root).getPropertyValue("--accent").trim();
    if(/^#[0-9a-f]{6}$/i.test(c)) rgb = parseInt(c.slice(1,3),16) + "," + parseInt(c.slice(3,5),16) + "," + parseInt(c.slice(5,7),16);
    if(floorEl) floorEl.style.setProperty("--arg", rgb);
    var t = root.getAttribute("data-theme");
    dark = t ? t === "dark" : !!(window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
  }
  function resize(){
    if(!ctx) return;
    var dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    W = window.innerWidth; H = window.innerHeight;
    rain.width = W * dpr; rain.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var small = W < 700;
    fs = small ? 14 : 16; colW = fs * (small ? 1.8 : 1.4);
    var n = Math.ceil(W / colW); cols = [];
    for(var i=0;i<n;i++) cols.push({y: Math.random() * (H / fs), sp: 0.18 + Math.random() * 0.4, len: 8 + Math.floor(Math.random() * 12)});
  }
  function drawRain(now, dt, mul){
    ctx.clearRect(0, 0, W, H);
    ctx.font = fs + "px 'JetBrains Mono', monospace";
    var rows = H / fs, base = dark ? 0.4 : 0.24, tick = Math.floor(now / 260);
    for(var c=0;c<cols.length;c++){
      var d = cols[c];
      d.y += d.sp * mul * dt / 33;
      if(d.y - d.len > rows){ d.y = -Math.random() * 12; d.sp = 0.18 + Math.random() * 0.4; d.len = 8 + Math.floor(Math.random() * 12); }
      for(var k=0;k<d.len;k++){
        var row = Math.floor(d.y) - k;
        if(row < 0 || row > rows) continue;
        var a = (1 - k / d.len) * base;
        ctx.fillStyle = "rgba(" + rgb + "," + a.toFixed(3) + ")";
        ctx.fillText(CH.charAt((c * 31 + row * 17 + tick) % CH.length), c * colW, row * fs);
      }
    }
  }
  readTheme(); resize();
  window.__readTheme = readTheme;
  window.addEventListener("resize", function(){ resize(); update(false); });
  var themeBtn = document.getElementById("theme");
  if(themeBtn) themeBtn.addEventListener("click", function(){ setTimeout(readTheme, 30); });
  if(window.matchMedia){ var mq = matchMedia("(prefers-color-scheme: dark)"); if(mq.addEventListener) mq.addEventListener("change", readTheme); }

  /* ---------- main loop: scroll velocity blur, colour shift, rain ---------- */
  var lastY = window.pageYOffset || 0, vel = 0, lastDraw = 0, frameN = 0, lastVb = "";
  function frame(now){
    requestAnimationFrame(frame);
    if(document.hidden) return;
    frameN++;
    var y = window.pageYOffset || 0, dy = y - lastY; lastY = y;
    vel += (dy - vel) * 0.25;
    var vb = Math.min(Math.abs(vel) * 0.04, 1.2);
    var vbs = vb < 0.15 ? "0px" : vb.toFixed(1) + "px";
    if(vbs !== lastVb){ root.style.setProperty("--vb", vbs); lastVb = vbs; }
    update(true);
    if(floorEl) floorEl.style.backgroundPosition = "0px " + (y * 0.35 + now * 0.012).toFixed(1) + "px";
    if(ctx && now - lastDraw > 32){
      if(frameN % 90 === 0) readTheme();
      drawRain(now, Math.min(now - lastDraw, 100), 1 + Math.min(Math.abs(vel) * 0.08, 4));
      lastDraw = now;
    }
  }
  if(reduce){
    var ticking = false;
    window.addEventListener("scroll", function(){
      if(ticking) return; ticking = true;
      requestAnimationFrame(function(){ ticking = false; update(false); });
    }, {passive:true});
  } else {
    requestAnimationFrame(frame);
  }
})();

/* pointer-following glow on cards and tiles */
(function(){
  var sel = ".pill,.anchor,.check,.drop,.filecard,.threat,.stack .col,#log li";
  document.addEventListener("pointermove", function(e){
    if(e.pointerType !== "mouse" || !e.target.closest) return;
    var t = e.target.closest(sel); if(!t) return;
    var r = t.getBoundingClientRect();
    t.style.setProperty("--mx", (e.clientX - r.left) + "px");
    t.style.setProperty("--my", (e.clientY - r.top) + "px");
  }, {passive:true});
})();

/* longer explanations that open when you hover (or tap) a threat or a pipeline step */
(function(){
  var THREATS = {
    "Document tampering": [
      "Tampering means someone changes a document after it was signed, for example raising an amount from INR 2,50,000 to 25,00,000. A digital signature is made over the document's hash, so even a one-character change produces a completely different SHA-256 hash and the signature no longer matches.",
      "The backend recomputes the SHA-256 hash and compares it with the signed digest. A mismatch is flagged as high risk and written to the audit log."
    ],
    "Compromised signing key": [
      "A private key is stolen or copied, so an attacker can create signatures that are mathematically valid. Signature verification alone says everything is fine. The giveaway is behavior: signing from a new device or place, at odd hours, or in sudden bursts.",
      "Isolation Forest and XGBoost compare each signing event with the signer's normal pattern, and SHAP shows which signals pushed the risk score up."
    ],
    "Replay attacks": [
      "An attacker captures a genuine signed request and sends it again to repeat an approval, such as a payment. The signature is still valid because the content has not changed, so the signature check passes.",
      "Nonces and timestamps are checked against earlier requests. A request that has been seen before is flagged as replayed."
    ],
    "Abnormal signing activity": [
      "These are unusual patterns around signing: many signatures in a short time, activity outside working hours, or unfamiliar devices and IP ranges. None of them breaks a signature on its own, but together they suggest misuse.",
      "Anomaly detection learns each signer's usual pattern, scores how far a new event strays from it, and lists the reasons."
    ]
  };
  var STEPS = {
    "Optimize": [
      "Out of every signal the system could look at, QUBO feature selection picks the smallest set that still separates normal signing from attacks.",
      "A classical simulated-annealing solver does the search, so no quantum hardware is needed and the models stay fast."
    ],
    "Upload": [
      "You provide a PDF or another signed document. In the planned backend the file goes to FastAPI, which keeps the original bytes so every later check runs on exactly what was signed.",
      "The file is read first, then handed to the verification step with its hash."
    ],
    "Verify": [
      "The SHA-256 hash is recomputed, then the Python cryptography library checks the RSA or ECDSA signature against the signer's public key. Available certificate details, such as issuer and expiry, are read too.",
      "Result: valid, invalid, hash mismatch, or certificate problem."
    ],
    "Analyze": [
      "This step looks at how the signing happened: device, IP address, time of day and recent activity. Isolation Forest finds unusual events and XGBoost classifies them.",
      "QUBO with simulated annealing picks which features are worth using, so the models stay fast and focused."
    ],
    "Score": [
      "The verification result and the behavior analysis are combined into one risk score from 0 to 100, with a decision: allow, send to review, or block.",
      "SHAP explains which issues contributed most, so a reviewer can see why."
    ],
    "Record": [
      "The result is saved to the database, SQLite to start. If chosen, only the document hash, score and timestamp are anchored on an EVM testnet through a Solidity contract.",
      "Keeping the data small keeps blockchain costs low while the record stays tamper-evident."
    ]
  };

  function build(host, tb, data, label){
    var more = document.createElement("div"); more.className = "more";
    var inn = document.createElement("div"); inn.className = "more-in";
    var p1 = document.createElement("p"); p1.textContent = data[0];
    var h = document.createElement("h4"); h.textContent = label;
    var p2 = document.createElement("p"); p2.style.marginTop = "4px"; p2.textContent = data[1];
    inn.appendChild(p1); inn.appendChild(h); inn.appendChild(p2);
    more.appendChild(inn); tb.appendChild(more);
    host.setAttribute("tabindex", "0");
    host.addEventListener("click", function(){
      if(window.matchMedia && matchMedia("(hover:none)").matches) host.classList.toggle("open");
    });
  }

  document.querySelectorAll(".threat").forEach(function(t){
    var h3 = t.querySelector("h3"), tb = t.children[1];
    if(!h3 || !tb) return;
    var d = THREATS[h3.textContent.trim()]; if(!d) return;
    tb.classList.add("tb");
    build(t, tb, d, "How Q-SIGNGUARD catches it");
  });
  document.querySelectorAll(".flow li").forEach(function(li){
    var b = li.querySelector("b"); if(!b) return;
    var d = STEPS[b.textContent.trim()]; if(!d) return;
    var tb = document.createElement("div"); tb.className = "tb";
    while(li.firstChild) tb.appendChild(li.firstChild);
    li.appendChild(tb);
    build(li, tb, d, "What happens");
  });
})();

/* animated theme switch: a circle of the new theme grows out from the button */
(function(){
  var root = document.documentElement, btn = document.getElementById("theme");
  if(!btn) return;
  var reduce = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
  var mq = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  if(!root.getAttribute("data-theme")) root.setAttribute("data-theme", mq && mq.matches ? "dark" : "light");
  var ring = document.createElement("div"); ring.id = "ripple"; ring.setAttribute("aria-hidden", "true");
  document.body.appendChild(ring);
  var busy = false;

  function apply(next){
    root.setAttribute("data-theme", next);
    if(window.__readTheme) window.__readTheme();
    btn.setAttribute("aria-label", next === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }

  window.__themeSwitch = function(e){
    if(busy) return;
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    if(reduce){ apply(next); return; }
    var rc = btn.getBoundingClientRect();
    var fromPointer = e && e.detail > 0 && typeof e.clientX === "number";
    var x = fromPointer ? e.clientX : rc.left + rc.width / 2;
    var y = fromPointer ? e.clientY : rc.top + rc.height / 2;
    var r = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
    var dur = 950, ease = "cubic-bezier(.65,0,.2,1)";
    busy = true;

    var reverse = next === "dark";
    ring.style.left = x + "px"; ring.style.top = y + "px";
    try{
      ring.animate(reverse ? [
        {width:(2 * r) + "px", height:(2 * r) + "px", opacity:0, offset:0},
        {opacity:1, offset:0.25},
        {width:"0px", height:"0px", opacity:1, offset:1}
      ] : [
        {width:"0px", height:"0px", opacity:1, offset:0},
        {opacity:1, offset:0.75},
        {width:(2 * r) + "px", height:(2 * r) + "px", opacity:0, offset:1}
      ], {duration:dur, easing:ease});
    }catch(err){}

    if(document.startViewTransition){
      root.classList.toggle("vt-reverse", reverse);
      var vt = document.startViewTransition(function(){ apply(next); });
      vt.ready.then(function(){
        try{
          var from = "circle(0px at " + x + "px " + y + "px)", to = "circle(" + r + "px at " + x + "px " + y + "px)";
          root.animate(
            {clipPath: reverse ? [to, from] : [from, to]},
            {duration:dur, easing:ease, pseudoElement: reverse ? "::view-transition-old(root)" : "::view-transition-new(root)"}
          );
        }catch(err){}
      }).catch(function(){});
      var done = function(){ busy = false; root.classList.remove("vt-reverse"); };
      vt.finished.then(done, done);
    } else {
      root.classList.add("theme-fade");
      apply(next);
      setTimeout(function(){ root.classList.remove("theme-fade"); busy = false; }, 850);
    }
  };
})();

(function(){
var $=function(i){return document.getElementById(i)};
var KEY="qsg.history.v1",H=[],q="",fl="all",seen={};
try{H=JSON.parse(localStorage.getItem(KEY)||"[]")}catch(e){H=[]}
function save(){try{localStorage.setItem(KEY,JSON.stringify(H))}catch(e){}}
function esc(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML}
function mk(id,pane,before){var d=document.createElement("div");d.id=id;var p=$(pane);before?p.insertBefore(d,$(before)):p.appendChild(d)}
mk("certPanel","pane1");mk("ctxPanel","pane2");mk("quboPanel","pane2");mk("xaiPanel","pane3");mk("txCard","pane4","log");mk("ipPanel","pane2","quboPanel");
function put(id,key,html){if(seen[id]===key)return;seen[id]=key;var e=$(id);e.innerHTML=html;if(e.firstElementChild)e.firstElementChild.classList.add("qin")}
function cards(rows){return rows.map(function(r){return '<div class="card '+(r[3]?"bad":"ok")+'"><small>'+r[0]+'</small><b>'+r[1]+'</b><small>'+r[2]+'</small></div>'}).join("")}
var FEAT=[["Replayed nonce",1],["Key location",1],["Signing burst",1],["IP mismatch",1],["New device",1],["Odd hours",1],["Geo-velocity",1],["Document size",0],["Signer tenure",0],["Cert issuer age",0],["Key age",0],["File type",0]];
var NEXT={ok:"Allow the signing and keep the result in the audit log.",warn:"Hold the approval, confirm with the signer through a second channel, then decide in the review queue.",bad:"Block the signing, rotate the signing key, alert the key owner and keep this record as evidence."};

window.__qsgPane=function(st,r){
  if(!st.file)return;
  var s=st.sig,o=st.outcome;lastR={st:st,r:r};
  if(st.step===1){
    var ex=o==="expired";
    put("certPanel","c"+o+st.file.hash,'<div class="panel"><h3>Certificate details</h3><p class="sub2">Simulated until the Python backend returns real values. Only the SHA-256 hash is computed in your browser.</p><div class="kv">'+cards([
      ["Signer","CN=R. Mehta, Finance Controller","Certificate subject",0],
      ["Issuer","Demo Root CA G2","Trusted root in this demo",0],
      ["Valid until",ex?"12 Sep 2026 (expired)":"31 Mar 2027",ex?"Expired last month":"Currently valid",ex],
      ["Algorithm","RSA-2048 with SHA-256","ECDSA P-256 is also supported",0],
      ["Chain",o==="invalid"?"Could not be built":"Leads to trusted root",o==="invalid"?"Public key did not verify":"Every link checked",o==="invalid"],
      ["Digest check",o==="hash"?"Does not match":"Matches","Recomputed SHA-256 vs signed digest",o==="hash"]])+'</div></div>');
  }
  if(st.step===2){
    var k=Object.keys(s).filter(function(x){return s[x]}).join();
    if(ipState==="idle")lookIp();
    put("ctxPanel","x"+k,'<div class="panel"><h3>Signing context</h3><p class="sub2">Simulated activity for this signature, compared with the signer\'s usual behavior.</p><div class="kv">'+cards([
      ["Signer","R. Mehta, Finance Controller","Usual: same signer",0],
      ["Device",s.device?"New: Firefox on Linux":"Registered laptop","Usual: registered laptop",s.device],
      ["IP and location",(s.ip||s.key)?"185.220.x.x, Lagos, NG":"103.21.x.x, Delhi, IN","Usual: Delhi, IN",s.ip||s.key],
      ["Timestamp",s.hours?"03:12 IST":"10:42 IST","Usual: 09:00 to 19:00 IST",s.hours],
      ["Nonce",s.replay?"Seen before: replayed":"Fresh, never seen","Usual: unique per request",s.replay],
      ["Signing rate",s.burst?"14 signatures in 2 min":"1 signature in 10 min","Usual: 1 to 2 per 10 min",s.burst]])+'</div></div>');
    var d="";for(var i=0;i<=24;i++)d+=(i?"L":"M")+(i*10)+","+(8+54*Math.exp(-i/6)+(i%4===3?3:0)).toFixed(1)+" ";
    put("quboPanel","q",'<div class="panel"><h3>QUBO feature selection</h3><p class="sub2">Simulated annealing keeps 7 of 12 features, so the models stay fast and focused. Simulated result.</p><div class="fchips">'+FEAT.map(function(f){return '<span class="fchip'+(f[1]?" keep":"")+'">'+(f[1]?"Kept: ":"Dropped: ")+f[0]+'</span>'}).join("")+'</div><svg class="spark" viewBox="0 0 240 70" preserveAspectRatio="none" role="img" aria-label="Energy falling over 24 annealing steps"><path pathLength="100" d="'+d+'"/></svg><p class="sub2" style="margin:6px 0 0">Energy over 24 annealing steps</p></div>');
  }
  if(st.step===3){
    var pos=r.items.slice().sort(function(a,b){return b.w-a.w}).map(function(x){return [x.name,x.w]});
    var neg=[["Valid signature",o==="valid",-8],["Registered device",!s.device,-6],["Working hours",!s.hours,-4],["Fresh nonce",!s.replay,-6]].filter(function(x){return x[1]}).map(function(x){return [x[0],x[2]]});
    var conf=r.items.length?Math.min(96,62+Math.round(r.raw/2)):92;
    put("xaiPanel","p"+r.score+o+Object.keys(s).filter(function(x){return s[x]}).join(),'<div class="panel"><h3>Feature contributions</h3><p class="sub2">Illustrative SHAP-style view. Real values will come from the XGBoost model in the backend.</p><ul class="contrib">'+pos.concat(neg).map(function(x){return '<li><span>'+x[0]+'</span><span class="tr"><i style="--c:var(--'+(x[1]>0?"bad":"ok")+')" data-w="'+Math.round(Math.abs(x[1])/50*100)+'"></i></span><span class="v">'+(x[1]>0?"+":"")+x[1]+'</span></li>'}).join("")+'</ul><div class="kv">'+cards([["Model confidence",conf+"%","Simulated",0],["Recommended next step",NEXT[r.level],"For the reviewer",r.level!=="ok"]])+'</div><div class="row" style="margin-top:14px"><button type="button" id="rpJson">Download report (JSON)</button><button type="button" id="rpPrint">Print or save as PDF</button></div></div>');
    requestAnimationFrame(function(){document.querySelectorAll("#xaiPanel .tr i").forEach(function(b){b.style.width=b.getAttribute("data-w")+"%"})});
  }
};

/* ----- blockchain transaction card ----- */
function showTx(d){
  var el=$("txCard");
  if(!d.anchored){el.innerHTML="";return}
  var head='<div class="panel qin"><h3>Blockchain transaction</h3>';
  el.innerHTML=head+'<p class="sub2"><span class="st warn"><i class="spin"></i>Pending</span> Waiting for confirmation (simulated)</p></div>';
  setTimeout(function(){
    var blk=5000000+parseInt(d.hash.slice(0,6),16)%900000;
    el.innerHTML=head+'<p class="sub2"><span class="st ok">Success</span> Simulated confirmation. Nothing was written on-chain.</p><div class="kv"><div class="card ok"><small>Network</small><b>Sepolia testnet</b></div><div class="card ok"><small>Block</small><b>#'+blk+'</b></div><div class="card ok"><small>Anchored data</small><b>Hash, score, timestamp</b></div></div><div class="card ok" style="margin-top:10px"><small>Transaction hash</small><b class="mono">'+d.tx+'</b></div><p class="note"><a href="https://sepolia.etherscan.io/tx/'+d.tx+'" target="_blank" rel="noopener">Open in explorer</a> (resolves once the backend anchors it for real)</p></div>';
  },1400);
}

/* ----- dashboard, history, review queue ----- */
function cnt(l){return H.filter(function(x){return x.level===l}).length}
function row(x,inQ){
  var c={ALLOW:"ok",REVIEW:"warn",BLOCK:"bad"}[x.level];
  var stt=x.review?(x.review==="approved"?"Approved by reviewer":"Rejected by reviewer"):(x.level==="ALLOW"?"Auto-allowed":"Awaiting review");
  return '<li class="hrow"><span class="st '+c+'">'+x.level+' '+x.score+'</span><b>'+esc(x.name)+'</b><div class="act">'+(inQ&&canRev()?'<button type="button" class="primary" data-id="'+x.id+'" data-a="approved">Approve</button><button type="button" data-id="'+x.id+'" data-a="rejected">Reject</button>':'')+'</div><span class="m">'+x.hash.slice(0,12)+'… · '+x.ts.replace("T"," ").slice(0,16)+' UTC · '+stt+(x.tx?' · anchored':'')+'</span></li>';
}
function draw(){
  var avg=H.length?Math.round(H.reduce(function(a,x){return a+x.score},0)/H.length):"–";
  [["stT",H.length],["stA",cnt("ALLOW")],["stR",cnt("REVIEW")],["stB",cnt("BLOCK")],["stV",avg]].forEach(function(p){$(p[0]).textContent=p[1]});
  var list=H.filter(function(x){return (fl==="all"||x.level===fl)&&(!q||(x.name+" "+x.hash+" "+x.level).toLowerCase().indexOf(q)>=0)});
  $("hist").innerHTML=list.length?list.map(function(x){return row(x)}).join(""):'<li class="empty2">'+(H.length?"No saved checks match your search.":"No checks saved yet. Run a check above and press Save result.")+'</li>';
  $("qNote").textContent=canRev()?"Approve or reject items sent to review.":"Sign in as a reviewer to approve or reject.";
  var pend=H.filter(function(x){return x.level!=="ALLOW"&&!x.review});
  $("queue").innerHTML=pend.length?pend.map(function(x){return row(x,true)}).join(""):'<li class="empty2">Nothing is waiting for review.</li>';
}
document.addEventListener("qsg:saved",function(e){var d=e.detail;d.id=Date.now()+Math.random().toString(36).slice(2,6);H.unshift(d);H=H.slice(0,200);save();draw();showTx(d);toast("Saved to audit log")});
$("hq").addEventListener("input",function(e){q=e.target.value.trim().toLowerCase();draw()});
$("hf").addEventListener("click",function(e){var b=e.target.closest("button");if(!b)return;fl=b.getAttribute("data-f");$("hf").querySelectorAll("button").forEach(function(x){x.setAttribute("aria-pressed",x===b?"true":"false")});draw()});
$("queue").addEventListener("click",function(e){var b=e.target.closest("button[data-id]");if(!b)return;var x=H.filter(function(h){return h.id===b.getAttribute("data-id")})[0];if(x){x.review=b.getAttribute("data-a");save();draw()}});
$("hc").addEventListener("click",function(){if(H.length&&confirm("Clear all saved checks from this browser?")){H=[];save();draw()}});
$("hx").addEventListener("click",function(){
  var rows=[["time_utc","file","sha256","decision","score","review","tx"]].concat(H.map(function(x){return [x.ts,x.name,x.hash,x.level,x.score,x.review||"",x.tx||""]}));
  var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(",")}).join("\n");
  var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));a.download="qsignguard-audit.csv";document.body.appendChild(a);a.click();a.remove();
});
document.addEventListener("pointermove",function(e){var t=e.target.closest&&e.target.closest(".card,.hrow,.stat");if(t){var r=t.getBoundingClientRect();t.style.setProperty("--mx",(e.clientX-r.left)+"px");t.style.setProperty("--my",(e.clientY-r.top)+"px")}});
var ipState="idle",ipInfo=null,lastR=null,pick="signer";
function toast(m){var t=document.createElement("div");t.className="toast qin";t.setAttribute("role","status");t.textContent=m;document.body.appendChild(t);setTimeout(function(){t.remove()},2600)}
function usualIp(){try{return localStorage.getItem("qsg.usualIp")}catch(e){return null}}
function setUsual(v){try{localStorage.setItem("qsg.usualIp",v)}catch(e){}}
function lookIp(){
  ipState="loading";drawIp();
  var ctl=new AbortController();setTimeout(function(){ctl.abort()},6000);
  fetch("https://ipapi.co/json/",{signal:ctl.signal}).then(function(r){return r.json()}).then(function(j){
    if(!j||!j.ip)throw 0;
    ipInfo={ip:j.ip,city:j.city||"",country:j.country_name||"",org:j.org||""};ipState="ok";drawIp();
  }).catch(function(){ipState="fail";drawIp()});
}
function drawIp(){
  var el=$("ipPanel"),h='<div class="panel'+(el.firstChild?'':' qin')+'"><h3>Network and IP check</h3><p class="sub2">Reads your public IP, remembers the first one as the usual IP, and flags a different one. Needs internet access.</p>';
  if(ipState==="loading")h+='<p class="sub2"><span class="st warn"><i class="spin"></i>Looking up</span></p>';
  else if(ipState==="fail")h+='<div class="card bad"><small>Lookup unavailable</small><b>Could not reach the IP service</b><small>The backend will supply the IP in the real system.</small></div><div class="row" style="margin-top:12px"><button type="button" data-a="retry">Try again</button></div>';
  else if(ipState==="ok"){
    var u=usualIp();if(!u){u=ipInfo.ip;setUsual(u)}
    var diff=u!==ipInfo.ip;
    h+='<div class="kv">'+cards([["Current IP",'<span class="mono">'+esc(ipInfo.ip)+'</span>',esc(ipInfo.city+(ipInfo.country?", "+ipInfo.country:"")),0],["Network",esc(ipInfo.org||"Unknown"),"Provider",0],["Usual IP",'<span class="mono">'+esc(u)+'</span>',"First one seen in this browser",0],["Comparison",diff?"Different from usual":"Matches usual",diff?"IP mismatch signal":"No mismatch",diff]])+'</div><div class="row" style="margin-top:12px">'+(diff?'<button type="button" class="primary" data-a="apply">Apply as IP mismatch signal</button>':'')+'<button type="button" data-a="set">Set this as usual IP</button></div>';
  }
  el.innerHTML=h+'</div>';
}
$("ipPanel").addEventListener("click",function(e){
  var b=e.target.closest("button[data-a]");if(!b)return;var a=b.getAttribute("data-a");
  if(a==="retry")lookIp();
  if(a==="set"&&ipInfo){setUsual(ipInfo.ip);drawIp();toast("Usual IP updated")}
  if(a==="apply"){var cb=$("s_ip");if(cb&&!cb.checked){cb.checked=true;cb.dispatchEvent(new Event("change",{bubbles:true}))}toast("IP mismatch signal applied")}
});
document.addEventListener("click",function(e){
  var b=e.target.closest("#rpJson,#rpPrint");if(!b||!lastR)return;
  if(b.id==="rpPrint"){window.print();return}
  var st=lastR.st,r=lastR.r,f=st.file;
  var rep={generated_utc:new Date().toISOString(),file:{name:f.name,size_bytes:f.size,sha256:f.hash,type:f.ext},verification:st.outcome,signals:Object.keys(st.sig).filter(function(k){return st.sig[k]}),risk_score:r.score,decision:{ok:"ALLOW",warn:"REVIEW",bad:"BLOCK"}[r.level],reasons:r.items,note:"Demo report. Verification and behavior values are simulated."};
  var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(rep,null,2)],{type:"application/json"}));a.download="qsignguard-report.json";document.body.appendChild(a);a.click();a.remove();toast("Report downloaded");
});
function getRole(){try{return localStorage.getItem("qsg.role")||"guest"}catch(e){return "guest"}}
function canRev(){var r=getRole();return r==="reviewer"||r==="admin"}
function who(){var r=getRole();$("whoBtn").textContent=r==="guest"?"Sign in":r.charAt(0).toUpperCase()+r.slice(1)+" · Sign out"}
$("whoBtn").addEventListener("click",function(){
  if(getRole()==="guest"){$("authErr").hidden=true;$("authDlg").showModal()}
  else{try{localStorage.setItem("qsg.role","guest")}catch(e){}who();draw();toast("Signed out")}
});
$("roleSeg").addEventListener("click",function(e){var b=e.target.closest("button");if(!b)return;pick=b.getAttribute("data-r");$("roleSeg").querySelectorAll("button").forEach(function(x){x.setAttribute("aria-pressed",x===b?"true":"false")})});
$("authCancel").addEventListener("click",function(){$("authDlg").close()});
$("authGo").addEventListener("click",function(){
  if(!/^\S+@\S+\.\S+$/.test($("authMail").value.trim())||!$("authPw").value){$("authErr").hidden=false;return}
  try{localStorage.setItem("qsg.role",pick);localStorage.setItem("qsg.api",$("authApi").value.trim())}catch(e){}
  $("authDlg").close();who();draw();toast("Signed in as "+pick+" (demo)");
});
who();
draw();
})();
