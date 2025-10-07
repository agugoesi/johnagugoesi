// CyberSecure Trainer v2 - script.js (fixed: DOMContentLoaded safe)
// All code runs after DOM is ready, avoiding null element errors.

document.addEventListener('DOMContentLoaded', () => {
  try {
    const qs = s => document.querySelector(s);
    const qsa = s => Array.from(document.querySelectorAll(s));

    // DOM anchors (safe to query now)
    const ownerInput = qs('#ownerInput');
    const usageSelect = qs('#usageSelect');
    const userNamePreview = qs('#userNamePreview');

    const pwd = qs('#password');
    const feedback = qs('#feedback');
    const meterBar = qs('#meterBar');
    const tipsList = qs('#tips');
    const generateBtn = qs('#generateBtn');

    const emailBox = qs('#emailBox');
    const explain = qs('#explain');
    const progress = qs('#progress');
    const correctCountEl = qs('#correctCount');

    const fab = qs('#fab');
    const themeSelect = qs('#themeSelect');
    const themePicker = qs('#themePicker');

    if (!ownerInput || !pwd || !emailBox) {
      console.error('Essential elements missing. Check that index.html has required IDs.');
      return;
    }

    // ---------------- Persistent settings ----------------
    if (localStorage.getItem('cst_user')) {
      ownerInput.value = localStorage.getItem('cst_user');
      if (userNamePreview) userNamePreview.textContent = localStorage.getItem('cst_user');
    }
    if (usageSelect) usageSelect.value = localStorage.getItem('cst_usage') || 'personal';
    if (themeSelect) themeSelect.value = localStorage.getItem('cst_theme') || 'default';

    // save when changed
    ownerInput.addEventListener('change', () => {
      const name = ownerInput.value.trim() || 'Guest';
      localStorage.setItem('cst_user', name);
      if (userNamePreview) userNamePreview.textContent = name;
    });
    if (usageSelect) usageSelect.addEventListener('change', () => {
      localStorage.setItem('cst_usage', usageSelect.value);
    });

    // ---------------- puff helper ----------------
    function doPuff(el){
      if(!el) return;
      el.classList.remove('puff');
      void el.offsetWidth;
      el.classList.add('puff');
      el.addEventListener('animationend', () => el.classList.remove('puff'), {once:true});
    }

    // ---------------- password analysis/generator ----------------
    function entropyEstimate(pw){
      let charset = 0;
      if (/[a-z]/.test(pw)) charset += 26;
      if (/[A-Z]/.test(pw)) charset += 26;
      if (/[0-9]/.test(pw)) charset += 10;
      if (/[^A-Za-z0-9]/.test(pw)) charset += 32;
      if (charset === 0) return 0;
      const bits = Math.log2(charset) * pw.length;
      return Math.round(bits);
    }
    function analyzePassword(p){
      const suggestions = [];
      let score = 0;
      if (p.length >= 12) score += 2;
      else if (p.length >= 8) score += 1;
      if (/[A-Z]/.test(p)) score++;
      if (/[a-z]/.test(p)) score++;
      if (/[0-9]/.test(p)) score++;
      if (/[^A-Za-z0-9]/.test(p)) score++;

      if (score >= 5) score = 5;
      else if (score <= 0) score = 0;

      if (p.length < 12) suggestions.push('Use at least 12 characters.');
      if (!/[A-Z]/.test(p)) suggestions.push('Add uppercase letters.');
      if (!/[a-z]/.test(p)) suggestions.push('Add lowercase letters.');
      if (!/[0-9]/.test(p)) suggestions.push('Add numbers.');
      if (!/[^A-Za-z0-9]/.test(p)) suggestions.push('Add symbols (e.g. !@#$%).');
      if (/password|1234|qwerty|admin|letmein/i.test(p)) suggestions.push('Avoid common words or patterns.');

      return {score, suggestions, entropy: entropyEstimate(p)};
    }

    const levels = ["Very Weak","Weak","Fair","Good","Strong","Excellent"];

    if (pwd) {
      pwd.addEventListener('input', () => {
        const p = pwd.value;
        const r = analyzePassword(p);
        const s = r.score;
        const pct = Math.round((s/5)*100);
        if (meterBar) meterBar.style.width = pct + '%';
        feedback.textContent = `Strength: ${levels[s]} • Entropy ≈ ${r.entropy} bits`;
        feedback.style.color = ['#ff4d4d','#ff944d','#ffcc00','#99cc00','#66ff66','#00a1ff'][s];

        tipsList.innerHTML = '';
        r.suggestions.slice(0,5).forEach(t => {
          const li = document.createElement('li'); li.textContent = t;
          tipsList.appendChild(li);
        });
      });
    }

    // generator
    if (generateBtn) {
      generateBtn.addEventListener('click', (ev) => {
        doPuff(ev.currentTarget);
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let out = '';
        for (let i=0;i<16;i++) out += chars[Math.floor(Math.random()*chars.length)];
        pwd.value = out;
        pwd.dispatchEvent(new Event('input'));
        try { navigator.clipboard.writeText(out); } catch(e){}
      });
    }

    // ---------------- phishing quiz (manual Next) ----------------
    const emails = [
      { id:'e1', text: "From: it-support@pau-edu.ng\nSubject: Reset Your Password\nDear user, click the link now: http://pau-internal.reset.example.com\n(Immediate action required)", real:false, explain:"Suspicious sender domain and urgent request; don't click links." },
      { id:'e2', text: "From: accounts@pau.edu.ng\nSubject: Library fine cleared\nYour book fine has been cleared. Please login if you want details.", real:true, explain:"Looks legitimate; sender domain matches." },
      { id:'e3', text: "From: bank@secure-login.net\nSubject: Confirm Your BVN\nWe couldn't verify your account. Provide your credentials immediately.", real:false, explain:"Banks won't ask for credentials over email." },
      { id:'e4', text: "From: support@zoom.us\nSubject: New meeting - please join\nHere's your meeting link: https://zoom.us/j/123\n(This one is a normal meeting invite)", real:true, explain:"Normal meeting invite; check link carefully." }
    ];

    let current = 0;
    let correctCount = 0;
    let quizLocked = false;

    function loadEmail(){
      if (!emailBox) return;
      if (current >= emails.length) current = 0;
      const e = emails[current];
      emailBox.textContent = e.text;
      explain.textContent = '';
      if (progress) progress.textContent = `${current+1} / ${emails.length}`;
    }
    let nextBtn = qs('#nextBtn');
    if (!nextBtn) {
      nextBtn = document.createElement('button');
      nextBtn.id = 'nextBtn';
      nextBtn.textContent = 'Next';
      nextBtn.className = 'btn-secondary';
      nextBtn.style.marginLeft = '10px';
      nextBtn.style.display = 'none';
      if (progress && progress.parentNode) progress.parentNode.insertBefore(nextBtn, progress.nextSibling);
    }

    function handleAnswer(choice){
      if (quizLocked) return;
      quizLocked = true;
      const e = emails[current];
      const correct = (choice === e.real);
      if (correct){ correctCount++; if (correctCountEl) correctCountEl.textContent = correctCount; }
      if (explain) explain.textContent = (correct ? "Good job! " : "Not quite. ") + e.explain;
      nextBtn.style.display = 'inline-block';
      doPuff(nextBtn);
    }

    if (nextBtn) nextBtn.addEventListener('click', () => {
      current++;
      nextBtn.style.display = 'none';
      quizLocked = false;
      if (current >= emails.length){
        if (emailBox) emailBox.textContent = 'Quiz complete. Well done — click Next to play again.';
        if (explain) explain.textContent = `You got ${correctCount} out of ${emails.length}.`;
        if (progress) progress.textContent = `${emails.length} / ${emails.length}`;
        current = 0;
        correctCount = 0;
        if (correctCountEl) correctCountEl.textContent = 0;
        return;
      }
      loadEmail();
    });

    const realBtn = qs('#realBtn');
    const phishBtn = qs('#phishBtn');
    if (realBtn) realBtn.addEventListener('click', (ev)=>{ doPuff(ev.currentTarget); setTimeout(()=>handleAnswer(true),50); });
    if (phishBtn) phishBtn.addEventListener('click', (ev)=>{ doPuff(ev.currentTarget); setTimeout(()=>handleAnswer(false),50); });

    loadEmail();

    // ---------------- theme system ----------------
    function applyTheme(name){
      document.body.className = '';
      if (name && name !== 'default') document.body.classList.add(name);
      else document.body.classList.add('default');
      localStorage.setItem('cst_theme', name || 'default');
    }
    applyTheme(localStorage.getItem('cst_theme') || 'default');

    if (themeSelect) {
      themeSelect.addEventListener('change', (e)=>{
        applyTheme(e.target.value);
      });
    }

    // ---------------- vault (PBKDF2 fallback if argon2 missing) ----------------
    const VAULT_KEY = 'cst_vault_v3';
    function arrayBufferToBase64(buf){
      const bytes = new Uint8Array(buf);
      let binary = '';
      for (let i=0;i<bytes.byteLength;i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    }
    function base64ToArrayBuffer(b64){
      const binary = atob(b64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    async function deriveKey(masterPassword, saltBytes){
      const enc = new TextEncoder();
      const passBytes = enc.encode(masterPassword);
      if (window.argon2 && typeof window.argon2.hash === 'function'){
        const res = await window.argon2.hash({ pass: masterPassword, salt: arrayBufferToBase64(saltBytes), time:2, mem:65536, hashLen:32, parallelism:1, type: window.argon2.ArgonType.Argon2id });
        const raw = base64ToArrayBuffer(res.hash);
        return crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
      } else {
        const baseKey = await crypto.subtle.importKey('raw', passBytes, {name:'PBKDF2'}, false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({ name:'PBKDF2', salt: saltBytes, iterations: 200000, hash:'SHA-256' }, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
        return key;
      }
    }

    async function encryptVault(vaultObj, masterPassword){
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(masterPassword, salt);
      const enc = new TextEncoder();
      const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(JSON.stringify(vaultObj)));
      return { salt: arrayBufferToBase64(salt), iv: arrayBufferToBase64(iv), ct: arrayBufferToBase64(ct) };
    }

    async function decryptVault(payload, masterPassword){
      const salt = base64ToArrayBuffer(payload.salt);
      const iv = base64ToArrayBuffer(payload.iv);
      const ct = base64ToArrayBuffer(payload.ct);
      const key = await deriveKey(masterPassword, salt);
      const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
      const dec = new TextDecoder();
      return JSON.parse(dec.decode(pt));
    }

    function saveEncryptedVault(payload){ localStorage.setItem(VAULT_KEY, JSON.stringify(payload)); }
    function loadEncryptedVault(){ const v = localStorage.getItem(VAULT_KEY); return v ? JSON.parse(v) : null; }

    // ---------------- simple FAB panel (offline) ----------------
    (function setupFabPanel(){
      const panel = document.createElement('div');
      panel.id = 'fabPanel';
      panel.style.position = 'fixed';
      panel.style.right = '20px';
      panel.style.bottom = '90px';
      panel.style.width = '320px';
      panel.style.maxWidth = 'calc(100% - 48px)';
      panel.style.background = 'var(--card-bg, #fff)';
      panel.style.border = '1px solid rgba(0,0,0,0.06)';
      panel.style.borderRadius = '12px';
      panel.style.boxShadow = '0 12px 40px rgba(0,0,0,0.12)';
      panel.style.padding = '12px';
      panel.style.zIndex = 2000;
      panel.style.display = 'none';
      panel.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong>CyberSecure Toolbox</strong>
          <button id="fabClose" class="btn-secondary" title="Close">Close</button>
        </div>
        <div style="margin-bottom:8px">
          <label style="font-size:13px;display:block;margin-bottom:6px">Master password (for vault)</label>
          <input id="fabMasterPwd" type="password" placeholder="Enter master password" />
        </div>
        <div style="display:flex;gap:8px;margin-bottom:8px">
          <button id="fabCreate" class="btn">Create Vault</button>
          <button id="fabUnlock" class="btn-secondary">Unlock Vault</button>
        </div>
        <div style="display:flex;gap:8px;margin-bottom:8px">
          <button id="fabSave" class="btn-secondary">Save Vault (Export)</button>
          <button id="fabLoad" class="btn-secondary">Load Vault (Import)</button>
        </div>
        <div style="margin-bottom:8px">
          <label style="font-size:13px;display:block;margin-bottom:6px">Theme</label>
          <select id="fabThemeSelect" style="width:100%"></select>
        </div>
        <div style="margin-top:6px;font-size:13px;color:var(--muted)"><em>Scanner highlights suspicious links on the page; autofill only after explicit confirmation.</em></div>
      `;
      document.body.appendChild(panel);

      const fabClose = panel.querySelector('#fabClose');
      const fabCreate = panel.querySelector('#fabCreate');
      const fabUnlock = panel.querySelector('#fabUnlock');
      const fabSave = panel.querySelector('#fabSave');
      const fabLoad = panel.querySelector('#fabLoad');
      const masterInput = panel.querySelector('#fabMasterPwd');
      const fabThemeSelect = panel.querySelector('#fabThemeSelect');

      // populate theme select
      if (themeSelect) {
        Array.from(themeSelect.options).forEach(opt => {
          const o = document.createElement('option'); o.value = opt.value; o.textContent = opt.textContent;
          fabThemeSelect.appendChild(o);
        });
        fabThemeSelect.value = themeSelect.value;
      }

      let open = false;
      if (fab) {
        fab.addEventListener('click', () => {
          open = !open;
          panel.style.display = open ? 'block' : 'none';
        });
      }
      if (fabClose) fabClose.addEventListener('click', ()=>{ open=false; panel.style.display='none'; });

      if (fabThemeSelect) fabThemeSelect.addEventListener('change', (e)=>{ if (themeSelect) { themeSelect.value = e.target.value; themeSelect.dispatchEvent(new Event('change')); } });

      fabCreate.addEventListener('click', async () => {
        const mp = masterInput.value;
        if (!mp) return alert('Enter a master password for your vault.');
        const v = { meta: { owner: localStorage.getItem('cst_user') || 'Guest', created: Date.now() }, entries: [] };
        const enc = await encryptVault(v, mp);
        saveEncryptedVault(enc);
        alert('Vault created and saved locally (encrypted). You can Export it for backup.');
      });

      fabUnlock.addEventListener('click', async () => {
        const mp = masterInput.value;
        if (!mp) return alert('Enter master password to unlock.');
        const payload = loadEncryptedVault();
        if (!payload) return alert('No vault found. Create one first.');
        try {
          const v = await decryptVault(payload, mp);
          alert('Vault unlocked. Entries: ' + (v.entries.length || 0));
        } catch (err){
          console.error(err);
          alert('Unable to decrypt vault. Check the master password.');
        }
      });

      fabSave.addEventListener('click', () => {
        const payload = loadEncryptedVault();
        if (!payload) return alert('No encrypted vault to export.');
        const blob = new Blob([JSON.stringify(payload)], {type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = 'cst_vault_export.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        alert('Encrypted vault exported as cst_vault_export.json');
      });

      fabLoad.addEventListener('click', ()=> {
        const inp = document.createElement('input'); inp.type='file'; inp.accept='.json,application/json';
        inp.addEventListener('change', (e)=> {
          const f = e.target.files[0];
          if (!f) return;
          const reader = new FileReader();
          reader.onload = ()=> {
            try {
              const obj = JSON.parse(reader.result);
              if (!obj.salt || !obj.iv || !obj.ct) return alert('File does not look like a valid encrypted vault.');
              localStorage.setItem(VAULT_KEY, JSON.stringify(obj));
              alert('Encrypted vault imported. Unlock with your master password to view entries.');
            } catch(err){ alert('Import failed: '+err.message); }
          };
          reader.readAsText(f);
        });
        inp.click();
      });

    })(); // end setupFabPanel

    // quick scan on double-click
    if (fab) {
      fab.addEventListener('dblclick', ()=> {
        doPuff(fab);
        const pwFields = Array.from(document.querySelectorAll('input[type=password]'));
        const links = Array.from(document.querySelectorAll('a[href]'));
        const alerts = [];
        links.forEach(l=>{
          if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(l.href)) alerts.push('IP-based link: '+l.href);
          if (/\.example\.com/.test(l.href)) alerts.push('Demo/example link: '+l.href);
        });
        if (pwFields.length){
          if (confirm('Password fields detected. Do you want to paste a saved password into the first field?')){
            const val = localStorage.getItem('cst_saved_password');
            if (val){
              pwFields[0].value = val;
              alert('Password pasted into first field.');
            } else {
              const np = prompt('No saved quick-password found. Enter one to store for quick use (local only):');
              if (np) localStorage.setItem('cst_saved_password', np);
            }
          }
        } else if (alerts.length){
          alert(alerts.join('\n\n'));
        } else alert('Quick scan: no issues detected.');
      });
    }

    console.log('CyberSecure Trainer initialized (fixed).');
  } catch(err){
    console.error('Initialization error:', err);
    alert('Initialization error: ' + err.message);
  }
}); // DOMContentLoaded
