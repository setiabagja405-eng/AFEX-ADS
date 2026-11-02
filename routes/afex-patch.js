(function () {
  'use strict';
  var BASE = (window.AFEX_BACKEND_URL || 'http://localhost:3000').replace(/\/$/, '');

  var st = document.createElement('style');
  st.textContent =
    '.kyc-face-mode > video.afex-bg-blur{position:absolute!important;left:0!important;top:0!important;right:auto!important;' +
    'width:100%!important;height:100%!important;max-width:none!important;min-width:0!important;aspect-ratio:auto!important;' +
    'border-radius:0!important;transform:scaleX(-1)!important;object-fit:cover!important;z-index:0!important;' +
    'filter:blur(14px) brightness(.55) saturate(1.1)!important;pointer-events:none!important;display:block!important;opacity:1!important;visibility:visible!important}' +
    'div:not(.kyc-face-mode) > video.afex-bg-blur{display:none!important}';
  document.head.appendChild(st);

  function syncBlur() {
    var main = document.getElementById('kyc-video');
    if (!main || !main.parentElement) return;
    var box = main.parentElement;
    var bg = box.querySelector('video.afex-bg-blur');
    if (!box.classList.contains('kyc-face-mode') || !main.srcObject) {
      if (bg && bg.srcObject) { bg.srcObject = null; }
      return;
    }
    if (!bg) {
      bg = document.createElement('video');
      bg.className = 'afex-bg-blur';
      bg.muted = true; bg.autoplay = true; bg.playsInline = true;
      bg.setAttribute('playsinline', ''); bg.setAttribute('aria-hidden', 'true');
      box.insertBefore(bg, box.firstChild);
    }
    if (bg.srcObject !== main.srcObject) {
      bg.srcObject = main.srcObject;
      var p = bg.play(); if (p && p.catch) p.catch(function () {});
    }
  }
  setInterval(syncBlur, 300);

  var LS = 'afex_kyc_synced_v1';
  function jget(k, d) { try { return JSON.parse(localStorage.getItem(k)) || d; } catch (e) { return d; } }
  function jset(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  var synced = jget(LS, {});
  var busy = {};

  function tgInit() { try { return window.Telegram.WebApp.initData || ''; } catch (e) { return ''; } }
  function uidNow() { try { return typeof userIdStr !== 'undefined' ? String(userIdStr) : ''; } catch (e) { return ''; } }
  function post(path, body) {
    body.initData = tgInit(); body.uid = uidNow();
    return fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json(); });
  }
  function readQueue() {
    try {
      var ls = window._afexLS || window.localStorage;
      var raw = ls.getItem('afex_global_admin_queue');
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }
  function syncKyc(q) {
    if (!tgInit() && !window.AFEX_ALLOW_INSECURE) return;
    q = q || readQueue();
    if (!q || !Array.isArray(q.kycRequests)) return;
    q.kycRequests.forEach(function (k) {
      if (!k || !k.id || busy[k.id]) return;
      var prev = synced[k.id];
      if (prev === undefined) {
        if (!k.photoData || k.photoData.length < 2000) return;
        if (String(k.uid) !== uidNow()) return;
        busy[k.id] = 1;
        post('/api/kyc/submit', { kyc: k }).then(function (r) {
          if (r && (r.ok || r.error === 'uid_mismatch' || r.error === 'bad_photo')) { synced[k.id] = k.status; jset(LS, synced); }
        }).catch(function () {}).then(function () { delete busy[k.id]; });
      } else if (prev !== k.status) {
        busy[k.id] = 1;
        post('/api/kyc/status', { id: k.id, target: k.uid, status: k.status }).then(function (r) {
          if (r && (r.ok || r.error === 'unauthorized')) { synced[k.id] = k.status; jset(LS, synced); }
        }).catch(function () {}).then(function () { delete busy[k.id]; });
      }
    });
  }
  if (typeof window.saveGlobalAdminQueue === 'function') {
    var _save = window.saveGlobalAdminQueue;
    window.saveGlobalAdminQueue = function (q) {
      var r = _save.apply(this, arguments);
      try { syncKyc(q); } catch (e) {}
      return r;
    };
  }
  setInterval(function () { try { syncKyc(); } catch (e) {} }, 6000);
  window.AFEX_KYC_SYNC = syncKyc;
})();
