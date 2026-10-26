#!/usr/bin/env node
'use strict'

// greet-cam: one-shot recorder. Arms on `record.js --out <dir>`, prints
// READY on stdout once the room is clean and the browser is in a known-good
// state, captures the FreeqWorld canvas as JPEG frames + a wire log until
// stopped (SIGTERM / stdin EOF / --timeout), then trims and writes a
// self-contained HTML player. Plain Node 22, no deps.
//
// Protocol (stdout only, exactly these lines):
//   GREETCAM READY <outdir>
//   GREETCAM FAILED <reason>
//   GREETCAM DONE <outdir>/player.html <frameCount> [reason info...]
// Everything else goes to stderr.

const fs = require('fs')
const net = require('net')
const http = require('http')
const path = require('path')
const crypto = require('crypto')
const { spawn } = require('child_process')

function isExec(p) {
  try {
    fs.accessSync(p, fs.constants.X_OK)
    return true
  } catch {
    return false
  }
}

function resolveChromePath() {
  if (process.env.CHROME_BIN && isExec(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN
  }
  if (process.env.GREETCAM_CHROME && isExec(process.env.GREETCAM_CHROME)) {
    return process.env.GREETCAM_CHROME
  }
  const linuxCandidates = ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser']
  for (const candidate of linuxCandidates) {
    if (isExec(candidate)) return candidate
  }
  const macPath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  if (isExec(macPath)) return macPath

  if (process.env.CHROME_BIN) {
    throw new Error(`CHROME_BIN=${process.env.CHROME_BIN} exists but is not executable`)
  }
  throw new Error('Chrome not found. Set CHROME_BIN=/path/to/chrome or install google-chrome/chromium')
}
const CHROME_PATH = resolveChromePath()
const WORLD_BASE = process.env.GREETCAM_WORLD_URL || 'http://127.0.0.1:8787/?freeq=ws://127.0.0.1:8080/irc'
const IRC_HOST = process.env.GREETCAM_IRC_HOST || '127.0.0.1'
const IRC_PORT = Number(process.env.GREETCAM_IRC_PORT || 6667)
const OUT_BASE = process.env.GREETCAM_OUT_BASE || '/tmp'

const CHROME_BOOT_TIMEOUT_MS = 20000
const ACTION_TIMEOUT_MS = 30000
const POLL_MS = 300
const CAMLOG_POLL_MS = 300

// Overlay selectors to hide unconditionally via injected CSS (addendum recon).
const HIDE_SELECTORS_FULL = [
  '#members', '#firststeps', '#landing', '#gate', '#travel', '#idcard',
  '#sparkbook', '#spark-hud', '#lightbox', '#townmap', '#helpcard',
  '#objcard', '#dmpanel', '#nowplaying', 'header',
]
// Default (--chrome=minimal): hide roster + header for sure, keep #transcript
// (it's deliberately absent from HIDE_SELECTORS_FULL). Kept as its own name,
// not just an alias, so we can change our minds on the split later without
// a rewrite -- see hideSelectorsFor().
const HIDE_SELECTORS_MINIMAL = HIDE_SELECTORS_FULL

// ---------------------------------------------------------------------------
// stdout protocol / stderr logging
// ---------------------------------------------------------------------------

function stdoutLine(s) {
  process.stdout.write(s + '\n')
}

function log(...args) {
  const t = new Date().toISOString()
  process.stderr.write(`[${t}] ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}\n`)
}

let readyPrinted = false
let finalPrinted = false

function printReady(outdir) {
  readyPrinted = true
  stdoutLine(`GREETCAM READY ${outdir}`)
}

function printFailed(reason) {
  finalPrinted = true
  stdoutLine(`GREETCAM FAILED ${reason}`)
}

function printDone(playerPath, frameCount, extra, stopReason, mp4Path) {
  finalPrinted = true
  const stoppedField = ` stopped=${stopReason || 'unknown'}`
  let fullExtra = (extra ? extra + stoppedField : stoppedField.trim())
  if (mp4Path) fullExtra += ` mp4:${mp4Path}`
  stdoutLine(`GREETCAM DONE ${playerPath} ${frameCount}${fullExtra ? ' ' + fullExtra : ''}`)
}

// ---------------------------------------------------------------------------
// args
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    out: null,
    channel: '#the-lab',
    timeout: 180,
    setupDeadline: 45,
    chrome: 'minimal',
    at: null,
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--out') out.out = argv[++i]
    else if (a === '--channel') out.channel = argv[++i]
    else if (a === '--timeout') out.timeout = Number(argv[++i])
    else if (a === '--setup-deadline') out.setupDeadline = Number(argv[++i])
    else if (a === '--chrome') out.chrome = argv[++i]
    else if (a === '--at') {
      const [x, y] = String(argv[++i]).split(',').map(Number)
      out.at = { x, y }
    }
  }
  return out
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function randSuffix(n) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let s = ''
  for (let i = 0; i < n; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

function nowStamp() {
  const d = new Date()
  const p = (n, w = 2) => String(n).padStart(w, '0')
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`
}

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`GET ${url} -> ${res.statusCode}`))
          return
        }
        try {
          resolve(JSON.parse(body))
        } catch (e) {
          reject(e)
        }
      })
    })
    req.on('error', reject)
    req.setTimeout(3000, () => req.destroy(new Error('timeout')))
  })
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port
      srv.close(() => resolve(port))
    })
  })
}

// ---------------------------------------------------------------------------
// S1: preflight the room over a plain, short-lived IRC connection
// ---------------------------------------------------------------------------

function stripNickPrefix(n) {
  return n.replace(/^[@+%~&]+/, '')
}

async function preflightRoom(channel) {
  return new Promise((resolve, reject) => {
    const nick = `camcheck-${randSuffix(4)}`
    const socket = net.createConnection({ host: IRC_HOST, port: IRC_PORT })
    let buf = ''
    let registered = false
    let namesRequested = false
    let names = []
    let settled = false
    const deadline = setTimeout(() => fail(new Error('preflight timed out waiting for IRC server')), ACTION_TIMEOUT_MS)

    const fail = (err) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      try {
        socket.destroy()
      } catch {}
      reject(err)
    }
    const done = (val) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      resolve(val)
    }

    socket.on('connect', () => {
      socket.write(`NICK ${nick}\r\n`)
      socket.write(`USER greetcam 0 * :greet cam preflight\r\n`)
    })

    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8')
      let idx
      while ((idx = buf.indexOf('\n')) >= 0) {
        let line = buf.slice(0, idx)
        buf = buf.slice(idx + 1)
        if (line.endsWith('\r')) line = line.slice(0, -1)
        if (!line) continue
        if (line.startsWith('PING')) {
          const token = line.slice(line.indexOf(':') + 1)
          socket.write(`PONG :${token}\r\n`)
        }
        const parts = line.split(' ')
        const numeric = parts[1]
        if (!registered && numeric === '001') {
          registered = true
          if (!namesRequested) {
            namesRequested = true
            socket.write(`NAMES ${channel}\r\n`)
          }
        }
        if (numeric === '353') {
          // :server 353 nick = #chan :nick1 nick2 nick3
          const colonIdx = line.indexOf(':', line.indexOf(' 353 '))
          const listStr = colonIdx >= 0 ? line.slice(colonIdx + 1) : ''
          for (const n of listStr.split(/\s+/).filter(Boolean)) {
            names.push(stripNickPrefix(n))
          }
        }
        if (numeric === '366') {
          socket.write('QUIT :preflight done\r\n')
          setTimeout(() => {
            try {
              socket.end()
              socket.destroy()
            } catch {}
          }, 150)
          done({ nicks: names })
        }
      }
    })

    socket.on('error', (e) => fail(e))
    socket.on('close', () => {
      if (!settled) fail(new Error('preflight socket closed before completion'))
    })
  })
}

// A dirty room -- other people merely present -- is fine and expected; we
// only refuse READY over our own stale ghosts (wanderer-*/greetcam-* nicks
// left behind by a prior run that hasn't ping-timed-out yet), since those
// would put a phantom camera sprite in shot. Anyone else just gets logged
// and recorded as roomAtStart for the run.json report -- presence never
// blocks setup and never counts as contamination (see Addendum 4).
async function runPreflight(channel) {
  const { nicks } = await preflightRoom(channel)
  const ghosts = nicks.filter((n) => /^(wanderer-|greetcam-)/i.test(n))
  if (ghosts.length) {
    throw new Error(`stale camera ghosts still in room: ${ghosts.join(', ')}`)
  }
  const others = nicks.filter((n) => {
    const low = n.toLowerCase()
    return low !== 'brian' && low !== 'greet'
  })
  if (others.length) {
    log('preflight: room not empty, carrying on:', others.join(', '))
  }
  return nicks
}

// ---------------------------------------------------------------------------
// Chrome lifecycle
// ---------------------------------------------------------------------------

function launchChrome(outdir, port) {
  const profileDir = path.join(outdir, 'profile')
  fs.mkdirSync(profileDir, { recursive: true })
  const args = [
    '--headless=new',
    `--user-data-dir=${profileDir}`,
    `--remote-debugging-port=${port}`,
    '--window-size=1920,1080',
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank',
  ]
  log('launching chrome:', CHROME_PATH, args.join(' '))
  const child = spawn(CHROME_PATH, args, { stdio: 'ignore', detached: false })
  fs.writeFileSync(path.join(outdir, 'chrome.pid'), String(child.pid) + '\n')
  child.on('error', (e) => log('chrome process error:', e.message))
  return child
}

async function waitForChrome(port) {
  const deadline = Date.now() + CHROME_BOOT_TIMEOUT_MS
  let lastErr = null
  while (Date.now() < deadline) {
    try {
      const version = await httpGetJson(`http://127.0.0.1:${port}/json/version`)
      if (version) return
    } catch (e) {
      lastErr = e
    }
    await sleep(300)
  }
  throw new Error(`chrome did not come up on CDP port ${port} within ${CHROME_BOOT_TIMEOUT_MS}ms: ${lastErr && lastErr.message}`)
}

async function findPageTarget(port) {
  const list = await httpGetJson(`http://127.0.0.1:${port}/json/list`)
  const page = list.find((t) => t.type === 'page')
  if (!page) throw new Error('no page target found in /json/list')
  return page
}

// killed only by its own positive pid, never a group, never by name.
function killChromePid(pid) {
  if (!pid) return
  try {
    process.kill(pid, 'SIGTERM')
    log('sent SIGTERM to chrome pid', pid)
  } catch (e) {
    if (e.code !== 'ESRCH') log('failed to kill chrome pid', pid, e.message)
  }
}

// ---------------------------------------------------------------------------
// CDP client: minimal JSON-RPC over the built-in WebSocket.
// ---------------------------------------------------------------------------

class CdpClient {
  constructor(ws) {
    this.ws = ws
    this.nextId = 1
    this.pending = new Map()
    this.eventHandlers = new Map()
    ws.addEventListener('message', (ev) => this._onMessage(ev))
  }

  _onMessage(ev) {
    let msg
    try {
      msg = JSON.parse(ev.data)
    } catch {
      return
    }
    if (msg.id !== undefined && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id)
      this.pending.delete(msg.id)
      if (msg.error) reject(new Error(msg.error.message || 'CDP error'))
      else resolve(msg.result)
      return
    }
    if (msg.method) {
      const handlers = this.eventHandlers.get(msg.method)
      if (handlers) for (const h of handlers) h(msg.params || {})
    }
  }

  on(method, fn) {
    if (!this.eventHandlers.has(method)) this.eventHandlers.set(method, [])
    this.eventHandlers.get(method).push(fn)
  }

  send(method, params = {}) {
    const id = this.nextId++
    const payload = JSON.stringify({ id, method, params })
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(payload)
    })
  }

  close() {
    try {
      this.ws.close()
    } catch {}
  }
}

// ---------------------------------------------------------------------------
// Injection payload (Page.addScriptToEvaluateOnNewDocument). Runs before any
// page script, so it can seed localStorage and wrap window.WebSocket before
// the FreeqWorld bundle ever constructs a socket.
// ---------------------------------------------------------------------------

function buildInjectionScript(channel, hideSelectors) {
  const flags = {
    'fimp-first-steps-dismissed': '1',
    'fimp-gate-accepted': '1',
    'fimp-share-offered': '1',
    'fimp-sound': 'off',
  }
  return `
(function() {
  try {
    var flags = ${JSON.stringify(flags)};
    for (var k in flags) { try { localStorage.setItem(k, flags[k]) } catch (e) {} }
  } catch (e) {}

  try {
    var css = ${JSON.stringify(hideSelectors)}.map(function(sel) {
      return sel + ' { display: none !important; visibility: hidden !important; }'
    }).join('\\n') + '\\n.toast { display: none !important; }'
    var style = document.createElement('style')
    style.setAttribute('data-greetcam', '1')
    style.textContent = css
    var attach = function() {
      if (document.head) document.head.appendChild(style)
      else document.documentElement.appendChild(style)
    }
    if (document.head || document.documentElement) attach()
    else document.addEventListener('DOMContentLoaded', attach)
  } catch (e) {}

  window.__camlog = []

  function pushLog(kind, nick, text) {
    try {
      window.__camlog.push({ ts: Date.now(), kind: kind, nick: nick, text: text })
      if (window.__camlog.length > 5000) window.__camlog.shift()
    } catch (e) {}
  }

  // NOTE ON WIRE FORMAT: the original plan assumed the socket carried JSON
  // ServerFrame objects (app.ts's onFrame union) and that we could intercept
  // those directly. It doesn't -- the wire is plain IRC protocol text
  // (NICK/USER/CAP/AUTHENTICATE/JOIN/PRIVMSG/BATCH/...), and app.ts parses
  // that into ServerFrame-shaped state internally, never re-serializing it
  // back out over the socket. Confirmed live via a raw probe on this exact
  // connection: every ev.data was a plain IRC line string, not JSON.
  // So this reads IRC text directly instead of JSON frames. It is a passive
  // OBSERVER, not a transform -- it never rewrites ev.data or constructs a
  // replacement event, so there's no risk of it changing what the app
  // itself renders (the visible #transcript is allowed to show real
  // history; only OUR contamination bookkeeping must ignore it).
  var channel = ${JSON.stringify(channel)}
  var batchIsHistory = {} // batch id -> true if it's a chathistory batch

  function parseTags(rest) {
    var tags = {}
    if (rest.charAt(0) === '@') {
      var sp = rest.indexOf(' ')
      if (sp < 0) return { tags: tags, rest: '' }
      var tagStr = rest.slice(1, sp)
      rest = rest.slice(sp + 1)
      tagStr.split(';').forEach(function(kv) {
        var eq = kv.indexOf('=')
        if (eq >= 0) tags[kv.slice(0, eq)] = kv.slice(eq + 1)
        else tags[kv] = true
      })
    }
    return { tags: tags, rest: rest }
  }

  function observeLine(line) {
    if (!line) return
    var p = parseTags(line)
    var tags = p.tags
    var rest = p.rest
    var nick = null
    if (rest.charAt(0) === ':') {
      var sp = rest.indexOf(' ')
      if (sp < 0) return
      var prefix = rest.slice(1, sp)
      nick = prefix.split('!')[0]
      rest = rest.slice(sp + 1)
    }
    var cmdEnd = rest.indexOf(' ')
    var cmd = cmdEnd >= 0 ? rest.slice(0, cmdEnd) : rest
    var params = cmdEnd >= 0 ? rest.slice(cmdEnd + 1) : ''

    if (cmd === 'BATCH') {
      var tok = params.split(' ')[0]
      if (tok && tok.charAt(0) === '+') {
        var id = tok.slice(1)
        var type = params.split(' ')[1] || ''
        batchIsHistory[id] = /chathistory/.test(type)
      }
      return
    }
    if (cmd === 'JOIN') {
      var joinChan = params.split(' ')[0]
      if (joinChan && joinChan.toLowerCase() === channel.toLowerCase()) {
        pushLog('member-joined', nick, null)
      }
      return
    }
    if (cmd === 'PART' || cmd === 'QUIT') {
      if (nick) pushLog('member-left', nick, null)
      return
    }
    if (cmd === 'PRIVMSG') {
      var target = params.split(' ')[0]
      if (target && target.toLowerCase() === channel.toLowerCase()) {
        var colonIdx = params.indexOf(':')
        var text = colonIdx >= 0 ? params.slice(colonIdx + 1) : ''
        if (tags.batch && batchIsHistory[tags.batch]) {
          pushLog('history-stripped', null, null) // replayed, not speech
        } else {
          pushLog('message', nick, text)
        }
      }
      return
    }
  }

  // Extend (not wrap-as-plain-object) WebSocket so the instance keeps
  // native internal slots -- a synthetic proxy sharing only .prototype throws
  // "TypeError: Illegal invocation" the moment the SDK bundle calls a
  // native method bound to it. We override addEventListener and onmessage
  // to filter out history lines before the app sees them, while maintaining
  // an accurate wire.log.
  var RealWebSocket = window.WebSocket
  class WrappedWebSocket extends RealWebSocket {
    constructor(url, protocols) {
      super(url, protocols)
      this.__appHandlers = []
      var self = this
      RealWebSocket.prototype.addEventListener.call(this, 'message', function(ev) {
        try {
          if (typeof ev.data !== 'string') return
          var lines = ev.data.split('\\r\\n')
          for (var i = 0; i < lines.length; i++) observeLine(lines[i])
          var filtered = self.__filterLines(lines)
          if (filtered && filtered.length > 0) {
            var filteredText = filtered.join('\\r\\n')
            var syntheticEv = new MessageEvent('message', { data: filteredText })
            for (var j = 0; j < self.__appHandlers.length; j++) {
              try { self.__appHandlers[j].call(self, syntheticEv) } catch (e) {}
            }
          }
        } catch (e) {}
      })
    }
    __filterLines(lines) {
      var filtered = []
      var localHistory = {}
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i]
        if (!line) continue
        var p = parseTags(line)
        var tags = p.tags
        var rest = p.rest
        if (rest.charAt(0) === ':') {
          var sp = rest.indexOf(' ')
          if (sp < 0) {
            filtered.push(line)
            continue
          }
          rest = rest.slice(sp + 1)
        }
        var cmdEnd = rest.indexOf(' ')
        var cmd = cmdEnd >= 0 ? rest.slice(0, cmdEnd) : rest
        var params = cmdEnd >= 0 ? rest.slice(cmdEnd + 1) : ''

        if (cmd === 'BATCH') {
          var tok = params.split(' ')[0]
          if (tok && tok.charAt(0) === '+') {
            var id = tok.slice(1)
            var type = params.split(' ')[1] || ''
            if (/chathistory/.test(type)) {
              batchIsHistory[id] = true
              localHistory[id] = true
              continue
            }
          } else if (tok && tok.charAt(0) === '-') {
            var closingId = tok.slice(1)
            if (localHistory[closingId] || batchIsHistory[closingId]) {
              delete localHistory[closingId]
              delete batchIsHistory[closingId]
              continue
            }
          }
        } else if (cmd === 'PRIVMSG') {
          if (tags.batch && (batchIsHistory[tags.batch] || localHistory[tags.batch])) {
            continue
          }
        }
        filtered.push(line)
      }
      return filtered
    }
    addEventListener(type, fn, options) {
      if (type === 'message') {
        var once = options && (typeof options === 'boolean' ? options : options.once)
        if (once) {
          var self = this
          var wrapper = function(ev) {
            self.removeEventListener(type, wrapper)
            fn.call(self, ev)
          }
          wrapper.__original = fn
          this.__appHandlers.push(wrapper)
        } else {
          this.__appHandlers.push(fn)
        }
      } else {
        RealWebSocket.prototype.addEventListener.call(this, type, fn, options)
      }
    }
    removeEventListener(type, fn) {
      if (type === 'message') {
        for (var i = 0; i < this.__appHandlers.length; i++) {
          if (this.__appHandlers[i] === fn || this.__appHandlers[i].__original === fn) {
            this.__appHandlers.splice(i, 1)
            break
          }
        }
      } else {
        RealWebSocket.prototype.removeEventListener.call(this, type, fn)
      }
    }
  }
  Object.defineProperty(WrappedWebSocket.prototype, 'onmessage', {
    get: function() { return this.__onmessage },
    set: function(fn) {
      if (this.__onmessage) {
        for (var i = 0; i < this.__appHandlers.length; i++) {
          if (this.__appHandlers[i] === this.__onmessage) {
            this.__appHandlers.splice(i, 1)
            break
          }
        }
      }
      this.__onmessage = fn
      if (fn) this.__appHandlers.push(fn)
    }
  })

  try {
    window.WebSocket = WrappedWebSocket
  } catch (e) {}
})();
`
}

// ---------------------------------------------------------------------------
// FreeqWorld interaction
// ---------------------------------------------------------------------------

async function evalValue(cdp, expression) {
  const res = await cdp.send('Runtime.evaluate', { expression, returnByValue: true })
  return res && res.result && res.result.value
}

async function ensureGuestLogin(cdp) {
  const deadline = Date.now() + ACTION_TIMEOUT_MS
  const clickExpr = `
    (function() {
      const btn = document.getElementById('enter-guest')
      if (!btn) return { ok: false, reason: 'no #enter-guest button' }
      btn.click()
      return { ok: true }
    })()
  `
  let clicked = false
  while (Date.now() < deadline) {
    const value = await evalValue(cdp, clickExpr)
    if (value && value.ok) {
      clicked = true
      break
    }
    await sleep(POLL_MS)
  }
  if (!clicked) throw new Error('failed to click guest login: #enter-guest never appeared')

  while (Date.now() < deadline) {
    const did = await evalValue(cdp, `(window.__fimp && window.__fimp.state) ? window.__fimp.state().did : null`)
    if (did) {
      log('guest identity established:', did)
      return
    }
    await sleep(POLL_MS)
  }
  throw new Error(`guest login did not establish an identity within ${ACTION_TIMEOUT_MS}ms`)
}

async function joinChannelViaDirectory(cdp, channel) {
  const deadline = Date.now() + ACTION_TIMEOUT_MS

  await cdp.send('Runtime.evaluate', {
    expression: `window.dispatchEvent(new KeyboardEvent('keydown', { key: 'g', bubbles: true }))`,
  })
  await sleep(200)

  const joinExpr = `
    (function() {
      const input = document.getElementById('dir-join')
      if (!input) return { ok: false, reason: 'no #dir-join element' }
      input.value = ${JSON.stringify(channel)}
      input.dispatchEvent(new Event('input', { bubbles: true }))
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
      return { ok: true }
    })()
  `
  const joinValue = await evalValue(cdp, joinExpr)
  if (!joinValue || !joinValue.ok) {
    throw new Error(`failed to submit directory join: ${JSON.stringify(joinValue)}`)
  }

  while (Date.now() < deadline) {
    const current = await evalValue(cdp, `(window.__fimp && window.__fimp.state) ? window.__fimp.state().channel : null`)
    if (current === channel) {
      log(`joined ${channel} in FreeqWorld canvas`)
      return
    }
    await sleep(POLL_MS)
  }
  throw new Error(`did not observe FreeqWorld join ${channel} within ${ACTION_TIMEOUT_MS}ms`)
}

async function cleanApp(cdp) {
  // Belt and braces: the injected CSS already hides #firststeps, but click
  // its own dismiss control too in case the panel exists in a state the CSS
  // selector doesn't cover.
  const value = await evalValue(
    cdp,
    `(function() {
      var btn = document.getElementById('firststeps-hide')
      if (btn) { btn.click(); return 'clicked-hide-button' }
      return 'no-button-found'
    })()`,
  )
  log('cleanApp: firststeps-hide ->', value)
}

async function maybeTeleport(cdp, at) {
  if (!at || Number.isNaN(at.x) || Number.isNaN(at.y)) return
  await cdp.send('Runtime.evaluate', {
    expression: `window.__fimp && window.__fimp.teleport && window.__fimp.teleport(${at.x}, ${at.y})`,
  })
  log(`teleported camera to ${at.x},${at.y}`)
}

// ---------------------------------------------------------------------------
// Camera-sprite-out-of-frame trick.
//
// app.ts's camera() (app.ts:1884-1897) is pinned at a fixed {x:0, y:0} only
// when the whole room already fits on screen:
//   if (mapW <= VIEW_W && mapH <= VIEW_H) return { x: 0, y: 0 }
// When that holds, moving our own sprite off the tilemap doesn't scroll the
// view at all -- the room stays framed exactly as it was, just without our
// own sprite/name tag drawn into it. This is the ONLY reason the trick is
// safe: if the room were bigger than the viewport, camera() would instead
// follow this.me, and teleporting away would drag the whole shot with it.
// So we never teleport blind -- we replicate roomFor()'s tile dimensions
// (shared/src/world.ts:201-221, read-only, not imported/modified) for the
// channel we're actually in, and refuse to record at all if the numbers
// don't clear the fit check.
const TILE_PX = 8
const CANVAS_W = 1920
const CANVAS_H = 1080
// LAUNCH_ROOMS channel -> tile dims, mirroring shared/src/world.ts:34-221.
// Any channel not in this table (i.e. every greet-cam test/lab channel)
// falls through to the 26x16 procedural-outskirts default at world.ts:210-211.
const KNOWN_ROOM_DIMS = {
  '#lobby': { w: 40, h: 24 },
  '#freeq-dev': { w: 32, h: 20 },
  '#agents': { w: 30, h: 20 },
  '#music': { w: 30, h: 20 },
  '#archive': { w: 32, h: 20 },
  '#private-demo': { w: 24, h: 16 },
  '#federation': { w: 34, h: 18 },
}
const FALLBACK_ROOM_DIMS = { w: 26, h: 16 }

function roomDimsFor(channel) {
  return KNOWN_ROOM_DIMS[channel] || FALLBACK_ROOM_DIMS
}

// Fit gate: camera() only pins {0,0} when the whole tilemap already fits
// inside the viewport at its own integer zoom. Numbers for the fallback
// 26x16 room (what any greet-cam test channel gets): 26*8=208, 16*8=128 px;
// zoom = floor(min(1920/208, 1080/128)) = floor(min(9.23, 8.44)) = 8; so
// VIEW_W=240, VIEW_H=135. 208<=240 (32px of horizontal headroom) and
// 128<=135 (only 7px of vertical headroom) -- it fits, but by a hair. Any
// room definition that grows past 135/8=16.875 tiles tall breaks this, the
// camera starts following the player instead of staying pinned, and the
// teleport-away trick would silently scroll the shot to an empty corner
// instead of failing loudly. That's why this is a hard gate, not a warning.
function computeFit(channel) {
  const dims = roomDimsFor(channel)
  const mapW = dims.w * TILE_PX
  const mapH = dims.h * TILE_PX
  const zoom = Math.floor(Math.min(CANVAS_W / mapW, CANVAS_H / mapH))
  const viewW = Math.floor(CANVAS_W / zoom)
  const viewH = Math.floor(CANVAS_H / zoom)
  return { mapW, mapH, viewW, viewH, fits: mapW <= viewW && mapH <= viewH, zoom }
}

async function hideCameraSprite(cdp, channel) {
  const fit = computeFit(channel)
  log('camera fit check:', fit)
  if (!fit.fits) {
    throw new Error(`room larger than viewport: map ${fit.mapW}x${fit.mapH} does not fit view ${fit.viewW}x${fit.viewH}`)
  }
  // Park the camera's own sprite far outside any real tilemap. checkDoor()
  // (called inside teleport) is harmless out here -- there's nothing to
  // walk through at (-40,-40).
  //
  // TRAP FOR FUTURE READERS: drawBubble (app.ts:2464-2475) clamps a
  // bubble's x into [2, VIEW_W-w-2] but only lower-bounds y -- it never
  // clamps a bubble off the top of the view the way it would off the
  // sides. A bubble belonging to the parked camera would NOT vanish off
  // screen along with its (invisible) sprite; it would re-render pinned to
  // the top-left corner of the room as a caption with nobody under it.
  // The only way this stays invisible is if the camera identity NEVER
  // sends a PRIVMSG. Do not add a "camera says hello" line -- it will
  // silently put a floating caption in every future recording.
  await cdp.send('Runtime.evaluate', {
    expression: `window.__fimp && window.__fimp.teleport && window.__fimp.teleport(-40, -40)`,
  })
  const state = await evalValue(cdp, `(window.__fimp && window.__fimp.state) ? window.__fimp.state() : null`)
  if (!state || state.x !== -40 || state.y !== -40) {
    throw new Error(`camera not parked (state: ${JSON.stringify(state)})`)
  }
  log('camera sprite parked at -40,-40, confirmed via state()')
}

async function logSpawnPosition(cdp) {
  const state = await evalValue(cdp, `(window.__fimp && window.__fimp.state) ? window.__fimp.state() : null`)
  if (state) log('spawn position:', { x: state.x, y: state.y, channel: state.channel, did: state.did })
  return state
}

async function checkTranscriptPanel(cdp, outdir, wireLogPath, liveMessages) {
  try {
    const rows = await evalValue(cdp, `
      (function() {
        var result = []
        var elements = document.querySelectorAll('#transcript .row')
        for (var i = 0; i < elements.length; i++) {
          var el = elements[i]
          if (el.classList.contains('sys')) continue
          var whoEl = el.querySelector('.who')
          var who = whoEl ? whoEl.textContent : ''
          var originEl = el.querySelector('.origin')
          var text = el.textContent.slice(who.length)
          if (originEl) {
            text = text.replace(originEl.textContent, '')
          }
          var fullRow = el.textContent || ''
          if (fullRow.includes('campfire')) continue
          who = who.replace(/\\s+⚙\\s*$/, '').trim()
          text = text.trim()
          result.push({who: who, text: text, fullRow: fullRow})
        }
        return result
      })()
    `)

    if (!Array.isArray(rows) || rows.length === 0) return { clean: true, offenders: [], rows: [] }

    const offenders = []
    for (const row of rows) {
      var found = false
      for (var j = 0; j < liveMessages.length; j++) {
        if (liveMessages[j].nick === row.who && liveMessages[j].text === row.text) {
          found = true
          break
        }
      }

      if (!found) {
        offenders.push({ fullRow: row.fullRow, stripped: { who: row.who, text: row.text } })
        if (offenders.length >= 20) break
      }
    }

    return { clean: offenders.length === 0, offenders, rows }
  } catch (e) {
    log('transcript panel check failed:', e.message)
    return { clean: false, offenders: [{ fullRow: 'transcript-check-failed: ' + e.message, stripped: {} }], checkFailed: true, rows: [] }
  }
}

// ---------------------------------------------------------------------------
// S7: setup screenshot gate
//
// (a) DOM assertion: query the known overlay elements directly.
// (b) Pixel assertion: capture the same viewport twice, once as rendered and
//     once with every hide-selector force-set to display:none via an
//     injected style, then compare sha256 of the two PNG byte streams. If
//     an overlay were actually painting pixels in the first shot, forcing
//     it hidden would change those pixel bytes and the hashes would differ.
//     If the two hashes match, nothing the force-hide touched was visibly
//     different, which is reasonably strong evidence the overlay was
//     already not painting. It is NOT proof the overlay is inert (a
//     div with 0x0 dimensions but live JS side effects would pass either
//     way), and it can't catch overlays outside our selector list. It's a
//     "would hiding it have changed the picture" check, not a semantic one.
//
//     HONEST CAVEAT: the FreeqWorld canvas is a live game loop (dust
//     particles, scanline shader, idle animation) that redraws on every
//     frame even when nothing overlay-related changes. The two shots are
//     fired back to back with no artificial delay between them to shrink
//     that window, but the canvas can still tick between them and produce
//     a byte-level mismatch that has nothing to do with an overlay. In
//     practice this makes the check noisier than the spec's "should be
//     strong evidence" framing suggests — a passing gate is real
//     evidence of cleanliness, but an occasional failing gate on a
//     perfectly clean page is expected, not a sign of a broken overlay.
//     There is no animation-freeze hook available (patching canvas is out
//     of bounds), so this is the honest ceiling of this check as built.
// ---------------------------------------------------------------------------

// The live game loop means an exact single-shot sha256 comparison almost
// never matches even when nothing overlay-related is different (see the
// honest caveat above). We take the DOM assertion as the primary signal and
// use a few quick shot1/shot2 pairs as corroboration: any pair matching
// byte-for-byte is real evidence nothing in the force-hide set was painting
// pixels at that instant. In practice FreeqWorld's canvas animates
// continuously (particles, idle motion, a scanline shader), so two
// screenshots essentially never match byte-for-byte regardless of whether
// an overlay is present -- confirmed against a live #the-lab run where the
// DOM check was clean (every hide-selector genuinely hidden) and the pixel
// check still failed after 5 attempts. Waiting on a lucky byte-identical
// pair is waiting on a coincidence that isn't guaranteed to ever happen.
//
// So: the DOM assertion is AUTHORITATIVE (computed style says a selector is
// actually hidden -- that's real evidence). The pixel check is ADVISORY
// ONLY -- it is recorded in run.json (pixelGate: {checked, clean, attempts})
// and logged once to stderr, but it NEVER blocks READY. A boolean called
// "clean" that really means "two screenshots happened to match" would be
// worse than no check at all, because someone would trust it -- hence it's
// reported as pixelGate.clean, not folded into the pass/fail decision.
// Two attempts, not more -- more attempts buy nothing against a signal this
// noisy, they just delay setup.
const PIXEL_GATE_ATTEMPTS = 2

async function setupScreenshotGate(cdp, outdir, hideSelectors) {
  const shot1 = await cdp.send('Page.captureScreenshot', { format: 'png' })
  fs.writeFileSync(path.join(outdir, 'setup.png'), Buffer.from(shot1.data, 'base64'))

  const domCheck = await evalValue(
    cdp,
    `(function() {
      var bad = []
      ${JSON.stringify(hideSelectors)}.forEach(function(sel) {
        try {
          var el = document.querySelector(sel)
          if (el) {
            var cs = window.getComputedStyle(el)
            if (cs.display !== 'none' && cs.visibility !== 'hidden') bad.push(sel)
          }
        } catch (e) {}
      })
      return bad
    })()`,
  )

  let pixelClean = false
  let attempts = 0
  for (; attempts < PIXEL_GATE_ATTEMPTS && !pixelClean; attempts++) {
    const before = await cdp.send('Page.captureScreenshot', { format: 'png' })
    const hashBefore = crypto.createHash('sha256').update(Buffer.from(before.data, 'base64')).digest('hex')
    await cdp.send('Runtime.evaluate', {
      expression: `(function() {
        var s = document.createElement('style')
        s.setAttribute('data-greetcam-forcehide', '1')
        s.textContent = ${JSON.stringify(hideSelectors)}.map(function(sel) {
          return sel + ' { display: none !important; }'
        }).join('\\n')
        document.head.appendChild(s)
      })()`,
    })
    const after = await cdp.send('Page.captureScreenshot', { format: 'png' })
    const hashAfter = crypto.createHash('sha256').update(Buffer.from(after.data, 'base64')).digest('hex')
    await cdp.send('Runtime.evaluate', {
      expression: `(function() {
        var s = document.querySelector('[data-greetcam-forcehide]')
        if (s) s.remove()
      })()`,
    })
    if (hashBefore === hashAfter) pixelClean = true
  }
  log(`S7: pixel gate (advisory only, never blocks READY): ${pixelClean ? 'clean' : 'not byte-identical'} after ${attempts} attempt(s)`)

  const domClean = !domCheck || domCheck.length === 0
  const wireLogPath = path.join(outdir, 'wire.log')
  const transcriptCheck = await checkTranscriptPanel(cdp, outdir, wireLogPath, [])

  return {
    ok: domClean && transcriptCheck.clean,
    domOffenders: domCheck || [],
    transcriptOffenders: transcriptCheck.offenders,
    pixelGate: { checked: true, clean: pixelClean, attempts },
  }
}

// ---------------------------------------------------------------------------
// Output writers (kept from the previous version, unchanged in spirit)
// ---------------------------------------------------------------------------

function writeFramesJson(outdir, runid, startedAt, frames) {
  const data = { runid, startedAt, frames }
  fs.writeFileSync(path.join(outdir, 'frames.json'), JSON.stringify(data, null, 2))
  return data
}

function writePlayerHtml(outdir, framesData) {
  const framesJsonInline = JSON.stringify(framesData)
  const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>greet-cam player — ${framesData.runid}</title>
<style>
  html, body { margin: 0; padding: 0; background: #111; color: #eee; font-family: -apple-system, sans-serif; height: 100%; }
  #stage { display: flex; align-items: center; justify-content: center; height: calc(100vh - 90px); background: #000; }
  #stage img { max-width: 100%; max-height: 100%; display: block; }
  #controls { height: 90px; box-sizing: border-box; padding: 10px 16px; display: flex; flex-direction: column; gap: 8px; background: #1a1a1a; }
  #controls .row { display: flex; align-items: center; gap: 10px; }
  #scrub { flex: 1; }
  button { background: #333; color: #eee; border: 1px solid #555; border-radius: 4px; padding: 6px 14px; cursor: pointer; font-size: 14px; }
  button:hover { background: #444; }
  #counter, #speedlabel { font-variant-numeric: tabular-nums; font-size: 13px; color: #aaa; min-width: 90px; }
  select { background: #333; color: #eee; border: 1px solid #555; border-radius: 4px; padding: 4px; }
</style>
</head>
<body>
  <div id="stage"><img id="frame" alt="frame"></div>
  <div id="controls">
    <div class="row">
      <button id="playpause">Play</button>
      <input id="scrub" type="range" min="0" value="0" step="1">
      <span id="counter">0 / 0</span>
    </div>
    <div class="row">
      <span id="speedlabel">Speed:</span>
      <select id="speed">
        <option value="0.25">0.25x</option>
        <option value="0.5">0.5x</option>
        <option value="1" selected>1x</option>
        <option value="2">2x</option>
        <option value="4">4x</option>
      </select>
      <span id="timelabel"></span>
    </div>
  </div>

<script type="application/json" id="frames-data">${framesJsonInline}</script>
<script>
(function() {
  var data = JSON.parse(document.getElementById('frames-data').textContent)
  var frames = data.frames
  var img = document.getElementById('frame')
  var scrub = document.getElementById('scrub')
  var counter = document.getElementById('counter')
  var playBtn = document.getElementById('playpause')
  var speedSel = document.getElementById('speed')
  var timelabel = document.getElementById('timelabel')

  scrub.max = String(Math.max(0, frames.length - 1))

  var idx = 0
  var playing = false
  var speed = 1
  var timer = null

  var images = frames.map(function(f) {
    var im = new Image()
    im.src = 'frames/' + f.file
    return im
  })

  function fmtMs(ms) {
    var s = ms / 1000
    return s.toFixed(2) + 's'
  }

  function show(i) {
    idx = Math.max(0, Math.min(frames.length - 1, i))
    img.src = images[idx].src
    scrub.value = String(idx)
    counter.textContent = (idx + 1) + ' / ' + frames.length
    timelabel.textContent = frames.length ? fmtMs(frames[idx].t) + ' / ' + fmtMs(frames[frames.length - 1].t) : ''
  }

  function scheduleNext() {
    if (!playing) return
    if (idx >= frames.length - 1) { playing = false; playBtn.textContent = 'Play'; return }
    var cur = frames[idx].t
    var next = frames[idx + 1].t
    var delay = Math.max(0, (next - cur) / speed)
    timer = setTimeout(function() {
      show(idx + 1)
      scheduleNext()
    }, delay)
  }

  function play() {
    if (frames.length === 0) return
    playing = true
    playBtn.textContent = 'Pause'
    if (idx >= frames.length - 1) idx = 0
    scheduleNext()
  }

  function pause() {
    playing = false
    playBtn.textContent = 'Play'
    if (timer) clearTimeout(timer)
  }

  playBtn.addEventListener('click', function() {
    if (playing) pause()
    else play()
  })

  scrub.addEventListener('input', function() {
    pause()
    show(Number(scrub.value))
  })

  speedSel.addEventListener('change', function() {
    speed = Number(speedSel.value)
  })

  if (frames.length) show(0)
})()
</script>
</body>
</html>
`
  fs.writeFileSync(path.join(outdir, 'player.html'), html)
}

// Retention: keep the 5 newest greet-cam-* dirs, mv the rest aside. No rm.
function applyRetention() {
  const entries = fs
    .readdirSync(OUT_BASE)
    .filter((name) => name.startsWith('greet-cam-') && !name.startsWith('greet-cam-old-'))
    .map((name) => {
      const full = path.join(OUT_BASE, name)
      let mtime = 0
      try {
        mtime = fs.statSync(full).mtimeMs
      } catch {}
      return { name, full, mtime }
    })
    .sort((a, b) => b.mtime - a.mtime)

  const stale = entries.slice(5)
  for (const e of stale) {
    const dest = path.join(OUT_BASE, `greet-cam-old-${e.name}`)
    try {
      fs.renameSync(e.full, dest)
      log('retention: moved', e.full, '->', dest)
    } catch (err) {
      log('retention: mv failed for', e.full, err.message)
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const opts = parseArgs(process.argv.slice(2))

const state = {
  outdir: null,
  chromePid: null,
  cdp: null,
  ws: null,
  cleanedUp: false,
  stopRequested: false,
  stopReason: null,
  stopResolve: null,
  runid: null,
  ownNick: null,
}

async function cleanup() {
  if (state.cleanedUp) return
  state.cleanedUp = true
  if (state.cdp) {
    try {
      await state.cdp.send('Page.stopScreencast')
    } catch {}
    state.cdp.close()
  }
  if (state.chromePid) killChromePid(state.chromePid)
}

async function failSetup(reason) {
  printFailed(reason)
  await cleanup()
  process.exitCode = 1
}

function hideSelectorsFor(mode) {
  return mode === 'none' ? [] : mode === 'full' ? HIDE_SELECTORS_FULL : HIDE_SELECTORS_MINIMAL
}

async function runSetup(outdir, channel) {
  fs.mkdirSync(path.join(outdir, 'frames'), { recursive: true })

  log('S1: preflighting room', channel)
  const roomAtStart = await runPreflight(channel)
  log('S1: room checked, occupants:', roomAtStart.join(', ') || '(empty)')

  log('S2: launching chrome headless')
  const port = await getFreePort()
  log('S2: using CDP port', port)
  const chromeChild = launchChrome(outdir, port)
  state.chromePid = chromeChild.pid
  await waitForChrome(port)
  log('S2: chrome CDP up on port', port)

  const target = await findPageTarget(port)
  const ws = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true })
    ws.addEventListener('error', reject, { once: true })
  })
  const cdp = new CdpClient(ws)
  state.cdp = cdp
  state.ws = ws

  await cdp.send('Page.enable')
  await cdp.send('Runtime.enable')
  log('S3: CDP connected to page target', target.id)

  const hideSelectors = hideSelectorsFor(opts.chrome)
  const injection = buildInjectionScript(channel, hideSelectors)
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: injection })
  log('S3: injection payload installed, chrome mode =', opts.chrome)

  const worldUrl = WORLD_BASE
  await cdp.send('Page.navigate', { url: worldUrl })
  log('S3: navigated to', worldUrl)

  await sleep(500)
  await ensureGuestLogin(cdp)
  await joinChannelViaDirectory(cdp, channel)
  await cleanApp(cdp)
  const spawnState = await logSpawnPosition(cdp)
  if (opts.at) {
    await maybeTeleport(cdp, opts.at)
  } else {
    await hideCameraSprite(cdp, channel)
  }
  if (spawnState && spawnState.members) {
    const mine = spawnState.did
    log('own identity established, did:', mine)
  }

  const gate = await setupScreenshotGate(cdp, outdir, hideSelectors)
  if (!gate.ok) {
    if (gate.transcriptOffenders && gate.transcriptOffenders.length > 0) {
      throw new Error(`setup not clean: transcript contamination: ${gate.transcriptOffenders.slice(0, 3).join('; ')}`)
    }
    throw new Error(`setup not clean: dom=${JSON.stringify(gate.domOffenders)}`)
  }
  log('S7: setup screenshot gate passed (dom clean; pixel check is advisory, see run.json)')

  return { cdp, port, roomAtStart, pixelGate: gate.pixelGate }
}

async function startScreencast(cdp, outdir) {
  const framesDir = path.join(outdir, 'frames')
  const frameTimestamps = []
  let frameCount = 0

  cdp.on('Page.screencastFrame', async (params) => {
    const file = `${String(frameCount + 1).padStart(6, '0')}.jpg`
    fs.writeFileSync(path.join(framesDir, file), Buffer.from(params.data, 'base64'))
    frameTimestamps.push({ file, cdpTs: params.metadata.timestamp, wallTs: Date.now() })
    frameCount++
    try {
      await cdp.send('Page.screencastFrameAck', { sessionId: params.sessionId })
    } catch (e) {
      log('screencastFrameAck failed:', e.message)
    }
  })

  await cdp.send('Page.startScreencast', { format: 'jpeg', quality: 80, maxWidth: 1920, maxHeight: 1080 })
  return { frameTimestamps, getCount: () => frameCount }
}

async function pollCamlog(cdp, outdir, onEntry) {
  const wireLogPath = path.join(outdir, 'wire.log')
  const fd = fs.openSync(wireLogPath, 'a')
  let seen = 0
  const timer = setInterval(async () => {
    try {
      const entries = await evalValue(cdp, `window.__camlog ? window.__camlog.slice(${seen}) : []`)
      if (Array.isArray(entries) && entries.length) {
        for (const e of entries) {
          fs.writeSync(fd, `[${new Date(e.ts).toISOString()}] ${e.kind} ${e.nick || ''} ${e.text ? JSON.stringify(e.text) : ''}\n`)
          onEntry(e)
        }
        seen += entries.length
      }
    } catch (e) {
      // page may be mid-navigation or torn down; ignore transient errors
    }
  }, CAMLOG_POLL_MS)
  return {
    stop: () => {
      clearInterval(timer)
      try {
        fs.closeSync(fd)
      } catch {}
    },
  }
}

function bubbleLifetimeMs(text) {
  return 4500 + 30 * (text ? text.length : 0)
}

async function waitForStop(timeoutSec) {
  return new Promise((resolve) => {
    let resolved = false
    const stopSources = { stdinArmed: false, sigtermArmed: false, timeoutArmed: false, firedBy: null }

    const finish = (firedBy) => {
      if (resolved) return
      resolved = true
      stopSources.firedBy = firedBy
      resolve({ stopReason: firedBy, stopSources })
    }

    const onSigterm = () => finish('sigterm')
    stopSources.sigtermArmed = true
    process.once('SIGTERM', onSigterm)

    const isTTY = process.stdin.isTTY
    if (!isTTY) {
      try {
        process.stdin.resume()
        stopSources.stdinArmed = true
        process.stdin.on('end', () => finish('eof'))
        process.stdin.on('close', () => finish('eof'))
      } catch (e) {
        stopSources.stdinArmed = false
      }
    }

    if (timeoutSec > 0) {
      stopSources.timeoutArmed = true
      setTimeout(() => finish('timeout'), timeoutSec * 1000)
    }
  })
}

async function main() {
  if (!opts.out) {
    printFailed('missing --out')
    process.exitCode = 1
    return
  }
  const outdir = path.resolve(opts.out)
  state.outdir = outdir
  const runid = nowStamp()
  state.runid = runid
  const startedAt = Date.now()

  const setupDeadlineMs = opts.setupDeadline * 1000
  let setupResult
  try {
    const setupPromise = runSetup(outdir, opts.channel)
    const timeoutPromise = sleep(setupDeadlineMs).then(() => {
      throw new Error('__SETUP_TIMEOUT__')
    })
    setupResult = await Promise.race([setupPromise, timeoutPromise])
  } catch (err) {
    if (err && err.message === '__SETUP_TIMEOUT__') {
      await failSetup('setup timeout')
    } else {
      await failSetup((err && err.message) || String(err))
    }
    return
  }

  const { cdp, roomAtStart, pixelGate } = setupResult

  // S8: start capture, then print READY. Capture starts before brian
  // connects so his arrival frame exists.
  const capture = await startScreencast(cdp, outdir)
  const captureStartedAt = Date.now()

  // Contamination is about SPEECH, not presence. A dirty room (extra nicks
  // merely sitting in the channel) is explicitly fine -- it's what stale
  // room-mates do that matters. Two independent guards make sure only live
  // post-join speech can ever set contaminated:
  //   1. history is stripped out of the welcome/joined frame before the
  //      app -- and therefore this camlog -- ever sees it (inspectFrame
  //      above), so replayed lines from earlier runs structurally cannot
  //      appear here at all.
  //   2. belt and braces: cameraJoinConfirmedAt is set once our own guest
  //      join is confirmed (well before capture even starts, since S8
  //      starts the screencast after S5), and any event timestamped
  //      earlier than that is ignored outright.
  // "member-joined"/"member-left" only ever update roomAtStart-style
  // presence bookkeeping (folded into participants below for anyone who
  // later speaks) -- presence alone never sets contaminated.
  const cameraJoinConfirmedAt = Date.now()
  const NEVER_ACTORS = /^(wanderer-|greetcam-)/i
  const seen = { brianJoinedAt: null, lastMessageAt: null, lastMessageText: '', participants: new Set(), offenders: new Set() }
  const liveMessages = []
  const liveEventTs = []
  const camPoller = await pollCamlog(cdp, outdir, (e) => {
    if (e.ts < cameraJoinConfirmedAt) return // pre-join event, treat as backdrop
    const nick = (e.nick || '').toLowerCase()
    if (nick && !NEVER_ACTORS.test(nick)) liveEventTs.push(e.ts)
    if (e.kind === 'member-joined') {
      if (nick === 'brian' && seen.brianJoinedAt === null) seen.brianJoinedAt = e.ts
      return
    }
    if (e.kind !== 'message') return
    liveMessages.push({ nick: e.nick, text: e.text || '' })
    seen.participants.add(nick)
    seen.lastMessageAt = e.ts
    seen.lastMessageText = e.text || ''
    if (nick !== 'brian' && nick !== 'greet' && !NEVER_ACTORS.test(nick)) seen.offenders.add(e.nick)
  })

  printReady(outdir)
  log('READY. capturing until SIGTERM / stdin EOF / timeout', opts.timeout, 's')

  const stopResult = await waitForStop(opts.timeout)
  const stopReason = stopResult.stopReason
  const stopSources = stopResult.stopSources
  log('stop signal received:', stopReason)

  camPoller.stop()

  const wireLogPath = path.join(outdir, 'wire.log')
  const finalTranscriptCheck = await checkTranscriptPanel(cdp, outdir, wireLogPath, liveMessages)
  let transcriptContaminated = false
  let gateInternalError = false

  if (liveMessages.length === 0 && finalTranscriptCheck.offenders && finalTranscriptCheck.offenders.length > 0) {
    gateInternalError = true
    log('gate internal error: transcript found rows but liveMessages is empty; possible timestamp mismatch')
  } else if (!finalTranscriptCheck.clean && finalTranscriptCheck.offenders && finalTranscriptCheck.offenders.length > 0) {
    transcriptContaminated = true
    for (const offender of finalTranscriptCheck.offenders) {
      seen.offenders.add(offender.fullRow || offender)
    }
  }

  try {
    await cdp.send('Page.stopScreencast')
  } catch (e) {
    log('Page.stopScreencast failed:', e.message)
  }

  // Clean IRC QUIT for the camera identity is implicit: the FreeqWorld guest
  // session closes its WebSocket on navigation teardown / process exit, and
  // we never opened a second raw IRC socket in this design (the injected
  // wrapper mirrors events out of the app's own connection instead).
  try {
    await cdp.send('Runtime.evaluate', {
      expression: `(window.__fimp && window.__fimp.join) ? true : true`,
    })
  } catch {}

  const endedAt = Date.now()
  const durationMs = endedAt - startedAt
  const allFrames = capture.frameTimestamps
  let baseTs = null
  const framesRel = allFrames.map(({ file, cdpTs, wallTs }) => {
    if (baseTs === null) baseTs = cdpTs
    return { file, t: Math.round((cdpTs - baseTs) * 1000), wallTs }
  })

  const frameCount = framesRel.length
  const contaminated = seen.offenders.size > 0
  const offenders = [...seen.offenders]

  let reason = null
  let exitCode = 0
  let trimStartIndex = 0
  let trimEndIndex = frameCount - 1
  let deliveredFrames = framesRel

  if (gateInternalError) {
    exitCode = 1
    reason = 'gate-internal-error'
  } else if (transcriptContaminated) {
    exitCode = 4
    reason = 'transcript-contamination'
  } else if (contaminated) {
    exitCode = 4
    reason = 'contaminated'
  } else if (seen.brianJoinedAt === null) {
    exitCode = 3
    reason = 'no-brian'
  } else if (frameCount === 0) {
    exitCode = 3
    reason = 'no-frames'
  } else {
    const trimStartMs = seen.brianJoinedAt - captureStartedAt
    const trimEndMs = seen.lastMessageAt !== null ? seen.lastMessageAt - captureStartedAt + bubbleLifetimeMs(seen.lastMessageText) : framesRel[framesRel.length - 1].t

    trimStartIndex = framesRel.findIndex((f) => f.t >= trimStartMs)
    if (trimStartIndex < 0) trimStartIndex = 0
    trimEndIndex = framesRel.length - 1
    for (let i = 0; i < framesRel.length; i++) {
      if (framesRel[i].t <= trimEndMs) trimEndIndex = i
    }
    if (trimEndIndex < trimStartIndex) trimEndIndex = framesRel.length - 1

    deliveredFrames = framesRel.slice(trimStartIndex, trimEndIndex + 1)
    if (deliveredFrames.length === 0) {
      exitCode = 3
      reason = 'no-frames'
    }
  }

  if (exitCode !== 4) {
    if (stopReason === 'eof') {
      exitCode = 1
      reason = 'camera-failed'
    } else if (stopReason === 'timeout' && frameCount === 0) {
      exitCode = 1
      reason = 'camera-failed'
    } else if (stopReason === 'sigterm' && !reason) {
      exitCode = 0
    }
  }

  const framesData = writeFramesJson(outdir, runid, new Date(startedAt).toISOString(), deliveredFrames)
  writePlayerHtml(outdir, framesData)

  // Build MP4 from selected frames
  let mp4Path = null
  let mp4Cut = null

  try {
    const liveEvents = liveEventTs.map(ts => ({ ts }))
    {
      let selectedFrames = deliveredFrames

      if (liveEvents.length > 0) {
        // Calculate time windows
        const firstLiveTs = Math.min(...liveEvents.map(e => e.ts))
        const lastLiveTs = Math.max(...liveEvents.map(e => e.ts))
        const cutStart = firstLiveTs - 5000
        const cutEnd = lastLiveTs + 2000

        // Select frames within [cutStart, cutEnd]
        const framesCut = deliveredFrames.filter(f => f.wallTs >= cutStart && f.wallTs <= cutEnd)
        if (framesCut.length > 0) {
          selectedFrames = framesCut
        }

        mp4Cut = {
          startTs: cutStart,
          endTs: cutEnd,
          frameCount: selectedFrames.length,
          durationSec: selectedFrames.length > 0
            ? (selectedFrames[selectedFrames.length - 1].wallTs - selectedFrames[0].wallTs) / 1000
            : 0
        }
      }

      // Build concat.txt
      const concatLines = []
      for (let i = 0; i < selectedFrames.length; i++) {
        const frame = selectedFrames[i]
        concatLines.push(`file 'frames/${frame.file}'`)

        // Calculate duration: next frame's wallTs - this frame's wallTs in seconds
        let duration
        if (i < selectedFrames.length - 1) {
          duration = (selectedFrames[i + 1].wallTs - frame.wallTs) / 1000
        } else {
          // Last frame: use previous duration or a default
          if (i > 0) {
            duration = (frame.wallTs - selectedFrames[i - 1].wallTs) / 1000
          } else {
            duration = 0.1 // fallback for single frame
          }
        }
        concatLines.push(`duration ${duration.toFixed(3)}`)
      }

      // Repeat the final file line (required by concat demuxer)
      if (selectedFrames.length > 0) {
        concatLines.push(`file 'frames/${selectedFrames[selectedFrames.length - 1].file}'`)
      }

      const concatPath = path.join(outdir, 'concat.txt')
      fs.writeFileSync(concatPath, concatLines.join('\n') + '\n')

      // Run ffmpeg
      const { spawnSync } = require('child_process')
      const ffmpegResult = spawnSync('ffmpeg', [
        '-y', '-f', 'concat', '-safe', '0',
        '-i', concatPath,
        '-vf', 'fps=30,crop=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p',
        '-c:v', 'libx264',
        '-pix_fmt', 'yuv420p',
        '-preset', 'veryfast',
        '-crf', '20',
        '-movflags', '+faststart',
        'greet.mp4'
      ], {
        cwd: outdir,
        encoding: 'utf8'
      })

      if (ffmpegResult.status === 0) {
        mp4Path = path.join(outdir, 'greet.mp4')
        log('ffmpeg succeeded, created', mp4Path)
      } else {
        const stderrLines = (ffmpegResult.stderr || '').split('\n')
        const tail = stderrLines.slice(-10).join('\n')
        log('ffmpeg failed with status', ffmpegResult.status, ':', tail)
        mp4Path = null
      }
    }
  } catch (e) {
    log('mp4 encoding error:', e.message)
    mp4Path = null
  }

  const sampleLive = liveMessages.slice(0, 3)
  const samplePanel = (finalTranscriptCheck.rows || []).slice(0, 3).map((r) => ({ who: r.who, text: r.text }))

  const runJson = {
    runid,
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date(endedAt).toISOString(),
    durationMs,
    frameCount,
    deliveredFrameCount: deliveredFrames.length,
    trimStartIndex,
    trimEndIndex,
    participants: [...seen.participants],
    roomAtStart: roomAtStart.filter((n) => {
      const low = n.toLowerCase()
      return low !== 'brian' && low !== 'greet'
    }),
    contaminated,
    offenders,
    reason,
    exitCode,
    stopSources,
    gateDiag: {
      liveMessageCount: liveMessages.length,
      panelRowCount: (finalTranscriptCheck.rows || []).length,
      sampleLive,
      samplePanel,
    },
    pixelGate, // advisory only -- see setupScreenshotGate comment. Never gated READY.
    mp4: mp4Path,
    mp4Cut,
  }
  fs.writeFileSync(path.join(outdir, 'run.json'), JSON.stringify(runJson, null, 2))

  await cleanup()

  const playerPath = path.join(outdir, 'player.html')
  if (exitCode === 0) {
    applyRetention()
    printDone(playerPath, deliveredFrames.length, '', stopReason, mp4Path)
  } else if (exitCode === 4) {
    const displayReason = transcriptContaminated ? 'transcript-contamination' : `contaminated:${offenders.join(',')}`
    printDone(playerPath, deliveredFrames.length, displayReason, stopReason, mp4Path)
  } else {
    printDone(playerPath, deliveredFrames.length, `reason:${reason}`, stopReason, mp4Path)
  }
  process.exitCode = exitCode
}

process.on('uncaughtException', async (err) => {
  log('uncaughtException:', err.stack || err.message)
  if (!readyPrinted) {
    if (!finalPrinted) printFailed(err.message || String(err))
  } else if (!finalPrinted) {
    printFailed(err.message || String(err))
  }
  await cleanup()
  process.exitCode = 1
  process.exit(process.exitCode)
})
process.on('unhandledRejection', async (err) => {
  log('unhandledRejection:', (err && err.stack) || err)
  if (!finalPrinted) printFailed((err && err.message) || String(err))
  await cleanup()
  process.exitCode = 1
  process.exit(process.exitCode)
})

main()
  .catch(async (err) => {
    log('main() rejected:', err.stack || err.message)
    if (!finalPrinted) printFailed(err.message || String(err))
    await cleanup()
    process.exitCode = 1
  })
  .finally(() => {
    if (!finalPrinted) {
      // Should be unreachable given the try/catch coverage above, but the
      // contract requires a final line no matter what.
      printFailed('unknown internal error: no final line was produced')
      process.exitCode = 1
    }
    process.exit(process.exitCode || 0)
  })
