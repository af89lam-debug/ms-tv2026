import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { createServer as createViteServer } from 'vite';
import {
  DEFAULT_MAINTENANCE_MESSAGE,
  getDb,
  saveDb,
  getCatalogRevision,
  upsertSourceChannels,
  getOrderedCategories,
  setCategoryOrder,
  moveCategoryInOrder,
  deleteCategoriesFromStore,
  restoreExcludedCategoriesInStore,
  getActiveSourcesAndChannels,
  computeDaysRemaining,
  isAccessCodeValidNow,
  exportEncryptedSnapshotChunks,
  importEncryptedSnapshotChunks,
  recordSecurityEvent,
} from './server/store.ts';
import type {
  HeroActionType,
  HeroSlide,
  HeroThemePreset,
  IptvSource,
  SecurityPolicyConfig,
  StoredChannel,
  ViewerAccessCode,
} from './server/store.ts';
import {
  cleanIptvUrl,
  parseM3uPlaylist,
  fetchM3uFromUrl,
  fetchXtreamPlaylist,
  computeStreamSignature,
  detectStreamFormat,
  detectContentKind,
  deriveStreamFallbackUrl,
  expandStreamUrlCandidates,
} from './server/m3uParser.ts';

interface TokenPayload {
  role: 'viewer' | 'admin';
  code: string;
  did?: string;
  iat: number;
}

interface StreamTicketPayload {
  tid: string;
  cid: string;
  code: string;
  uah: string;
  dvh: string;
  iph: string;
  apple?: boolean;
  exp: number;
}

interface StreamSessionTokenPayload {
  sid: string;
  code: string;
  uah: string;
  dvh: string;
  iph: string;
  apple?: boolean;
  exp: number;
}

interface EncryptedStreamRef {
  url: string;
  ua?: string;
  ref?: string;
  cookie?: string;
  cexp?: number;
}

interface ActiveStreamLease {
  tid: string;
  code: string;
  deviceId: string;
  channelId: string;
  createdAt: number;
  lastHeartbeatAt: number;
}

const activeStreamLeases = new Map<string, ActiveStreamLease>();

// Persistent Keep-Alive connection pools for HLS manifests & segment chunks (eliminates repeated TCP/TLS handshakes)
const keepAliveHttpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 128,
  maxFreeSockets: 32,
  keepAliveMsecs: 30000,
});

const keepAliveHttpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 128,
  maxFreeSockets: 32,
  keepAliveMsecs: 30000,
  rejectUnauthorized: false,
});

function getSecretKey(): Buffer {
  const db = getDb();
  return crypto.createHash('sha256').update(db.serverSecret).digest();
}

function computeUserAgentHash(req: Request): string {
  const ua = String(req.headers['user-agent'] || 'unknown-ua');
  return crypto.createHash('sha256').update(ua).digest('hex').slice(0, 14);
}

function computeDeviceHash(deviceId: string): string {
  return crypto
    .createHash('sha256')
    .update(String(deviceId || 'unknown-device').trim())
    .digest('hex')
    .slice(0, 16);
}

function extractClientIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  const rawXff = Array.isArray(xff) ? xff[0] : xff;
  if (typeof rawXff === 'string' && rawXff.trim()) {
    const firstHop = rawXff.split(',')[0]?.trim();
    if (firstHop) return firstHop.replace(/^::ffff:/i, '');
  }
  const direct = String(req.ip || req.socket?.remoteAddress || '0.0.0.0').trim();
  return direct.replace(/^::ffff:/i, '');
}

function isPrivateOrLoopbackIp(ip: string): boolean {
  const clean = ip.toLowerCase().trim();
  if (
    !clean ||
    clean === '0.0.0.0' ||
    clean === '::1' ||
    clean === 'localhost' ||
    clean.startsWith('127.') ||
    clean.startsWith('10.') ||
    clean.startsWith('192.168.') ||
    clean.startsWith('169.254.') ||
    clean.startsWith('fc00:') ||
    clean.startsWith('fd00:') ||
    clean.startsWith('fe80:')
  ) {
    return true;
  }
  const m172 = clean.match(/^172\.(\d{1,3})\./);
  if (m172) {
    const second = Number(m172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function computeIpFingerprint(ip: string): string {
  const clean = ip.trim().toLowerCase();
  if (isPrivateOrLoopbackIp(clean)) {
    return 'local-net';
  }
  let subnet = clean;
  if (clean.includes('.')) {
    const parts = clean.split('.');
    if (parts.length === 4) {
      // Use /16 carrier prefix so mobile 4G/5G CGNAT /24 pool rotation never drops active streams
      subnet = `${parts[0]}.${parts[1]}.0.0`;
    }
  } else if (clean.includes(':')) {
    const parts = clean.split(':');
    subnet = parts.slice(0, 2).join(':');
  }
  return crypto.createHash('sha256').update(subnet).digest('hex').slice(0, 14);
}

function sanitizePlayId(raw: unknown): string {
  return String(raw || '')
    .replace(/[^a-zA-Z0-9_\-]/g, '')
    .trim()
    .slice(0, 48);
}

function sanitizeDeviceId(raw: unknown): string {
  return String(raw || '')
    .replace(/[^a-zA-Z0-9_\-:.]/g, '')
    .trim()
    .slice(0, 96);
}

function extractDeviceInfo(req: Request): { deviceId: string; deviceName: string } {
  const hdrId = req.headers['x-device-id'];
  const qId = req.query?.d;
  const bodyId = req.body?.deviceId;
  const deviceId = sanitizeDeviceId(
    (Array.isArray(hdrId) ? hdrId[0] : hdrId) ||
      (typeof qId === 'string' ? qId : '') ||
      bodyId ||
      ''
  );

  const hdrName = req.headers['x-device-name'];
  const rawHdrName = Array.isArray(hdrName) ? hdrName[0] : hdrName;
  let decodedName = '';
  if (typeof rawHdrName === 'string' && rawHdrName.trim()) {
    try {
      decodedName = decodeURIComponent(rawHdrName).trim();
    } catch {
      decodedName = rawHdrName.trim();
    }
  }
  if (!decodedName && typeof req.body?.deviceName === 'string') {
    decodedName = req.body.deviceName.trim();
  }
  if (!decodedName) {
    const ua = String(req.headers['user-agent'] || '');
    const xReqWith = String(req.headers['x-requested-with'] || '');
    if (/MSTVApp\//i.test(ua) || xReqWith === 'com.mstv.iptv') {
      decodedName = 'تطبيق MS TV (Android)';
    } else if (/android/i.test(ua)) decodedName = 'Android';
    else if (/iphone|ipad/i.test(ua)) decodedName = 'iOS';
    else if (/windows/i.test(ua)) decodedName = 'Windows';
    else if (/macintosh/i.test(ua)) decodedName = 'Mac';
    else decodedName = 'متصفح ويب';
  }

  return {
    deviceId,
    deviceName: decodedName.slice(0, 80),
  };
}

const SNIFFER_APP_REGEX =
  /httpcanary|guoshi|reqable|pcapdroid|emanuelef|sslcapture|greyshirts|packetcapture|netcapture|mitmproxy|charles|fiddler|burpsuite|burp|proxyman|httptoolkit|wireshark|telerik|har-capture|sniffer/i;

const EXTERNAL_SCRAPER_UA_REGEX =
  /\b(vlc|libvlc|lavf\/|ffmpeg|avformat|curl\/|wget\/|python-requests|python-urllib|aiohttp|httpx\/|go-http-client|okhttp|dalvik\/|exoplayer|stagefright|iptvsmarters|smarters|tivimate|ott\s*navigator|perfect\s*player|kodi|xbmc|aria2|idm\/|fdm\/|adm\/|java\/|apache-httpclient|axios\/|node-fetch|postmanruntime|insomnia)\b/i;

/**
 * Inspects incoming request for HttpCanary, Packet Capture, MITM proxy headers,
 * Android capture WebViews, and external IPTV grabbers/players.
 */
function inspectSnifferRequest(
  req: Request,
  options: { isMediaRoute?: boolean; allowAppleCoreMedia?: boolean } = {}
): string | null {
  const ua = String(req.headers['user-agent'] || '').trim();
  const xRequestedWith = String(req.headers['x-requested-with'] || '').trim();
  const via = String(req.headers['via'] || '').trim();

  if (
    req.headers['x-mitmproxy'] ||
    req.headers['x-charles-proxy'] ||
    req.headers['x-fiddler'] ||
    req.headers['x-burp'] ||
    req.headers['x-httpcanary']
  ) {
    return 'تم رصد ترويسات اعتراض حزم الشبكة (MITM Proxy / HttpCanary).';
  }

  if (SNIFFER_APP_REGEX.test(ua) || SNIFFER_APP_REGEX.test(xRequestedWith) || SNIFFER_APP_REGEX.test(via)) {
    return 'تم اكتشاف برنامج سحب وتحليل روابط البث (مثل HttpCanary أو Packet Capture).';
  }

  if (
    xRequestedWith &&
    /\b(canary|capture|pcap|sniff|mitm|proxy|grab|downloader|idm|adm|reqable)\b/i.test(
      xRequestedWith
    )
  ) {
    return `تم حظر بيئة التقاط الشبكة (${xRequestedWith}).`;
  }

  if (EXTERNAL_SCRAPER_UA_REGEX.test(ua)) {
    return 'تم حظر محاولة سحب أو تشغيل البث عبر مشغل أو أداة خارجية.';
  }

  if (!ua || ua.length < 14) {
    return 'طلب غير موثوق بدون بصمة متصفح صالحة.';
  }

  const isAppleCoreMedia = /^AppleCoreMedia\//i.test(ua);
  if (isAppleCoreMedia && options.isMediaRoute && options.allowAppleCoreMedia) {
    return null;
  }

  if (!/Mozilla\/5\.0/i.test(ua)) {
    return 'تم رفض الطلب لعدم صدوره من متصفح رسمي موثوق.';
  }

  return null;
}

interface VpnCacheRecord {
  blocked: boolean;
  reason: string | null;
  checkedAt: number;
}

const vpnIpCache = new Map<string, VpnCacheRecord>();

const VPN_ASN_ORG_REGEX =
  /\b(nordvpn|expressvpn|surfshark|proton\s*vpn|proton\s*ag|cyberghost|mullvad|windscribe|private\s*internet\s*access|psiphon|hotspot\s*shield|anchorfree|hidemyass|astrill|vyprvpn|tunnelbear|purevpn|ipvanish|zenmate|urban\s*vpn|cloudflare\s*warp|m247|datacamp|cdn77|tzulo|choopa|vultr|digitalocean|linode|hetzner|contabo|ovh\s*sas|leaseweb|hostroyale|packethub|worldstream|clouvider|sharktech|frantech|tefincom)\b/i;

function queryIpIntelligence(ip: string): Promise<{
  proxy?: boolean;
  hosting?: boolean;
  isp?: string;
  org?: string;
  as?: string;
} | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val: any) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    const timer = setTimeout(() => finish(null), 1100);
    const url = `http://ip-api.com/json/${encodeURIComponent(
      ip
    )}?fields=status,isp,org,as,proxy,hosting`;

    const req = http.get(url, { timeout: 1100 }, (res) => {
      const chunks: Buffer[] = [];
      let total = 0;
      res.on('data', (c) => {
        const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
        total += b.length;
        if (total <= 16384) chunks.push(b);
      });
      res.on('end', () => {
        clearTimeout(timer);
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
          if (parsed && parsed.status === 'success') {
            finish(parsed);
          } else {
            finish(null);
          }
        } catch {
          finish(null);
        }
      });
      res.on('error', () => {
        clearTimeout(timer);
        finish(null);
      });
    });

    req.on('timeout', () => {
      clearTimeout(timer);
      req.destroy();
      finish(null);
    });
    req.on('error', () => {
      clearTimeout(timer);
      finish(null);
    });
  });
}

async function inspectVpnOrProxy(req: Request): Promise<string | null> {
  const cfCountry = String(req.headers['cf-ipcountry'] || '').toUpperCase();
  if (cfCountry === 'T1') {
    return 'تم اكتشاف اتصال عبر شبكة Tor أو كاسر بروكسي مجهول.';
  }

  const via = String(req.headers['via'] || '');
  const proxyConn = String(req.headers['proxy-connection'] || '');
  if (
    proxyConn ||
    /\b(squid|privoxy|tinyproxy|3proxy|polipo|tor|vpn|anon|mikrotik-proxy)\b/i.test(via) ||
    req.headers['x-proxy-id'] ||
    req.headers['x-forwarded-proxy']
  ) {
    return 'تم رصد خادم بروكسي أو تطبيق VPN نشط في الاتصال.';
  }

  const ip = extractClientIp(req);
  if (isPrivateOrLoopbackIp(ip)) {
    return null;
  }

  const now = Date.now();
  const cached = vpnIpCache.get(ip);
  if (cached && now - cached.checkedAt < 30 * 60 * 1000) {
    return cached.blocked ? cached.reason : null;
  }

  if (vpnIpCache.size > 2000) {
    for (const [k, v] of vpnIpCache.entries()) {
      if (now - v.checkedAt > 30 * 60 * 1000) vpnIpCache.delete(k);
    }
  }

  const intel = await queryIpIntelligence(ip);
  if (!intel) {
    return null;
  }

  const combinedMeta = `${intel.isp || ''} ${intel.org || ''} ${intel.as || ''}`;
  const isGoogleInfra = /\b(google\s*llc|google\s*cloud)\b/i.test(combinedMeta);

  let blockedReason: string | null = null;
  if (VPN_ASN_ORG_REGEX.test(combinedMeta)) {
    blockedReason = 'تم اكتشاف اتصال عبر خادم VPN خارجي، يرجى إيقاف تطبيق الـ VPN.';
  } else if (intel.hosting === true && !isGoogleInfra) {
    blockedReason =
      intel.proxy === true
        ? 'تم اكتشاف اتصال عبر تطبيق VPN أو بروكسي، يرجى إيقافه للمتابعة.'
        : 'تم اكتشاف اتصال عبر خادم مركز بيانات (VPN / Proxy)، يرجى استخدام اتصالك العادي.';
  }

  vpnIpCache.set(ip, {
    blocked: Boolean(blockedReason),
    reason: blockedReason,
    checkedAt: now,
  });

  return blockedReason;
}

function signToken(payload: TokenPayload): string {
  const data = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getSecretKey())
    .update(data)
    .digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token: string | undefined): TokenPayload | null {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.', 2);
  if (!data || !sig) return null;
  const expectedSig = crypto
    .createHmac('sha256', getSecretKey())
    .update(data)
    .digest('base64url');

  const bufA = Buffer.from(sig);
  const bufB = Buffer.from(expectedSig);
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(data, 'base64url').toString('utf-8')) as TokenPayload;
  } catch {
    return null;
  }
}

function encryptAesJson(payload: object): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getSecretKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf-8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

function decryptAesJson<T>(token: string): T | null {
  try {
    const raw = Buffer.from(token, 'base64url');
    if (raw.length < 28) return null;
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const encrypted = raw.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', getSecretKey(), iv);
    decipher.setAuthTag(tag);
    const json = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

function safeEqualString(a: string, b: string): boolean {
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Rate limiter to block automated M3U / stream ticket scrapers.
 */
const ticketRateMap = new Map<string, { count: number; windowStart: number }>();

function checkTicketRateLimit(key: string, maxPerMinute = 180): boolean {
  const now = Date.now();
  if (ticketRateMap.size > 2000) {
    for (const [k, v] of ticketRateMap.entries()) {
      if (now - v.windowStart > 60000) ticketRateMap.delete(k);
    }
  }
  const entry = ticketRateMap.get(key);
  if (!entry || now - entry.windowStart > 60000) {
    ticketRateMap.set(key, { count: 1, windowStart: now });
    return true;
  }
  entry.count += 1;
  return entry.count <= maxPerMinute;
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Strips all upstream URLs and source secrets before sending channel objects to viewers.
 */
function sanitizeChannelForViewer(ch: StoredChannel) {
  return {
    id: ch.id,
    name: ch.name,
    group: ch.group,
    originalGroup: ch.originalGroup,
    logo: ch.logo,
    streamFormat: ch.streamFormat,
    contentType: ch.contentType,
    year: ch.year,
    featured: ch.featured,
    views: ch.views,
    order: ch.order,
    addedAt: ch.addedAt,
  };
}

function isAdminRequest(req: Request): boolean {
  const adminHeader = req.headers['x-admin-token'];
  const tokenStr = Array.isArray(adminHeader) ? adminHeader[0] : adminHeader;
  if (verifyToken(tokenStr)?.role === 'admin') {
    return true;
  }
  const viewer = extractViewerToken(req);
  return viewer?.code === 'ADMIN_OWNER';
}

function extractOsFamilyFromDeviceLabel(label: string): string {
  const s = String(label || '').toLowerCase();
  if (s.includes('windows')) return 'windows';
  if (s.includes('android')) return 'android';
  if (s.includes('iphone')) return 'iphone';
  if (s.includes('ipad')) return 'ipad';
  if (s.includes('mac')) return 'mac';
  if (s.includes('tv') || s.includes('شاشة')) return 'tv';
  if (s.includes('linux')) return 'linux';
  return 'other';
}

function checkAndBindSubscriberDevice(
  matched: ViewerAccessCode,
  deviceId: string,
  deviceName: string,
  ip: string,
  options?: { allowSameOwnerRebind?: boolean }
): { allowed: boolean; reason?: string } {
  const maxDevices = Math.max(1, Math.floor(Number(matched.maxDevices) || 1));
  if (!Array.isArray(matched.boundDevices)) {
    matched.boundDevices = [];
  }

  if (!deviceId || deviceId.length < 8) {
    return {
      allowed: false,
      reason: 'تعذر التحقق من بصمة الجهاز الآمنة، يرجى تحديث الصفحة والمحاولة مجدداً.',
    };
  }

  const nowIso = new Date().toISOString();
  const existing = matched.boundDevices.find((d) => d.deviceId === deviceId);

  if (existing) {
    const prevMs = Date.parse(existing.lastSeenAt || '') || 0;
    if (Date.now() - prevMs > 45000 || existing.ip !== ip) {
      existing.lastSeenAt = nowIso;
      existing.ip = ip;
      if (deviceName) existing.deviceName = deviceName;
      saveDb();
    }
    return { allowed: true };
  }

  if (matched.boundDevices.length < maxDevices) {
    matched.boundDevices.push({
      deviceId,
      deviceName: deviceName || 'جهاز متصل',
      ip,
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
    });
    saveDb();
    return { allowed: true };
  }

  // Seamless rebind when the exact same user (same IP + same OS family) opens a new tab, shared URL, PWA, or Android APK
  if (options?.allowSameOwnerRebind && ip && ip !== '0.0.0.0') {
    const incomingOs = extractOsFamilyFromDeviceLabel(deviceName);
    const sameHostSlot = matched.boundDevices.find(
      (d) =>
        d.ip === ip &&
        (incomingOs === 'other' ||
          extractOsFamilyFromDeviceLabel(d.deviceName) === incomingOs)
    );
    if (sameHostSlot) {
      const oldDeviceId = sameHostSlot.deviceId;
      sameHostSlot.deviceId = deviceId;
      sameHostSlot.deviceName = deviceName || sameHostSlot.deviceName;
      sameHostSlot.lastSeenAt = nowIso;
      saveDb();
      if (oldDeviceId && oldDeviceId !== deviceId) {
        abortViewerUpstreamConnections(matched.code, {
          deviceId: oldDeviceId,
          includeChunks: true,
        });
      }
      return { allowed: true };
    }
  }

  const reason =
    maxDevices === 1
      ? 'هذا الاشتراك مخصص لشخص واحد فقط ومرتبط بجهاز آخر حالياً. لا يمكن فتحه على أكثر من جهاز.'
      : `تم الوصول إلى الحد الأقصى المسموح به لهذا الاشتراك (${maxDevices} أشخاص / أجهزة). لا يمكن الدخول من جهاز إضافي.`;

  return { allowed: false, reason };
}

function validateSubscriberCodeLive(
  code: string,
  deviceInfo?: { deviceId: string; deviceName: string; ip: string }
): {
  valid: boolean;
  expiresAt: string | null;
  durationDays: number;
  maxDevices?: number;
  connectedDevicesCount?: number;
  errorCode?: string;
  reason?: string;
} {
  if (code === 'ADMIN_OWNER') {
    return {
      valid: true,
      expiresAt: null,
      durationDays: 365,
      maxDevices: 999,
      connectedDevicesCount: 1,
    };
  }
  const db = getDb();
  const matched = db.accessCodes.find((ac) => safeEqualString(ac.code, code));
  if (!matched) {
    return {
      valid: false,
      expiresAt: null,
      durationDays: 0,
      reason: 'تم إلغاء كود الاشتراك هذا.',
    };
  }
  if (!matched.active) {
    return {
      valid: false,
      expiresAt: matched.expiresAt,
      durationDays: 0,
      reason: 'هذا الاشتراك موقوف مؤقتاً من قبل الإدارة.',
    };
  }
  if (!isAccessCodeValidNow(matched)) {
    return {
      valid: false,
      expiresAt: matched.expiresAt,
      durationDays: 0,
      reason: 'انتهت مدة اشتراكك، يرجى التواصل مع الإدارة للتجديد.',
    };
  }

  if (deviceInfo) {
    const devCheck = checkAndBindSubscriberDevice(
      matched,
      deviceInfo.deviceId,
      deviceInfo.deviceName,
      deviceInfo.ip
    );
    if (!devCheck.allowed) {
      return {
        valid: false,
        expiresAt: matched.expiresAt,
        durationDays: 0,
        errorCode: 'DEVICE_LIMIT_REACHED',
        reason: devCheck.reason,
      };
    }
  }

  return {
    valid: true,
    expiresAt: matched.expiresAt,
    durationDays: computeDaysRemaining(matched.expiresAt),
    maxDevices: matched.maxDevices || 1,
    connectedDevicesCount: matched.boundDevices?.length || 0,
  };
}

function extractViewerToken(req: Request): TokenPayload | null {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const verified = verifyToken(authHeader.slice(7));
    if (verified) return verified;
  }
  return null;
}

async function enforceRequestProtection(
  req: Request,
  res: Response,
  subscriberCode?: string
): Promise<boolean> {
  if (isAdminRequest(req) || subscriberCode === 'ADMIN_OWNER') {
    return true;
  }

  const db = getDb();
  const policy = db.securityPolicy;
  const ip = extractClientIp(req);
  const { deviceName } = extractDeviceInfo(req);
  const ua = String(req.headers['user-agent'] || '');

  if (policy.blockSniffers) {
    const snifferReason = inspectSnifferRequest(req);
    if (snifferReason) {
      recordSecurityEvent({
        type: 'sniffer_blocked',
        reason: snifferReason,
        ip,
        deviceName,
        subscriberCode,
        userAgent: ua,
      });
      res.status(403).json({
        error: `${snifferReason} يرجى إغلاق برامج سحب الروابط للمتابعة.`,
        code: 'SNIFFER_BLOCKED',
      });
      return false;
    }
  }

  if (policy.blockVpn) {
    const vpnReason = await inspectVpnOrProxy(req);
    if (vpnReason) {
      recordSecurityEvent({
        type: 'vpn_blocked',
        reason: vpnReason,
        ip,
        deviceName,
        subscriberCode,
        userAgent: ua,
      });
      res.status(403).json({
        error: vpnReason,
        code: 'VPN_BLOCKED',
      });
      return false;
    }
  }

  return true;
}

async function requireViewerAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const payload = extractViewerToken(req);
  if (!payload) {
    res.status(401).json({ error: 'جلسة الدخول غير صالحة، يرجى إدخال كود التفعيل.' });
    return;
  }

  const db = getDb();
  if (db.maintenanceMode && payload.code !== 'ADMIN_OWNER' && !isAdminRequest(req)) {
    abortViewerUpstreamConnections(payload.code, { includeChunks: true });
    res.status(503).json({
      error: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
      code: 'MAINTENANCE_MODE',
    });
    return;
  }

  const passedSecurity = await enforceRequestProtection(req, res, payload.code);
  if (!passedSecurity) {
    return;
  }

  const { deviceId, deviceName } = extractDeviceInfo(req);
  const effectiveDeviceId = deviceId || payload.did || '';
  const ip = extractClientIp(req);

  const subCheck = validateSubscriberCodeLive(
    payload.code,
    payload.code === 'ADMIN_OWNER' ? undefined : { deviceId: effectiveDeviceId, deviceName, ip }
  );
  if (!subCheck.valid) {
    if (subCheck.errorCode === 'DEVICE_LIMIT_REACHED') {
      recordSecurityEvent({
        type: 'device_limit',
        reason: subCheck.reason || 'تجاوز عدد الأجهزة المسموح بها للاشتراك.',
        ip,
        deviceName,
        subscriberCode: payload.code,
        userAgent: String(req.headers['user-agent'] || ''),
      });
    }
    res.status(401).json({
      error: subCheck.reason || 'انتهت صلاحية الاشتراك.',
      code: subCheck.errorCode,
    });
    return;
  }
  (req as any).viewer = { ...payload, did: effectiveDeviceId };
  (req as any).subscriptionInfo = subCheck;
  next();
}

function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  const adminHeader = req.headers['x-admin-token'];
  const tokenStr = Array.isArray(adminHeader) ? adminHeader[0] : adminHeader;
  const payload = verifyToken(tokenStr);
  if (!payload || payload.role !== 'admin') {
    res.status(403).json({ error: 'غير مصرح لك بالوصول إلى لوحة الإدارة السرية.' });
    return;
  }
  (req as any).admin = payload;
  next();
}

/**
 * Validates anti-theft stream playback tickets:
 * - Blocks direct browser address-bar / document scraping
 * - Blocks HttpCanary / MITM / external VLC/FFmpeg/okhttp players when blockSniffers is ON
 * - Verifies AES-256-GCM signature, expiration, User-Agent, Device ID, IP subnet, and heartbeat lease
 */
async function verifyProtectedStreamTicket(
  req: Request,
  rawTicket: string
): Promise<{ ticket: StreamTicketPayload; deviceId: string } | null> {
  const secFetchMode = String(req.headers['sec-fetch-mode'] || '').toLowerCase();
  const secFetchDest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
  const acceptHdr = String(req.headers['accept'] || '').toLowerCase();
  const isMediaOrXhrDest =
    secFetchDest === 'video' || secFetchDest === 'audio' || secFetchDest === 'empty';
  if (
    secFetchMode === 'navigate' ||
    secFetchDest === 'document' ||
    secFetchDest === 'iframe' ||
    (acceptHdr.includes('text/html') && !isMediaOrXhrDest)
  ) {
    return null;
  }

  const parsed = decryptAesJson<StreamTicketPayload>(rawTicket);
  if (!parsed || !parsed.cid || !parsed.code || !parsed.uah || !parsed.exp) {
    return null;
  }
  if (Date.now() > parsed.exp) {
    return null;
  }

  const db = getDb();
  const policy = db.securityPolicy;
  const isAdminStream = parsed.code === 'ADMIN_OWNER' || isAdminRequest(req);
  if (db.maintenanceMode && !isAdminStream) {
    return null;
  }
  const ip = extractClientIp(req);
  const { deviceId, deviceName } = extractDeviceInfo(req);
  const ua = String(req.headers['user-agent'] || '');

  if (!isAdminStream && policy.blockSniffers) {
    const snifferReason = inspectSnifferRequest(req, {
      isMediaRoute: true,
      allowAppleCoreMedia: Boolean(parsed.apple),
    });
    if (snifferReason) {
      recordSecurityEvent({
        type: 'sniffer_blocked',
        reason: snifferReason,
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }
  }

  if (!isAdminStream && policy.blockVpn) {
    const vpnReason = await inspectVpnOrProxy(req);
    if (vpnReason) {
      recordSecurityEvent({
        type: 'vpn_blocked',
        reason: vpnReason,
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }
  }

  // Bind ticket strictly to browser User-Agent (or iOS native AppleCoreMedia when issued to Safari)
  const currentUah = computeUserAgentHash(req);
  const isAppleNativeMedia = Boolean(parsed.apple) && /^AppleCoreMedia\//i.test(ua);
  if (!isAppleNativeMedia && !safeEqualString(parsed.uah, currentUah)) {
    return null;
  }

  if (!isAdminStream && policy.strictStreamBinding) {
    if (!deviceId || !parsed.dvh || !safeEqualString(parsed.dvh, computeDeviceHash(deviceId))) {
      recordSecurityEvent({
        type: 'sniffer_blocked',
        reason: 'محاولة تشغيل رابط بث مسحوب على جهاز أو برنامج غير مصرح به.',
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }

    if (parsed.iph && parsed.iph !== 'local-net') {
      const currentIph = computeIpFingerprint(ip);
      if (currentIph !== 'local-net' && !safeEqualString(parsed.iph, currentIph)) {
        recordSecurityEvent({
          type: 'sniffer_blocked',
          reason: 'محاولة مشاركة أو سحب رابط البث إلى شبكة اتصال خارجية مختلفة.',
          ip,
          deviceName,
          subscriberCode: parsed.code,
          userAgent: ua,
        });
        return null;
      }
    }

    if (parsed.tid) {
      const lease = activeStreamLeases.get(parsed.tid);
      // Lease stays alive seamlessly via FastPlayer's 40s authenticated heartbeat, and expires 110s after app closes!
      if (!lease || Date.now() - lease.lastHeartbeatAt > 110000) {
        return null;
      }
    }
  }

  const subCheck = validateSubscriberCodeLive(
    parsed.code,
    isAdminStream || !deviceId ? undefined : { deviceId, deviceName, ip }
  );
  if (!subCheck.valid) {
    return null;
  }

  return { ticket: parsed, deviceId: deviceId || 'default' };
}

/**
 * Verifies viewer-bound fast stream session token (allows 0ms single-round-trip channel launch
 * while preserving full anti-HttpCanary, anti-VPN, device binding, IP subnet, and heartbeat lease security).
 */
async function verifyProtectedStreamSessionToken(
  req: Request,
  rawSessionToken: string,
  channelId: string
): Promise<{
  session: StreamSessionTokenPayload;
  synthesizedTicket: string;
  deviceId: string;
} | null> {
  const secFetchMode = String(req.headers['sec-fetch-mode'] || '').toLowerCase();
  const secFetchDest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
  const acceptHdr = String(req.headers['accept'] || '').toLowerCase();
  const isMediaOrXhrDest =
    secFetchDest === 'video' || secFetchDest === 'audio' || secFetchDest === 'empty';
  if (
    secFetchMode === 'navigate' ||
    secFetchDest === 'document' ||
    secFetchDest === 'iframe' ||
    (acceptHdr.includes('text/html') && !isMediaOrXhrDest)
  ) {
    return null;
  }

  const parsed = decryptAesJson<StreamSessionTokenPayload>(rawSessionToken);
  if (!parsed || !parsed.sid || !parsed.code || !parsed.uah || !parsed.exp) {
    return null;
  }
  if (Date.now() > parsed.exp) {
    return null;
  }

  const db = getDb();
  const policy = db.securityPolicy;
  const isAdminStream = parsed.code === 'ADMIN_OWNER' || isAdminRequest(req);
  if (db.maintenanceMode && !isAdminStream) {
    return null;
  }
  const ip = extractClientIp(req);
  const { deviceId, deviceName } = extractDeviceInfo(req);
  const ua = String(req.headers['user-agent'] || '');

  if (!isAdminStream && policy.blockSniffers) {
    const snifferReason = inspectSnifferRequest(req, {
      isMediaRoute: true,
      allowAppleCoreMedia: Boolean(parsed.apple),
    });
    if (snifferReason) {
      recordSecurityEvent({
        type: 'sniffer_blocked',
        reason: snifferReason,
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }
  }

  if (!isAdminStream && policy.blockVpn) {
    const vpnReason = await inspectVpnOrProxy(req);
    if (vpnReason) {
      recordSecurityEvent({
        type: 'vpn_blocked',
        reason: vpnReason,
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }
  }

  const currentUah = computeUserAgentHash(req);
  const isAppleNativeMedia = Boolean(parsed.apple) && /^AppleCoreMedia\//i.test(ua);
  if (!isAppleNativeMedia && !safeEqualString(parsed.uah, currentUah)) {
    return null;
  }

  if (!isAdminStream && policy.strictStreamBinding) {
    if (!deviceId || !parsed.dvh || !safeEqualString(parsed.dvh, computeDeviceHash(deviceId))) {
      recordSecurityEvent({
        type: 'sniffer_blocked',
        reason: 'محاولة تشغيل رابط بث مسحوب على جهاز أو برنامج غير مصرح به.',
        ip,
        deviceName,
        subscriberCode: parsed.code,
        userAgent: ua,
      });
      return null;
    }

    if (parsed.iph && parsed.iph !== 'local-net') {
      const currentIph = computeIpFingerprint(ip);
      if (currentIph !== 'local-net' && !safeEqualString(parsed.iph, currentIph)) {
        recordSecurityEvent({
          type: 'sniffer_blocked',
          reason: 'محاولة مشاركة أو سحب رابط البث إلى شبكة اتصال خارجية مختلفة.',
          ip,
          deviceName,
          subscriberCode: parsed.code,
          userAgent: ua,
        });
        return null;
      }
    }

  }

  const subCheck = validateSubscriberCodeLive(
    parsed.code,
    isAdminStream || !deviceId ? undefined : { deviceId, deviceName, ip }
  );
  if (!subCheck.valid) {
    return null;
  }

  // Always refresh or recreate the active lease on authenticated session-token stream launch
  // so browsing idle > 2 minutes or server restarts never cause 403 failures on first click!
  const now = Date.now();
  const existingLease = activeStreamLeases.get(parsed.sid);
  if (existingLease) {
    existingLease.channelId = channelId;
    existingLease.lastHeartbeatAt = now;
  } else {
    activeStreamLeases.set(parsed.sid, {
      tid: parsed.sid,
      code: parsed.code,
      deviceId: deviceId || 'default',
      channelId,
      createdAt: now,
      lastHeartbeatAt: now,
    });
  }

  const synthesizedTicket = encryptAesJson({
    tid: parsed.sid,
    cid: channelId,
    code: parsed.code,
    uah: parsed.uah,
    dvh: parsed.dvh,
    iph: parsed.iph,
    apple: parsed.apple,
    exp: parsed.exp,
  } satisfies StreamTicketPayload);

  return {
    session: parsed,
    synthesizedTicket,
    deviceId: deviceId || 'default',
  };
}

function rewriteHlsManifest(
  manifestText: string,
  baseUrl: string,
  streamTicket: string,
  deviceId: string,
  strictBinding: boolean,
  ua?: string,
  ref?: string,
  cookie?: string,
  playId?: string,
  publicApiOrigin?: string
): string {
  const lines = manifestText.split(/\r?\n/);
  const chunkExpiresAt = strictBinding ? Date.now() + 3 * 60 * 1000 : undefined;
  const pidParam = playId ? `&pid=${encodeURIComponent(playId)}` : '';
  const originPrefix = publicApiOrigin ? publicApiOrigin.replace(/\/+$/, '') : '';
  const makeProxyUrl = (rawUri: string) => {
    let resolved: string;
    try {
      resolved = new URL(rawUri.trim(), baseUrl).toString();
    } catch {
      return rawUri;
    }
    const enc = encryptAesJson({
      url: resolved,
      ua,
      ref,
      cookie,
      cexp: chunkExpiresAt,
    } satisfies EncryptedStreamRef);
    return `${originPrefix}/api/proxy-chunk?t=${encodeURIComponent(streamTicket)}&d=${encodeURIComponent(
      deviceId
    )}${pidParam}&u=${encodeURIComponent(enc)}`;
  };

  return lines
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;

      if (trimmed.startsWith('#')) {
        return line.replace(/URI="([^"]+)"/gi, (_match, uriVal: string) => {
          return `URI="${makeProxyUrl(uriVal)}"`;
        });
      }

      return makeProxyUrl(trimmed);
    })
    .join('\n');
}

interface UpstreamConnection {
  res: http.IncomingMessage;
  finalUrl: string;
  cookieHeader?: string;
  destroy: () => void;
}

/**
 * Tracks active upstream connections per viewer+device so switching channels or closing the player
 * immediately destroys that device's previous TCP socket without interrupting other allowed devices on multi-user codes.
 */
interface ActiveUpstreamEntry {
  id: string;
  viewerCode: string;
  deviceId: string;
  channelId: string;
  ticket: string;
  playId: string;
  isSegmentChunk: boolean;
  startedAt: number;
  destroy: () => void;
}

const activeUpstreamMap = new Map<string, ActiveUpstreamEntry>();

function abortViewerUpstreamConnections(
  viewerCode: string,
  options: {
    deviceId?: string;
    matchSameDeviceAnyCode?: boolean;
    onlyTicket?: string;
    onlyPlayId?: string;
    exceptPlayId?: string;
    exceptChannelId?: string;
    includeChunks?: boolean;
  } = {}
): number {
  let count = 0;
  for (const [id, entry] of activeUpstreamMap.entries()) {
    const sameDeviceAcrossCode = Boolean(
      options.matchSameDeviceAnyCode &&
        options.deviceId &&
        options.deviceId !== 'default' &&
        entry.deviceId === options.deviceId
    );
    if (!sameDeviceAcrossCode) {
      if (entry.viewerCode !== viewerCode) continue;
      if (options.deviceId && entry.deviceId !== options.deviceId) continue;
    }
    if (options.onlyTicket && entry.ticket !== options.onlyTicket) continue;
    if (options.onlyPlayId && entry.playId !== options.onlyPlayId) continue;
    if (options.exceptPlayId && entry.playId && entry.playId === options.exceptPlayId) continue;
    if (options.exceptChannelId && entry.channelId === options.exceptChannelId) continue;
    if (!options.includeChunks && entry.isSegmentChunk) continue;
    activeUpstreamMap.delete(id);
    try {
      entry.destroy();
    } catch {
      // ignore
    }
    count++;
  }
  return count;
}

function abortAllNonAdminStreams(): number {
  let aborted = 0;
  for (const [id, entry] of activeUpstreamMap.entries()) {
    if (entry.viewerCode === 'ADMIN_OWNER') continue;
    activeUpstreamMap.delete(id);
    try {
      entry.destroy();
    } catch {
      // ignore
    }
    aborted++;
  }
  for (const [tid, lease] of activeStreamLeases.entries()) {
    if (lease.code !== 'ADMIN_OWNER') {
      activeStreamLeases.delete(tid);
    }
  }
  return aborted;
}

interface HlsEdgeSession {
  edgeUrl: string;
  ua: string;
  cookie?: string;
  updatedAt: number;
}

const hlsEdgeSessionCache = new Map<string, HlsEdgeSession>();

function clearViewerOtherHlsSessions(
  viewerCode: string,
  deviceId: string,
  keepChannelId?: string
): void {
  const prefix = `${viewerCode}:${deviceId}:`;
  for (const key of hlsEdgeSessionCache.keys()) {
    if (key.startsWith(prefix) && (!keepChannelId || key !== `${prefix}${keepChannelId}`)) {
      hlsEdgeSessionCache.delete(key);
    }
  }
}

function openResilientStream(
  rawUrl: string,
  headers: Record<string, string>,
  onAbortRegister?: (abortFn: () => void) => void,
  useKeepAlive = false,
  redirectCount = 0,
  accumulatedCookies: string[] = []
): Promise<UpstreamConnection> {
  return new Promise((resolve, reject) => {
    if (redirectCount > 6) {
      reject(new Error('Too many redirects'));
      return;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch (err) {
      reject(err);
      return;
    }

    const reqHeaders: Record<string, string> = {
      ...headers,
      Connection: useKeepAlive ? 'keep-alive' : 'close',
    };
    if (accumulatedCookies.length > 0 && !reqHeaders['Cookie']) {
      reqHeaders['Cookie'] = accumulatedCookies.join('; ');
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;
    const agent = useKeepAlive
      ? isHttps
        ? keepAliveHttpsAgent
        : keepAliveHttpAgent
      : false;

    let activeRes: http.IncomingMessage | null = null;
    let connectTimer: NodeJS.Timeout | null = setTimeout(() => {
      connectTimer = null;
      upstreamReq.destroy(new Error('Upstream connect timeout'));
    }, 6500);

    const clearConnectTimer = () => {
      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }
    };

    const upstreamReq = transport.request(
      parsedUrl,
      {
        method: 'GET',
        agent,
        insecureHTTPParser: true,
        rejectUnauthorized: false,
        headers: reqHeaders,
      },
      (upstreamRes) => {
        clearConnectTimer();
        activeRes = upstreamRes;
        const status = upstreamRes.statusCode || 0;
        const location = upstreamRes.headers.location;
        const rawSetCookie = upstreamRes.headers['set-cookie'];

        const nextCookies = [...accumulatedCookies];
        if (Array.isArray(rawSetCookie)) {
          for (const sc of rawSetCookie) {
            const pair = sc.split(';')[0]?.trim();
            if (pair && !nextCookies.includes(pair)) nextCookies.push(pair);
          }
        }

        if ([301, 302, 303, 307, 308].includes(status) && location) {
          upstreamRes.resume();
          if (!useKeepAlive) {
            upstreamRes.destroy();
          }
          let nextUrl: string;
          try {
            nextUrl = new URL(location, parsedUrl).toString();
          } catch (err) {
            reject(err);
            return;
          }
          openResilientStream(
            nextUrl,
            headers,
            onAbortRegister,
            useKeepAlive,
            redirectCount + 1,
            nextCookies
          )
            .then(resolve)
            .catch(reject);
          return;
        }

        resolve({
          res: upstreamRes,
          finalUrl: rawUrl,
          cookieHeader: nextCookies.length > 0 ? nextCookies.join('; ') : undefined,
          destroy: () => {
            clearConnectTimer();
            try {
              upstreamRes.destroy();
            } catch {
              // ignore
            }
            try {
              upstreamReq.destroy();
            } catch {
              // ignore
            }
          },
        });
      }
    );

    upstreamReq.setNoDelay(true);

    if (onAbortRegister) {
      onAbortRegister(() => {
        clearConnectTimer();
        try {
          activeRes?.destroy();
        } catch {
          // ignore
        }
        try {
          upstreamReq.destroy();
        } catch {
          // ignore
        }
      });
    }

    upstreamReq.on('error', (err) => {
      clearConnectTimer();
      reject(err);
    });

    upstreamReq.end();
  });
}

/**
 * Peeks at the very first chunk of an upstream response (with timeout) so we can
 * accurately detect #EXTM3U vs raw binary MPEG-TS (0x47) / MP4 without losing a single byte!
 */
function peekFirstStreamChunk(
  stream: NodeJS.ReadableStream,
  timeoutMs = 5000
): Promise<{ firstChunk: Buffer | null; ended: boolean }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error('First byte timeout'));
      }
    }, timeoutMs);

    const onData = (chunk: Buffer | string) => {
      if (settled) return;
      settled = true;
      stream.pause();
      cleanup();
      resolve({
        firstChunk: Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        ended: false,
      });
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({ firstChunk: null, ended: true });
    };

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };

    stream.once('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onError);
  });
}

async function pipeUpstreamStream(
  req: Request,
  res: Response,
  candidateUrls: string[],
  streamTicket: string,
  options: {
    viewerCode: string;
    deviceId: string;
    channelId: string;
    playId?: string;
    ua?: string;
    ref?: string;
    cookie?: string;
    requestedEngine?: string;
    isSegmentChunk?: boolean;
    refreshEdge?: boolean;
  }
): Promise<void> {
  req.socket?.setNoDelay(true);

  let clientClosed = false;
  let abortedInternally = false;
  let activeConn: UpstreamConnection | null = null;
  let inFlightAbort: (() => void) | null = null;
  let winningUa = options.ua || 'VLC/3.0.20 LibVLC/3.0.20';

  const trackingId = `up_${crypto.randomBytes(6).toString('hex')}`;
  const destroyAllUpstream = () => {
    activeUpstreamMap.delete(trackingId);
    if (inFlightAbort) {
      const fn = inFlightAbort;
      inFlightAbort = null;
      fn();
    }
    if (activeConn) {
      const c = activeConn;
      activeConn = null;
      c.destroy();
    }
  };

  const terminateResponseCleanly = () => {
    try {
      if (!res.headersSent) {
        res.status(499).end();
      } else if (!res.writableEnded) {
        res.end();
      }
    } catch {
      // ignore socket teardown errors
    }
  };

  activeUpstreamMap.set(trackingId, {
    id: trackingId,
    viewerCode: options.viewerCode,
    deviceId: options.deviceId,
    channelId: options.channelId,
    ticket: streamTicket,
    playId: options.playId || '',
    isSegmentChunk: Boolean(options.isSegmentChunk),
    startedAt: Date.now(),
    destroy: () => {
      abortedInternally = true;
      destroyAllUpstream();
      terminateResponseCleanly();
    },
  });

  // Listen to outgoing response close (NOT req.on('close'), which fires early on GET in Node 18+)
  res.on('close', () => {
    if (!res.writableEnded) {
      clientClosed = true;
    }
    destroyAllUpstream();
  });

  const buildHeaders = (
    urlStr: string,
    userAgent: string,
    extraCookie?: string
  ): Record<string, string> => {
    let originRef = options.ref;
    if (!originRef) {
      try {
        const u = new URL(urlStr);
        originRef = `${u.protocol}//${u.host}/`;
      } catch {
        originRef = undefined;
      }
    }
    const h: Record<string, string> = {
      'User-Agent': userAgent,
      Accept: '*/*',
    };
    if (originRef) h['Referer'] = originRef;
    if (extraCookie || options.cookie) h['Cookie'] = extraCookie || options.cookie!;
    if (req.headers.range) h['Range'] = String(req.headers.range);
    return h;
  };

  const hlsSessionKey = `${options.viewerCode}:${options.deviceId}:${options.channelId}`;
  if (options.refreshEdge) {
    hlsEdgeSessionCache.delete(hlsSessionKey);
  }

  let lastStatus = 502;
  let firstChunk: Buffer | null = null;
  let streamEndedOnPeek = false;

  // 1. Try Sticky Redirected HLS Edge URL ONLY for HLS manifest refreshes (never for one-time-token .ts streams!)
  if (!options.isSegmentChunk && !options.refreshEdge && options.requestedEngine !== 'mpegts') {
    const cachedEdge = hlsEdgeSessionCache.get(hlsSessionKey);
    const maxEdgeAgeMs = 10 * 60 * 1000;

    if (
      cachedEdge &&
      Date.now() - cachedEdge.updatedAt < maxEdgeAgeMs &&
      !clientClosed &&
      !abortedInternally
    ) {
      try {
        const conn = await openResilientStream(
          cachedEdge.edgeUrl,
          buildHeaders(cachedEdge.edgeUrl, cachedEdge.ua, cachedEdge.cookie),
          (abortFn) => {
            inFlightAbort = abortFn;
          },
          true
        );
        inFlightAbort = null;
        const status = conn.res.statusCode || 502;
        if (status >= 200 && status < 400 && !clientClosed && !abortedInternally) {
          const peeked = await peekFirstStreamChunk(conn.res, 3400);
          if (peeked.firstChunk && peeked.firstChunk.length > 0) {
            activeConn = conn;
            winningUa = cachedEdge.ua;
            firstChunk = peeked.firstChunk;
            streamEndedOnPeek = peeked.ended;
          } else {
            conn.destroy();
            hlsEdgeSessionCache.delete(hlsSessionKey);
          }
        } else {
          conn.destroy();
          hlsEdgeSessionCache.delete(hlsSessionKey);
        }
      } catch {
        inFlightAbort = null;
        hlsEdgeSessionCache.delete(hlsSessionKey);
      }
    }
  }

  // 2. Fast Resilient Upstream Probe with Cold-Stream & Xtream Slot-Release Auto-Retry
  if (!activeConn && !clientClosed && !abortedInternally) {
    const maxAttemptsPerUrl = options.isSegmentChunk ? 2 : 4;
    const slotBackoffSchedule = [350, 650, 950];

    outer: for (const urlCandidate of candidateUrls) {
      let currentUa = options.ua || 'VLC/3.0.20 LibVLC/3.0.20';
      const lowerCand = urlCandidate.toLowerCase().split('?')[0];
      const useKeepAlive = Boolean(
        options.isSegmentChunk ||
          options.requestedEngine === 'hls' ||
          lowerCand.endsWith('.m3u8')
      );

      for (let attempt = 0; attempt < maxAttemptsPerUrl; attempt++) {
        if (clientClosed || abortedInternally) break outer;
        try {
          const conn = await openResilientStream(
            urlCandidate,
            buildHeaders(urlCandidate, currentUa),
            (abortFn) => {
              inFlightAbort = abortFn;
            },
            useKeepAlive
          );
          inFlightAbort = null;
          const status = conn.res.statusCode || 502;
          lastStatus = status;

          if (status >= 200 && status < 400) {
            try {
              const peeked = await peekFirstStreamChunk(
                conn.res,
                options.isSegmentChunk ? 4800 : 3800
              );
              if (peeked.firstChunk && peeked.firstChunk.length > 0) {
                activeConn = conn;
                winningUa = currentUa;
                firstChunk = peeked.firstChunk;
                streamEndedOnPeek = peeked.ended;
                break outer;
              }
            } catch {
              // Timed out waiting for first bytes (cold on-demand IPTV transcoder warming up)
            }
            conn.destroy();
            if (attempt < maxAttemptsPerUrl - 1 && !clientClosed && !abortedInternally) {
              if (!options.ua && attempt === 1) {
                currentUa = 'IPTVSmartersPro/1.1.1 (iPad; iOS 16.5; Scale/2.00)';
              }
              await sleepMs(options.isSegmentChunk ? 180 : 350);
              continue;
            }
            break;
          }

          conn.destroy();

          // Only rotate UA immediately on 403; on 401 Xtream is usually releasing active_cons (~500-1500ms)
          if (status === 403 && !options.ua && attempt === 0) {
            currentUa = 'IPTVSmartersPro/1.1.1 (iPad; iOS 16.5; Scale/2.00)';
          } else if (status === 401 && !options.ua && attempt === 2) {
            currentUa = 'IPTVSmartersPro/1.1.1 (iPad; iOS 16.5; Scale/2.00)';
          }

          if (
            [401, 403, 404, 429, 456, 458, 500, 502, 503, 504].includes(status) &&
            attempt < maxAttemptsPerUrl - 1 &&
            !clientClosed &&
            !abortedInternally
          ) {
            const waitMs = options.isSegmentChunk
              ? 180
              : [401, 429, 456, 458, 503].includes(status)
              ? slotBackoffSchedule[attempt] ?? 850
              : 300;
            await sleepMs(waitMs);
            continue;
          }

          break;
        } catch {
          inFlightAbort = null;
          if (attempt < maxAttemptsPerUrl - 1 && !clientClosed && !abortedInternally) {
            await sleepMs(options.isSegmentChunk ? 160 : 280);
            continue;
          }
        }
      }
    }
  }

  if (clientClosed || abortedInternally) {
    destroyAllUpstream();
    terminateResponseCleanly();
    return;
  }

  if (!activeConn || !firstChunk) {
    destroyAllUpstream();
    if (!res.headersSent) {
      res.status(lastStatus >= 400 ? lastStatus : 502).json({
        error: `تعذر استلام إشارة البث من المصدر (HTTP ${lastStatus})`,
      });
    }
    return;
  }

  const upstreamRes = activeConn.res;
  const finalUrl = activeConn.finalUrl || candidateUrls[0];
  const mergedCookie = activeConn.cookieHeader || options.cookie;
  const contentType = String(upstreamRes.headers['content-type'] || '').toLowerCase();
  const encoding = String(upstreamRes.headers['content-encoding'] || '').toLowerCase();
  const lowerUrl = finalUrl.toLowerCase().split('?')[0];

  // Check if first bytes look like an HLS #EXTM3U manifest (plain or gzipped)
  const isCompressed = encoding === 'gzip' || encoding === 'deflate';
  const rawHeadPreview = !isCompressed
    ? firstChunk
        .subarray(0, Math.min(firstChunk.length, 256))
        .toString('utf-8')
        .replace(/^\uFEFF/, '')
        .trimStart()
    : '';

  const looksLikeHlsManifest =
    rawHeadPreview.startsWith('#EXTM3U') ||
    (isCompressed &&
      (contentType.includes('mpegurl') ||
        contentType.includes('x-mpegurl') ||
        lowerUrl.endsWith('.m3u8')));

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Accel-Buffering', 'no');

  if (looksLikeHlsManifest && !options.isSegmentChunk) {
    // Remember learned format so future plays launch HLS directly at 0ms
    const storedCh = getDb().channels.find((c) => c.id === options.channelId);
    if (storedCh && storedCh.streamFormat === 'auto') {
      storedCh.streamFormat = 'hls';
    }

    // If client explicitly asked for raw MPEG-TS engine, notify immediately to switch to HLS!
    if (options.requestedEngine === 'mpegts') {
      destroyAllUpstream();
      res.status(415).json({ error: 'HLS_DETECTED', detectedFormat: 'hls' });
      return;
    }

    try {
      const rawChunks: Buffer[] = [firstChunk];
      if (!streamEndedOnPeek) {
        upstreamRes.resume();
        let total = firstChunk.length;
        for await (const chunk of upstreamRes) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          total += buf.length;
          if (total > 6 * 1024 * 1024) break;
          rawChunks.push(buf);
        }
      }
      destroyAllUpstream();

      let fullBuffer = Buffer.concat(rawChunks);
      if (encoding === 'gzip') {
        fullBuffer = zlib.gunzipSync(fullBuffer);
      } else if (encoding === 'deflate') {
        fullBuffer = zlib.inflateSync(fullBuffer);
      }

      const rawText = fullBuffer.toString('utf-8').replace(/^\uFEFF/, '');
      if (rawText.trimStart().startsWith('#EXTM3U')) {
        // Cache sticky edge URL so subsequent 5s HLS refreshes stay on the exact same edge node & token!
        if (hlsEdgeSessionCache.size > 1000) {
          const cutoff = Date.now() - 10 * 60 * 1000;
          for (const [k, v] of hlsEdgeSessionCache.entries()) {
            if (v.updatedAt < cutoff) hlsEdgeSessionCache.delete(k);
          }
        }
        hlsEdgeSessionCache.set(hlsSessionKey, {
          edgeUrl: finalUrl,
          ua: winningUa,
          cookie: mergedCookie,
          updatedAt: Date.now(),
        });

        const strictBinding = Boolean(getDb().securityPolicy?.strictStreamBinding);
        const forwardedProto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https')
          .split(',')[0]
          .trim();
        const reqHost = req.get('host');
        const crossOriginBase =
          req.headers.origin && reqHost ? `${forwardedProto}://${reqHost}` : '';
        const rewritten = rewriteHlsManifest(
          rawText,
          finalUrl,
          streamTicket,
          options.deviceId,
          strictBinding,
          winningUa,
          options.ref,
          mergedCookie,
          options.playId,
          crossOriginBase
        );
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl; charset=utf-8');
        res.status(200).send(rewritten);
        return;
      }

      res.setHeader('Content-Type', contentType || 'video/mp2t');
      res.status(200).send(fullBuffer);
      return;
    } catch {
      destroyAllUpstream();
      if (!res.headersSent) {
        res.status(502).json({ error: 'تعذر قراءة قائمة البث.' });
      }
      return;
    }
  }

  // Binary media stream (.ts, .mp4, .m4s, AAC, live MPEG-TS)
  const isMp4 =
    contentType.includes('mp4') ||
    lowerUrl.endsWith('.mp4') ||
    lowerUrl.endsWith('.mkv') ||
    firstChunk.subarray(4, 8).toString('ascii') === 'ftyp';

  if (!options.isSegmentChunk) {
    const storedCh = getDb().channels.find((c) => c.id === options.channelId);
    if (storedCh && storedCh.streamFormat === 'auto') {
      storedCh.streamFormat = isMp4 ? 'mp4' : 'mpegts';
    }
  }

  if (!options.isSegmentChunk && options.requestedEngine === 'hls') {
    destroyAllUpstream();
    res.status(415).json({
      error: isMp4 ? 'MP4_DETECTED' : 'MPEGTS_DETECTED',
      detectedFormat: isMp4 ? 'mp4' : 'mpegts',
    });
    return;
  }

  if (contentType && !contentType.includes('text/plain') && !contentType.includes('octet-stream')) {
    res.setHeader('Content-Type', contentType);
  } else if (isMp4) {
    res.setHeader('Content-Type', 'video/mp4');
  } else {
    res.setHeader('Content-Type', 'video/mp2t');
  }

  const contentLength = upstreamRes.headers['content-length'];
  if (contentLength) res.setHeader('Content-Length', contentLength);
  const contentRange = upstreamRes.headers['content-range'];
  if (contentRange) res.setHeader('Content-Range', contentRange);
  const acceptRanges = upstreamRes.headers['accept-ranges'];
  if (acceptRanges) res.setHeader('Accept-Ranges', acceptRanges);

  res.status(upstreamRes.statusCode || 200);
  res.flushHeaders();

  // Write the peeked first chunk before piping the remainder so zero bytes are lost!
  res.write(firstChunk);

  if (streamEndedOnPeek) {
    destroyAllUpstream();
    res.end();
    return;
  }

  // Dead-socket watchdog: if a live stream stops sending bytes for 22s, close cleanly so client auto-reconnects
  let stallTimer: NodeJS.Timeout | null = null;
  const resetStallTimer = () => {
    if (stallTimer) clearTimeout(stallTimer);
    stallTimer = setTimeout(() => {
      destroyAllUpstream();
      if (!res.writableEnded) res.end();
    }, 22000);
  };
  resetStallTimer();

  const clearStall = () => {
    if (stallTimer) {
      clearTimeout(stallTimer);
      stallTimer = null;
    }
  };

  upstreamRes.on('data', resetStallTimer);
  upstreamRes.on('end', () => {
    clearStall();
    destroyAllUpstream();
    if (!res.writableEnded) res.end();
  });
  upstreamRes.on('error', () => {
    clearStall();
    destroyAllUpstream();
    if (!res.writableEnded) res.end();
  });
  res.on('close', () => {
    clearStall();
    destroyAllUpstream();
  });

  upstreamRes.resume();
  upstreamRes.pipe(res);
}

async function startServer() {
  const app = express();
  const isProd =
    process.env.NODE_ENV === 'production' || process.env.npm_lifecycle_event === 'start';
  const PORT = isProd ? Number(process.env.PORT) || 3000 : 3000;

  app.set('trust proxy', 1);

  // Initialize persistent database on boot
  getDb();

  // CORS middleware for Capacitor Android APK (https://localhost / capacitor://localhost) & cross-origin clients
  app.use('/api', (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Admin-Token, X-Device-Id, X-Device-Name, X-Client-Tz, Range'
    );
    res.setHeader(
      'Access-Control-Expose-Headers',
      'Content-Length, Content-Range, Accept-Ranges, Content-Type'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(express.json({ limit: '50mb' }));

  const resolveDetectedServerUrl = (req: Request): string => {
    const normalizePublicHost = (rawUrl: string): string =>
      rawUrl
        .trim()
        .replace(/\/+$/, '')
        .replace(/^(https?:\/\/)ais-dev-/i, '$1ais-pre-');

    const db = getDb();
    if (db.apkServerUrl && /^https?:\/\//i.test(db.apkServerUrl.trim())) {
      return normalizePublicHost(db.apkServerUrl);
    }
    if (process.env.APP_URL && /^https?:\/\//i.test(process.env.APP_URL.trim())) {
      return normalizePublicHost(process.env.APP_URL);
    }
    const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https')
      .split(',')[0]
      .trim();
    const host = req.get('host') || 'localhost:3000';
    return normalizePublicHost(`${proto}://${host}`);
  };

  const syncApkConfigJsonOnDisk = (serverUrl: string) => {
    const cleanUrl = serverUrl.trim().replace(/\/+$/, '');
    if (!cleanUrl) return;
    const payload = JSON.stringify(
      {
        appName: 'MS TV',
        appId: 'com.mstv.iptv',
        serverUrl: cleanUrl,
      },
      null,
      2
    );
    const candidateTargets = [
      path.resolve(process.cwd(), 'public', 'apk-config.json'),
      path.resolve(process.cwd(), 'dist', 'apk-config.json'),
      path.resolve(
        process.cwd(),
        'android',
        'app',
        'src',
        'main',
        'assets',
        'public',
        'apk-config.json'
      ),
    ];
    for (const filePath of candidateTargets) {
      const dir = path.dirname(filePath);
      if (fs.existsSync(dir)) {
        try {
          fs.writeFileSync(filePath, `${payload}\n`, 'utf-8');
        } catch {
          // ignore read-only fs errors in restricted containers
        }
      }
    }
  };

  const resolvePublicTelegramUrl = (): string => {
    const db = getDb();
    if (db.telegramCodeUrl && db.telegramCodeUrl.trim()) {
      return db.telegramCodeUrl.trim();
    }
    const tgSlide = (db.heroSlides || []).find(
      (s) =>
        s.active &&
        s.externalUrl &&
        /(t\.me\/|telegram\.me\/|tg:\/\/)/i.test(s.externalUrl)
    );
    return tgSlide?.externalUrl || '';
  };

  // ---------------------------------------------------------------------------
  // Public Boot Info (zero secrets leaked; enforces Anti-Sniffer & Anti-VPN immediately on boot)
  // ---------------------------------------------------------------------------
  app.get('/api/auth/public-status', async (req: Request, res: Response) => {
    const passed = await enforceRequestProtection(req, res);
    if (!passed) return;

    const db = getDb();
    const hasRealSources = db.sources.some((s) => s.type !== 'starter');
    res.json({
      appName: 'MS TV',
      isInitialSetup: db.isInitialSetup,
      hideAdminEntryForUsers: db.hideAdminEntryForUsers,
      hasRealSources,
      securityPolicy: db.securityPolicy,
      maintenanceMode: Boolean(db.maintenanceMode),
      maintenanceMessage: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
      telegramUrl: resolvePublicTelegramUrl(),
      apkDownloadUrl: db.apkDownloadUrl || '',
      initialHint: db.isInitialSetup
        ? { defaultUserCode: '1111', defaultAdminCode: '9999' }
        : null,
    });
  });

  // Live Security Check & Client Tamper Reporting
  app.get('/api/security/check', async (req: Request, res: Response) => {
    const db = getDb();
    const passed = await enforceRequestProtection(req, res);
    if (!passed) return;
    res.json({
      ok: true,
      securityPolicy: db.securityPolicy,
      maintenanceMode: Boolean(db.maintenanceMode),
      maintenanceMessage: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
    });
  });

  app.post('/api/security/report', (req: Request, res: Response) => {
    if (isAdminRequest(req)) {
      res.json({ ok: true });
      return;
    }
    const viewer = extractViewerToken(req);
    const rawType = String(req.body?.type || '');
    const type = rawType === 'devtools_tamper' ? 'devtools_tamper' : 'sniffer_blocked';
    const reason =
      String(req.body?.reason || '').trim() ||
      (type === 'devtools_tamper'
        ? 'تم رصد محاولة فتح أدوات فحص الشبكة أو المطورين.'
        : 'تم رصد أداة اعتراض أو حقن طلبات الشبكة على المتصفح.');
    const { deviceName } = extractDeviceInfo(req);
    recordSecurityEvent({
      type,
      reason,
      ip: extractClientIp(req),
      deviceName,
      subscriberCode: viewer?.code,
      userAgent: String(req.headers['user-agent'] || ''),
    });
    res.json({ ok: true });
  });

  // ---------------------------------------------------------------------------
  // Single-Code Login (Viewer Subscription Code OR Master Admin Code)
  // ---------------------------------------------------------------------------
  app.post('/api/auth/login', async (req: Request, res: Response) => {
    const code = String(req.body?.code || '').trim();
    if (!code) {
      res.status(400).json({ error: 'يرجى إدخال كود الدخول.' });
      return;
    }

    const db = getDb();
    const { deviceId, deviceName } = extractDeviceInfo(req);

    // 1. Check Master Admin Code FIRST (Admin is never blocked by VPN or device limits!)
    if (safeEqualString(db.adminCode, code)) {
      const viewerToken = signToken({
        role: 'viewer',
        code: 'ADMIN_OWNER',
        did: deviceId || 'admin_device',
        iat: Date.now(),
      });
      const adminToken = signToken({
        role: 'admin',
        code: 'ADMIN_OWNER',
        did: deviceId || 'admin_device',
        iat: Date.now(),
      });
      res.json({
        token: viewerToken,
        adminToken,
        label: 'مدير النظام',
        durationDays: 365,
        expiresAt: null,
        maxDevices: 999,
        connectedDevicesCount: 1,
        isAdminUnlocked: true,
      });
      return;
    }

    // 2. Enforce Maintenance Mode for non-admin subscribers BEFORE binding any device
    if (db.maintenanceMode && !isAdminRequest(req)) {
      res.status(503).json({
        error: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
        code: 'MAINTENANCE_MODE',
      });
      return;
    }

    // 3. Enforce Anti-HttpCanary & Anti-VPN policies for regular subscribers
    const passedProtection = await enforceRequestProtection(req, res, code);
    if (!passedProtection) {
      return;
    }

    // 3. Check Subscriber Access Codes (Expiration + Single/Multi-Person Device Limit!)
    const matchedViewer = db.accessCodes.find((ac) => safeEqualString(ac.code, code));
    if (matchedViewer) {
      if (!matchedViewer.active) {
        res.status(401).json({
          error: 'هذا الاشتراك موقوف حالياً، يرجى التواصل مع الإدارة.',
        });
        return;
      }
      if (!isAccessCodeValidNow(matchedViewer)) {
        res.status(401).json({
          error: 'انتهت مدة هذا الاشتراك، يرجى التواصل مع الإدارة لتجديد اشتراكك.',
        });
        return;
      }

      const ip = extractClientIp(req);
      const deviceCheck = checkAndBindSubscriberDevice(matchedViewer, deviceId, deviceName, ip, {
        allowSameOwnerRebind: true,
      });
      if (!deviceCheck.allowed) {
        recordSecurityEvent({
          type: 'device_limit',
          reason: deviceCheck.reason || 'تجاوز عدد الأجهزة المسموح بها للاشتراك.',
          ip,
          deviceName,
          subscriberCode: matchedViewer.code,
          userAgent: String(req.headers['user-agent'] || ''),
        });
        res.status(409).json({
          error: deviceCheck.reason,
          code: 'DEVICE_LIMIT_REACHED',
        });
        return;
      }

      const remainingDays = computeDaysRemaining(matchedViewer.expiresAt);
      const token = signToken({
        role: 'viewer',
        code: matchedViewer.code,
        did: deviceId,
        iat: Date.now(),
      });

      res.json({
        token,
        label: matchedViewer.label,
        durationDays: remainingDays,
        expiresAt: matchedViewer.expiresAt,
        maxDevices: matchedViewer.maxDevices || 1,
        connectedDevicesCount: matchedViewer.boundDevices?.length || 1,
        isAdminUnlocked: false,
      });
      return;
    }

    res.status(401).json({ error: 'كود الدخول غير صحيح أو غير مسجل.' });
  });

  // ---------------------------------------------------------------------------
  // Admin Secret Gate Authentication (Protects M3U / Xtream Panel)
  // ---------------------------------------------------------------------------
  app.post('/api/admin/auth', (req: Request, res: Response) => {
    const adminCode = String(req.body?.adminCode || '').trim();
    if (!adminCode) {
      res.status(400).json({ error: 'يرجى إدخال كود لوحة الإدارة الخاص.' });
      return;
    }

    const db = getDb();
    if (!safeEqualString(db.adminCode, adminCode)) {
      res.status(401).json({ error: 'كود الإدارة غير صحيح.' });
      return;
    }

    const adminToken = signToken({
      role: 'admin',
      code: 'ADMIN_OWNER',
      iat: Date.now(),
    });

    res.json({ adminToken });
  });

  // ---------------------------------------------------------------------------
  // Viewer Catalog (Strictly Sanitized — NO M3U or Xtream URLs ever sent!)
  // Uses revision-keyed in-memory cache + GZIP compression (shrinks 15k-channel payload from ~4.8MB to ~280KB!)
  // ---------------------------------------------------------------------------
  let cachedCatalogSnap: {
    revision: number;
    channelsJson: string;
    categories: ReturnType<typeof getOrderedCategories>;
    heroSlides: HeroSlide[];
  } | null = null;

  app.get('/api/catalog', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const rev = getCatalogRevision();
    const viewer = (req as any).viewer as TokenPayload;
    const subInfo = (req as any).subscriptionInfo as {
      durationDays: number;
      expiresAt: string | null;
      maxDevices?: number;
      connectedDevicesCount?: number;
    };

    if (!cachedCatalogSnap || cachedCatalogSnap.revision !== rev) {
      const { sources: activeSources, channels: activeChannels } = getActiveSourcesAndChannels();
      const sourcePriority = new Map<string, number>();
      activeSources.forEach((s, idx) => sourcePriority.set(s.id, idx));

      const orderedChannels = [...activeChannels].sort((a, b) => {
        const pa = sourcePriority.get(a.sourceId) ?? 99;
        const pb = sourcePriority.get(b.sourceId) ?? 99;
        if (pa !== pb) return pa - pb;
        return a.order - b.order;
      });

      const sanitizedChannels = orderedChannels.map(sanitizeChannelForViewer);
      const categories = getOrderedCategories();
      const activeHeroSlides = [...(db.heroSlides || [])]
        .filter((s) => s.active)
        .sort((a, b) => a.order - b.order);

      cachedCatalogSnap = {
        revision: rev,
        channelsJson: JSON.stringify(sanitizedChannels),
        categories,
        heroSlides: activeHeroSlides,
      };
    }

    const visibleLists = db.customLists.filter(
      (lst) => lst.isGlobal || lst.ownerCode === viewer.code
    );

    const favorites = db.favoritesByCode[viewer.code] || [];
    const history = db.historyByCode[viewer.code] || [];

    // Mint viewer-bound encrypted stream session token so channel clicks start in 0ms (1 single round-trip!)
    const { deviceId } = extractDeviceInfo(req);
    const effectiveDeviceId = deviceId || viewer.did || 'default';

    // When browser boots or user refreshes page (?boot=1), immediately release any orphaned upstream stream for this device
    if (req.query.boot === '1') {
      abortViewerUpstreamConnections(viewer.code, {
        deviceId: effectiveDeviceId,
        matchSameDeviceAnyCode: true,
        includeChunks: true,
      });
    }

    const ip = extractClientIp(req);
    const ua = String(req.headers['user-agent'] || '');
    const isAppleDevice = /iPhone|iPad|iPod|Macintosh|AppleCoreMedia/i.test(ua);
    const now = Date.now();
    const sid = `ses_${crypto
      .createHash('sha256')
      .update(`${viewer.code}|${effectiveDeviceId}`)
      .digest('hex')
      .slice(0, 16)}`;

    activeStreamLeases.set(sid, {
      tid: sid,
      code: viewer.code,
      deviceId: effectiveDeviceId,
      channelId: '',
      createdAt: now,
      lastHeartbeatAt: now,
    });

    const streamSessionToken = encryptAesJson({
      sid,
      code: viewer.code,
      uah: computeUserAgentHash(req),
      dvh: computeDeviceHash(effectiveDeviceId),
      iph: computeIpFingerprint(ip),
      apple: isAppleDevice || undefined,
      exp: now + 6 * 60 * 60 * 1000,
    } satisfies StreamSessionTokenPayload);

    const metaJson = JSON.stringify({
      categories: cachedCatalogSnap.categories,
      heroSlides: cachedCatalogSnap.heroSlides,
      customLists: visibleLists,
      favorites,
      history,
      durationDays: subInfo?.durationDays ?? 365,
      expiresAt: subInfo?.expiresAt ?? null,
      maxDevices: subInfo?.maxDevices ?? 1,
      connectedDevicesCount: subInfo?.connectedDevicesCount ?? 1,
      hideAdminEntryForUsers: db.hideAdminEntryForUsers,
      securityPolicy: db.securityPolicy,
      maintenanceMode: Boolean(db.maintenanceMode),
      maintenanceMessage: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
      apkDownloadUrl: db.apkDownloadUrl || '',
      streamSessionToken,
    });

    // Splice pre-serialized channelsJson directly into JSON response (zero repeated 15k-object JSON.stringify!)
    const fullJson = `{"channels":${cachedCatalogSnap.channelsJson},${metaJson.slice(1)}`;

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Vary', 'Accept-Encoding');

    const acceptEnc = String(req.headers['accept-encoding'] || '');
    if (acceptEnc.includes('gzip') && fullJson.length > 2048) {
      zlib.gzip(Buffer.from(fullJson, 'utf-8'), { level: 4 }, (err, compressed) => {
        if (err) {
          res.status(200).send(fullJson);
          return;
        }
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Content-Length', String(compressed.length));
        res.status(200).end(compressed);
      });
      return;
    }

    res.status(200).send(fullJson);
  });

  // ---------------------------------------------------------------------------
  // Viewer Interactions: Favorites, Watch History, Custom Lists
  // ---------------------------------------------------------------------------
  app.post('/api/channels/:id/view', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const viewer = (req as any).viewer as TokenPayload;
    const channelId = req.params.id;
    const ch = db.channels.find((c) => c.id === channelId);
    if (ch) {
      ch.views = (ch.views || 0) + 1;
      const prevHist = db.historyByCode[viewer.code] || [];
      db.historyByCode[viewer.code] = [
        channelId,
        ...prevHist.filter((id) => id !== channelId),
      ].slice(0, 40);
      saveDb();
    }
    res.json({ ok: true });
  });

  app.post('/api/favorites/toggle', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const viewer = (req as any).viewer as TokenPayload;
    const channelId = String(req.body?.channelId || '');
    if (!channelId) {
      res.status(400).json({ error: 'معرف القناة مطلوب.' });
      return;
    }
    const list = db.favoritesByCode[viewer.code] || [];
    const exists = list.includes(channelId);
    db.favoritesByCode[viewer.code] = exists
      ? list.filter((id) => id !== channelId)
      : [channelId, ...list];
    saveDb();
    res.json({ favorites: db.favoritesByCode[viewer.code] });
  });

  app.post('/api/lists', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const viewer = (req as any).viewer as TokenPayload;
    const adminHeader = req.headers['x-admin-token'];
    const isAdmin = Boolean(
      verifyToken(Array.isArray(adminHeader) ? adminHeader[0] : adminHeader)?.role === 'admin'
    );

    const name = String(req.body?.name || '').trim();
    const color = String(req.body?.color || '#2563EB').trim();
    const channelIds = Array.isArray(req.body?.channelIds)
      ? req.body.channelIds.map(String)
      : [];
    const isGlobal = isAdmin ? Boolean(req.body?.isGlobal ?? true) : false;

    if (!name) {
      res.status(400).json({ error: 'يرجى كتابة اسم القائمة الخاصة.' });
      return;
    }

    const newList = {
      id: `lst_${crypto.randomBytes(6).toString('hex')}`,
      name,
      color,
      channelIds,
      isGlobal,
      ownerCode: isGlobal ? undefined : viewer.code,
      createdAt: new Date().toISOString(),
    };

    db.customLists.push(newList);
    saveDb();
    res.json({ list: newList });
  });

  app.put('/api/lists/:id', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const viewer = (req as any).viewer as TokenPayload;
    const adminHeader = req.headers['x-admin-token'];
    const isAdmin = Boolean(
      verifyToken(Array.isArray(adminHeader) ? adminHeader[0] : adminHeader)?.role === 'admin'
    );

    const list = db.customLists.find((l) => l.id === req.params.id);
    if (!list) {
      res.status(404).json({ error: 'القائمة غير موجودة.' });
      return;
    }
    if (list.isGlobal && !isAdmin) {
      res.status(403).json({ error: 'هذه القائمة عامة وتدار من لوحة المدير فقط.' });
      return;
    }
    if (!list.isGlobal && list.ownerCode !== viewer.code && !isAdmin) {
      res.status(403).json({ error: 'غير مصرح بتعديل هذه القائمة.' });
      return;
    }

    if (typeof req.body?.name === 'string' && req.body.name.trim()) {
      list.name = req.body.name.trim();
    }
    if (typeof req.body?.color === 'string' && req.body.color.trim()) {
      list.color = req.body.color.trim();
    }
    if (Array.isArray(req.body?.channelIds)) {
      list.channelIds = req.body.channelIds.map(String);
    }

    saveDb();
    res.json({ list });
  });

  app.delete('/api/lists/:id', requireViewerAuth, (req: Request, res: Response) => {
    const db = getDb();
    const viewer = (req as any).viewer as TokenPayload;
    const adminHeader = req.headers['x-admin-token'];
    const isAdmin = Boolean(
      verifyToken(Array.isArray(adminHeader) ? adminHeader[0] : adminHeader)?.role === 'admin'
    );

    const idx = db.customLists.findIndex((l) => l.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'القائمة غير موجودة.' });
      return;
    }
    const target = db.customLists[idx];
    if (target.isGlobal && !isAdmin) {
      res.status(403).json({ error: 'لا يمكن حذف القائمة العامة إلا من لوحة الإدارة.' });
      return;
    }
    if (!target.isGlobal && target.ownerCode !== viewer.code && !isAdmin) {
      res.status(403).json({ error: 'غير مصرح بحذف هذه القائمة.' });
      return;
    }

    db.customLists.splice(idx, 1);
    saveDb();
    res.json({ ok: true });
  });

  // ---------------------------------------------------------------------------
  // Anti-Theft Encrypted Stream Ticket & Resilient Stream Proxy
  // ---------------------------------------------------------------------------
  app.post(
    '/api/stream-ticket/:channelId',
    requireViewerAuth,
    async (req: Request, res: Response) => {
      const viewer = (req as any).viewer as TokenPayload;
      const { deviceId } = extractDeviceInfo(req);
      const effectiveDeviceId = deviceId || viewer.did || 'default';
      const ip = extractClientIp(req);

      const clientKey = `${ip}:${viewer.code}:${effectiveDeviceId}`;
      if (!checkTicketRateLimit(clientKey, 180)) {
        res.status(429).json({ error: 'عدد طلبات تبديل القنوات كبير جداً، يرجى الانتظار لحظة.' });
        return;
      }

      const db = getDb();
      const channel = db.channels.find((c) => c.id === req.params.channelId);
      if (!channel) {
        res.status(404).json({ error: 'القناة غير موجودة.' });
        return;
      }

      const refreshEdge = Boolean(req.body?.refreshEdge);
      clearViewerOtherHlsSessions(
        viewer.code,
        effectiveDeviceId,
        refreshEdge ? undefined : channel.id
      );

      // Release previous upstream socket for THIS specific device so switching channels is instant
      const aborted = abortViewerUpstreamConnections(viewer.code, {
        deviceId: effectiveDeviceId,
        matchSameDeviceAnyCode: true,
        includeChunks: true,
      });
      if (aborted > 0) {
        await sleepMs(60);
      }

      // Prune stale leases & revoke previous non-session lease for this viewer+device
      const now = Date.now();
      for (const [k, lease] of activeStreamLeases.entries()) {
        if (
          now - lease.lastHeartbeatAt > 180000 ||
          (!k.startsWith('ses_') &&
            lease.code === viewer.code &&
            lease.deviceId === effectiveDeviceId)
        ) {
          activeStreamLeases.delete(k);
        }
      }

      const tid = crypto.randomBytes(8).toString('hex');
      activeStreamLeases.set(tid, {
        tid,
        code: viewer.code,
        deviceId: effectiveDeviceId,
        channelId: channel.id,
        createdAt: now,
        lastHeartbeatAt: now,
      });

      const ua = String(req.headers['user-agent'] || '');
      const isAppleDevice = /iPhone|iPad|iPod|Macintosh|AppleCoreMedia/i.test(ua);

      const expiresAtMs = now + 6 * 60 * 60 * 1000;
      const ticket = encryptAesJson({
        tid,
        cid: channel.id,
        code: viewer.code,
        uah: computeUserAgentHash(req),
        dvh: computeDeviceHash(effectiveDeviceId),
        iph: computeIpFingerprint(ip),
        apple: isAppleDevice || undefined,
        exp: expiresAtMs,
      } satisfies StreamTicketPayload);

      res.json({
        ticket,
        streamFormat: channel.streamFormat,
        expiresAtMs,
      });
    }
  );

  app.post('/api/stream-heartbeat', requireViewerAuth, (req: Request, res: Response) => {
    const viewer = (req as any).viewer as TokenPayload;
    const rawTicket = typeof req.body?.ticket === 'string' ? req.body.ticket : '';
    const parsedTicket = rawTicket ? decryptAesJson<StreamTicketPayload>(rawTicket) : null;
    const parsedSession = rawTicket ? decryptAesJson<StreamSessionTokenPayload>(rawTicket) : null;

    const leaseKey = parsedTicket?.tid || parsedSession?.sid;
    const tokenOwnerCode = parsedTicket?.code || parsedSession?.code;
    if (!leaseKey || tokenOwnerCode !== viewer.code) {
      res.status(400).json({ error: 'تذكرة البث غير صالحة.' });
      return;
    }

    const { deviceId } = extractDeviceInfo(req);
    const effectiveDeviceId = deviceId || viewer.did || 'default';
    const channelId =
      typeof req.body?.channelId === 'string' && req.body.channelId
        ? req.body.channelId
        : parsedTicket?.cid || '';

    const existing = activeStreamLeases.get(leaseKey);
    if (existing) {
      existing.lastHeartbeatAt = Date.now();
      if (channelId) existing.channelId = channelId;
    } else {
      activeStreamLeases.set(leaseKey, {
        tid: leaseKey,
        code: viewer.code,
        deviceId: effectiveDeviceId,
        channelId,
        createdAt: Date.now(),
        lastHeartbeatAt: Date.now(),
      });
    }
    res.json({ ok: true });
  });

  app.post('/api/stream-release', (req: Request, res: Response) => {
    const bodyToken =
      typeof req.body?.viewerToken === 'string' ? verifyToken(req.body.viewerToken) : null;
    const viewer = extractViewerToken(req) || (bodyToken?.role === 'viewer' ? bodyToken : null);
    const { deviceId } = extractDeviceInfo(req);
    const rawTicket = typeof req.body?.ticket === 'string' ? req.body.ticket : '';
    const releasePlayId = sanitizePlayId(req.body?.playId);
    const isPageHide = req.body?.reason === 'pagehide';
    const parsedTicket = rawTicket ? decryptAesJson<StreamTicketPayload>(rawTicket) : null;
    const parsedSession = rawTicket ? decryptAesJson<StreamSessionTokenPayload>(rawTicket) : null;

    if (parsedTicket?.tid && !parsedTicket.tid.startsWith('ses_')) {
      activeStreamLeases.delete(parsedTicket.tid);
    }

    // Never abort a newer stream! If releasePlayId is provided, ONLY abort connections matching that exact playId.
    if (releasePlayId) {
      const ownerCode = viewer?.code || parsedTicket?.code || parsedSession?.code;
      if (ownerCode) {
        abortViewerUpstreamConnections(ownerCode, {
          deviceId: deviceId || viewer?.did || undefined,
          matchSameDeviceAnyCode: true,
          onlyPlayId: releasePlayId,
          includeChunks: true,
        });
      }
      res.json({ ok: true });
      return;
    }

    if (parsedTicket?.tid && !parsedTicket.tid.startsWith('ses_')) {
      abortViewerUpstreamConnections(viewer?.code || parsedTicket.code, {
        onlyTicket: rawTicket,
        includeChunks: true,
      });
    } else if (isPageHide) {
      const ownerCode = viewer?.code || parsedSession?.code;
      if (ownerCode && (deviceId || viewer?.did)) {
        abortViewerUpstreamConnections(ownerCode, {
          deviceId: deviceId || viewer?.did,
          matchSameDeviceAnyCode: true,
          includeChunks: true,
        });
      }
    }
    res.json({ ok: true });
  });

  // Zero-Roundtrip Instant Channel Playback Endpoint (saves 1 full HTTP round-trip + 400ms per zap!)
  app.get(
    '/api/stream-play-fast/:sessionToken/:channelId',
    async (req: Request, res: Response) => {
      const rawSessionToken = String(req.params.sessionToken || '');
      const channelId = String(req.params.channelId || '');
      const playId = sanitizePlayId(req.query.pid);
      const verified = await verifyProtectedStreamSessionToken(req, rawSessionToken, channelId);
      if (!verified) {
        res.status(403).json({ error: 'رابط البث محمي ضد السحب والنسخ أو انتهت الجلسة.' });
        return;
      }
      const { session, synthesizedTicket, deviceId } = verified;

      const ip = extractClientIp(req);
      const clientKey = `${ip}:${session.code}:${deviceId}`;
      if (!checkTicketRateLimit(clientKey, 240)) {
        res.status(429).json({ error: 'عدد طلبات تبديل القنوات كبير جداً، يرجى الانتظار لحظة.' });
        return;
      }

      const db = getDb();
      const channel = db.channels.find((c) => c.id === channelId);
      if (!channel) {
        res.status(404).json({ error: 'القناة غير موجودة.' });
        return;
      }

      const rawEngine = typeof req.query.engine === 'string' ? req.query.engine : 'auto';
      const requestedEngine: 'hls' | 'mpegts' | 'native' | 'auto' =
        rawEngine === 'hls' || rawEngine === 'mpegts' || rawEngine === 'native'
          ? rawEngine
          : 'auto';
      const refreshEdge = req.query.r === '1';

      clearViewerOtherHlsSessions(
        session.code,
        deviceId,
        refreshEdge ? undefined : channel.id
      );

      if (requestedEngine === 'mpegts') {
        const aborted = abortViewerUpstreamConnections(session.code, {
          deviceId,
          matchSameDeviceAnyCode: true,
          exceptPlayId: playId || undefined,
          includeChunks: true,
        });
        if (aborted > 0) await sleepMs(60);
      } else {
        abortViewerUpstreamConnections(session.code, {
          deviceId,
          matchSameDeviceAnyCode: true,
          exceptPlayId: playId || undefined,
          exceptChannelId: playId ? undefined : channel.id,
          includeChunks: true,
        });
      }

      const candidates = expandStreamUrlCandidates(
        channel.streamUrl,
        channel.fallbackStreamUrl,
        requestedEngine
      );

      await pipeUpstreamStream(req, res, candidates, synthesizedTicket, {
        viewerCode: session.code,
        deviceId,
        channelId: channel.id,
        playId,
        ua: channel.userAgent,
        ref: channel.referrer,
        requestedEngine,
        isSegmentChunk: false,
        refreshEdge,
      });
    }
  );

  app.get('/api/stream-play/:ticket', async (req: Request, res: Response) => {
    const rawTicket = String(req.params.ticket || '');
    const playId = sanitizePlayId(req.query.pid);
    const verified = await verifyProtectedStreamTicket(req, rawTicket);
    if (!verified) {
      res.status(403).json({ error: 'رابط البث محمي ضد السحب والنسخ أو انتهت الجلسة.' });
      return;
    }
    const { ticket: verifiedTicket, deviceId } = verified;

    const db = getDb();
    const channel = db.channels.find((c) => c.id === verifiedTicket.cid);
    if (!channel) {
      res.status(404).json({ error: 'القناة غير موجودة.' });
      return;
    }

    const rawEngine = typeof req.query.engine === 'string' ? req.query.engine : 'auto';
    const requestedEngine: 'hls' | 'mpegts' | 'native' | 'auto' =
      rawEngine === 'hls' || rawEngine === 'mpegts' || rawEngine === 'native' ? rawEngine : 'auto';

    // Tear down any lingering connections for THIS device from previous playIds
    if (requestedEngine === 'mpegts') {
      const aborted = abortViewerUpstreamConnections(verifiedTicket.code, {
        deviceId,
        matchSameDeviceAnyCode: true,
        exceptPlayId: playId || undefined,
        includeChunks: true,
      });
      if (aborted > 0) await sleepMs(60);
    } else {
      abortViewerUpstreamConnections(verifiedTicket.code, {
        deviceId,
        matchSameDeviceAnyCode: true,
        exceptPlayId: playId || undefined,
        exceptChannelId: playId ? undefined : channel.id,
        includeChunks: true,
      });
    }

    const candidates = expandStreamUrlCandidates(
      channel.streamUrl,
      channel.fallbackStreamUrl,
      requestedEngine
    );

    await pipeUpstreamStream(req, res, candidates, rawTicket, {
      viewerCode: verifiedTicket.code,
      deviceId,
      channelId: channel.id,
      playId,
      ua: channel.userAgent,
      ref: channel.referrer,
      requestedEngine,
      isSegmentChunk: false,
    });
  });

  app.get('/api/proxy-chunk', async (req: Request, res: Response) => {
    const rawTicket = typeof req.query.t === 'string' ? req.query.t : '';
    const playId = sanitizePlayId(req.query.pid);
    const verified = await verifyProtectedStreamTicket(req, rawTicket);
    if (!verified) {
      res.status(403).json({ error: 'مقطع البث محمي أو انتهت الجلسة.' });
      return;
    }
    const { ticket: verifiedTicket, deviceId } = verified;

    const enc = typeof req.query.u === 'string' ? req.query.u : '';
    const decoded = decryptAesJson<EncryptedStreamRef>(enc);
    if (!decoded || !decoded.url) {
      res.status(400).json({ error: 'مرجع البث غير صالح.' });
      return;
    }

    const strictBinding = Boolean(getDb().securityPolicy?.strictStreamBinding);
    if (strictBinding && decoded.cexp && Date.now() > decoded.cexp) {
      res.status(403).json({ error: 'انتهت صلاحية مقطع البث المؤقت.' });
      return;
    }

    await pipeUpstreamStream(req, res, [decoded.url], rawTicket, {
      viewerCode: verifiedTicket.code,
      deviceId,
      channelId: verifiedTicket.cid,
      playId,
      ua: decoded.ua,
      ref: decoded.ref,
      cookie: decoded.cookie,
      isSegmentChunk: true,
    });
  });

  // ===========================================================================
  // ADMIN-ONLY ROUTES (Protected by Secret Admin Token — Hidden from Users!)
  // ===========================================================================

  let cachedUrlProbe: {
    url: string;
    status: 'live' | 'not_published_404' | 'blocked_403' | 'unreachable';
    checkedAt: number;
  } | null = null;

  const probePublicUrlStatus = async (
    targetUrl: string
  ): Promise<'live' | 'not_published_404' | 'blocked_403' | 'unreachable'> => {
    const clean = targetUrl.trim().replace(/\/+$/, '');
    if (!clean) return 'unreachable';
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(clean)) {
      return 'live';
    }
    const now = Date.now();
    if (cachedUrlProbe && cachedUrlProbe.url === clean && now - cachedUrlProbe.checkedAt < 8000) {
      return cachedUrlProbe.status;
    }
    try {
      const probeRes = await fetch(`${clean}/api/auth/public-status`, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(2500),
      });
      let status: 'live' | 'not_published_404' | 'blocked_403' | 'unreachable' = 'live';
      if (probeRes.status === 404) {
        status = 'not_published_404';
      } else if (probeRes.status === 401 || probeRes.status === 403 || (probeRes.status >= 300 && probeRes.status < 400)) {
        status = 'blocked_403';
      } else if (probeRes.status >= 200 && probeRes.status < 300) {
        status = 'live';
      } else if (probeRes.status === 503) {
        status = 'live';
      } else {
        status = 'unreachable';
      }
      cachedUrlProbe = { url: clean, status, checkedAt: now };
      return status;
    } catch {
      return 'unreachable';
    }
  };

  app.get('/api/admin/overview', requireAdminAuth, async (req: Request, res: Response) => {
    const db = getDb();
    const detectedServerUrl = resolveDetectedServerUrl(req);
    const publicUrlStatus = await probePublicUrlStatus(detectedServerUrl);
    res.json({
      sources: db.sources,
      accessCodes: db.accessCodes,
      heroSlides: [...(db.heroSlides || [])].sort((a, b) => a.order - b.order),
      adminCode: db.adminCode,
      telegramCodeUrl: db.telegramCodeUrl || '',
      apkServerUrl: db.apkServerUrl || '',
      apkDownloadUrl: db.apkDownloadUrl || '',
      detectedServerUrl,
      publicUrlStatus,
      hideAdminEntryForUsers: db.hideAdminEntryForUsers,
      isInitialSetup: db.isInitialSetup,
      totalChannels: getActiveSourcesAndChannels().channels.length,
      categories: getOrderedCategories(),
      excludedCategories: db.excludedCategories || [],
      maintenanceMode: Boolean(db.maintenanceMode),
      maintenanceMessage: db.maintenanceMessage || DEFAULT_MAINTENANCE_MESSAGE,
      securityPolicy: db.securityPolicy,
      securityEvents: db.securityEvents || [],
    });
  });

  // Cloud Firestore Zero-Knowledge Encrypted Snapshot Export / Restore
  app.get('/api/admin/cloud-snapshot', requireAdminAuth, (_req: Request, res: Response) => {
    const snapshot = exportEncryptedSnapshotChunks();
    res.json({
      appName: 'MS TV',
      ...snapshot,
    });
  });

  app.post('/api/admin/cloud-restore', requireAdminAuth, (req: Request, res: Response) => {
    try {
      const chunks = Array.isArray(req.body?.chunks) ? req.body.chunks.map(String) : [];
      const result = importEncryptedSnapshotChunks(chunks);
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ error: err?.message || 'تعذر استعادة النسخة السحابية.' });
    }
  });

  // 1. Add M3U Source (URL or Uploaded/Pasted M3U Content — Exact Group Preservation & Permanent Save)
  app.post('/api/admin/sources/m3u', requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const name = String(req.body?.name || '').trim() || 'قائمة M3U';
      const rawM3uUrl = String(req.body?.m3uUrl || '').trim();
      const m3uUrl = rawM3uUrl ? cleanIptvUrl(rawM3uUrl) : '';
      const m3uContent = String(req.body?.m3uContent || '').trim();

      if (!m3uUrl && !m3uContent) {
        res.status(400).json({ error: 'يرجى إدخال رابط M3U أو رفع/لصق محتوى ملف M3U.' });
        return;
      }

      let parsed;
      if (m3uContent) {
        if (
          m3uUrl &&
          (m3uContent.includes('#EXT-X-STREAM-INF') || m3uContent.includes('#EXT-X-TARGETDURATION'))
        ) {
          parsed = {
            channels: [
              {
                signature: computeStreamSignature(m3uUrl, name),
                name,
                group: 'بث مباشر',
                logo: '',
                streamUrl: m3uUrl,
                fallbackStreamUrl: deriveStreamFallbackUrl(m3uUrl),
                streamFormat: 'hls' as const,
                contentType: 'live' as const,
                order: 0,
              },
            ],
            groupsInOrder: ['بث مباشر'],
          };
        } else {
          parsed = parseM3uPlaylist(m3uContent);
        }
      } else {
        parsed = await fetchM3uFromUrl(m3uUrl);
      }

      if (parsed.channels.length === 0) {
        res.status(400).json({ error: 'لم يتم العثور على قنوات صالحة داخل محتوى M3U.' });
        return;
      }

      const now = new Date().toISOString();
      const source: IptvSource = {
        id: `src_m3u_${crypto.randomBytes(5).toString('hex')}`,
        name,
        type: m3uUrl ? 'm3u_url' : 'm3u_text',
        m3uUrl: m3uUrl || undefined,
        channelCount: parsed.channels.length,
        groupsInOrder: parsed.groupsInOrder,
        createdAt: now,
        lastSyncedAt: now,
      };

      const { addedCount } = upsertSourceChannels(source, parsed.channels);

      res.json({
        source,
        addedCount,
        groupsCount: parsed.groupsInOrder.length,
      });
    } catch (err: any) {
      res.status(400).json({
        error: err?.message || 'حدث خطأ أثناء جلب وتحليل رابط M3U.',
      });
    }
  });

  // 2. Add Xtream Codes Source
  app.post('/api/admin/sources/xtream', requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const name = String(req.body?.name || '').trim() || 'سيرفر Xtream';
      const rawHost = String(req.body?.host || '').trim();
      const host = rawHost ? cleanIptvUrl(rawHost).replace(/\/+$/, '') : '';
      const username = String(req.body?.username || '').trim();
      const password = String(req.body?.password || '').trim();
      const includeVod = Boolean(req.body?.includeVod ?? true);

      if (!host || !username || !password) {
        res.status(400).json({ error: 'يرجى إدخال رابط السيرفر واسم المستخدم وكلمة المرور.' });
        return;
      }

      const result = await fetchXtreamPlaylist(host, username, password, {
        includeLive: true,
        includeVod,
      });

      const now = new Date().toISOString();
      const source: IptvSource = {
        id: `src_xt_${crypto.randomBytes(5).toString('hex')}`,
        name,
        type: 'xtream',
        xtreamHost: host,
        xtreamUsername: username,
        xtreamPassword: password,
        includeVod,
        accountInfo: result.accountInfo,
        channelCount: result.channels.length,
        groupsInOrder: result.groupsInOrder,
        createdAt: now,
        lastSyncedAt: now,
      };

      const { addedCount } = upsertSourceChannels(source, result.channels);

      res.json({
        source,
        addedCount,
        groupsCount: result.groupsInOrder.length,
        accountInfo: result.accountInfo,
      });
    } catch (err: any) {
      res.status(400).json({
        error: err?.message || 'تعذر الاتصال بسيرفر Xtream Codes.',
      });
    }
  });

  // 3. Add Direct Stream Link(s)
  app.post('/api/admin/sources/direct', requireAdminAuth, (req: Request, res: Response) => {
    const channelName = String(req.body?.name || '').trim();
    const rawStreamUrl = String(req.body?.streamUrl || '').trim();
    const streamUrl = rawStreamUrl ? cleanIptvUrl(rawStreamUrl) : '';
    const group = String(req.body?.group || 'قنوات مضافة يدوياً').trim();
    const logo = String(req.body?.logo || '').trim();
    const contentType = (req.body?.contentType as any) || detectContentKind(streamUrl, group);

    if (!channelName || !streamUrl) {
      res.status(400).json({ error: 'اسم القناة ورابط البث المباشر مطلوبان.' });
      return;
    }

    const db = getDb();
    const now = new Date().toISOString();
    let directSource = db.sources.find((s) => s.type === 'direct');
    if (!directSource) {
      directSource = {
        id: 'src_direct_links',
        name: 'روابط بث مضافة يدوياً',
        type: 'direct',
        channelCount: 0,
        groupsInOrder: [],
        createdAt: now,
        lastSyncedAt: now,
      };
      db.sources.push(directSource);
    }

    if (!directSource.groupsInOrder.includes(group)) {
      directSource.groupsInOrder.push(group);
    }
    if (!db.categoryOrder.includes(group)) {
      db.categoryOrder.push(group);
    }

    const sig = computeStreamSignature(streamUrl, `${channelName}_${Date.now()}`);
    const newCh: StoredChannel = {
      id: `ch_dir_${sig}`,
      sourceId: directSource.id,
      signature: sig,
      name: channelName,
      originalName: channelName,
      group,
      originalGroup: group,
      logo,
      streamUrl,
      fallbackStreamUrl: deriveStreamFallbackUrl(streamUrl),
      streamFormat: detectStreamFormat(streamUrl),
      contentType:
        contentType === 'movie' || contentType === 'series' ? contentType : 'live',
      featured: Boolean(req.body?.featured ?? true),
      views: 0,
      order: db.channels.length,
      addedAt: now,
    };

    db.channels.unshift(newCh);
    directSource.channelCount = db.channels.filter((c) => c.sourceId === directSource!.id).length;
    directSource.lastSyncedAt = now;
    db.isInitialSetup = false;
    saveDb();

    res.json({ channel: sanitizeChannelForViewer(newCh) });
  });

  // 4. Refresh an M3U URL or Xtream Source (Preserving Renamed Channels, Moved Groups & Custom Category Order)
  app.post('/api/admin/sources/:id/refresh', requireAdminAuth, async (req: Request, res: Response) => {
    try {
      const db = getDb();
      const source = db.sources.find((s) => s.id === req.params.id);
      if (!source) {
        res.status(404).json({ error: 'المصدر غير موجود.' });
        return;
      }

      if (source.type === 'm3u_url' && source.m3uUrl) {
        const parsed = await fetchM3uFromUrl(source.m3uUrl);
        source.groupsInOrder = parsed.groupsInOrder;
        const { addedCount } = upsertSourceChannels(source, parsed.channels);
        res.json({ source, addedCount });
        return;
      }

      if (
        source.type === 'xtream' &&
        source.xtreamHost &&
        source.xtreamUsername &&
        source.xtreamPassword
      ) {
        const result = await fetchXtreamPlaylist(
          source.xtreamHost,
          source.xtreamUsername,
          source.xtreamPassword,
          { includeLive: true, includeVod: source.includeVod ?? true }
        );
        source.groupsInOrder = result.groupsInOrder;
        source.accountInfo = result.accountInfo;
        const { addedCount } = upsertSourceChannels(source, result.channels);
        res.json({ source, addedCount });
        return;
      }

      res.status(400).json({ error: 'هذا المصدر محفوظ محلياً بالفعل ولا يحتاج إلى جلب خارجي.' });
    } catch (err: any) {
      res.status(400).json({ error: err?.message || 'فشل تحديث المصدر.' });
    }
  });

  // 5. Delete Source
  app.delete('/api/admin/sources/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const sourceId = req.params.id;
    const idx = db.sources.findIndex((s) => s.id === sourceId);
    if (idx === -1) {
      res.status(404).json({ error: 'المصدر غير موجود.' });
      return;
    }

    const removedIds = new Set(
      db.channels.filter((c) => c.sourceId === sourceId).map((c) => c.id)
    );
    db.sources.splice(idx, 1);
    db.channels = db.channels.filter((c) => c.sourceId !== sourceId);
    for (const lst of db.customLists) {
      lst.channelIds = lst.channelIds.filter((id) => !removedIds.has(id));
    }
    saveDb();
    res.json({ ok: true });
  });

  // 6. Edit Channel Name, Move to Another Category, Toggle Featured, or Delete Channel
  app.patch('/api/admin/channels/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const ch = db.channels.find((c) => c.id === req.params.id);
    if (!ch) {
      res.status(404).json({ error: 'القناة غير موجودة.' });
      return;
    }

    const override = db.channelOverrides[ch.signature] || {};

    if (typeof req.body?.name === 'string' && req.body.name.trim()) {
      ch.name = req.body.name.trim();
      override.customName = ch.name;
    }

    if (typeof req.body?.group === 'string' && req.body.group.trim()) {
      const targetGroup = req.body.group.trim();
      ch.group = targetGroup;
      override.customGroup = targetGroup;
      if (!db.customCategories.includes(targetGroup)) {
        db.customCategories.push(targetGroup);
      }
      if (!db.categoryOrder.includes(targetGroup)) {
        db.categoryOrder.push(targetGroup);
      }
    }

    if (typeof req.body?.logo === 'string') {
      ch.logo = req.body.logo.trim();
      override.customLogo = ch.logo;
    }

    if (typeof req.body?.featured === 'boolean') {
      ch.featured = req.body.featured;
      override.featured = ch.featured;
    }

    if (typeof req.body?.streamUrl === 'string' && req.body.streamUrl.trim()) {
      ch.streamUrl = cleanIptvUrl(req.body.streamUrl.trim());
      ch.fallbackStreamUrl = deriveStreamFallbackUrl(ch.streamUrl);
      ch.streamFormat = detectStreamFormat(ch.streamUrl);
    }

    db.channelOverrides[ch.signature] = override;
    saveDb();

    res.json({ channel: sanitizeChannelForViewer(ch) });
  });

  app.delete('/api/admin/channels/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const idx = db.channels.findIndex((c) => c.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'القناة غير موجودة.' });
      return;
    }
    const ch = db.channels[idx];
    db.channelOverrides[ch.signature] = {
      ...(db.channelOverrides[ch.signature] || {}),
      hidden: true,
    };
    db.channels.splice(idx, 1);
    saveDb();
    res.json({ ok: true });
  });

  // 7. Bulk Move Channels to Another Category / Section
  app.post('/api/admin/channels/bulk-move', requireAdminAuth, (req: Request, res: Response) => {
    const channelIds = Array.isArray(req.body?.channelIds)
      ? new Set(req.body.channelIds.map(String))
      : new Set<string>();
    const targetGroup = String(req.body?.targetGroup || '').trim();

    if (channelIds.size === 0 || !targetGroup) {
      res.status(400).json({ error: 'يرجى تحديد القنوات والقسم الجديد.' });
      return;
    }

    const db = getDb();
    if (!db.customCategories.includes(targetGroup)) {
      db.customCategories.push(targetGroup);
    }
    if (!db.categoryOrder.includes(targetGroup)) {
      db.categoryOrder.push(targetGroup);
    }

    let movedCount = 0;
    for (const ch of db.channels) {
      if (channelIds.has(ch.id)) {
        ch.group = targetGroup;
        db.channelOverrides[ch.signature] = {
          ...(db.channelOverrides[ch.signature] || {}),
          customGroup: targetGroup,
        };
        movedCount++;
      }
    }

    saveDb();
    res.json({ movedCount, targetGroup });
  });

  // 8. Create, Rename, Logo Update, or Move/Reorder Categories Up/Down
  app.post('/api/admin/categories', requireAdminAuth, (req: Request, res: Response) => {
    const name = String(req.body?.name || '').trim();
    const logo = String(req.body?.logo || '').trim();
    if (!name) {
      res.status(400).json({ error: 'يرجى إدخال اسم القسم الجديد.' });
      return;
    }
    const db = getDb();
    if (Array.isArray(db.excludedCategories) && db.excludedCategories.includes(name)) {
      db.excludedCategories = db.excludedCategories.filter((c) => c !== name);
    }
    if (!db.customCategories.includes(name)) {
      db.customCategories.push(name);
    }
    if (!db.categoryOrder.includes(name)) {
      db.categoryOrder.push(name);
    }
    if (logo) {
      if (!db.categoryLogos) db.categoryLogos = {};
      db.categoryLogos[name] = logo;
    }
    saveDb();
    res.json({ categories: getOrderedCategories() });
  });

  app.patch('/api/admin/categories/logo', requireAdminAuth, (req: Request, res: Response) => {
    const name = String(req.body?.name || '').trim();
    const logo = String(req.body?.logo || '').trim();
    if (!name) {
      res.status(400).json({ error: 'اسم القسم مطلوب.' });
      return;
    }
    const db = getDb();
    if (!db.categoryLogos) {
      db.categoryLogos = {};
    }
    if (logo) {
      db.categoryLogos[name] = logo;
    } else {
      delete db.categoryLogos[name];
    }
    saveDb();
    res.json({ categories: getOrderedCategories() });
  });

  app.patch('/api/admin/categories/rename', requireAdminAuth, (req: Request, res: Response) => {
    const oldName = String(req.body?.oldName || '').trim();
    const newName = String(req.body?.newName || '').trim();
    if (!oldName || !newName) {
      res.status(400).json({ error: 'الاسم القديم والاسم الجديد مطلوبان.' });
      return;
    }

    const db = getDb();
    for (const ch of db.channels) {
      if (ch.group === oldName) {
        ch.group = newName;
        db.channelOverrides[ch.signature] = {
          ...(db.channelOverrides[ch.signature] || {}),
          customGroup: newName,
        };
      }
    }
    for (const src of db.sources) {
      src.groupsInOrder = src.groupsInOrder.map((g) => (g === oldName ? newName : g));
    }
    db.customCategories = db.customCategories.map((g) => (g === oldName ? newName : g));
    db.categoryOrder = db.categoryOrder.map((g) => (g === oldName ? newName : g));
    if (oldName !== newName && db.categoryLogos && db.categoryLogos[oldName]) {
      if (!db.categoryLogos[newName]) {
        db.categoryLogos[newName] = db.categoryLogos[oldName];
      }
      delete db.categoryLogos[oldName];
    }
    saveDb();

    res.json({ categories: getOrderedCategories() });
  });

  app.post('/api/admin/categories/move', requireAdminAuth, (req: Request, res: Response) => {
    const name = String(req.body?.name || '').trim();
    const direction = req.body?.direction as 'up' | 'down' | 'top' | 'bottom';
    if (!name || !['up', 'down', 'top', 'bottom'].includes(direction)) {
      res.status(400).json({ error: 'بيانات تحريك القسم غير صالحة.' });
      return;
    }
    moveCategoryInOrder(name, direction);
    res.json({ categories: getOrderedCategories() });
  });

  app.put('/api/admin/categories/reorder', requireAdminAuth, (req: Request, res: Response) => {
    const orderedNames = Array.isArray(req.body?.orderedNames)
      ? req.body.orderedNames.map(String)
      : [];
    setCategoryOrder(orderedNames);
    res.json({ categories: getOrderedCategories() });
  });

  app.post('/api/admin/categories/delete', requireAdminAuth, (req: Request, res: Response) => {
    const rawCats = Array.isArray(req.body?.categories) ? req.body.categories : [];
    const categories = rawCats
      .map((c: unknown) => String(c || '').trim())
      .filter((c: string) => c.length > 0);

    if (categories.length === 0) {
      res.status(400).json({ error: 'يرجى تحديد قسم واحد على الأقل للحذف.' });
      return;
    }

    const blockFutureSync = req.body?.blockFutureSync !== false;
    const { deletedCategoriesCount, deletedChannelsCount, removedChannelIds } =
      deleteCategoriesFromStore(categories, blockFutureSync);

    if (removedChannelIds.size > 0) {
      for (const [id, entry] of activeUpstreamMap.entries()) {
        if (removedChannelIds.has(entry.channelId)) {
          activeUpstreamMap.delete(id);
          try {
            entry.destroy();
          } catch {
            // ignore
          }
        }
      }
    }

    const db = getDb();
    res.json({
      deletedCategoriesCount,
      deletedChannelsCount,
      categories: getOrderedCategories(),
      excludedCategories: db.excludedCategories || [],
      totalChannels: getActiveSourcesAndChannels().channels.length,
    });
  });

  app.post(
    '/api/admin/categories/excluded/restore',
    requireAdminAuth,
    (req: Request, res: Response) => {
      const rawCats = Array.isArray(req.body?.categories) ? req.body.categories : [];
      const categories = rawCats
        .map((c: unknown) => String(c || '').trim())
        .filter((c: string) => c.length > 0);

      const excludedCategories = restoreExcludedCategoriesInStore(categories);
      res.json({ excludedCategories });
    }
  );

  // 9. Hero Banner Slides Control (Add, Update, Reorder Up/Down, Delete)
  const normalizeExternalSlideUrl = (raw: unknown): string => {
    const cleaned = String(raw || '')
      .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00A0]/g, '')
      .trim();
    if (!cleaned) return '';
    if (/^(javascript|vbscript|data):/i.test(cleaned)) return '';
    if (cleaned.startsWith('@') && cleaned.length > 1) {
      return `https://t.me/${cleaned.slice(1).replace(/^\/+/, '')}`;
    }
    if (/^(t\.me|telegram\.me|wa\.me)\//i.test(cleaned)) {
      return `https://${cleaned}`;
    }
    if (/^(https?:\/\/|tg:\/\/)/i.test(cleaned)) {
      return cleaned;
    }
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(cleaned)) {
      return `https://${cleaned}`;
    }
    return cleaned;
  };

  const parseHeroActionType = (raw: unknown, fallbackExternalUrl?: string): HeroActionType => {
    const val = String(raw || '').trim();
    if (
      val === 'watch_channel' ||
      val === 'external_url' ||
      val === 'category' ||
      val === 'none'
    ) {
      return val;
    }
    return fallbackExternalUrl ? 'external_url' : 'watch_channel';
  };

  const parseHeroThemePreset = (raw: unknown): HeroThemePreset => {
    const val = String(raw || '').trim();
    if (val === 'telegram' || val === 'promo' || val === 'default') {
      return val;
    }
    return 'default';
  };

  app.post('/api/admin/hero-slides', requireAdminAuth, (req: Request, res: Response) => {
    const title = String(req.body?.title || '').trim();
    const subtitle = String(req.body?.subtitle || '').trim();
    const badge = String(req.body?.badge ?? '').trim();
    const imageUrl = String(req.body?.imageUrl || '').trim();
    const externalUrl = normalizeExternalSlideUrl(req.body?.externalUrl);
    const actionType = parseHeroActionType(req.body?.actionType, externalUrl);
    const buttonText = String(req.body?.buttonText || '').trim() || undefined;
    const channelId = String(req.body?.channelId || '').trim() || undefined;
    const targetCategory = String(req.body?.targetCategory || '').trim() || undefined;
    const showLiveBadge =
      typeof req.body?.showLiveBadge === 'boolean'
        ? req.body.showLiveBadge
        : actionType === 'watch_channel';
    const themePreset = parseHeroThemePreset(req.body?.themePreset);
    const active = req.body?.active !== false;

    if (!title && !imageUrl) {
      res.status(400).json({ error: 'يرجى كتابة عنوان للشريحة أو رفع صورة للعرض.' });
      return;
    }

    if (actionType === 'external_url' && !externalUrl) {
      res.status(400).json({ error: 'يرجى إدخال رابط التليجرام أو الرابط الخارجي للزر.' });
      return;
    }

    const db = getDb();
    const slide: HeroSlide = {
      id: `hero_${crypto.randomBytes(5).toString('hex')}`,
      title,
      subtitle,
      badge,
      imageUrl,
      actionType,
      buttonText,
      externalUrl: externalUrl || undefined,
      channelId,
      targetCategory,
      showLiveBadge,
      themePreset,
      order: db.heroSlides.length,
      active,
    };

    db.heroSlides.push(slide);
    saveDb();
    res.json({ heroSlides: [...db.heroSlides].sort((a, b) => a.order - b.order) });
  });

  app.put('/api/admin/hero-slides/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const slide = db.heroSlides.find((s) => s.id === req.params.id);
    if (!slide) {
      res.status(404).json({ error: 'شريحة العرض غير موجودة.' });
      return;
    }

    if (typeof req.body?.title === 'string') {
      slide.title = req.body.title.trim();
    }
    if (typeof req.body?.subtitle === 'string') {
      slide.subtitle = req.body.subtitle.trim();
    }
    if (typeof req.body?.badge === 'string') {
      slide.badge = req.body.badge.trim();
    }
    if (typeof req.body?.imageUrl === 'string') {
      slide.imageUrl = req.body.imageUrl.trim();
    }
    if (req.body?.externalUrl !== undefined) {
      const normalized = normalizeExternalSlideUrl(req.body.externalUrl);
      slide.externalUrl = normalized || undefined;
    }
    if (req.body?.actionType !== undefined) {
      slide.actionType = parseHeroActionType(req.body.actionType, slide.externalUrl);
    }
    if (req.body?.buttonText !== undefined) {
      slide.buttonText = String(req.body.buttonText || '').trim() || undefined;
    }
    if (req.body?.channelId !== undefined) {
      slide.channelId = String(req.body.channelId || '').trim() || undefined;
    }
    if (req.body?.targetCategory !== undefined) {
      slide.targetCategory = String(req.body.targetCategory || '').trim() || undefined;
    }
    if (typeof req.body?.showLiveBadge === 'boolean') {
      slide.showLiveBadge = req.body.showLiveBadge;
    }
    if (req.body?.themePreset !== undefined) {
      slide.themePreset = parseHeroThemePreset(req.body.themePreset);
    }
    if (typeof req.body?.active === 'boolean') {
      slide.active = req.body.active;
    }

    if (!slide.title && !slide.imageUrl) {
      res.status(400).json({ error: 'يرجى الإبقاء على عنوان للشريحة أو صورة للعرض.' });
      return;
    }

    if (slide.actionType === 'external_url' && !slide.externalUrl) {
      res.status(400).json({ error: 'يرجى إدخال رابط التليجرام أو الرابط الخارجي للزر.' });
      return;
    }

    saveDb();
    res.json({ heroSlides: [...db.heroSlides].sort((a, b) => a.order - b.order) });
  });

  app.post('/api/admin/hero-slides/:id/move', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const sorted = [...db.heroSlides].sort((a, b) => a.order - b.order);
    const idx = sorted.findIndex((s) => s.id === req.params.id);
    const direction = req.body?.direction as 'up' | 'down';

    if (idx === -1) {
      res.status(404).json({ error: 'شريحة العرض غير موجودة.' });
      return;
    }

    if (direction === 'up' && idx > 0) {
      [sorted[idx - 1], sorted[idx]] = [sorted[idx], sorted[idx - 1]];
    } else if (direction === 'down' && idx < sorted.length - 1) {
      [sorted[idx + 1], sorted[idx]] = [sorted[idx], sorted[idx + 1]];
    }

    sorted.forEach((s, i) => {
      s.order = i;
    });
    db.heroSlides = sorted;
    saveDb();
    res.json({ heroSlides: sorted });
  });

  app.delete('/api/admin/hero-slides/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    db.heroSlides = db.heroSlides
      .filter((s) => s.id !== req.params.id)
      .sort((a, b) => a.order - b.order)
      .map((s, idx) => ({ ...s, order: idx }));
    saveDb();
    res.json({ heroSlides: db.heroSlides });
  });

  // 10. Manage User Subscriptions (1-Person or Custom Multi-Person + Expiration Date) & Security Shield
  app.post('/api/admin/codes', requireAdminAuth, (req: Request, res: Response) => {
    const code = String(req.body?.code || '').trim();
    const label = String(req.body?.label || 'مشترك').trim();
    const notes = String(req.body?.notes || '').trim() || undefined;
    const rawExpiresAt = String(req.body?.expiresAt || '').trim();
    const maxDevices = Math.min(1000, Math.max(1, Math.floor(Number(req.body?.maxDevices) || 1)));

    if (!code || code.length < 3) {
      res.status(400).json({ error: 'يجب أن يتكون كود الاشتراك من 3 خانات على الأقل.' });
      return;
    }

    let expiresAtIso: string;
    if (rawExpiresAt && !Number.isNaN(Date.parse(rawExpiresAt))) {
      expiresAtIso = new Date(rawExpiresAt).toISOString();
    } else {
      const days = Math.max(1, Number(req.body?.durationDays) || 30);
      expiresAtIso = new Date(Date.now() + days * 86400000).toISOString();
    }

    const db = getDb();
    if (
      safeEqualString(db.adminCode, code) ||
      db.accessCodes.some((c) => safeEqualString(c.code, code))
    ) {
      res.status(400).json({ error: 'هذا الكود مستخدم بالفعل، يرجى اختيار كود آخر.' });
      return;
    }

    const entry: ViewerAccessCode = {
      id: `code_${crypto.randomBytes(5).toString('hex')}`,
      code,
      label,
      durationDays: computeDaysRemaining(expiresAtIso),
      expiresAt: expiresAtIso,
      createdAt: new Date().toISOString(),
      active: true,
      maxDevices,
      boundDevices: [],
      notes,
    };

    db.accessCodes.unshift(entry);
    db.isInitialSetup = false;
    saveDb();
    res.json({ accessCodes: db.accessCodes });
  });

  app.patch('/api/admin/codes/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const target = db.accessCodes.find((c) => c.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'الاشتراك غير موجود.' });
      return;
    }

    if (typeof req.body?.code === 'string' && req.body.code.trim()) {
      const nextCode = req.body.code.trim();
      if (nextCode.length < 3) {
        res.status(400).json({ error: 'يجب أن يتكون كود الاشتراك من 3 خانات على الأقل.' });
        return;
      }
      const conflict = db.accessCodes.some(
        (c) => c.id !== target.id && safeEqualString(c.code, nextCode)
      );
      if (conflict || safeEqualString(db.adminCode, nextCode)) {
        res.status(400).json({ error: 'هذا الكود مستخدم بالفعل.' });
        return;
      }
      target.code = nextCode;
    }

    if (typeof req.body?.label === 'string' && req.body.label.trim()) {
      target.label = req.body.label.trim();
    }

    if (typeof req.body?.expiresAt === 'string' && !Number.isNaN(Date.parse(req.body.expiresAt))) {
      target.expiresAt = new Date(req.body.expiresAt).toISOString();
      target.durationDays = computeDaysRemaining(target.expiresAt);
    }

    if (typeof req.body?.active === 'boolean') {
      target.active = req.body.active;
      if (!target.active) {
        abortViewerUpstreamConnections(target.code, { includeChunks: true });
      }
    }

    if (req.body?.maxDevices !== undefined) {
      const nextMax = Math.min(1000, Math.max(1, Math.floor(Number(req.body.maxDevices) || 1)));
      target.maxDevices = nextMax;
      if (Array.isArray(target.boundDevices) && target.boundDevices.length > nextMax) {
        // Keep the most recently active devices up to nextMax, and disconnect excess devices immediately
        const sorted = [...target.boundDevices].sort(
          (a, b) => (Date.parse(b.lastSeenAt) || 0) - (Date.parse(a.lastSeenAt) || 0)
        );
        const kept = sorted.slice(0, nextMax);
        const keptIds = new Set(kept.map((d) => d.deviceId));
        for (const removed of target.boundDevices) {
          if (!keptIds.has(removed.deviceId)) {
            abortViewerUpstreamConnections(target.code, {
              deviceId: removed.deviceId,
              includeChunks: true,
            });
          }
        }
        target.boundDevices = kept;
      }
    }

    if (req.body?.notes !== undefined) {
      target.notes = String(req.body.notes || '').trim() || undefined;
    }

    saveDb();
    res.json({ accessCodes: db.accessCodes });
  });

  app.post('/api/admin/codes/:id/reset-devices', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const target = db.accessCodes.find((c) => c.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'الاشتراك غير موجود.' });
      return;
    }

    const singleDeviceId =
      typeof req.body?.deviceId === 'string' ? req.body.deviceId.trim() : '';

    if (singleDeviceId) {
      target.boundDevices = (target.boundDevices || []).filter(
        (d) => d.deviceId !== singleDeviceId
      );
      abortViewerUpstreamConnections(target.code, {
        deviceId: singleDeviceId,
        includeChunks: true,
      });
      for (const [tid, lease] of activeStreamLeases.entries()) {
        if (lease.code === target.code && lease.deviceId === singleDeviceId) {
          activeStreamLeases.delete(tid);
        }
      }
    } else {
      target.boundDevices = [];
      abortViewerUpstreamConnections(target.code, { includeChunks: true });
      for (const [tid, lease] of activeStreamLeases.entries()) {
        if (lease.code === target.code) {
          activeStreamLeases.delete(tid);
        }
      }
    }

    saveDb();
    res.json({ accessCodes: db.accessCodes });
  });

  app.delete('/api/admin/codes/:id', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    if (db.accessCodes.length <= 1) {
      res.status(400).json({ error: 'يجب الإبقاء على اشتراك واحد على الأقل.' });
      return;
    }
    const target = db.accessCodes.find((c) => c.id === req.params.id);
    if (target) {
      abortViewerUpstreamConnections(target.code, { includeChunks: true });
    }
    db.accessCodes = db.accessCodes.filter((c) => c.id !== req.params.id);
    saveDb();
    res.json({ accessCodes: db.accessCodes });
  });

  // 11. Admin Maintenance Mode & Security Policy Toggles
  app.patch('/api/admin/maintenance', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    if (typeof req.body?.maintenanceMode === 'boolean') {
      db.maintenanceMode = req.body.maintenanceMode;
      if (db.maintenanceMode) {
        abortAllNonAdminStreams();
      }
    }
    if (typeof req.body?.maintenanceMessage === 'string') {
      const cleanedMsg = req.body.maintenanceMessage.trim();
      db.maintenanceMessage = cleanedMsg || DEFAULT_MAINTENANCE_MESSAGE;
    }
    saveDb();
    res.json({
      maintenanceMode: db.maintenanceMode,
      maintenanceMessage: db.maintenanceMessage,
    });
  });

  // 11b. Admin Android APK Settings & Ready-to-Build Project Export
  app.patch('/api/admin/apk-settings', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    if (req.body?.apkServerUrl !== undefined) {
      const rawServer = String(req.body.apkServerUrl || '').trim().replace(/\/+$/, '');
      if (rawServer && !/^https?:\/\//i.test(rawServer)) {
        res.status(400).json({ error: 'رابط السيرفر يجب أن يبدأ بـ https:// أو http://' });
        return;
      }
      db.apkServerUrl = rawServer;
    }
    if (req.body?.apkDownloadUrl !== undefined) {
      const rawDl = String(req.body.apkDownloadUrl || '').trim();
      db.apkDownloadUrl = rawDl ? normalizeExternalSlideUrl(rawDl) : '';
    }
    saveDb();

    const effectiveServerUrl = resolveDetectedServerUrl(req);
    syncApkConfigJsonOnDisk(effectiveServerUrl);

    res.json({
      apkServerUrl: db.apkServerUrl,
      apkDownloadUrl: db.apkDownloadUrl,
      detectedServerUrl: effectiveServerUrl,
    });
  });

  app.get('/api/admin/apk-project/download', (req: Request, res: Response) => {
    const hdrToken = Array.isArray(req.headers['x-admin-token'])
      ? req.headers['x-admin-token'][0]
      : req.headers['x-admin-token'];
    const queryToken = typeof req.query.at === 'string' ? req.query.at : undefined;
    const verified = verifyToken(hdrToken || queryToken);
    if (!verified || verified.role !== 'admin') {
      res.status(403).json({ error: 'غير مصرح لك بتحميل حزمة مشروع الأندرويد.' });
      return;
    }

    const effectiveServerUrl = resolveDetectedServerUrl(req);
    syncApkConfigJsonOnDisk(effectiveServerUrl);

    const rootDir = process.cwd();
    const excludedDirs = new Set([
      'node_modules',
      '.git',
      '.aistudio',
      'data',
      '.gradle',
      'build',
    ]);
    const excludedRelPaths = new Set([
      'server/ms-tv-db.json',
      'android/local.properties',
    ]);

    const createTarHeader = (relPath: string, size: number, mtimeSec: number, modeOctal: string): Buffer => {
      const header = Buffer.alloc(512, 0);
      let namePart = relPath.replace(/\\/g, '/');
      let prefixPart = '';
      if (Buffer.byteLength(namePart, 'utf-8') > 100) {
        const idx = namePart.lastIndexOf('/');
        if (idx > 0) {
          prefixPart = namePart.slice(0, idx);
          namePart = namePart.slice(idx + 1);
        }
      }
      header.write(namePart.slice(0, 100), 0, 100, 'utf-8');
      header.write(modeOctal, 100, 8, 'ascii');
      header.write('0000000\0', 108, 8, 'ascii');
      header.write('0000000\0', 116, 8, 'ascii');
      header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
      header.write(`${Math.floor(mtimeSec).toString(8).padStart(11, '0')}\0`, 136, 12, 'ascii');
      header.write('        ', 148, 8, 'ascii');
      header.write('0', 156, 1, 'ascii');
      header.write('ustar\0', 257, 6, 'ascii');
      header.write('00', 263, 2, 'ascii');
      if (prefixPart) {
        header.write(prefixPart.slice(0, 155), 345, 155, 'utf-8');
      }
      let sum = 0;
      for (let i = 0; i < 512; i++) sum += header[i];
      header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
      return header;
    };

    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="MS-TV-Android-APK-Project.tar.gz"'
    );
    res.setHeader('Cache-Control', 'no-store');

    const gzip = zlib.createGzip({ level: 6 });
    gzip.pipe(res);

    const apkConfigOverrideContent = Buffer.from(
      `${JSON.stringify(
        {
          appName: 'MS TV',
          appId: 'com.mstv.iptv',
          serverUrl: effectiveServerUrl,
        },
        null,
        2
      )}\n`,
      'utf-8'
    );

    const walk = (absDir: string, relDir: string) => {
      let entries: fs.Dirent[] = [];
      try {
        entries = fs.readdirSync(absDir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const ent of entries) {
        const relPath = relDir ? `${relDir}/${ent.name}` : ent.name;
        if (excludedRelPaths.has(relPath)) continue;
        if (ent.name.endsWith('.keystore') || ent.name.endsWith('.jks') || ent.name.endsWith('.tmp')) {
          continue;
        }
        const fullPath = path.join(absDir, ent.name);
        if (ent.isDirectory()) {
          if (excludedDirs.has(ent.name)) continue;
          if (relPath === 'android/app/build' || relPath === 'android/build') continue;
          walk(fullPath, relPath);
        } else if (ent.isFile()) {
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > 25 * 1024 * 1024) continue;
            const isApkConfig =
              relPath === 'public/apk-config.json' ||
              relPath === 'dist/apk-config.json' ||
              relPath === 'android/app/src/main/assets/public/apk-config.json';
            const content = isApkConfig ? apkConfigOverrideContent : fs.readFileSync(fullPath);
            const isExec = ent.name === 'gradlew';
            const archivePath = `ms-tv-android/${relPath}`;
            const hdr = createTarHeader(
              archivePath,
              content.length,
              stat.mtimeMs / 1000,
              isExec ? '0000755\0' : '0000644\0'
            );
            gzip.write(hdr);
            gzip.write(content);
            const rem = content.length % 512;
            if (rem > 0) {
              gzip.write(Buffer.alloc(512 - rem, 0));
            }
          } catch {
            // skip unreadable file
          }
        }
      }
    };

    walk(rootDir, '');
    gzip.write(Buffer.alloc(1024, 0));
    gzip.end();
  });

  app.patch('/api/admin/security-policy', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    const next: SecurityPolicyConfig = { ...db.securityPolicy };

    if (typeof req.body?.blockSniffers === 'boolean') {
      next.blockSniffers = req.body.blockSniffers;
    }
    if (typeof req.body?.blockVpn === 'boolean') {
      next.blockVpn = req.body.blockVpn;
      if (!next.blockVpn) {
        vpnIpCache.clear();
      }
    }
    if (typeof req.body?.blockDevTools === 'boolean') {
      next.blockDevTools = req.body.blockDevTools;
    }
    if (typeof req.body?.strictStreamBinding === 'boolean') {
      next.strictStreamBinding = req.body.strictStreamBinding;
    }

    db.securityPolicy = next;
    saveDb();
    res.json({
      securityPolicy: db.securityPolicy,
      securityEvents: db.securityEvents || [],
    });
  });

  app.delete('/api/admin/security-events', requireAdminAuth, (_req: Request, res: Response) => {
    const db = getDb();
    db.securityEvents = [];
    saveDb();
    res.json({ securityEvents: [] });
  });

  app.patch('/api/admin/security', requireAdminAuth, (req: Request, res: Response) => {
    const db = getDb();
    if (typeof req.body?.newAdminCode === 'string' && req.body.newAdminCode.trim()) {
      const nextCode = req.body.newAdminCode.trim();
      if (nextCode.length < 4) {
        res.status(400).json({ error: 'كود المدير السري يجب ألا يقل عن 4 خانات.' });
        return;
      }
      db.adminCode = nextCode;
      db.isInitialSetup = false;
    }

    if (typeof req.body?.primaryUserCode === 'string' && req.body.primaryUserCode.trim()) {
      const nextUserCode = req.body.primaryUserCode.trim();
      if (nextUserCode.length < 3) {
        res.status(400).json({ error: 'كود المستخدم يجب ألا يقل عن 3 خانات.' });
        return;
      }
      if (db.accessCodes.length > 0) {
        db.accessCodes[0].code = nextUserCode;
      }
      db.isInitialSetup = false;
    }

    if (req.body?.telegramCodeUrl !== undefined) {
      db.telegramCodeUrl = normalizeExternalSlideUrl(req.body.telegramCodeUrl);
    }

    if (typeof req.body?.hideAdminEntryForUsers === 'boolean') {
      db.hideAdminEntryForUsers = req.body.hideAdminEntryForUsers;
    }

    if (typeof req.body?.dismissInitialHint === 'boolean' && req.body.dismissInitialHint) {
      db.isInitialSetup = false;
    }

    saveDb();
    res.json({
      adminCode: db.adminCode,
      telegramCodeUrl: db.telegramCodeUrl,
      accessCodes: db.accessCodes,
      hideAdminEntryForUsers: db.hideAdminEntryForUsers,
      isInitialSetup: db.isInitialSetup,
    });
  });

  // ---------------------------------------------------------------------------
  // Vite Middleware (Dev) or Static Assets (Production)
  // ---------------------------------------------------------------------------
  const distPath = path.resolve(process.cwd(), 'dist');

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Gentle idle background playlist refresh so rotated upstream provider URLs stay fresh
  let bgSyncRunning = false;
  setInterval(async () => {
    if (bgSyncRunning || activeUpstreamMap.size > 0) return;
    const db = getDb();
    const eightHoursAgo = Date.now() - 8 * 60 * 60 * 1000;
    const staleSources = db.sources.filter((s) => {
      if (s.type !== 'm3u_url' && s.type !== 'xtream') return false;
      const syncedMs = Date.parse(s.lastSyncedAt || '') || 0;
      return syncedMs < eightHoursAgo;
    });
    if (staleSources.length === 0) return;

    bgSyncRunning = true;
    try {
      for (const source of staleSources) {
        if (activeUpstreamMap.size > 0) break;
        try {
          if (source.type === 'm3u_url' && source.m3uUrl) {
            const parsed = await fetchM3uFromUrl(source.m3uUrl);
            if (parsed.channels.length > 0) {
              source.groupsInOrder = parsed.groupsInOrder;
              upsertSourceChannels(source, parsed.channels);
            }
          } else if (
            source.type === 'xtream' &&
            source.xtreamHost &&
            source.xtreamUsername &&
            source.xtreamPassword
          ) {
            const result = await fetchXtreamPlaylist(
              source.xtreamHost,
              source.xtreamUsername,
              source.xtreamPassword,
              { includeLive: true, includeVod: source.includeVod ?? true }
            );
            if (result.channels.length > 0) {
              source.groupsInOrder = result.groupsInOrder;
              source.accountInfo = result.accountInfo;
              upsertSourceChannels(source, result.channels);
            }
          }
        } catch {
          // ignore transient background refresh errors
        }
      }
    } finally {
      bgSyncRunning = false;
    }
  }, 30 * 60 * 1000);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MS TV Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
