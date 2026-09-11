'use strict';

const crypto = require('node:crypto');
const { release: { version } } = require('./package.json');

module.exports.RELEASE = version;
module.exports.PORT = process.env.PORT || '51821';
module.exports.WEBUI_HOST = process.env.WEBUI_HOST || '0.0.0.0';
module.exports.PASSWORD_HASH = process.env.PASSWORD_HASH;
module.exports.MAX_AGE = parseInt(process.env.MAX_AGE, 10) * 1000 * 60 || 0;
module.exports.WG_PATH = process.env.WG_PATH || '/etc/amnezia/amneziawg/';
module.exports.WG_DEVICE = process.env.WG_DEVICE || 'eth0';
module.exports.WG_HOST = process.env.WG_HOST;
module.exports.WG_PORT = process.env.WG_PORT || '51820';
module.exports.WG_CONFIG_PORT = process.env.WG_CONFIG_PORT || process.env.WG_PORT || '51820';
module.exports.WG_MTU = process.env.WG_MTU || null;
module.exports.WG_PERSISTENT_KEEPALIVE = process.env.WG_PERSISTENT_KEEPALIVE || '0';
module.exports.WG_DEFAULT_ADDRESS = process.env.WG_DEFAULT_ADDRESS || '10.8.0.x';
module.exports.WG_DEFAULT_DNS = typeof process.env.WG_DEFAULT_DNS === 'string'
  ? process.env.WG_DEFAULT_DNS
  : '1.1.1.1';
module.exports.WG_ALLOWED_IPS = process.env.WG_ALLOWED_IPS || '0.0.0.0/0, ::/0';

module.exports.WG_PRE_UP = process.env.WG_PRE_UP || '';
module.exports.WG_POST_UP = process.env.WG_POST_UP || `
iptables -t nat -A POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -A INPUT -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -A FORWARD -i wg0 -j ACCEPT;
iptables -A FORWARD -o wg0 -j ACCEPT;
`.split('\n').join(' ');

module.exports.WG_PRE_DOWN = process.env.WG_PRE_DOWN || '';
module.exports.WG_POST_DOWN = process.env.WG_POST_DOWN || `
iptables -t nat -D POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -D INPUT -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -D FORWARD -i wg0 -j ACCEPT;
iptables -D FORWARD -o wg0 -j ACCEPT;
`.split('\n').join(' ');
module.exports.LANG = process.env.LANG || 'en';
module.exports.UI_TRAFFIC_STATS = process.env.UI_TRAFFIC_STATS || 'false';
module.exports.UI_CHART_TYPE = process.env.UI_CHART_TYPE || 0;
module.exports.WG_ENABLE_ONE_TIME_LINKS = process.env.WG_ENABLE_ONE_TIME_LINKS || 'false';
module.exports.UI_ENABLE_SORT_CLIENTS = process.env.UI_ENABLE_SORT_CLIENTS || 'false';
module.exports.WG_ENABLE_EXPIRES_TIME = process.env.WG_ENABLE_EXPIRES_TIME || 'false';
module.exports.ENABLE_PROMETHEUS_METRICS = process.env.ENABLE_PROMETHEUS_METRICS || 'false';
module.exports.PROMETHEUS_METRICS_PASSWORD = process.env.PROMETHEUS_METRICS_PASSWORD;

module.exports.DICEBEAR_TYPE = process.env.DICEBEAR_TYPE || false;
module.exports.USE_GRAVATAR = process.env.USE_GRAVATAR || false;

// --- AmneziaWG helpers ---

const getRandomInt = (min, max) => min + Math.floor(Math.random() * (max - min));
const getRandomJunkSize = () => getRandomInt(15, 150);
const getRandomUint32 = () => getRandomInt(1, 2_147_483_647);

/** AmneziaWG 2.0: disjoint header ranges so DPI sees varying types */
const HEADER_SEGMENTS = [
  [100_000_000, 450_000_000],
  [500_000_000, 950_000_000],
  [1_000_000_000, 1_150_000_000],
  [1_200_000_000, 2_100_000_000],
];

function randomRangeInSegment(lo, hi, widthMin, widthMax) {
  const width = getRandomInt(widthMin, Math.min(widthMax, hi - lo));
  const maxStart = hi - width;
  if (maxStart <= lo) {
    return `${lo}-${hi}`;
  }
  const start = getRandomInt(lo, maxStart);
  return `${start}-${start + width}`;
}

function defaultHeaderForSlot(slotIndex) {
  const [lo, hi] = HEADER_SEGMENTS[slotIndex];
  if (slotIndex === 2) {
    return randomRangeInSegment(lo, hi, 1, 12);
  }
  if (slotIndex === 3) {
    return randomRangeInSegment(lo, hi, 40_000, 900_000);
  }
  return randomRangeInSegment(lo, hi, 64, 1500);
}

function headerFromEnv(name) {
  const v = process.env[name];
  if (v === undefined || v === '') return null;
  return String(v).trim();
}

const parseOptionalNonNegInt = (v, defaultValue) => {
  if (v === undefined || v === '') return defaultValue;
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? defaultValue : n;
};

/** Parse env as range string "min-max" or single value, return as-is for awg config */
function parseRangeOrValue(envName, defaultFn) {
  const v = process.env[envName];
  if (v === undefined || v === '') return defaultFn();
  return String(v).trim();
}

// --- AWG 1.5: junk packets + magic headers ---
module.exports.JC = process.env.JC || getRandomInt(4, 12);
module.exports.JMIN = process.env.JMIN || 50;
module.exports.JMAX = process.env.JMAX || 1000;
module.exports.S1 = process.env.S1 || getRandomJunkSize();
module.exports.S2 = process.env.S2 || getRandomJunkSize();
module.exports.H1 = headerFromEnv('H1') || defaultHeaderForSlot(0);
module.exports.H2 = headerFromEnv('H2') || defaultHeaderForSlot(1);
module.exports.H3 = headerFromEnv('H3') || defaultHeaderForSlot(2);
module.exports.H4 = headerFromEnv('H4') || defaultHeaderForSlot(3);

// --- AWG 2.0: cookie / transport padding ---
module.exports.S3 = parseOptionalNonNegInt(process.env.S3, 32);
module.exports.S4 = parseOptionalNonNegInt(process.env.S4, 16);

// --- AWG 2.0: CPS initialization padding ---
module.exports.I1 = process.env.I1 ?? '';
module.exports.I2 = process.env.I2 ?? '';
module.exports.I3 = process.env.I3 ?? '';
module.exports.I4 = process.env.I4 ?? '';
module.exports.I5 = process.env.I5 ?? '';

// --- AWG 3.0: header protection key (32 bytes, base64) ---
module.exports.HeaderProtectionKey = process.env.HeaderProtectionKey || crypto.randomBytes(32).toString('base64');

// --- AWG 3.0: content padding addition ---
module.exports.ContentPaddingAddition = parseRangeOrValue('ContentPaddingAddition', () => '0');

// --- AWG 3.0: timing/rekey (range<uint16>) ---
module.exports.RekeyAfterTime = parseRangeOrValue('RekeyAfterTime', () => '0');
module.exports.RekeyTimeout = parseRangeOrValue('RekeyTimeout', () => '0');
module.exports.RejectAfterTime = parseRangeOrValue('RejectAfterTime', () => '0');
module.exports.KeepaliveTimeout = parseRangeOrValue('KeepaliveTimeout', () => '0');
module.exports.MaxHandshakeAttempts = parseRangeOrValue('MaxHandshakeAttempts', () => '0');

// --- AWG 3.1: random trailers + disable cookies (on/off) ---
module.exports.RandomTrailers = process.env.RandomTrailers || 'off';
module.exports.DisableCookies = process.env.DisableCookies || 'off';
