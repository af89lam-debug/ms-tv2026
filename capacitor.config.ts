import type { CapacitorConfig } from '@capacitor/cli';

const liveServerUrl = (process.env.CAPACITOR_SERVER_URL || '').trim().replace(/\/+$/, '');

const config: CapacitorConfig = {
  appId: 'com.mstv.iptv',
  appName: 'MS TV',
  webDir: 'dist',
  backgroundColor: '#060B16',
  server: liveServerUrl
    ? {
        url: liveServerUrl,
        cleartext: true,
      }
    : {
        androidScheme: 'https',
        cleartext: true,
      },
  android: {
    allowMixedContent: true,
    captureInput: true,
    webContentsDebuggingEnabled: false,
    backgroundColor: '#060B16',
    appendUserAgent: 'MSTVApp/1.0',
  },
};

export default config;
