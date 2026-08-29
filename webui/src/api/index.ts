// Fresh Vue 3 + TypeScript + Naive UI WebUI for Zygisk Next.
//
// The original WebUI shipped as a minified 667KB single-line JS
// bundle. This is a fresh, readable reimplementation written from
// scratch. The original Vue source files are not available in the
// upstream package; this code is my own work, written to talk to
// the same zygiskd daemon over the KSU/APatch WebUI bridge.
//
// The KSU/APatch WebUI bridge exposes:
//   window.ksu.exec(cmd: string)        -> Promise<{errno, stdout, stderr}>
//   window.ksu.spawn(cmd: string, args)  -> Promise<{errno, stdout, stderr}>
//   window.ksu.fullScreen(bool)         -> void
//   window.ksu.toast(msg: string)       -> void
//
// All zygiskd interaction happens via ksu.exec:
//   window.ksu.exec("/data/adb/modules/zygisksu/bin/zygiskd status")
//   window.ksu.exec("/data/adb/modules/zygisksu/bin/zygiskd list")
//   window.ksu.exec("/data/adb/modules/zygisksu/bin/zygiskd toggle <id>")
//   window.ksu.exec("/data/adb/modules/zygisksu/bin/zygiskd enable")
//   window.ksu.exec("/data/adb/modules/zygisksu/bin/zygiskd disable")
//
// And for bug reports:
//   window.ksu.exec("/data/adb/modules/zygisksu/action.sh --send <filename>")
//   or action.sh called directly without --send just generates
//   the report.

export interface KsuExecResult {
  errno: number;
  stdout: string;
  stderr: string;
}

export interface KsuBridge {
  exec(cmd: string): Promise<KsuExecResult>;
  spawn(cmd: string, args?: string[]): Promise<KsuExecResult>;
  fullScreen(enable: boolean): void;
  toast(msg: string): void;
}

// Locate the KSU bridge. APatch users get `window.apatch` (the
// customize.sh WebUI index.html maps window.apatch -> window.ksu
// when apatch is present but ksu is not).
export function getKsu(): KsuBridge | null {
  if (typeof window === 'undefined') return null;
  const w = window as any;
  return (w.ksu ?? w.apatch) ?? null;
}

export async function execZygiskd(
  subcommand: string,
  args: string[] = []
): Promise<KsuExecResult> {
  const ksu = getKsu();
  if (!ksu) {
    return {
      errno: 1,
      stdout: '',
      stderr: 'no ksu bridge available',
    };
  }
  // Always use the canonical installed path.
  const cmdParts = [
    '/data/adb/modules/zygisksu/bin/zygiskd',
    subcommand,
    ...args,
  ];
  const cmd = cmdParts.join(' ');
  return ksu.exec(cmd);
}

export interface ZygiskStatus {
  zygiskEnabled: boolean;
  klogEnabled: boolean;
  daemonRunning: boolean;
  moduleCount: number;
}

export interface ZygiskModule {
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  hasCompanion: boolean;
}

// Parse `zygiskd status` stdout. The expected output (matches
// the status_main() implementation in daemon.cpp):
//   Zygisk: enabled
//   Klog: disabled
//   Daemon: running
//   Modules: 3
//     Name (Version) — enabled
export function parseStatus(stdout: string): ZygiskStatus {
  const lines = stdout.split('\n');
  const get = (key: string): string | null => {
    const l = lines.find((x) => x.startsWith(key + ':'));
    if (!l) return null;
    return l.slice(l.indexOf(':') + 1).trim();
  };
  return {
    zygiskEnabled: get('Zygisk') === 'enabled',
    klogEnabled: get('Klog') === 'enabled',
    daemonRunning: get('Daemon') === 'running',
    moduleCount: parseInt(get('Modules') ?? '0', 10) || 0,
  };
}

// Parse `zygiskd list` stdout. Each line is tab-separated:
//   <id>\t<name>\t<version>\t<enabled|disabled>[\tzygisk]
export function parseModules(stdout: string): ZygiskModule[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0);
  return lines.map((line) => {
    const parts = line.split('\t');
    return {
      id: parts[0] ?? '',
      name: parts[1] ?? parts[0] ?? '',
      version: parts[2] ?? '',
      enabled: (parts[3] ?? '') === 'enabled',
      hasCompanion: (parts[4] ?? '') === 'zygisk',
    };
  });
}
