<!--
  App.vue — root component.

  Layout:
    ┌────────────────────────────────────────────┐
    │              Zygisk Next (title)             │
    ├────────────────────────────────────────────┤
    │  Status card (toggle Zygisk, toggle klog)   │
    ├────────────────────────────────────────────┤
    │  Module list (each module: enable toggle)    │
    ├────────────────────────────────────────────┤
    │  Bug report button (calls action.sh)         │
    └────────────────────────────────────────────┘
-->

<template>
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <n-dialog-provider>
        <n-notification-provider>
          <div class="root_layout">
            <n-space vertical size="large">
              <h1 class="title">Zygisk Next</h1>
              <n-card title="Status">
                <n-space vertical size="medium">
                  <n-space align="center" justify="space-between">
                    <n-text>Zygisk enabled</n-text>
                    <n-switch
                      :value="status.zygiskEnabled"
                      :loading="togglingZygisk"
                      @update:value="(v) => onToggleZygisk(v)"
                    />
                  </n-space>
                  <n-space align="center" justify="space-between">
                    <n-text>Kernel log</n-text>
                    <n-switch
                      :value="status.klogEnabled"
                      :loading="togglingKlog"
                      @update:value="(v) => onToggleKlog(v)"
                    />
                  </n-space>
                  <n-space align="center" justify="space-between">
                    <n-text>Daemon</n-text>
                    <n-tag :type="status.daemonRunning ? 'success' : 'error'">
                      {{ status.daemonRunning ? 'running' : 'not running' }}
                    </n-tag>
                  </n-space>
                </n-space>
              </n-card>

              <n-card title="Modules">
                <n-spin :show="loadingModules">
                  <n-empty
                    v-if="modules.length === 0"
                    description="No modules loaded"
                  />
                  <n-list v-else bordered>
                    <n-list-item v-for="m in modules" :key="m.id">
                      <n-thing>
                        <template #header>
                          {{ m.name || m.id }}
                          <n-tag
                            v-if="m.hasCompanion"
                            size="small"
                            type="info"
                            style="margin-left: 8px"
                          >zygisk</n-tag>
                        </template>
                        <template #description>
                          <n-text depth="3">
                            id: {{ m.id }} · version: {{ m.version }}
                          </n-text>
                        </template>
                        <template #action>
                          <n-switch
                            :value="m.enabled"
                            :loading="togglingId === m.id"
                            @update:value="(v) => onToggleModule(m, v)"
                          />
                        </template>
                      </n-thing>
                    </n-list-item>
                  </n-list>
                </n-spin>
              </n-card>

              <n-card title="Bug Report">
                <n-space vertical>
                  <n-text>
                    Generate a Zygisk Next bug report. The report
                    will include klog output, module list, and
                    recent logcat. After generation, it will be
                    shared via Android's share sheet.
                  </n-text>
                  <n-button
                    type="primary"
                    :loading="generatingBugreport"
                    @click="onGenerateBugreport"
                  >
                    Generate Bug Report
                  </n-button>
                  <n-text v-if="bugreportPath" depth="3">
                    Last report: {{ bugreportPath }}
                  </n-text>
                </n-space>
              </n-card>
            </n-space>
          </div>
        </n-notification-provider>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { darkTheme } from 'naive-ui';
import { useMessage } from 'naive-ui';

import {
  execZygiskd,
  parseStatus,
  parseModules,
  type ZygiskStatus,
  type ZygiskModule,
  getKsu,
} from './api';

const message = useMessage();

const status = ref<ZygiskStatus>({
  zygiskEnabled: false,
  klogEnabled: false,
  daemonRunning: false,
  moduleCount: 0,
});

const modules = ref<ZygiskModule[]>([]);
const loadingModules = ref(true);

const togglingZygisk = ref(false);
const togglingKlog = ref(false);
const togglingId = ref<string | null>(null);
const generatingBugreport = ref(false);
const bugreportPath = ref<string>('');

async function refreshStatus() {
  const r = await execZygiskd('status');
  if (r.errno !== 0) {
    message.error(`status failed: ${r.stderr || 'unknown error'}`);
    return;
  }
  status.value = parseStatus(r.stdout);
}

async function refreshModules() {
  loadingModules.value = true;
  const r = await execZygiskd('list');
  loadingModules.value = false;
  if (r.errno !== 0) {
    message.error(`list failed: ${r.stderr || 'unknown error'}`);
    return;
  }
  modules.value = parseModules(r.stdout);
}

async function onToggleZygisk(enable: boolean) {
  togglingZygisk.value = true;
  const r = await execZygiskd(enable ? 'enable' : 'disable');
  togglingZygisk.value = false;
  if (r.errno !== 0) {
    message.error(`toggle Zygisk failed: ${r.stderr}`);
    return;
  }
  message.success(enable ? 'Zygisk enabled (next boot)' : 'Zygisk disabled (next boot)');
  await refreshStatus();
}

async function onToggleKlog(enable: boolean) {
  togglingKlog.value = true;
  // zygiskd doesn't have a klog subcommand; we have to write
  // the config file directly via the ksu bridge.
  const ksu = getKsu();
  if (!ksu) {
    message.error('no ksu bridge');
    togglingKlog.value = false;
    return;
  }
  const cmd = `sh -c "echo ${enable ? 1 : 0} > /data/adb/zygisksu/klog"`;
  const r = await ksu.exec(cmd);
  togglingKlog.value = false;
  if (r.errno !== 0) {
    message.error(`toggle klog failed: ${r.stderr}`);
    return;
  }
  message.success(enable ? 'klog enabled' : 'klog disabled');
  await refreshStatus();
}

async function onToggleModule(m: ZygiskModule, enable: boolean) {
  togglingId.value = m.id;
  const r = await execZygiskd('toggle', [m.id]);
  togglingId.value = null;
  if (r.errno !== 0) {
    message.error(`toggle ${m.id} failed: ${r.stderr}`);
    return;
  }
  m.enabled = enable;
  message.success(`${m.name || m.id} ${enable ? 'enabled' : 'disabled'} (next boot)`);
}

async function onGenerateBugreport() {
  generatingBugreport.value = true;
  const ksu = getKsu();
  if (!ksu) {
    message.error('no ksu bridge');
    generatingBugreport.value = false;
    return;
  }
  // action.sh is invoked with FROM_WEBUI=1 to get back a path.
  const cmd = 'FROM_WEBUI=1 /data/adb/modules/zygisksu/action.sh';
  const r = await ksu.exec(cmd);
  generatingBugreport.value = false;
  if (r.errno !== 0) {
    message.error(`bugreport failed: ${r.stderr}`);
    return;
  }
  // action.sh prints the path of the generated tarball.
  bugreportPath.value = r.stdout.trim();
  message.success(`bugreport generated: ${bugreportPath.value}`);
}

onMounted(async () => {
  await refreshStatus();
  await refreshModules();
});
</script>

<style scoped>
.root_layout {
  padding: 16px;
  padding-top: var(--window-inset-top, 16px);
  padding-bottom: var(--window-inset-bottom, 16px);
}
.title {
  font-size: 24px;
  font-weight: 600;
  margin: 0;
}
</style>
