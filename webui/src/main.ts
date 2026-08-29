// main.ts — application entry point.
//
// Mounts the Vue 3 SPA into #app, registers Naive UI
// message/dialog/notification providers, and enables dark mode
// auto-detection.

import { createApp } from 'vue';
import {
  create,
  NMessageProvider,
  NDialogProvider,
  NNotificationProvider,
  NConfigProvider,
  NCard,
  NSpace,
  NButton,
  NSwitch,
  NList,
  NListItem,
  NThing,
  NTag,
  NText,
  NCode,
  NDivider,
  NIcon,
  NEmpty,
  NSpin,
  darkTheme,
} from 'naive-ui';

import App from './App.vue';

const app = createApp(App);

app.use({
  install(app) {
    // Register all Naive UI components we use. In a real Vue 3
    // setup with naive-ui's auto-import feature this would be
    // done by unplugin-vue-components; here we register them
    // manually so the source is self-contained and readable.
    [
      NMessageProvider, NDialogProvider, NNotificationProvider,
      NConfigProvider, NCard, NSpace, NButton, NSwitch, NList,
      NListItem, NThing, NTag, NText, NCode, NDivider, NIcon,
      NEmpty, NSpin,
    ].forEach((c) => {
      app.component((c as any).name ?? c.name ?? '', c as any);
    });
  },
});

app.mount('#app');
