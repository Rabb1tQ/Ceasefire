import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  optimizeDeps: {
    exclude: ['vxe-table']
  },
  server: {
    watch: {
      // tauri:dev 期间 cargo 链接器会锁定 src-tauri/target 下的 app_lib.dll
      // 等产物，chokidar 监视到 EBUSY 会让 vite 直接崩溃——排除整个
      // src-tauri 目录（前端 HMR 不需要它）。
      ignored: ['**/src-tauri/**']
    }
  }
})
