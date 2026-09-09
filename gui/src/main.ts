import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import router from './router'
import './style.css'
import App from './App.vue'

// ask 置顶小窗是独立窗口入口（index.html#/ask），不套主窗口布局、不走路由
// （路由为 createWebHistory，解析不了 hash 入口）
if (window.location.hash.startsWith('#/ask')) {
  import('./AskWindow.vue').then(({ default: AskWindow }) => {
    const askApp = createApp(AskWindow)
    askApp.use(ElementPlus)
    askApp.config.errorHandler = (err, _instance, info) => {
      console.error('Unhandled error in ask window:', err, 'info:', info)
    }
    askApp.mount('#app')
  })
} else {

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
app.use(ElementPlus)

// Register all icons
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

// 全局兜底：组件内未捕获的异常在这里统一记录。默认行为是只打到 console 且
// 不阻断后续渲染；这里额外提示用户出了问题，避免界面静默异常无任何反馈。
app.config.errorHandler = (err, _instance, info) => {
  console.error('Unhandled error in app:', err, 'info:', info)
  try {
    // 动态引入，避免 errorHandler 初始化与 ElementPlus 装载顺序耦合
    import('element-plus').then(({ ElMessage }) => {
      ElMessage.error('发生未处理的错误，详情见控制台')
    })
  } catch {
    // 忽略提示失败，console 已记录
  }
}

app.mount('#app')
}
