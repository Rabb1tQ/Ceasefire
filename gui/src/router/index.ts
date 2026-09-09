import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue')
  },
  {
    path: '/rules',
    name: 'Rules',
    component: () => import('../views/RuleManager.vue')
  },
  {
    path: '/network-activity',
    name: 'NetworkActivity',
    component: () => import('../views/NetworkActivity.vue')
  },
  {
    path: '/app-groups',
    name: 'AppGroups',
    component: () => import('../views/AppGroups.vue')
  },
  {
    path: '/notifications',
    name: 'Notifications',
    component: () => import('../views/Notifications.vue')
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import('../views/Settings.vue')
  },
  // 兜底：未知路径一律回仪表盘，避免输入错误路径时白屏
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
