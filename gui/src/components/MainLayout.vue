<template>
  <el-container class="main-layout">
    <el-aside width="220px" class="sidebar">
      <div class="logo">
        <h2>Ceasefire</h2>
      </div>
      <el-menu
        :default-active="activeMenu"
        router
        class="menu"
        text-color="#1f1f1f"
        active-text-color="#0078d4"
      >
        <el-menu-item index="/">
          <el-icon><House /></el-icon>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="/rules">
          <el-icon><Lock /></el-icon>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/network-activity">
          <el-icon><Connection /></el-icon>
          <span>网络活动</span>
        </el-menu-item>
        <el-menu-item index="/app-groups">
          <el-icon><User /></el-icon>
          <span>应用分组</span>
        </el-menu-item>
        <el-menu-item index="/notifications">
          <el-icon><List /></el-icon>
          <span>通知</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-main class="content">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { House, Lock, Setting, User, List, Connection } from '@element-plus/icons-vue'

const route = useRoute()
const activeMenu = computed(() => route.path)
</script>

<style scoped>
.main-layout {
  height: 100vh;
  background-color: #f5f5f5;
}

.sidebar {
  background-color: #ffffff;
  border-right: 1px solid #e0e0e0;
}

.logo {
  padding: 16px;
  color: #0078d4;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
  background-color: #f8f8f8;
}

.logo h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.menu {
  border-right: none;
  background-color: #ffffff;
  padding-top: 4px;
}

:deep(.el-menu-item) {
  height: 36px;
  line-height: 36px;
  color: #1f1f1f;
  padding-left: 20px !important;
  margin: 2px 8px;
  border-radius: 0;
  font-size: 13px;
}

:deep(.el-menu-item .el-icon) {
  margin-right: 8px;
  font-size: 16px;
}

:deep(.el-menu-item:hover) {
  background-color: #f3f3f3;
}

:deep(.el-menu-item.is-active) {
  background-color: #e0e0e0;
  color: #0078d4;
  font-weight: 600;
}

:deep(.el-menu-item.is-active::before) {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  background-color: #0078d4;
}

.content {
  background-color: #f5f5f5;
  padding: 20px;
  overflow-y: auto;
}
</style>