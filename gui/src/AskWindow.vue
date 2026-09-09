<template>
  <div class="ask-page">
    <div v-if="currentAsk" class="ask-body">
      <p class="ask-line">
        <strong>{{ currentAsk.process_name || '未知程序' }}</strong>
        尝试连接
        <span class="font-mono">{{ currentAsk.remote_addr }}:{{ currentAsk.remote_port }}</span>
        <span v-if="askDomain" class="font-mono">（{{ askDomain }}）</span>
        （{{ currentAsk.protocol }} / {{ currentAsk.direction === 'Inbound' ? '入站' : '出站' }}）
      </p>
      <p class="ask-path font-mono" :title="currentAsk.process_path || ''">{{ currentAsk.process_path || '（未知）' }}</p>
      <p v-if="!hasProcessPath" class="ask-path-warning">无法定位进程路径，无法创建持久规则；可跳过保持默认拦截。</p>
      <p v-else class="ask-tip">允许/阻止将创建持久规则，可在规则管理页修改或删除。</p>
    </div>
    <div v-else class="ask-empty">暂无待处理的联网询问</div>
    <div class="ask-footer">
      <el-button :disabled="resolving" @click="resolveAsk('Skip')">跳过（保持拦截）</el-button>
      <el-button type="danger" :disabled="resolving || !hasProcessPath" @click="resolveAsk('Block')">阻止</el-button>
      <el-button type="primary" :loading="resolving" :disabled="resolving || !hasProcessPath" @click="resolveAsk('Allow')">允许</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { ElMessage } from 'element-plus'

interface NotificationItem {
  id: number
  kind: 'Blocked' | 'Ask'
  timestamp: string
  process_path?: string | null
  process_name?: string | null
  remote_addr: string
  remote_port: number
  protocol: string
  direction: string
  rule_id?: number | null
}

const askQueue = ref<NotificationItem[]>([])
const resolving = ref(false)
let unlistenAsk: UnlistenFn | null = null
let unlistenSkip: UnlistenFn | null = null

const currentAsk = computed<NotificationItem | null>(() => askQueue.value[0] || null)

// 反查队头连接的域名（DNS 缓存命中才显示），队头变化即重查
const askDomain = ref<string | null>(null)
watch(currentAsk, async (item) => {
  askDomain.value = null
  if (!item) return
  try {
    askDomain.value = await invoke<string | null>('lookup_domain', { ip: item.remote_addr })
  } catch {
    askDomain.value = null
  }
}, { immediate: true })

// 事件缺进程路径时 Allow/Block 会落成 process_path=null 的持久规则 =
// 对所有进程生效的全局放行/拦截，必须禁用；用户仍可跳过（保持默认拦截）
// 且不产生任何规则写入
const hasProcessPath = computed(() => {
  const p = currentAsk.value?.process_path
  return typeof p === 'string' && p.trim().length > 0
})

// 队列空时隐藏窗口（不销毁，避免频繁创建）；有新 Ask 时置顶并抢焦点
const syncVisibility = async () => {
  try {
    if (askQueue.value.length > 0) {
      await invoke('show_ask_window')
    } else {
      await invoke('hide_ask_window')
    }
  } catch (error) {
    console.error('切换询问窗口可见性失败', error)
  }
}

// 弹窗决策：允许/阻止 = 直接创建按进程精确匹配的持久规则（不限端点）；
// 跳过 = 只收走弹窗、保持拦截。不再调用 record_connection_decision。
const resolveAsk = async (decision: 'Allow' | 'Block' | 'Skip') => {
  // 决策在途时忽略一切新点击/事件（含 Rust 侧转发的 skip），防止队头被
  // 双重 shift 吞掉下一条询问
  if (resolving.value) return
  const item = askQueue.value[0]
  if (!item) {
    await syncVisibility()
    return
  }
  if (decision === 'Skip') {
    shiftIfStillHead(item)
    return
  }

  // 空路径防御性兜底（按钮已置灰，此栏防事件入口漏判/批量触发）：
  // 不写规则、不报错，按跳过处理
  if (!hasProcessPath.value) {
    shiftIfStillHead(item)
    return
  }

  // await 期间队列可能被新事件重排/去重，shift 前必须校验队头仍是
  // 当初看到的那条（按 item.id 比对）
  resolving.value = true
  try {
    const processName = item.process_name || '未知程序'
    // 持久规则：按进程精确匹配（不限端点）
    await invoke('create_rule', {
      rule: {
        name: `[弹窗] ${processName}`,
        description: `通知弹窗决策：${decision === 'Allow' ? '允许' : '阻止'} ${processName}`,
        enabled: true,
        priority: 50,
        action: decision,
        direction: item.direction === 'Inbound' ? 'Inbound' : item.direction === 'Outbound' ? 'Outbound' : 'Both',
        protocol: null,
        process_path: item.process_path || null,
        remote_addr: null,
        remote_port: null,
        local_port: null
      }
    })
    ElMessage.success(decision === 'Allow' ? `已放行 ${processName}` : `已阻止 ${processName}`)
    shiftIfStillHead(item)
  } catch (error) {
    ElMessage.error('应用决策失败')
    console.error(error)
  } finally {
    resolving.value = false
  }
}

// 队头仍是发起决策时的那条才 shift；否则只刷新可见性，绝不吞掉别的条目
const shiftIfStillHead = async (item: NotificationItem) => {
  if (askQueue.value[0]?.id === item.id) {
    askQueue.value.shift()
  }
  await syncVisibility()
}

onMounted(async () => {
  unlistenAsk = await listen<NotificationItem>('firewall-ask', (event) => {
    // 同一程序只保留最新一条待询问记录
    askQueue.value = askQueue.value.filter(
      (q) => q.process_path !== event.payload.process_path
    )
    askQueue.value.push(event.payload)
    syncVisibility()
  })
  // 点标题栏 X = 跳过当前这条（保持拦截），Rust 侧拦截关闭后发此事件
  unlistenSkip = await listen('firewall-ask-skip', () => {
    resolveAsk('Skip')
  })
})

onUnmounted(() => {
  unlistenAsk?.()
  unlistenSkip?.()
})
</script>

<style scoped>
.ask-page {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 16px;
}

.ask-body {
  flex: 1;
  min-height: 0;
}

.ask-empty {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #605e5c;
  font-size: 13px;
}

.ask-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0;
  padding-top: 12px;
}

.ask-line {
  font-size: 14px;
  margin-bottom: 8px;
}

.ask-path {
  font-size: 11px;
  color: #605e5c;
  word-break: break-all;
  margin-bottom: 12px;
}

.ask-tip {
  font-size: 12px;
  color: #605e5c;
  margin-bottom: 12px;
}

.ask-path-warning {
  font-size: 12px;
  color: #d4740e;
  margin-bottom: 12px;
}

.font-mono {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}
</style>
