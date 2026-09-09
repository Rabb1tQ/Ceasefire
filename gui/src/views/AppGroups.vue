<template>
  <div class="app-groups">
    <div class="header">
      <h1>应用程序分组</h1>
      <el-button @click="initializePredefined">
        初始化预定义分组
      </el-button>
    </div>

    <el-row :gutter="20">
      <!-- 分组列表：紧凑单行条目 -->
      <el-col :span="8">
        <el-card class="groups-card">
          <template #header>
            <div class="card-header-content">
              <span>分组列表</span>
              <el-button type="primary" size="small" @click="openCreateGroup">
                + 新建分组
              </el-button>
            </div>
          </template>

          <div v-if="loading && groups.length === 0" class="loading-text">
            加载中...
          </div>

          <div v-else-if="groups.length === 0" class="empty-text">
            暂无分组，点击「+ 新建分组」创建，或点击上方「初始化预定义分组」导入常用分组
          </div>

          <div v-else class="groups-list">
            <div
              v-for="group in sortedGroups"
              :key="group.id"
              @click="selectGroup(group)"
              :class="['group-item', selectedGroup?.id === group.id ? 'active' : '']"
            >
              <span v-if="group.is_predefined" class="predefined-dot" title="预定义分组"></span>
              <span class="group-name" :title="group.name">{{ group.name }}</span>
              <span class="member-badge">{{ memberCounts[group.id!] ?? 0 }}</span>
              <span class="item-actions" @click.stop>
                <el-tooltip :content="group.enabled ? '禁用分组' : '启用分组'" placement="top">
                  <el-button
                    link
                    size="small"
                    :type="group.enabled ? 'warning' : 'success'"
                    class="item-btn"
                    @click="toggleGroup(group)"
                  >
                    {{ group.enabled ? '禁用' : '启用' }}
                  </el-button>
                </el-tooltip>
                <el-button link size="small" type="danger" class="item-btn" @click="deleteGroup(group)">
                  删除
                </el-button>
              </span>
            </div>
          </div>
        </el-card>
      </el-col>

      <!-- 分组详情 -->
      <el-col :span="16">
        <el-card class="members-card">
          <template v-if="!selectedGroup" #header>
            <span>分组详情</span>
          </template>

          <template v-else #header>
            <div class="card-header-content">
              <div class="detail-title">
                <div class="detail-name">
                  {{ selectedGroup.name }}
                  <el-tag v-if="selectedGroup.is_predefined" type="warning" size="small">预定义</el-tag>
                </div>
                <div class="description">{{ selectedGroup.description || '（无描述）' }}</div>
              </div>
              <div class="detail-actions">
                <el-switch
                  :model-value="selectedGroup.enabled"
                  active-text="启用"
                  inactive-text="禁用"
                  inline-prompt
                  @change="toggleGroup(selectedGroup!)"
                />
                <el-button @click="openRenameGroup">重命名</el-button>
                <el-button type="success" @click="openAddMember">添加成员</el-button>
              </div>
            </div>
          </template>

          <div v-if="!selectedGroup" class="empty-text">
            请选择一个分组查看详情
          </div>

          <div v-else-if="loading && members.length === 0" class="loading-text">
            加载中...
          </div>

          <div v-else-if="members.length === 0" class="empty-text">
            此分组暂无成员
          </div>

          <el-table v-else :data="members" stripe style="width: 100%">
            <el-table-column prop="process_name" label="进程名称" width="150">
              <template #default="{ row }">
                {{ row.process_name || '-' }}
              </template>
            </el-table-column>
            <el-table-column prop="process_path" label="进程路径" min-width="300">
              <template #default="{ row }">
                <span class="font-mono">{{ row.process_path }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button link type="danger" @click="removeMember(row)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 添加成员对话框 -->
    <el-dialog v-model="showAddMember" title="添加进程到分组" width="500px">
      <el-form label-width="100px">
        <el-form-item label="进程路径">
          <el-input
            v-model="newMemberPath"
            placeholder="例如: C:\Program Files\app.exe"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeAddMember">取消</el-button>
        <el-button type="primary" @click="addMember">添加</el-button>
      </template>
    </el-dialog>

    <!-- 新建分组对话框（重命名复用同一表单） -->
    <el-dialog
      v-model="showGroupForm"
      :title="groupFormMode === 'create' ? '新建分组' : '重命名分组'"
      width="480px"
    >
      <el-form label-width="80px" @submit.prevent>
        <el-form-item label="名称" required>
          <el-input
            ref="groupNameInput"
            v-model="groupFormName"
            placeholder="分组名称"
            maxlength="64"
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input
            v-model="groupFormDesc"
            type="textarea"
            :rows="2"
            placeholder="描述（可选）"
            maxlength="200"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showGroupForm = false">取消</el-button>
        <el-button type="primary" @click="submitGroupForm">
          {{ groupFormMode === 'create' ? '创建' : '保存' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { ElMessage, ElMessageBox } from 'element-plus'

interface AppGroup {
  id?: number
  name: string
  description: string
  enabled: boolean
  is_predefined: boolean
  created_at?: string | null
  updated_at?: string | null
}

interface AppGroupMember {
  id?: number
  group_id: number
  process_path: string
  process_name?: string
}

const groups = ref<AppGroup[]>([])
const members = ref<AppGroupMember[]>([])
const selectedGroup = ref<AppGroup | null>(null)
const loading = ref(false)
const showAddMember = ref(false)
const newMemberPath = ref('')

// 分组成员数徽标（分组数量级小，整表拉一次成员即可）
const memberCounts = ref<Record<number, number>>({})

// 新建/重命名共用表单
const showGroupForm = ref(false)
const groupFormMode = ref<'create' | 'rename'>('create')
const groupFormName = ref('')
const groupFormDesc = ref('')
const groupNameInput = ref()

// 前端按名称排序（分组数量级小，不分页）
const sortedGroups = computed(() =>
  [...groups.value].sort((a, b) => a.name.localeCompare(b.name))
)

// 竞态守卫（与 Dashboard/NetworkActivity 同模式）：快速切换分组或组件
// 卸载时，旧响应不得覆盖新数据
let membersRequestId = 0
let groupsRequestId = 0
let isDisposed = false
onUnmounted(() => {
  isDisposed = true
})

const loadGroups = async () => {
  const reqId = ++groupsRequestId
  loading.value = true
  try {
    const data: AppGroup[] = await invoke('list_app_groups')
    if (isDisposed || reqId !== groupsRequestId) return
    groups.value = data
    // 选中组被删除后清掉详情，避免展示悬空数据
    if (selectedGroup.value) {
      const stillThere = data.find(g => g.id === selectedGroup.value!.id!)
      if (!stillThere) {
        selectedGroup.value = null
        members.value = []
      }
    }
    await loadMemberCounts()
  } catch (error) {
    if (isDisposed || reqId !== groupsRequestId) return
    ElMessage.error('加载应用分组失败')
    console.error('加载应用分组失败:', error)
  } finally {
    if (!isDisposed && reqId === groupsRequestId) {
      loading.value = false
    }
  }
}

const loadMemberCounts = async () => {
  const targets = [...groups.value]
  const entries = await Promise.all(
    targets
      .filter(g => g.id !== undefined)
      .map(async g => {
        try {
          const list: AppGroupMember[] = await invoke('get_app_group_members', { groupId: g.id })
          return [g.id!, list.length] as const
        } catch {
          return [g.id!, 0] as const
        }
      })
  )
  if (isDisposed) return
  memberCounts.value = Object.fromEntries(entries)
}

const loadMembers = async (groupId: number) => {
  const reqId = ++membersRequestId
  loading.value = true
  try {
    const data: AppGroupMember[] = await invoke('get_app_group_members', { groupId })
    if (isDisposed || reqId !== membersRequestId) return
    members.value = data
    memberCounts.value = { ...memberCounts.value, [groupId]: data.length }
  } catch (error) {
    if (isDisposed || reqId !== membersRequestId) return
    ElMessage.error('加载分组成员失败')
    console.error('加载分组成员失败:', error)
  } finally {
    if (!isDisposed && reqId === membersRequestId) {
      loading.value = false
    }
  }
}

const selectGroup = (group: AppGroup) => {
  selectedGroup.value = group
  if (group.id) {
    loadMembers(group.id)
  }
}

const initializePredefined = async () => {
  try {
    await invoke('initialize_predefined_groups')
    ElMessage.success('预定义分组初始化成功')
    await loadGroups()
  } catch (error) {
    ElMessage.error('初始化预定义分组失败')
    console.error('初始化预定义分组失败:', error)
  }
}

// ---------- 新建 / 重命名 ----------

const openCreateGroup = () => {
  groupFormMode.value = 'create'
  groupFormName.value = ''
  groupFormDesc.value = ''
  showGroupForm.value = true
  nextTick(() => groupNameInput.value?.focus?.())
}

const openRenameGroup = () => {
  if (!selectedGroup.value) return
  groupFormMode.value = 'rename'
  groupFormName.value = selectedGroup.value.name
  groupFormDesc.value = selectedGroup.value.description
  showGroupForm.value = true
  nextTick(() => groupNameInput.value?.focus?.())
}

const submitGroupForm = async () => {
  const name = groupFormName.value.trim()
  if (!name) {
    ElMessage.warning('请输入分组名称')
    return
  }

  try {
    if (groupFormMode.value === 'create') {
      const created: AppGroup = await invoke('create_app_group', {
        group: {
          id: null,
          name,
          description: groupFormDesc.value.trim(),
          enabled: true,
          is_predefined: false,
          created_at: null,
          updated_at: null
        }
      })
      ElMessage.success('分组创建成功')
      showGroupForm.value = false
      await loadGroups()
      if (created.id) {
        selectGroup(created)
      }
    } else if (selectedGroup.value?.id) {
      await invoke('update_app_group', {
        id: selectedGroup.value.id,
        group: {
          ...selectedGroup.value,
          name,
          description: groupFormDesc.value.trim()
        }
      })
      ElMessage.success('分组已更新')
      showGroupForm.value = false
      await loadGroups()
      // 同步刷新选中对象的最新字段
      const refreshed = groups.value.find(g => g.id === selectedGroup.value?.id)
      if (refreshed) {
        selectedGroup.value = refreshed
      }
    }
  } catch (error) {
    ElMessage.error(groupFormMode.value === 'create' ? '创建分组失败' : '更新分组失败')
    console.error('保存分组失败:', error)
  }
}

// ---------- 启停 / 删除 ----------

const toggleGroup = async (group: AppGroup) => {
  if (!group.id) return
  try {
    await invoke('set_app_group_enabled', { id: group.id, enabled: !group.enabled })
    if (isDisposed) return
    // 本地同步状态，避免整表重载闪烁；选中对象同步更新
    group.enabled = !group.enabled
    const inList = groups.value.find(g => g.id === group.id)
    if (inList) inList.enabled = group.enabled
    if (selectedGroup.value?.id === group.id) {
      selectedGroup.value = { ...selectedGroup.value, enabled: group.enabled }
    }
  } catch (error) {
    ElMessage.error('切换分组状态失败')
    console.error('切换分组状态失败:', error)
  }
}

const deleteGroup = async (group: AppGroup) => {
  if (!group.id) return
  try {
    await ElMessageBox.confirm(
      `确定要删除分组「${group.name}」吗？其成员列表将一并删除。`,
      '删除分组',
      {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
  } catch {
    return // 用户取消
  }

  try {
    await invoke('delete_app_group', { id: group.id })
    ElMessage.success('分组已删除')
    if (selectedGroup.value?.id === group.id) {
      selectedGroup.value = null
      members.value = []
    }
    await loadGroups()
  } catch (error) {
    ElMessage.error('删除分组失败')
    console.error('删除分组失败:', error)
  }
}

// ---------- 成员管理 ----------

const openAddMember = () => {
  showAddMember.value = true
  newMemberPath.value = ''
}

const closeAddMember = () => {
  showAddMember.value = false
  newMemberPath.value = ''
}

const addMember = async () => {
  if (!selectedGroup.value?.id || !newMemberPath.value) {
    ElMessage.warning('请选择分组并输入进程路径')
    return
  }

  try {
    await invoke('add_app_group_member', {
      groupId: selectedGroup.value.id,
      processPath: newMemberPath.value,
      processName: undefined
    })
    ElMessage.success('添加成员成功')
    closeAddMember()
    if (selectedGroup.value.id) {
      loadMembers(selectedGroup.value.id)
    }
  } catch (error) {
    ElMessage.error('添加成员失败')
    console.error('添加成员失败:', error)
  }
}

const removeMember = async (member: AppGroupMember) => {
  try {
    await ElMessageBox.confirm('确定要删除此成员吗？', '确认', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await invoke('remove_app_group_member', {
      groupId: member.group_id,
      processPath: member.process_path
    })
    ElMessage.success('删除成员成功')
    if (selectedGroup.value?.id) {
      loadMembers(selectedGroup.value.id)
    }
  } catch (error) {
    // 'cancel'=点取消，'close'=ESC/点关闭按钮，均为用户主动放弃而非失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error('删除成员失败')
      console.error('删除成员失败:', error)
    }
  }
}

onMounted(() => {
  loadGroups()
})
</script>

<style scoped>
.app-groups {
  padding: 0;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.header h1 {
  margin: 0;
  color: #1f1f1f;
}

.groups-card,
.members-card {
  margin-bottom: 16px;
}

.loading-text,
.empty-text {
  text-align: center;
  padding: 32px 20px;
  color: #605e5c;
  font-size: 13px;
}

.card-header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

/* 紧凑单行条目：一行 = 名称 + 成员数徽标 +（悬停显示的）启停/删除 */
.group-item {
  display: flex;
  align-items: center;
  height: 40px;
  padding: 0 10px;
  border-radius: 4px;
  /* 左侧固定 3px 透明占位，选中态只换色不换宽，避免内容跳动 */
  border-left: 3px solid transparent;
  cursor: pointer;
  transition: background-color 0.1s, border-color 0.1s;
}

.group-item:hover {
  background-color: #f3f3f3;
}

.group-item.active {
  background-color: #f0f7fd;
  border-left-color: #0078d4;
}

/* 预定义角标：小圆点，不单独占行 */
.predefined-dot {
  flex-shrink: 0;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: #d97706;
  margin-right: 8px;
}

.group-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
  color: #1f1f1f;
}

.member-badge {
  flex-shrink: 0;
  min-width: 20px;
  text-align: center;
  padding: 0 6px;
  border-radius: 10px;
  background-color: #e5e5e5;
  color: #605e5c;
  font-size: 11px;
  line-height: 18px;
}

.group-item.active .member-badge {
  background-color: #d3e8f8;
  color: #0078d4;
}

/* 启停/删除小按钮：悬停才显示，占位常驻避免行宽跳动 */
.item-actions {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  visibility: hidden;
  margin-left: 8px;
}

.group-item:hover .item-actions {
  visibility: visible;
}

.item-btn {
  padding: 0 4px;
  font-size: 12px;
}

.detail-title {
  min-width: 0;
}

.detail-name {
  font-size: 15px;
  font-weight: 600;
  color: #1f1f1f;
  display: flex;
  align-items: center;
  gap: 8px;
}

.detail-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.description {
  color: #605e5c;
  font-size: 12px;
  margin-top: 4px;
}

.font-mono {
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 12px;
}
</style>
