/**
 * 路径比较用归一化：与服务端 models::normalize_path 同口径（小写 + 分隔符
 * 统一为反斜杠）。仅用于前端比较（规则徽标、路径去重等），不得把归一化
 * 结果写回数据库或下发给服务端——显示与存储始终用原始路径。
 */
export const normalizePathForCompare = (path?: string | null): string => {
  if (!path) return ''
  return path.toLowerCase().replace(/\//g, '\\')
}
