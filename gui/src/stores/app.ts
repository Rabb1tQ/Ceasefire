import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const isConnected = ref(false)
  const isLoading = ref(false)
  const errorMessage = ref<string | null>(null)

  function setConnected(connected: boolean) {
    isConnected.value = connected
  }

  function setLoading(loading: boolean) {
    isLoading.value = loading
  }

  function setError(message: string | null) {
    errorMessage.value = message
  }

  function clearError() {
    errorMessage.value = null
  }

  return {
    isConnected,
    isLoading,
    errorMessage,
    setConnected,
    setLoading,
    setError,
    clearError
  }
})
