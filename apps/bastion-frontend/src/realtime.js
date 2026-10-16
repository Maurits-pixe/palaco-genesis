import { io } from 'socket.io-client'
import { normalizeCommand } from './api.js'

export function createRealtime({ onEntry, onStatus, onReset, createSocket = (options) => io(options) }) {
  let current = null

  function disconnect(status = 'disconnected') {
    const socket = current
    current = null
    if (socket) {
      socket.removeAllListeners()
      socket.auth = {}
      if (socket.io?.opts) socket.io.opts.auth = {}
      socket.disconnect()
    }
    onReset()
    onStatus(status)
  }

  function connect(token) {
    disconnect()
    if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
      onStatus('error')
      return
    }
    onStatus('connecting')
    try {
      const socket = createSocket({
        path: '/socket.io',
        auth: { token },
        autoConnect: false,
        reconnection: false,
        withCredentials: false,
      })
      current = socket
      socket.on('connect', () => {
        if (current === socket) onStatus('connected')
      })
      socket.on('command:committed', (payload) => {
        if (current !== socket) return
        const entry = normalizeCommand(payload)
        if (entry) onEntry(entry)
      })
      socket.on('disconnect', () => {
        if (current === socket) disconnect()
      })
      socket.on('connect_error', () => {
        if (current === socket) disconnect('error')
      })
      socket.connect()
    } catch {
      disconnect('error')
    }
  }

  return { connect, disconnect }
}
