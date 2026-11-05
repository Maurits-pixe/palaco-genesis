import { io } from 'socket.io-client'
import { normalizeCommand } from './api.js'

export function createRealtime({ onEntry, onStatus, onReset, createSocket = (options) => io(options) }) {
  let current = null
  let generation = 0

  function cleanup(socket) {
    if (socket) {
      socket.removeAllListeners()
      socket.auth = {}
      if (socket.io?.opts) socket.io.opts.auth = {}
      socket.disconnect()
    }
  }

  function disconnect(status = 'disconnected') {
    const owner = ++generation
    const socket = current
    current = null
    cleanup(socket)
    if (generation !== owner) return
    onReset()
    if (generation !== owner) return
    onStatus(status)
  }

  function connect(token) {
    const owner = generation + 1
    disconnect()
    if (generation !== owner) return
    if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
      onStatus('error')
      return
    }
    onStatus('connecting')
    if (generation !== owner) return
    try {
      const socket = createSocket({
        path: '/socket.io',
        auth: { token },
        autoConnect: false,
        reconnection: false,
        withCredentials: false,
      })
      if (generation !== owner) {
        cleanup(socket)
        return
      }
      current = socket
      socket.on('connect', () => {
        if (generation === owner && current === socket) onStatus('connected')
      })
      socket.on('command:committed', (payload) => {
        if (generation !== owner || current !== socket) return
        const entry = normalizeCommand(payload)
        if (entry) onEntry(entry)
      })
      socket.on('disconnect', () => {
        if (generation === owner && current === socket) disconnect()
      })
      socket.on('connect_error', () => {
        if (generation === owner && current === socket) disconnect('error')
      })
      socket.connect()
    } catch {
      if (generation === owner) disconnect('error')
    }
  }

  return { connect, disconnect }
}
