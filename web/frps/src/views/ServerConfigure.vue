<template>
  <div class="config-page">
    <h1>Configuration</h1>
    <p v-if="loaded">{{ encrypted ? 'Encrypted on disk (AES-256-GCM).' : 'Plaintext mode.' }} Changes take effect after restarting frps.</p>
    <p v-else>Loading configuration…</p>
    <label for="server-config">Server configuration (original YAML, TOML or JSON fields)</label>
    <textarea id="server-config" v-model="content" :disabled="!loaded || saving" spellcheck="false" autocomplete="off" autocapitalize="off" />
    <div class="actions">
      <el-button :disabled="!loaded || saving" @click="load">Reload file</el-button>
      <el-button type="primary" :disabled="!loaded || !content.trim()" :loading="saving" @click="save">Save configuration</el-button>
    </div>
    <p role="status">{{ message }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const content = ref('')
const revision = ref('')
const encrypted = ref(false)
const loaded = ref(false)
const saving = ref(false)
const message = ref('')

async function load() {
  try {
    const res = await fetch('../api/config', { credentials: 'include', cache: 'no-store' })
    if (!res.ok) throw new Error('Cannot load configuration. Start frps with a config file and dashboard credentials.')
    const doc = await res.json()
    content.value = doc.content
    revision.value = doc.revision
    encrypted.value = doc.encrypted
    loaded.value = true
    message.value = ''
  } catch (err) {
    message.value = err instanceof Error ? err.message : 'Cannot load configuration'
  }
}

async function save() {
  saving.value = true
  try {
    const res = await fetch('../api/config', {
      method: 'PUT', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-FRP-Config': '1' },
      body: JSON.stringify({ content: content.value, revision: revision.value }),
    })
    if (!res.ok) throw new Error(await res.text())
    const result = await res.json()
    revision.value = result.revision
    message.value = 'Saved. Restart frps to apply this configuration.'
  } catch (err) {
    message.value = err instanceof Error ? err.message : 'Save failed'
  } finally {
    saving.value = false
  }
}

load()
</script>

<style scoped>
.config-page { display: flex; flex-direction: column; gap: 16px; max-width: 1000px; height: 100%; margin: auto; padding: 24px; box-sizing: border-box; }
h1, p { margin: 0; }
textarea { flex: 1; min-height: 240px; width: 100%; box-sizing: border-box; resize: vertical; padding: 16px; font: 14px/1.6 ui-monospace, monospace; color: var(--text-primary); background: var(--content-bg); border: 1px solid var(--header-border); border-radius: 8px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
@media (max-width: 768px) { .config-page { padding: 16px; } textarea { font-size: 16px; } }
</style>
