const $ = (id) => document.getElementById(id)
const params = new URLSearchParams(location.hash.slice(1))
if (params.has('token')) {
  sessionStorage.setItem('kaboo-token', params.get('token'))
  history.replaceState(null, '', location.pathname)
}
const token = sessionStorage.getItem('kaboo-token') || ''
let state

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    cache: 'no-store',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) throw new Error(await response.text())
  return response.json()
}

async function load(first = false) {
  state = await api('/api/status')
  document.title = state.role === 'server' ? 'kaboo-server' : 'kaboo-cli'
  $('title').textContent = document.title
  $('status').textContent = state.status
  $('server-fields').hidden = state.role !== 'server'
  $('client-fields').hidden = state.role !== 'client'
  $('provision-fields').hidden = state.configured
  $('setup-title').textContent = state.configured ? '连接设置' : '首次初始化'
  $('ip-label').textContent = state.role === 'server' ? '隧道与 SS 的监听 IP' : '服务端 IP 或域名'
  $('sharing').hidden = !state.configured
  $('build').textContent = `版本 ${state.version} · 提交 ${state.commit}`
  $('trust').textContent = `内置证书 ${state.trust}`
  $('endpoint-path').textContent = `地址文件：${state.endpointPath}`
  if (first) {
    $('ip').value = state.endpoint.ip
    $('port').value = state.endpoint.port
    $('ss-port').value = state.ssPort
  }
}

$('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  $('save').disabled = true
  $('message').textContent = '正在验证并加密保存…'
  try {
    const file = $('provision').files[0]
    if (file && file.size > 1024 * 1024) throw new Error('部署包过大')
    await api('/api/setup', {
      ip: $('ip').value.trim(), port: Number($('port').value), ssPort: Number($('ss-port').value),
      provision: file ? await file.text() : '', activation: $('activation').value.trim(), pairing: $('pairing-input').value.trim(),
    })
    $('activation').value = ''
    $('pairing-input').value = ''
    $('provision').value = ''
    $('sharing-values').hidden = true
    $('message').textContent = '已加密保存，正在启动连接。'
    await load(true)
  } catch (error) {
    $('message').textContent = error.message || '保存失败'
  } finally {
    $('save').disabled = false
  }
})

$('show-sharing').addEventListener('click', async () => {
  try {
    const data = await api('/api/pairing', {})
    $('pairing-output-label').hidden = state.role !== 'server'
    $('pairing-output').value = data.pairing
    $('ss-url').value = data.ssURL
    $('sharing-values').hidden = false
  } catch (error) { $('message').textContent = error.message }
})

load(true).catch((error) => { $('status').textContent = error.message })
setInterval(() => { load().catch(() => { $('status').textContent = '本机管理服务已断开' }) }, 3000)
