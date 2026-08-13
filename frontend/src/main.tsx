import React, { Suspense, lazy } from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider, theme } from 'antd'
import { BrowserRouter, useLocation } from 'react-router-dom'
import 'antd/dist/reset.css'
import './styles.css'
import './light-theme.css'
import './mission-control.css'
import './agent-mode.css'
import MissionControlApp from './MissionControlApp'

const ApiSourceEnhancer = lazy(() => import('./ApiSourceEnhancer'))
const AgentModeEnhancer = lazy(() => import('./AgentModeEnhancer'))

function AppEnhancers() {
  const location = useLocation()
  const showSourceEnhancer = location.pathname.startsWith('/sources')
  const showAgentEnhancer = location.pathname.startsWith('/assistant')

  if (!showSourceEnhancer && !showAgentEnhancer) {
    return null
  }

  return (
    <Suspense fallback={null}>
      {showSourceEnhancer && <ApiSourceEnhancer />}
      {showAgentEnhancer && <AgentModeEnhancer />}
    </Suspense>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#0f62fe',
          colorBgBase: '#ffffff',
          colorBgContainer: '#ffffff',
          colorBgElevated: '#ffffff',
          colorBorder: '#e4e9ef',
          colorText: '#253247',
          colorTextSecondary: '#7b8796',
          borderRadius: 8,
        },
      }}
    >
      <BrowserRouter>
        <MissionControlApp />
        <AppEnhancers />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
)
