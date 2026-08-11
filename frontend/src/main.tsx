import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider, theme } from 'antd'
import { BrowserRouter } from 'react-router-dom'
import 'antd/dist/reset.css'
import './styles.css'
import './light-theme.css'
import './mission-control.css'
import './agent-mode.css'
import MissionControlApp from './MissionControlApp'
import ApiSourceEnhancer from './ApiSourceEnhancer'
import AgentModeEnhancer from './AgentModeEnhancer'

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
        <ApiSourceEnhancer />
        <AgentModeEnhancer />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
)
