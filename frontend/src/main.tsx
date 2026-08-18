import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider, theme } from 'antd'
import { BrowserRouter } from 'react-router-dom'
import 'antd/dist/reset.css'
import './styles.css'
import './light-theme.css'
import './anomaly-visuals.css'
import App from './App'
import AnomalyTimelineEnhancer from './AnomalyTimelineEnhancer'
import AssetPieEnhancer from './AssetPieEnhancer'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#2d84e5',
          colorBgBase: '#ffffff',
          colorBgContainer: '#ffffff',
          colorBgElevated: '#ffffff',
          colorBorder: '#e4e9ef',
          colorText: '#253247',
          colorTextSecondary: '#7b8796',
          borderRadius: 9,
        },
      }}
    >
      <BrowserRouter>
        <App />
        <AssetPieEnhancer />
        <AnomalyTimelineEnhancer />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
)
