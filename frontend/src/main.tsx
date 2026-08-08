import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider, theme } from 'antd'
import { BrowserRouter } from 'react-router-dom'
import 'antd/dist/reset.css'
import './styles.css'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#4da3ff',
          colorBgBase: '#071019',
          colorBgContainer: '#0d1824',
          colorBgElevated: '#101d2a',
          colorBorder: '#1d3044',
          borderRadius: 9,
        },
      }}
    >
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
)
