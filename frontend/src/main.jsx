import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { DashboardProvider } from './context/DashboardContext.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <DashboardProvider>
    <App />
  </DashboardProvider>
)