import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './ui/App.tsx';
import './ui/styles.css';

const container = document.getElementById('root');
if (!container) throw new Error('BugPack root element is missing.');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
