import { createBrowserRouter } from 'react-router-dom';

import MainRoutes from './MainRoutes';

// Auth / demo Berry routes removed — classic BOI has none

const router = createBrowserRouter([MainRoutes], {
  basename: import.meta.env.VITE_APP_BASE_NAME
});

export default router;
