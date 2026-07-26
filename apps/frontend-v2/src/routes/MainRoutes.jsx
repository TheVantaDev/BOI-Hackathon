import { lazy } from 'react';
import { Navigate } from 'react-router-dom';

import MainLayout from 'layout/MainLayout';
import Loadable from 'ui-component/Loadable';

const BoiDashboard = Loadable(lazy(() => import('views/boi/Dashboard')));
const BoiUpload = Loadable(lazy(() => import('views/boi/Upload')));
const BoiHistory = Loadable(lazy(() => import('views/boi/History')));
const BoiAnalysis = Loadable(lazy(() => import('views/boi/Analysis')));

const MainRoutes = {
  path: '/',
  element: <MainLayout />,
  children: [
    { path: '/', element: <BoiDashboard /> },
    { path: 'upload', element: <BoiUpload /> },
    { path: 'history', element: <BoiHistory /> },
    { path: 'analysis/:id', element: <BoiAnalysis /> },
    { path: '*', element: <Navigate to="/" replace /> }
  ]
};

export default MainRoutes;
