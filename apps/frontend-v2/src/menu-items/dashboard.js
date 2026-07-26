import { IconDashboard, IconHistory, IconUpload } from '@tabler/icons-react';

const icons = { IconDashboard, IconUpload, IconHistory };

const dashboard = {
  id: 'boi-main',
  title: 'NAVIGATION',
  type: 'group',
  children: [
    {
      id: 'dashboard',
      title: 'Dashboard',
      type: 'item',
      url: '/',
      icon: icons.IconDashboard,
      breadcrumbs: false
    },
    {
      id: 'upload',
      title: 'Upload APK',
      type: 'item',
      url: '/upload',
      icon: icons.IconUpload,
      breadcrumbs: false
    },
    {
      id: 'history',
      title: 'History',
      type: 'item',
      url: '/history',
      icon: icons.IconHistory,
      breadcrumbs: false
    }
  ]
};

export default dashboard;
