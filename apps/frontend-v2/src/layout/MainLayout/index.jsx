import { useEffect } from 'react';
import { Outlet } from 'react-router-dom';

import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';

import { IconMenu2 } from '@tabler/icons-react';

import Sidebar from './Sidebar';
import MainContentStyled from './MainContentStyled';
import Loader from 'ui-component/Loader';

import useConfig from 'hooks/useConfig';
import { handlerDrawerOpen, useGetMenuMaster } from 'api/menu';

// Slim layout: sidebar + content only (matches classic BOI structure; Berry theme kept)

export default function MainLayout() {
  const theme = useTheme();
  const downMD = useMediaQuery(theme.breakpoints.down('md'));

  const {
    state: { borderRadius, miniDrawer }
  } = useConfig();
  const { menuMaster, menuMasterLoading } = useGetMenuMaster();
  const drawerOpen = menuMaster?.isDashboardDrawerOpened;

  useEffect(() => {
    // Always show full sidebar like classic (no mini-drawer chrome)
    handlerDrawerOpen(true);
  }, [miniDrawer]);

  useEffect(() => {
    if (downMD) handlerDrawerOpen(false);
    else handlerDrawerOpen(true);
  }, [downMD]);

  if (menuMasterLoading) return <Loader />;

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      {downMD && !drawerOpen && (
        <Avatar
          variant="rounded"
          sx={{
            position: 'fixed',
            top: 12,
            left: 12,
            zIndex: 1200,
            ...theme.typography.commonAvatar,
            ...theme.typography.mediumAvatar,
            color: theme.vars.palette.secondary.dark,
            background: theme.vars.palette.secondary.light
          }}
          onClick={() => handlerDrawerOpen(true)}
        >
          <IconMenu2 stroke={1.5} size="20px" />
        </Avatar>
      )}

      <Sidebar />

      <MainContentStyled {...{ borderRadius, open: drawerOpen }}>
        <Box sx={{ minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
          <Outlet />
        </Box>
      </MainContentStyled>
    </Box>
  );
}
