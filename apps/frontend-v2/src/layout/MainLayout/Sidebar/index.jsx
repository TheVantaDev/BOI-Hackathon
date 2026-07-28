import { memo } from 'react';

import useMediaQuery from '@mui/material/useMediaQuery';
import Avatar from '@mui/material/Avatar';
import Drawer from '@mui/material/Drawer';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';

import { IconChevronLeft } from '@tabler/icons-react';

import MenuList from '../MenuList';
import LogoSection from '../LogoSection';
import MiniDrawerStyled from './MiniDrawerStyled';

import { drawerWidth } from 'store/constant';
import { handlerDrawerOpen, useGetMenuMaster } from 'api/menu';

const MINI_WIDTH = 72;
const TRANSITION_MS = 300;
const DRAWER_SHADOW = '0 2px 14px 0 rgba(32, 40, 45, 0.08)';

function Sidebar() {
  const theme = useTheme();
  const downMD = useMediaQuery((theme) => theme.breakpoints.down('md'));

  const { menuMaster } = useGetMenuMaster();
  const drawerOpen = menuMaster.isDashboardDrawerOpened;

  const paperColumn = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden',
    // soft lavender wash at top (Berry secondary.light)
    backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.secondary.light, 0.55)} 0%, ${theme.palette.background.paper} 22%)`
  };

  const collapseBtn = (
    <Avatar
      variant="rounded"
      sx={{
        ...theme.typography.commonAvatar,
        ...theme.typography.mediumAvatar,
        cursor: 'pointer',
        flexShrink: 0,
        color: 'secondary.dark',
        bgcolor: 'secondary.light',
        transition: 'all .2s ease-in-out',
        '&:hover': {
          color: 'secondary.light',
          bgcolor: 'secondary.dark'
        }
      }}
      onClick={() => handlerDrawerOpen(false)}
      aria-label="Collapse sidebar"
    >
      <IconChevronLeft stroke={1.5} size="18px" />
    </Avatar>
  );

  const inner = (
    <>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: drawerOpen ? 'space-between' : 'center',
          gap: 1,
          px: drawerOpen ? 2 : 0,
          py: 2,
          flexShrink: 0,
          borderBottom: '1px solid',
          borderColor: 'divider',
          minHeight: 72,
          transition: theme.transitions.create(['padding', 'justify-content'], {
            easing: theme.transitions.easing.easeInOut,
            duration: TRANSITION_MS
          })
        }}
      >
        <Box
          onClick={!drawerOpen ? () => handlerDrawerOpen(true) : undefined}
          sx={{ cursor: !drawerOpen ? 'pointer' : 'default', display: 'flex', justifyContent: 'center' }}
          aria-label={!drawerOpen ? 'Expand sidebar' : undefined}
          role={!drawerOpen ? 'button' : undefined}
        >
          <LogoSection />
        </Box>
        {drawerOpen && collapseBtn}
      </Box>

      <Box
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          overflowX: 'hidden',
          // collapsed: equal inset so 46px icon wells sit centered in 72px rail
          px: drawerOpen ? 1.5 : 1.625,
          pt: 2,
          pb: 1,
          transition: theme.transitions.create('padding', {
            easing: theme.transitions.easing.easeInOut,
            duration: TRANSITION_MS
          })
        }}
      >
        <MenuList />
      </Box>
    </>
  );

  return (
    <Box
      component="nav"
      sx={{
        flexShrink: { md: 0 },
        width: { xs: 'auto', md: drawerOpen ? drawerWidth : MINI_WIDTH },
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.easeInOut,
          duration: TRANSITION_MS
        })
      }}
      aria-label="navigation"
    >
      {downMD ? (
        <Drawer
          variant="temporary"
          anchor="left"
          open={drawerOpen}
          onClose={() => handlerDrawerOpen(false)}
          slotProps={{
            paper: {
              sx: {
                zIndex: 1099,
                width: drawerWidth,
                bgcolor: 'background.paper',
                color: 'text.primary',
                borderRight: '1px solid',
                borderColor: 'divider',
                boxShadow: DRAWER_SHADOW,
                ...paperColumn
              }
            }
          }}
          ModalProps={{ keepMounted: true }}
        >
          {inner}
        </Drawer>
      ) : (
        <MiniDrawerStyled variant="permanent" open={drawerOpen} PaperProps={{ sx: paperColumn }}>
          {inner}
        </MiniDrawerStyled>
      )}
    </Box>
  );
}

export default memo(Sidebar);
