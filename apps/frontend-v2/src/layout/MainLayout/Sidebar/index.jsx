import { memo } from 'react';

import useMediaQuery from '@mui/material/useMediaQuery';
import Drawer from '@mui/material/Drawer';
import Stack from '@mui/material/Stack';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';

import { IconActivity } from '@tabler/icons-react';

import MenuList from '../MenuList';
import LogoSection from '../LogoSection';
import MiniDrawerStyled from './MiniDrawerStyled';

import { drawerWidth } from 'store/constant';

import { handlerDrawerOpen, useGetMenuMaster } from 'api/menu';

// Classic layout: logo | scrollable nav (flex:1) | AI Engine footer pinned bottom

function AiEngineFooter() {
  return (
    <Stack
      direction="row"
      alignItems="center"
      spacing={1}
      sx={{
        px: 2.5,
        py: 2,
        flexShrink: 0,
        borderTop: '1px solid',
        borderColor: 'divider'
      }}
    >
      <Box
        sx={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          bgcolor: 'success.main',
          flexShrink: 0
        }}
      />
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="caption" sx={{ display: 'block', fontWeight: 500, lineHeight: 1.2, color: 'text.primary', fontSize: 11 }}>
          AI Engine
        </Typography>
        <Typography variant="caption" color="success.main" sx={{ fontSize: 10 }}>
          Online
        </Typography>
      </Box>
      <IconActivity size={14} style={{ opacity: 0.45, marginLeft: 'auto' }} />
    </Stack>
  );
}

function Sidebar() {
  const downMD = useMediaQuery((theme) => theme.breakpoints.down('md'));

  const { menuMaster } = useGetMenuMaster();
  const drawerOpen = menuMaster.isDashboardDrawerOpened;

  const paperColumn = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden'
  };

  const inner = (
    <>
      <Box sx={{ display: 'flex', p: 2, flexShrink: 0, borderBottom: '1px solid', borderColor: 'divider' }}>
        <LogoSection />
      </Box>

      <Box
        sx={{
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          px: drawerOpen ? 1.5 : 1,
          pt: 2,
          pb: 1
        }}
      >
        <MenuList />
      </Box>

      {drawerOpen && <AiEngineFooter />}
    </>
  );

  return (
    <Box component="nav" sx={{ flexShrink: { md: 0 }, width: { xs: 'auto', md: drawerWidth } }} aria-label="navigation">
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
