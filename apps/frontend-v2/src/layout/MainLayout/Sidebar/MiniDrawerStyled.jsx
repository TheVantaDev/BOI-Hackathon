// material-ui
import { styled } from '@mui/material/styles';
import Drawer from '@mui/material/Drawer';

// project imports
import { drawerWidth } from 'store/constant';

const TRANSITION_MS = 300;
const DRAWER_SHADOW = '0 2px 14px 0 rgba(32, 40, 45, 0.08)';

function openedMixin(theme) {
  return {
    width: drawerWidth,
    borderRight: '1px solid',
    borderColor: theme.vars.palette.divider,
    zIndex: 1099,
    background: theme.vars.palette.background.paper,
    overflowX: 'hidden',
    height: '100%',
    boxShadow: DRAWER_SHADOW,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.easeInOut,
      duration: TRANSITION_MS
    })
  };
}

function closedMixin(theme) {
  return {
    borderRight: '1px solid',
    borderColor: theme.vars.palette.divider,
    zIndex: 1099,
    background: theme.vars.palette.background.paper,
    overflowX: 'hidden',
    width: 72,
    boxShadow: DRAWER_SHADOW,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.easeInOut,
      duration: TRANSITION_MS
    })
  };
}

// ==============================|| DRAWER - MINI STYLED ||============================== //

const MiniDrawerStyled = styled(Drawer, { shouldForwardProp: (prop) => prop !== 'open' })(({ theme, open }) => ({
  width: open ? drawerWidth : 72,
  borderRight: '0px',
  flexShrink: 0,
  whiteSpace: 'nowrap',
  boxSizing: 'border-box',
  transition: theme.transitions.create('width', {
    easing: theme.transitions.easing.easeInOut,
    duration: TRANSITION_MS
  }),
  ...(open && {
    ...openedMixin(theme),
    '& .MuiDrawer-paper': openedMixin(theme)
  }),
  ...(!open && {
    ...closedMixin(theme),
    '& .MuiDrawer-paper': closedMixin(theme)
  })
}));

export default MiniDrawerStyled;
