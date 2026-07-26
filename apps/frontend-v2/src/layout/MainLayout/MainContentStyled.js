// material-ui
import { styled } from '@mui/material/styles';

// project imports
import { drawerWidth } from 'store/constant';

// ==============================|| MAIN LAYOUT - STYLED (classic padding parity) ||============================== //

const MainContentStyled = styled('main', {
  shouldForwardProp: (prop) => prop !== 'open' && prop !== 'borderRadius'
})(({ theme, open, borderRadius }) => ({
  backgroundColor: theme.vars.palette.grey[100],
  minWidth: '1%',
  width: '100%',
  minHeight: '100vh',
  flexGrow: 1,
  padding: '28px 32px',
  marginTop: 0,
  marginRight: 0,
  borderRadius: `${borderRadius}px`,
  borderBottomLeftRadius: 0,
  borderBottomRightRadius: 0,
  ...(!open && {
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.shorter + 200
    }),
    [theme.breakpoints.up('md')]: {
      marginLeft: 0,
      width: `calc(100% - ${drawerWidth}px)`,
      marginTop: 0
    }
  }),
  ...(open && {
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.shorter + 200
    }),
    marginLeft: 0,
    marginTop: 0,
    width: `calc(100% - ${drawerWidth}px)`,
    [theme.breakpoints.up('md')]: {
      marginTop: 0
    }
  }),
  [theme.breakpoints.down('md')]: {
    marginLeft: 0,
    marginRight: 0,
    padding: '16px',
    marginTop: 0,
    width: '100%'
  }
}));

export default MainContentStyled;
