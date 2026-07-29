import PropTypes from 'prop-types';
import { Activity, useEffect, useRef, useState } from 'react';
import { Link, matchPath, useLocation } from 'react-router-dom';

// material-ui
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';
import Avatar from '@mui/material/Avatar';
import Chip from '@mui/material/Chip';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';

// project imports
import { handlerDrawerOpen, useGetMenuMaster } from 'api/menu';
import useConfig from 'hooks/useConfig';

// assets
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord';

export default function NavItem({ item, level, isParents = false, setSelectedID }) {
  const theme = useTheme();
  const downMD = useMediaQuery(theme.breakpoints.down('md'));
  const ref = useRef(null);

  const { pathname } = useLocation();
  const {
    state: { borderRadius }
  } = useConfig();

  const { menuMaster } = useGetMenuMaster();
  const drawerOpen = menuMaster.isDashboardDrawerOpened;
  const isSelected = !!matchPath({ path: item?.link ? item.link : item.url, end: true }, pathname);

  const [hoverStatus, setHover] = useState(false);

  const compareSize = () => {
    const compare = ref.current && ref.current.scrollWidth > ref.current.clientWidth;
    setHover(compare);
  };

  useEffect(() => {
    compareSize();
    window.addEventListener('resize', compareSize);
    return () => window.removeEventListener('resize', compareSize);
  }, []);

  const Icon = item?.icon;
  const itemIcon = item?.icon ? (
    <Icon stroke={1.5} size={drawerOpen ? '20px' : '22px'} style={{ ...(isParents && { fontSize: 20, stroke: '1.5' }) }} />
  ) : (
    <FiberManualRecordIcon sx={{ width: isSelected ? 8 : 6, height: isSelected ? 8 : 6 }} fontSize={level > 0 ? 'inherit' : 'medium'} />
  );

  let itemTarget = '_self';
  if (item.target) {
    itemTarget = '_blank';
  }

  const itemHandler = () => {
    if (downMD) handlerDrawerOpen(false);

    if (isParents && setSelectedID) {
      setSelectedID();
    }
  };

  const button = (
    <ListItemButton
      component={Link}
      to={item.url}
      target={itemTarget}
      disabled={item.disabled}
      disableRipple={!drawerOpen}
      sx={{
        zIndex: 1201,
        borderRadius: `${borderRadius}px`,
        mb: 0.5,
        position: 'relative',
        overflow: 'hidden',
        transition: theme.transitions.create(['padding', 'background-color', 'width', 'box-shadow'], {
          easing: theme.transitions.easing.easeInOut,
          duration: 250
        }),
        ...(drawerOpen && level !== 1 && { ml: `${level * 18}px` }),
        ...(drawerOpen
          ? {
              // selected: lavender wash + purple left accent (Berry secondary)
              '&.Mui-selected': {
                bgcolor: 'secondary.light',
                color: 'secondary.dark',
                boxShadow: `inset 3px 0 0 ${theme.palette.secondary.main}`,
                '&:hover': {
                  bgcolor: 'secondary.light',
                  boxShadow: `inset 3px 0 0 ${theme.palette.secondary.dark}`
                },
                '& .MuiListItemIcon-root': { color: 'secondary.dark' }
              }
            }
          : level === 1
            ? {
                justifyContent: 'center',
                alignItems: 'center',
                px: 0,
                py: 0.75,
                minHeight: 48,
                width: '100%',
                '&:hover': { bgcolor: 'transparent' },
                '&.Mui-selected': {
                  bgcolor: 'transparent',
                  '&:hover': { bgcolor: 'transparent' }
                }
              }
            : {
                py: 1,
                '&:hover': { bgcolor: 'transparent' },
                '&.Mui-selected': {
                  bgcolor: 'transparent',
                  '&:hover': { bgcolor: 'transparent' }
                }
              })
      }}
      selected={isSelected}
      onClick={() => itemHandler()}
    >
      <ListItemIcon
        sx={{
          minWidth: drawerOpen ? (level === 1 ? 36 : 18) : 0,
          color: isSelected ? 'secondary.main' : 'text.primary',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: theme.transitions.create(['min-width', 'width', 'height', 'margin'], {
            easing: theme.transitions.easing.easeInOut,
            duration: 250
          }),
          ...(!drawerOpen &&
            level === 1 && {
              width: 46,
              height: 46,
              margin: 0,
              borderRadius: `${borderRadius}px`,
              '&:hover': { bgcolor: 'secondary.light' },
              ...(isSelected && {
                bgcolor: 'secondary.light',
                color: 'secondary.dark',
                boxShadow: `0 0 0 1px ${theme.palette.secondary.main}33, 0 4px 12px ${theme.palette.secondary.main}28`,
                '&:hover': { bgcolor: 'secondary.light' }
              })
            })
        }}
      >
        {itemIcon}
      </ListItemIcon>

      <ListItemText
        primary={
          <Typography
            ref={ref}
            noWrap
            variant={isSelected ? 'h5' : 'body1'}
            sx={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              color: 'inherit'
            }}
          >
            {item.title}
          </Typography>
        }
        secondary={
          item.caption &&
          drawerOpen && (
            <Typography
              variant="caption"
              gutterBottom
              sx={{
                display: 'block',
                fontSize: '0.6875rem',
                fontWeight: 500,
                color: 'text.secondary',
                textTransform: 'capitalize',
                lineHeight: 1.66
              }}
            >
              {item.caption}
            </Typography>
          )
        }
        sx={{
          opacity: drawerOpen ? 1 : 0,
          maxWidth: drawerOpen ? 160 : 0,
          m: 0,
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          transition: theme.transitions.create(['opacity', 'max-width'], {
            easing: theme.transitions.easing.easeInOut,
            duration: 220
          }),
          ...(!drawerOpen && { display: level === 1 ? 'none' : 'block' })
        }}
      />

      <Activity mode={drawerOpen && item.chip ? 'visible' : 'hidden'}>
        <Chip
          color={item.chip?.color}
          variant={item.chip?.variant}
          size={item.chip?.size}
          label={item.chip?.label}
          avatar={
            <Activity mode={item.chip?.avatar ? 'visible' : 'hidden'}>
              <Avatar>{item.chip?.avatar}</Avatar>
            </Activity>
          }
        />
      </Activity>
    </ListItemButton>
  );

  // Tooltip on collapsed icons so labels remain discoverable
  if (!drawerOpen && level === 1) {
    return (
      <Tooltip title={item.title} placement="right" arrow>
        {button}
      </Tooltip>
    );
  }

  if (drawerOpen && hoverStatus) {
    return (
      <Tooltip title={item.title} disableHoverListener={!hoverStatus}>
        {button}
      </Tooltip>
    );
  }

  return button;
}

NavItem.propTypes = { item: PropTypes.any, level: PropTypes.number, isParents: PropTypes.bool, setSelectedID: PropTypes.func };
