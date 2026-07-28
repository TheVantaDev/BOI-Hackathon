import PropTypes from 'prop-types';

// material-ui
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CardHeader from '@mui/material/CardHeader';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';

// Soft SaaS elevation (Linear / Vercel-ish): rest + hover, no hard border by default
export const CARD_SHADOW_REST = '0 1px 2px rgba(16, 24, 40, 0.04), 0 4px 16px rgba(16, 24, 40, 0.06)';
export const CARD_SHADOW_HOVER = '0 4px 8px rgba(16, 24, 40, 0.04), 0 12px 28px rgba(16, 24, 40, 0.1)';

const headerStyle = {
  '& .MuiCardHeader-action': { mr: 0 }
};

export default function MainCard({
  border = false,
  boxShadow = true,
  children,
  content = true,
  contentClass = '',
  contentSX = {},
  headerSX = {},
  darkTitle,
  secondary,
  shadow,
  sx = {},
  title,
  ref,
  hoverLift = false,
  ...others
}) {
  const restShadow = shadow || CARD_SHADOW_REST;
  const hoverShadow = CARD_SHADOW_HOVER;

  return (
    <Card
      ref={ref}
      {...others}
      sx={(theme) => ({
        border: border ? '1px solid' : 'none',
        borderColor: 'divider',
        boxShadow: boxShadow ? restShadow : 'none',
        transition: theme.transitions.create(['box-shadow', 'transform'], {
          duration: 200,
          easing: theme.transitions.easing.easeInOut
        }),
        ...(boxShadow && {
          '&:hover': {
            boxShadow: hoverShadow,
            ...(hoverLift ? { transform: 'translateY(-3px)' } : {})
          }
        }),
        ...(typeof sx === 'function' ? sx(theme) : sx || {})
      })}
    >
      {!darkTitle && title && <CardHeader sx={{ ...headerStyle, ...headerSX }} title={title} action={secondary} />}
      {darkTitle && title && (
        <CardHeader sx={{ ...headerStyle, ...headerSX }} title={<Typography variant="h3">{title}</Typography>} action={secondary} />
      )}

      {title && <Divider />}

      {content && (
        <CardContent sx={contentSX} className={contentClass}>
          {children}
        </CardContent>
      )}
      {!content && children}
    </Card>
  );
}

MainCard.propTypes = {
  border: PropTypes.bool,
  boxShadow: PropTypes.bool,
  hoverLift: PropTypes.bool,
  children: PropTypes.oneOfType([PropTypes.string, PropTypes.node]),
  content: PropTypes.bool,
  contentClass: PropTypes.string,
  contentSX: PropTypes.object,
  headerSX: PropTypes.object,
  darkTitle: PropTypes.bool,
  secondary: PropTypes.any,
  shadow: PropTypes.string,
  sx: PropTypes.object,
  title: PropTypes.oneOfType([PropTypes.string, PropTypes.node]),
  ref: PropTypes.object,
  others: PropTypes.any
};
