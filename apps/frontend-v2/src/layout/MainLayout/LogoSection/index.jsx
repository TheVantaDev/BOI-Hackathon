import Logo from 'ui-component/Logo';
import { useGetMenuMaster } from 'api/menu';

// Classic sidebar logo is not a link — display only

export default function LogoSection() {
  const { menuMaster } = useGetMenuMaster();
  const drawerOpen = menuMaster?.isDashboardDrawerOpened;

  return (
    <span aria-label="boi-sentinel-logo">
      <Logo compact={!drawerOpen} />
    </span>
  );
}
