import Logo from 'ui-component/Logo';

// Classic sidebar logo is not a link — display only

export default function LogoSection() {
  return (
    <span aria-label="boi-sentinel-logo">
      <Logo />
    </span>
  );
}
