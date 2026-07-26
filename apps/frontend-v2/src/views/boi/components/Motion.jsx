import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';

const ease = [0.22, 1, 0.36, 1];

/** Whole page enter */
export function PageEnter({ children, className, style }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return (
      <div className={className} style={style}>
        {children}
      </div>
    );
  }

  return (
    <motion.div
      className={className}
      style={style}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, ease }}
    >
      {children}
    </motion.div>
  );
}

/**
 * Staggered block. Works inside MUI Grid — uses delayIndex, not parent variants.
 * @param {number} delayIndex - 0, 1, 2… for cascade
 */
export function StaggerItem({ children, delayIndex = 0, className, style }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return (
      <div className={className} style={style}>
        {children}
      </div>
    );
  }

  return (
    <motion.div
      className={className}
      style={style}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: delayIndex * 0.07, ease }}
    >
      {children}
    </motion.div>
  );
}

/** @deprecated use StaggerItem with delayIndex — kept as pass-through for wrappers */
export function Stagger({ children, className, style }) {
  return (
    <div className={className} style={style}>
      {children}
    </div>
  );
}

/** Tab / panel swap */
export function TabFade({ tabKey, children }) {
  const reduce = useReducedMotion();
  if (reduce) return <div key={tabKey}>{children}</div>;

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={tabKey}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ duration: 0.25, ease }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
