import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckIcon, AlertIcon, TerminalIcon } from './Icons'

export default function ToastContainer({ toasts }) {
  return (
    <div className="toasts-container" aria-live="polite">
      <AnimatePresence>
        {toasts.map(toast => {
          let IconComp = CheckIcon
          let typeClass = 'toast-info'
          if (toast.type === 'error' || toast.type === 'bad') {
            IconComp = AlertIcon
            typeClass = 'toast-error'
          } else if (toast.type === 'success') {
            IconComp = CheckIcon
            typeClass = 'toast-success'
          } else {
            IconComp = TerminalIcon
          }

          return (
            <motion.div
              key={toast.id}
              className={`toast-card ${typeClass}`}
              initial={{ x: 50, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 50, opacity: 0 }}
              transition={{ duration: 0.25 }}
            >
              <div className="toast-icon-wrap">
                <IconComp size={16} />
              </div>
              <div className="toast-message">{toast.message}</div>
            </motion.div>
          )
        })}
      </AnimatePresence>
    </div>
  )
}

