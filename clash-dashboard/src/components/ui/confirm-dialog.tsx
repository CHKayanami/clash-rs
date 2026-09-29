import * as React from 'react';
import { useEffect } from 'react';
import { AlertTriangle, Trash2, X, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description?: React.ReactNode;
  children?: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  variant?: 'destructive' | 'default';
  icon?: 'trash' | 'warning' | 'none';
  isLoading?: boolean;
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  children,
  confirmText = '确定',
  cancelText = '取消',
  variant = 'destructive',
  icon = 'none',
  isLoading = false,
}: ConfirmDialogProps) {
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isLoading) {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = originalOverflow;
    };
  }, [open, isLoading, onClose]);

  if (!open) return null;

  const isDestructive = variant === 'destructive';

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/45 backdrop-blur-md transition-opacity duration-200"
        onClick={() => !isLoading && onClose()}
      />

      {/* Dialog Card */}
      <div
        className={cn(
          'relative w-full max-w-md rounded-2xl p-6 shadow-2xl border transition-all z-10',
          'transform animate-in fade-in zoom-in-95 duration-200'
        )}
        style={{
          background: 'var(--color-surface-float)',
          borderColor: 'var(--color-border)',
          boxShadow: '0 24px 64px -12px rgba(0, 0, 0, 0.35), 0 0 0 1px var(--color-separator-subtle)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          disabled={isLoading}
          className="absolute top-4 right-4 p-1.5 rounded-full text-[#8e8e93] hover:text-[#1d1d1f] hover:bg-black/5 dark:hover:bg-white/10 transition-colors disabled:opacity-40 cursor-pointer"
          aria-label="关闭"
        >
          <X size={18} />
        </button>

        <div className={cn(
          icon !== 'none'
            ? 'flex flex-col items-center text-center sm:items-start sm:text-left gap-4'
            : 'space-y-1.5'
        )}>
          {/* Icon Badge */}
          {icon !== 'none' && (
            <div
              className={cn(
                'w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 transition-transform shadow-sm',
                isDestructive
                  ? 'bg-red-500/10 text-[#ff3b30] ring-4 ring-red-500/10'
                  : 'bg-[#0071e3]/10 text-[#0071e3] ring-4 ring-[#0071e3]/10'
              )}
            >
              {icon === 'trash' ? (
                <Trash2 size={24} className="stroke-[2.2]" />
              ) : (
                <AlertTriangle size={24} className="stroke-[2.2]" />
              )}
            </div>
          )}

          {/* Header Texts */}
          <div className="space-y-1.5 w-full pr-6">
            <h3
              className="text-[17px] font-semibold tracking-tight"
              style={{ color: 'var(--color-text-primary)' }}
            >
              {title}
            </h3>
            {description && (
              <div
                className="text-[13px] leading-relaxed"
                style={{ color: 'var(--color-text-secondary)' }}
              >
                {description}
              </div>
            )}
          </div>
        </div>

        {/* Custom Content Slot */}
        {children && <div className="mt-4">{children}</div>}

        {/* Action Buttons */}
        <div className="mt-6 flex flex-col-reverse sm:flex-row items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className="w-full sm:w-auto px-4 py-2 text-[14px] font-medium rounded-xl border transition-all cursor-pointer disabled:opacity-50"
            style={{
              background: 'var(--color-fill-subtle)',
              borderColor: 'var(--color-border)',
              color: 'var(--color-text-primary)',
            }}
          >
            {cancelText}
          </button>

          <button
            type="button"
            onClick={onConfirm}
            disabled={isLoading}
            className={cn(
              'w-full sm:w-auto px-4 py-2 text-[14px] font-medium rounded-xl text-white shadow-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 active:scale-[0.98]',
              isDestructive
                ? 'bg-[#ff3b30] hover:bg-[#ff453a] hover:shadow-red-500/20 hover:shadow-md'
                : 'bg-[#0071e3] hover:bg-[#0077ed] hover:shadow-blue-500/20 hover:shadow-md'
            )}
          >
            {isLoading && <Loader2 size={16} className="animate-spin" />}
            <span>{isLoading ? '正在处理…' : confirmText}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
