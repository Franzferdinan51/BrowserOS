import React from 'react'
import { useSettingsStore } from '@/sidepanel/v2/stores/settingsStore'

/**
 * ModeToggle - Toggle between Chat Mode (Q&A) and Browse Mode (automation)
 * Inspired by the Write/Chat toggle design
 */
export function ModeToggle() {
  const { chatMode, setChatMode } = useSettingsStore()

  return (
    <div className='flex items-center'>
      {/* Use design tokens via CSS variables to auto-adapt across light, gray and dark */}
      <div className='inline-flex h-[25px] items-center gap-[2px] rounded-2xl border border-border bg-[hsl(var(--secondary))] p-[2px]'>
        <button
          className={`h-[21px] px-3 rounded-xl text-[12px] font-semibold transition-colors ${!chatMode ? 'bg-[hsl(var(--background-alt))] text-foreground border border-border' : 'text-muted-foreground hover:bg-[hsl(var(--accent))]'}`}
          onClick={() => setChatMode(false)}
          aria-label='Browse mode for automation'
          title='Browse mode - For complex automation tasks'
        >
          Browse Mode
        </button>
        <button
          className={`h-[21px] px-3 rounded-xl text-[12px] font-semibold transition-colors ${chatMode ? 'bg-[hsl(var(--background-alt))] text-foreground border border-border' : 'text-muted-foreground hover:bg-[hsl(var(--accent))]'}`}
          onClick={() => setChatMode(true)}
          aria-label='Chat mode for Q&A'
          title='Chat mode - Quick Q&A about pages'
        >
          Chat Mode
        </button>
      </div>
    </div>
  )
}