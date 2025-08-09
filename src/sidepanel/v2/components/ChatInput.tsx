import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react'
import { Textarea } from '@/sidepanel/components/ui/textarea'
import { Button } from '@/sidepanel/components/ui/button'
import { LazyTabSelector } from './LazyTabSelector'
import { useTabsStore, BrowserTab } from '@/sidepanel/store/tabsStore'
import { useChatStore } from '../stores/chatStore'
import { useKeyboardShortcuts, useAutoResize } from '../hooks/useKeyboardShortcuts'
import { useSidePanelPortMessaging } from '@/sidepanel/hooks'
import { MessageType } from '@/lib/types/messaging'
import { cn } from '@/sidepanel/lib/utils'
import { SendIcon, LoadingPawTrail } from './ui/Icons'


interface ChatInputProps {
  isConnected: boolean
  isProcessing: boolean
  onToggleSelectTabs: () => void
  showSelectTabsButton: boolean
}

/**
 * Chat input component with auto-resize, tab selection, and keyboard shortcuts
 */
export function ChatInput({ isConnected, isProcessing }: ChatInputProps) {
  const [input, setInput] = useState('')
  const [showTabSelector, setShowTabSelector] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  
  const { addMessage, setProcessing, selectedTabIds, clearSelectedTabs, messages } = useChatStore()
  const { sendMessage, addMessageListener, removeMessageListener, connected: portConnected } = useSidePanelPortMessaging()
  const { getContextTabs, toggleTabSelection } = useTabsStore()
  
  // Auto-resize textarea
  useAutoResize(textareaRef, input)
  
  // history navigation state
  const [historyIndex, setHistoryIndex] = useState<number>(-1) // -1 means not browsing history
  const [draftBeforeHistory, setDraftBeforeHistory] = useState<string>('')

  const userHistory: string[] = useMemo(() => {
    // Build list of previous user messages in chronological order
    return messages.filter(m => m.role === 'user').map(m => m.content)
  }, [messages])
  
  // Focus textarea on mount and when processing stops
  useEffect(() => {
    const timer = setTimeout(() => {
      if (textareaRef.current && !isProcessing) {
        textareaRef.current.focus()
      }
    }, 100)
    
    return () => clearTimeout(timer)
  }, [isProcessing])
  
  // Listen for example prompt clicks
  useEffect(() => {
    const handleSetInput = (e: CustomEvent) => {
      setInput(e.detail)
      textareaRef.current?.focus()
    }
    
    window.addEventListener('setInputValue', handleSetInput as EventListener)
    return () => {
      window.removeEventListener('setInputValue', handleSetInput as EventListener)
    }
  }, [])
  

  
  const submitTask = (query: string) => {
    if (!query.trim()) return
    
    if (!isConnected) {
      // Show error message in chat
      addMessage({
        role: 'system',
        content: 'Cannot send message: Extension is disconnected',
        metadata: { error: true }
      })
      return
    }
    
    // Add user message
    addMessage({
      role: 'user',
      content: query
    })
    
    // Get selected tab IDs from store
    const tabIds = selectedTabIds.length > 0 ? selectedTabIds : undefined
    
    // Send to background
    setProcessing(true)
    sendMessage(MessageType.EXECUTE_QUERY, {
      query: query.trim(),
      tabIds,
      source: 'sidepanel'
    })
    
    // Clear input and selected tabs
    setInput('')
    setHistoryIndex(-1)
    setDraftBeforeHistory('')
    clearSelectedTabs()
    setShowTabSelector(false)
  }
  
  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault()
    // Block submissions while processing
    if (isProcessing) return
    if (!input.trim()) return
    submitTask(input)
  }
  
  const handleCancel = () => {
    sendMessage(MessageType.CANCEL_TASK, {
      reason: 'User requested cancellation',
      source: 'sidepanel'
    })
    // Do not change local processing state here; wait for background WORKFLOW_STATUS
  }
  
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value
    setInput(newValue)
    // If user types while browsing history, remain in current position
    // Only show selector when user just typed '@' starting a new token
    const lastChar: string = newValue.slice(-1)
    if (lastChar === '@' && !showTabSelector) {
      const beforeAt: string = newValue.slice(0, -1)
      if (beforeAt === '' || /\s$/.test(beforeAt)) {
        setShowTabSelector(true)
      }
      return
    }
    // Hide selector when input cleared
    if (newValue === '' && showTabSelector) {
      setShowTabSelector(false)
    }
  }
  
  const handleTabSelectorClose = () => {
    setShowTabSelector(false)
    textareaRef.current?.focus()
  }

  const handleTabSelected = (tabId: number) => {
    // Remove trailing '@' that triggered the selector
    setInput(prev => prev.replace(/@$/, ''))
  }

  const handleRemoveSelectedTab = (tabId: number): void => {
    toggleTabSelection(tabId)
  }

  const selectedContextTabs: BrowserTab[] = getContextTabs()
  
  // Keyboard shortcuts
  useKeyboardShortcuts(
    {
      onSubmit: handleSubmit,
      onCancel: isProcessing ? handleCancel : undefined,
      onTabSelectorClose: handleTabSelectorClose
    },
    {
      isProcessing,
      showTabSelector
    }
  )
  
  // Move caret to end after programmatic updates
  const moveCaretToEnd = useCallback(() => {
    const ta = textareaRef.current
    if (!ta) return
    const len: number = ta.value.length
    ta.selectionStart = len
    ta.selectionEnd = len
  }, [])

  // Handle ArrowUp/ArrowDown history navigation when caret is at boundaries
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (showTabSelector) return
    if (e.altKey || e.ctrlKey || e.metaKey) return
    const ta = textareaRef.current
    if (!ta) return
    const atStart: boolean = ta.selectionStart === 0 && ta.selectionEnd === 0
    const atEnd: boolean = ta.selectionStart === input.length && ta.selectionEnd === input.length

    if (e.key === 'ArrowUp' && !e.shiftKey) {
      if (!atStart) return
      if (userHistory.length === 0) return
      e.preventDefault()
      if (historyIndex === -1) setDraftBeforeHistory(input)
      const nextIndex: number = historyIndex === -1 ? userHistory.length - 1 : Math.max(0, historyIndex - 1)
      setHistoryIndex(nextIndex)
      setInput(userHistory[nextIndex] || '')
      requestAnimationFrame(moveCaretToEnd)
      return
    }

    if (e.key === 'ArrowDown' && !e.shiftKey) {
      if (!atEnd) return
      if (userHistory.length === 0) return
      if (historyIndex === -1) return
      e.preventDefault()
      const nextIndex: number = historyIndex + 1
      if (nextIndex >= userHistory.length) {
        setHistoryIndex(-1)
        setInput(draftBeforeHistory)
      } else {
        setHistoryIndex(nextIndex)
        setInput(userHistory[nextIndex] || '')
      }
      requestAnimationFrame(moveCaretToEnd)
    }
  }
  
  const getPlaceholder = () => {
    if (!isConnected) return 'Disconnected'
    if (isProcessing) return 'Task running…'
    return 'Ask me anything...'
  }
  
  const getHintText = () => {
    if (!isConnected) return 'Waiting for connection'
    if (isProcessing) return 'Task running… Press Esc to cancel'
    return 'Press Enter to send • @ to select tabs'
  }

  const getLoadingIndicator = () => {
    if (!isConnected || isProcessing) {
      return <LoadingPawTrail />
    }
    return null
  }
  
  return (
    <div className="relative bg-[hsl(var(--header))] border-t border-border/50 px-2 py-1 flex-shrink-0 overflow-hidden">
      
      
      {/* Select Tabs Button (appears when '@' is present) */}
      
      {/* Input container */}
      <div className="relative">
        {/* Toggle Select Tabs Button */}
        {/* <div className="flex justify-center mb-2">
          <Button
            type="button"
            onClick={onToggleSelectTabs}
            size="sm"
            variant="ghost"
            className="h-6 px-3 rounded-lg bg-muted/50 hover:bg-muted text-muted-foreground hover:text-foreground transition-all duration-200 text-xs"
            aria-label={showSelectTabsButton ? 'Hide tab selector' : 'Show tab selector'}
          >
            <TabsIcon />
            {showSelectTabsButton ? 'Hide Tabs' : 'Show Tabs'}
          </Button>
        </div> */}
        
        {/* Selected tabs chips */}
        {selectedContextTabs.length > 0 && (
          <div className="px-2 mb-1">
            <div className="flex items-center gap-2 overflow-x-auto no-scrollbar py-1">
              {selectedContextTabs.map(tab => (
                <div
                  key={tab.id}
                  className="flex items-center gap-2 pl-2 pr-1 py-1 rounded-full bg-muted text-foreground/90 border border-border shadow-sm shrink-0"
                  title={tab.title}
                >
                  <div className="w-4 h-4 rounded-sm overflow-hidden bg-muted-foreground/10 flex items-center justify-center">
                    {tab.favIconUrl ? (
                      <img src={tab.favIconUrl} alt="" className="w-full h-full object-contain" />
                    ) : (
                      <div className="w-full h-full bg-muted-foreground/20" />
                    )}
                  </div>
                  <span className="text-xs max-w-[140px] truncate">
                    {tab.title}
                  </span>
                  <button
                    type="button"
                    className="ml-1 inline-flex items-center justify-center w-4 h-4 rounded-full hover:bg-foreground/10 text-xs text-muted-foreground hover:text-foreground"
                    aria-label={`Remove ${tab.title} from selection`}
                    onClick={() => handleRemoveSelectedTab(tab.id)}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {showTabSelector && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
            <LazyTabSelector
              isOpen={showTabSelector}
              onClose={handleTabSelectorClose}
              onTabSelect={handleTabSelected}
            />
          </div>
        )}

        <form onSubmit={handleSubmit} className="w-full px-2" role="form" aria-label="Chat input form">
          <div className="relative flex items-end w-full transition-all duration-300 ease-out">
            <Textarea
              ref={textareaRef}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              placeholder={getPlaceholder()}
              disabled={!isConnected}
              className={cn(
                'max-h-[200px] resize-none pr-16 text-sm w-full',
                'bg-background/80 backdrop-blur-sm border-2 border-brand/30',
                'focus-visible:outline-none focus-visible:border-brand/60',
                'focus:outline-none focus:border-brand/60',
                'hover:border-brand/50 hover:bg-background/90',
                'rounded-2xl shadow-lg',
                'px-3 py-2',
                'transition-all duration-300 ease-out',
                !isConnected && 'opacity-50 cursor-not-allowed bg-muted'
              )}
              rows={1}
              aria-label="Chat message input"
              aria-describedby="input-hint"
              aria-invalid={!isConnected}
              aria-disabled={!isConnected}
            />
            
            <Button
              type="submit"
              disabled={!isConnected || isProcessing || !input.trim()}
              size="sm"
              className="absolute right-2 bottom-2 h-10 px-4 rounded-xl bg-gradient-to-r from-brand to-brand/80 hover:from-brand/90 hover:to-brand/70 text-white font-medium shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 focus-visible:outline-none"
              variant={'default'}
              aria-label={'Send message'}
            >
              <SendIcon />
            </Button>
          </div>
        </form>
        
        <div 
          id="input-hint" 
          className="mt-1 sm:mt-2 text-center text-xs text-muted-foreground font-medium flex items-center justify-center gap-2 px-2"
          role="status"
          aria-live="polite"
        >
          {/*getLoadingIndicator()*/}
          <span>{getHintText()}</span>
        </div>
      </div>
    </div>
  )
}