import React, { useState, useRef, useEffect } from 'react'
import { Textarea } from '@/sidepanel/components/ui/textarea'
import { Button } from '@/sidepanel/components/ui/button'
import { SelectTabsButton } from './SelectTabsButton'
import { useChatStore } from '../stores/chatStore'
import { useKeyboardShortcuts, useAutoResize } from '../hooks/useKeyboardShortcuts'
import { useSidePanelPortMessaging } from '@/sidepanel/hooks'
import { MessageType } from '@/lib/types/messaging'
import { cn } from '@/sidepanel/lib/utils'
import { CloseIcon, SendIcon, LoadingPawTrail } from './ui/Icons'


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
  
  const { addMessage, setProcessing, selectedTabIds, clearSelectedTabs } = useChatStore()
  const { sendMessage } = useSidePanelPortMessaging()
  
  // Auto-resize textarea
  useAutoResize(textareaRef, input)
  
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
    clearSelectedTabs()
    setShowTabSelector(false)
  }
  
  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault()
    
    // If processing and no input, act like pause button (cancel current task)
    if (isProcessing && !input.trim()) {
      handleCancel()
      return
    }

    if (isProcessing && input.trim()) {
      // Interrupt and follow-up pattern
      const followUpQuery = input.trim()
      
      // Cancel current task
      sendMessage(MessageType.CANCEL_TASK, {
        reason: 'User interrupted with new query',
        source: 'sidepanel'
      })
      
      // Keep processing state and submit follow-up after delay
      setTimeout(() => {
        submitTask(followUpQuery)
      }, 300)
    } else {
      // Normal submission
      submitTask(input)
    }
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
  
  const getPlaceholder = () => {
    if (!isConnected) return 'Disconnected'
    if (isProcessing) return 'Interrupt with new task'
    return 'Ask me anything'
  }
  
  const getHintText = () => {
    if (!isConnected) return 'Waiting for connection'
    if (isProcessing) return 'Press Enter to interrupt • Esc to cancel'
    return 'Press Enter to send • @ to select tabs'
  }

  const getLoadingIndicator = () => {
    if (!isConnected || isProcessing) {
      return <LoadingPawTrail />
    }
    return null
  }
  
  return (
    <div className="relative bg-gradient-to-t from-background via-background to-background/95 p-2 flex-shrink-0 overflow-hidden">
      
      
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
        
        {showTabSelector && (
          <div className="px-4 mb-2">
            <SelectTabsButton />
          </div>
        )}

        <form onSubmit={handleSubmit} className="w-full px-4" role="form" aria-label="Chat input form">
          <div className="relative flex items-end w-full transition-all duration-300 ease-out">
            <Textarea
              ref={textareaRef}
              value={input}
              onChange={handleInputChange}
              placeholder={getPlaceholder()}
              disabled={!isConnected}
              className={cn(
                'max-h-[200px] resize-none pr-20 text-sm w-full',
                'bg-background/80 backdrop-blur-sm border-2 border-brand/30',
                'focus:ring-2 focus:ring-brand focus:ring-offset-2 focus:border-brand',
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
              disabled={!isConnected || (!input.trim() && !isProcessing)}
              size="sm"
              className="absolute right-2 bottom-2 h-10 px-4 rounded-xl bg-gradient-to-r from-brand to-brand/80 hover:from-brand/90 hover:to-brand/70 text-white font-medium shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 focus:ring-2 focus:ring-brand focus:ring-offset-2"
              variant={isProcessing && !input.trim() ? 'destructive' : 'default'}
              aria-label={isProcessing && !input.trim() ? 'Cancel current task' : 'Send message'}
            >
              {isProcessing && !input.trim() ? (
                <CloseIcon />
              ) : (
                <SendIcon />
              )}
            </Button>
          </div>
        </form>
        
        <div 
          id="input-hint" 
          className="mt-2 sm:mt-3 text-center text-xs text-muted-foreground font-medium flex items-center justify-center gap-2 px-2"
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