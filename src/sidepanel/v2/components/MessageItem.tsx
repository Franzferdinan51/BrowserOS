import React, { memo, useEffect, useState, useMemo, useCallback } from 'react'
import { MarkdownContent } from './shared/Markdown'
import { cn } from '@/sidepanel/lib/utils'
import type { Message } from '../stores/chatStore'
import { useChatStore } from '../stores/chatStore'
//import { UserIcon } from './ui/Icons'
import { DogHeadSpinner } from './ui/DogHeadSpinner'
import { TaskManagerDropdown } from './TaskManagerDropdown'

interface MessageItemProps {
  message: Message
  shouldIndent?: boolean
  showLocalIndentLine?: boolean  // When true, renders per-item vertical line
  applyIndentMargin?: boolean  // Control whether to apply left margin for indent
}

// Helper function to detect and parse JSON content
const parseJsonContent = (content: string) => {
  try {
    let trimmedContent = content.trim()
    
    // Handle quoted JSON strings (e.g., "[{...}]" or '{"key": "value"}')
    if ((trimmedContent.startsWith('"') && trimmedContent.endsWith('"')) ||
        (trimmedContent.startsWith("'") && trimmedContent.endsWith("'"))) {
      // Remove the outer quotes and try to parse the inner JSON
      trimmedContent = trimmedContent.slice(1, -1)
      // Handle escaped quotes
      trimmedContent = trimmedContent.replace(/\\"/g, '"')
    }
    
    // Check if content looks like JSON (starts with [ or {)
    if (trimmedContent.startsWith('[') || trimmedContent.startsWith('{')) {
      const parsed = JSON.parse(trimmedContent)
      return parsed
    }
    return null
  } catch {
    return null
  }
}

// Helper function to check if JSON contains tab data (with windowId)
const isTabData = (data: any): data is Array<{id: number, url: string, title: string, windowId: number}> => {
  return Array.isArray(data) && 
         data.length > 0 && 
         data.every(item => 
           typeof item === 'object' && 
           typeof item.id === 'number' && 
           typeof item.url === 'string' && 
           typeof item.title === 'string' && 
           typeof item.windowId === 'number'
         )
}

// Helper function to check if JSON contains selected tab data (without windowId)
const isSelectedTabData = (data: any): data is Array<{id: number, url: string, title: string}> => {
  return Array.isArray(data) && 
         data.length > 0 && 
         data.every(item => 
           typeof item === 'object' && 
           typeof item.id === 'number' && 
           typeof item.url === 'string' && 
           typeof item.title === 'string'
         )
}

// TabDataDisplay component for rendering tab information
interface TabDataDisplayProps {
  content: string
}

const TabDataDisplay = ({ content }: TabDataDisplayProps) => {
  const tabData = parseJsonContent(content)
  
  if (!tabData || !isTabData(tabData)) {
    return (
      <div className="text-sm text-muted-foreground">
        Invalid tab data format
      </div>
    )
  }

  // Group tabs by window
  const tabsByWindow = tabData.reduce((acc, tab) => {
    if (!acc[tab.windowId]) {
      acc[tab.windowId] = []
    }
    acc[tab.windowId].push(tab)
    return acc
  }, {} as Record<number, typeof tabData>)

  return (
    <div className="space-y-4">
      <div className="text-sm font-medium text-foreground mb-3">
        Found {tabData.length} tab{tabData.length !== 1 ? 's' : ''} across {Object.keys(tabsByWindow).length} window{Object.keys(tabsByWindow).length !== 1 ? 's' : ''}
      </div>
      
      {Object.entries(tabsByWindow).map(([windowId, tabs]) => (
        <div key={windowId} className="bg-muted/30 rounded-lg p-3 border border-border/50">
          <div className="space-y-2">
            {tabs.map((tab) => (
              <div 
                key={tab.id} 
                className="flex items-start gap-3 p-2 bg-background/50 rounded border border-border/30 hover:bg-background/70 transition-colors"
              >
                <div className="flex-shrink-0 w-2 h-2 rounded-full bg-brand/60 mt-2"></div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-foreground truncate" title={tab.title}>
                    {tab.title}
                  </div>
                  <div className="text-xs text-muted-foreground truncate" title={tab.url}>
                    {tab.url}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// SelectedTabDataDisplay component for rendering selected tab information
interface SelectedTabDataDisplayProps {
  content: string
}

const SelectedTabDataDisplay = ({ content }: SelectedTabDataDisplayProps) => {
  const tabData = parseJsonContent(content)
  
  if (!tabData || !isSelectedTabData(tabData)) {
    return (
      <div className="text-sm text-muted-foreground">
        Invalid selected tab data format
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="text-sm font-medium text-foreground mb-3">
        Selected {tabData.length} tab{tabData.length !== 1 ? 's' : ''}
      </div>
      
      <div className="bg-muted/30 rounded-lg p-3 border border-border/50">
        <div className="space-y-2">
          {tabData.map((tab) => (
            <div 
              key={tab.id} 
              className="flex items-start gap-3 p-2 bg-background/50 rounded border border-border/30 hover:bg-background/70 transition-colors"
            >
              <div className="flex-shrink-0 w-2 h-2 rounded-full bg-brand/60 mt-2"></div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-foreground truncate" title={tab.title}>
                  {tab.title}
                </div>
                <div className="text-xs text-muted-foreground truncate" title={tab.url}>
                  {tab.url}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/**
 * MessageItem component
 * Renders individual messages with role-based styling
 * Memoized to prevent re-renders when message hasn't changed
 */
export const MessageItem = memo<MessageItemProps>(function MessageItem({ message, shouldIndent = false, showLocalIndentLine = false, applyIndentMargin = true }: MessageItemProps) {
  const isUser = message.role === 'user'
  const isError = message.metadata?.error || message.content.includes('## Task Failed')
  const isSystem = message.role === 'system'
  const { markMessageAsCompleting, removeExecutingMessage, messages, executingMessageRemoving } = useChatStore()
  
  const isExecuting = message.metadata?.isExecuting || message.content.includes('executing') || message.content.includes('Executing')
  const isCompleting = message.metadata?.isCompleting || (isExecuting && executingMessageRemoving)
  const [isAnimating, setIsAnimating] = useState(false)
  const [slideUpAmount, setSlideUpAmount] = useState(0)

  // Memoize expensive content checks to avoid recalculation on every render
  const contentChecks = useMemo(() => {
    const content = message.content
    return {
      isTodoTable: content.includes('| # | Status | Task |'),
      isTaskSummary: content.includes('## Task Summary:') || content.includes('## Task Summary'),
      isTaskFailed: content.includes('## Task Failed'),
      isTaskAnalysisOrPlanning: content.includes('Analyzing task complexity') || 
                                content.includes('Creating a step-by-step plan') ||
                                content.includes('Analyzing task') ||
                                content.includes('Creating plan'),
      isTaskComplete: content.includes('## Task Completed') || 
                     content.includes('Task Complete') || 
                     content.includes('Task Completed') ||
                     content.includes('Task completed successfully') ||
                     content.includes('Task completed.')
    }
  }, [message.content])

  // Memoize message styling to avoid recalculation
  const messageStyling = useMemo(() => {
    // User message styling
    if (isUser) {
      return {
        bubble: 'ml-4 bg-gradient-to-br from-brand/90 to-brand/80 text-white rounded-br-md backdrop-blur-sm border border-transparent',
        glow: 'bg-gradient-to-bl from-brand/20 to-transparent',
        shadow: 'shadow-lg hover:shadow-xl'  // User messages get hover shadow
      }
    }

    // Special styling for TODO lists (task manager)
    if (contentChecks.isTodoTable) {
      return {
        bubble: 'mr-4 bg-gradient-to-br from-card/80 to-card/60 text-foreground rounded-bl-md border-border/50',
        glow: '',  // Remove hover gradient for task manager
        shadow: 'shadow-lg'  // Task manager gets static shadow, no hover effect
      }
    }

    // Default styling (should not be used since only user and TODO messages get bubbles)
    return {
      bubble: 'mr-4 bg-gradient-to-br from-card/80 to-card/60 text-foreground rounded-bl-md border-border/50',
      glow: 'bg-gradient-to-bl from-primary/10 to-transparent',
      shadow: 'shadow-lg hover:shadow-xl'
    }
  }, [isUser, contentChecks.isTodoTable])

  // Determine content renderer based on tool name
  const getToolContentRenderer = useCallback((toolName: string) => {
    switch (toolName) {
      case 'classification_tool':
      case 'planner_tool':
      case 'navigation_tool':
      case 'tab_operations':
      case 'tab_operations_tool':
      case 'refresh_browser_state':
      case 'refresh_browser_state_tool':
      case 'find_element':
      case 'find_element_tool':
      case 'interact':
      case 'interact_tool':
      case 'scroll':
      case 'scroll_tool':
      case 'search':
      case 'search_tool':
      case 'group_tabs':
      case 'group_tabs_tool':
      case 'get_selected_tabs':
      case 'get_selected_tabs_tool':
      case 'extract_tool':
      case 'screenshot_tool':
      case 'done_tool':
      case 'todo_manager':
      case 'todo_manager_tool':
      case 'validator_tool':
        return 'tool-result'
      case 'result_tool':
        // Check if this is a task summary message
        if (message.content.includes('## Task Summary:') || message.content.includes('## Task Summary')) {
          return 'task-summary'
        }
        return 'tool-result'
      default:
        return 'markdown'
    }
  }, [message.content])

  // Memoize content renderer to avoid recalculation
  const contentRenderer = useMemo(() => {
    // User messages - plain text
    if (isUser) {
      return 'plain-text'
    }

    // TODO lists - custom table rendering
    if (contentChecks.isTodoTable) {
      return 'todo-table'
    }

    // Task summaries - markdown with special styling
    if (contentChecks.isTaskSummary) {
      return 'task-summary'
    }

    // Task failed - markdown with error styling
    if (contentChecks.isTaskFailed) {
      return 'task-failed'
    }

    // Task completion - special single line display
    if (contentChecks.isTaskComplete) {
      return 'task-complete'
    }

    // Check for JSON content (like tab data)
    const jsonData = parseJsonContent(message.content)
    if (jsonData && isTabData(jsonData)) {
      return 'tab-data'
    }
    if (jsonData && isSelectedTabData(jsonData)) {
      return 'selected-tab-data'
    }

    // Tool-specific messages - check metadata
    if (message.metadata?.toolName) {
      return getToolContentRenderer(message.metadata.toolName)
    }

    // Default to markdown for assistant messages
    if (message.role === 'assistant') {
      return 'markdown'
    }

    // Plain text for system messages
    return 'plain-text'
  }, [isUser, contentChecks, message.content, message.metadata?.toolName, message.role, getToolContentRenderer])

  // Memoize whether to show bubble and timestamp
  const displayOptions = useMemo(() => {
    const shouldShowBubble = isUser || contentChecks.isTodoTable
    const shouldShowTimestamp = isUser || contentChecks.isTodoTable
    const shouldShowToolName = false // Tool names are not shown since only user and TODO messages get bubbles
    
    return {
      shouldShowBubble,
      shouldShowTimestamp,
      shouldShowToolName
    }
  }, [isUser, contentChecks.isTodoTable])

  // Calculate slide-up amount when executing message is being removed
  useEffect(() => {
    if (executingMessageRemoving && !isExecuting) {
      // Find the executing message that's being removed
      const executingMessage = messages.find(msg => msg.metadata?.isCompleting)
      if (executingMessage) {
        // Find the executing message element and get its height
        const executingElement = document.querySelector(`[data-message-id="${executingMessage.id}"]`)
        if (executingElement) {
          const height = executingElement.getBoundingClientRect().height
          setSlideUpAmount(height)
        }
      }
    } else {
      setSlideUpAmount(0)
    }
  }, [executingMessageRemoving, isExecuting, messages])
  
  // Handle executing message completion
  useEffect(() => {
    if (isExecuting && !isCompleting && !isAnimating) {
      // Check if there's a newer message after this executing message
      const currentIndex = messages.findIndex(msg => msg.id === message.id)
      const hasNewerMessages = currentIndex !== -1 && currentIndex < messages.length - 1
      
      if (hasNewerMessages) {
        // There's a newer message, so this executing message should complete
        markMessageAsCompleting(message.id)
        setIsAnimating(true)
        
        // Remove the message after animation completes
        setTimeout(() => {
          removeExecutingMessage(message.id)
        }, 400) // Match the CSS animation duration
      }
    }
  }, [isExecuting, isCompleting, isAnimating, message.id, messages, markMessageAsCompleting, removeExecutingMessage])
  
  // Extract the executing text (remove "executing - " prefix)
  const executingText = isExecuting ? message.content.replace(/^executing\s*-\s*/i, '') : ''
  
  // Render content based on the determined renderer
  const renderContent = useCallback(() => {
    switch (contentRenderer) {
      case 'plain-text':
        return (
          <div className="whitespace-pre-wrap break-words font-medium">
            {message.content}
          </div>
        )

      case 'todo-table':
        return <TaskManagerDropdown 
          key={`task-manager-${message.id}`} 
          content={message.content} 
        />

      case 'tab-data':
        return <TabDataDisplay content={message.content} />

      case 'selected-tab-data':
        return <SelectedTabDataDisplay content={message.content} />

      case 'task-complete':
        return (
          <div className="space-y-3">
            <div className="py-2">
              <div className="text-base font-semibold">Task Complete</div>
              <div className="text-sm text-muted-foreground mt-1">The task has been completed successfully.</div>
            </div>
          </div>
        )

      case 'task-summary':
      case 'task-failed':
        return (
          <div className="space-y-3">
            <MarkdownContent
              content={message.content}
              className="break-words"
              compact={false}
            />
          </div>
        )
      
      case 'tool-result':
      case 'markdown':
        return (
          <MarkdownContent
            content={message.content}
            className="break-words"
            compact={false}
          />
        )

      default:
        return (
          <MarkdownContent
            content={message.content}
            className="break-words"
            compact={false}
          />
        )
    }
  }, [contentRenderer, message.content, message.id])
  
  // Startup status lines metadata flag
  const isStartup = !!message.metadata && (message.metadata as any).isStartup === true

  return (
    <div 
      data-message-id={message.id}
      className={cn(
        'flex w-full group message-container',
        isUser ? 'justify-end' : 'justify-start',
        // Add indentation for messages that should be indented
        shouldIndent && 'ml-8 relative',
        // Add special styling for TODO table messages
        contentChecks.isTodoTable && 'relative'
      )}
      style={!isExecuting && executingMessageRemoving && slideUpAmount > 0 ? {
        transform: `translateY(-${slideUpAmount}px)`,
        transition: 'transform 0.4s ease-out'
      } : undefined}
    >
      
      {/* Vertical connecting line for indented messages (used only when not grouped) */}
      {shouldIndent && showLocalIndentLine && (
        <div className="absolute left-[-16px] top-0 bottom-0 w-px bg-gradient-to-b from-brand/30 via-brand/20 to-brand/10" />
      )}

      {/* Task manager indicators - these will be handled by parent component data attributes */}
      {/* Removed DOM queries for these - they're now handled by parent component */}

      {/* User avatar - disabled
      {isUser && (
        <div className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ml-1 mt-1 bg-gradient-to-br from-brand to-brand/80 text-white shadow-lg">
          <UserIcon />
        </div>
      )} */}

      {/* Message content - with or without bubble */}
      {displayOptions.shouldShowBubble ? (
        // Message bubble layout
        <div className={cn(
          'relative max-w-[85%] rounded-2xl px-3 py-1 transition-all duration-300',
          messageStyling.shadow,
          isUser ? 'group-hover:scale-[1.02]' : '',
          messageStyling.bubble,
          // Slightly darker text for indented bubble messages to improve contrast
          shouldIndent && 'opacity-90 text-foreground'
        )}>
          {/* Glow effect */}
          <div className={cn(
            'absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300',
            messageStyling.glow
          )} />

          {/* Tool name */}
          {displayOptions.shouldShowToolName && message.metadata?.toolName && (
            <div className="text-xs opacity-80 mb-2 font-medium flex items-center gap-1">
              {message.metadata.toolName}
            </div>
          )}

          {/* Markdown content */}
          <div className="relative z-10">
            {renderContent()}
          </div>

          {/* Timestamp - only show for specific message types */}
          {displayOptions.shouldShowTimestamp && (
            <div className={cn('text-xs opacity-50', isUser ? 'text-right' : 'text-left')}>
              {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </div>
          )}
        </div>
      ) : (
        // Non-bubble messages (system messages, tool results, task summaries, etc.)
        <div className={cn(
          'mr-4 mt-1 max-w-[85%]',
          isCompleting && 'animate-dash-off-left',
          // Add subtle styling for indented messages
          shouldIndent && 'opacity-90'
        )}>
          {isExecuting ? (
            <div className="flex items-center gap-3 text-sm font-medium text-muted-foreground">
              <DogHeadSpinner size={24} className="text-brand" />
              <span>{executingText}</span>
            </div>
          ) : (
            <div className={cn(
              'text-sm',
              isStartup
                ? 'text-muted-foreground'
                : (shouldIndent ? 'text-foreground' : 'text-foreground')
            )}>
              {renderContent()}
            </div>
          )}
        </div>
      )}
    </div>
  )
})