import { ExecutionContext } from '@/lib/runtime/ExecutionContext'
import { MessageManager } from '@/lib/runtime/MessageManager'
import { ToolManager } from '@/lib/tools/ToolManager'
import { createScreenshotTool } from '@/lib/tools/utils/ScreenshotTool'
import { createScrollTool } from '@/lib/tools/navigation/ScrollTool'
import { createRefreshStateTool } from '@/lib/tools/navigation/RefreshStateTool'
import { generateChatSystemPrompt } from './ChatAgent.prompt'
import { AIMessage, AIMessageChunk } from '@langchain/core/messages'
import { EventProcessor } from '@/lib/events/EventProcessor'
import { AbortError } from '@/lib/utils/Abortable'
import { Logging } from '@/lib/utils/Logging'

// Type definitions
interface ExtractedPageContext {
  tabs: Array<{
    id: number
    url: string
    title: string
    text: string
  }>
  isSingleTab: boolean
}

/**
 * ChatAgent - Lightweight agent for Q&A interactions with web pages
 * Direct streaming answers without planning or complex tool orchestration
 */
export class ChatAgent {
  // Constants
  private static readonly MAX_TURNS = 20
  private static readonly TOOLS = ['screenshot_tool', 'scroll_tool', 'refresh_browser_state_tool']
  private static readonly DEFAULT_CHARS_PER_TAB = 6000
  
  private readonly executionContext: ExecutionContext
  private readonly toolManager: ToolManager

  constructor(executionContext: ExecutionContext) {
    this.executionContext = executionContext
    this.toolManager = new ToolManager(executionContext)
    this._registerTools()
  }

  // Getters for context components
  private get messageManager(): MessageManager {
    return this.executionContext.messageManager
  }

  private get eventEmitter(): EventProcessor {
    return this.executionContext.getEventProcessor()
  }

  /**
   * Register only the minimal tools needed for Q&A
   */
  private _registerTools(): void {
    // Only register the 3 essential tools for Q&A
    this.toolManager.register(createScreenshotTool(this.executionContext))
    this.toolManager.register(createScrollTool(this.executionContext))
    this.toolManager.register(createRefreshStateTool(this.executionContext))
    
    Logging.log('ChatAgent', `Registered ${this.toolManager.getAll().length} tools for Q&A mode`)
  }

  /**
   * Check abort signal and throw if aborted
   */
  private _checkAborted(): void {
    if (this.executionContext.abortController.signal.aborted) {
      throw new AbortError()
    }
  }

  /**
   * Main execution entry point - streamlined for Q&A
   */
  async execute(query: string): Promise<void> {
    try {
      this._checkAborted()
      
      // Configure EventProcessor for direct streaming (no thinking UI)
      this.eventEmitter.setAgentName('ChatAgent')
      this.eventEmitter.setShowThinking(false)
      
      // Extract page context once
      const pageContext = await this._extractPageContext()
      
      // Generate minimal system prompt
      const systemPrompt = generateChatSystemPrompt(pageContext)
      
      // Initialize chat with system prompt and query
      this._initializeChat(systemPrompt, query)
      
      // Stream direct answer without tools
      await this._streamLLM({ tools: false })
      
      Logging.log('ChatAgent', 'Q&A response completed')
      
    } catch (error) {
      if (error instanceof AbortError) {
        Logging.log('ChatAgent', 'Execution aborted by user')
        this.eventEmitter.info('Execution cancelled')
      } else {
        const errorMessage = error instanceof Error ? error.message : String(error)
        Logging.log('ChatAgent', `Execution failed: ${errorMessage}`, 'error')
        this.eventEmitter.error(errorMessage)
      }
      throw error
    }
  }

  /**
   * Extract page context from selected tabs
   */
  private async _extractPageContext(): Promise<ExtractedPageContext> {
    // Get selected tab IDs from execution context
    const selectedTabIds = this.executionContext.getSelectedTabIds()
    const hasUserSelectedTabs = Boolean(selectedTabIds && selectedTabIds.length > 0)
    
    // Get browser pages
    const pages = await this.executionContext.browserContext.getPages(
      hasUserSelectedTabs && selectedTabIds ? selectedTabIds : undefined
    )
    
    if (pages.length === 0) {
      throw new Error('No tabs available for context extraction')
    }
    
    // Extract content from each tab
    const tabs = await Promise.all(
      pages.map(async page => {
        const textSnapshot = await page.getTextSnapshot()
        const text = textSnapshot.sections?.map((section: any) => 
          section.content || section.text || ''
        ).join('\n') || 'No content found'
        
        // Simple truncation for initial implementation
        const truncatedText = text.length > ChatAgent.DEFAULT_CHARS_PER_TAB 
          ? text.substring(0, ChatAgent.DEFAULT_CHARS_PER_TAB) 
          : text
        
        return {
          id: page.tabId,
          url: page.url(),
          title: await page.title(),
          text: truncatedText
        }
      })
    )
    
    return {
      tabs,
      isSingleTab: tabs.length === 1
    }
  }


  /**
   * Initialize chat session with system prompt and user query
   */
  private _initializeChat(systemPrompt: string, query: string): void {
    // Clear any previous messages
    this.messageManager.clear()
    
    // Add system prompt
    this.messageManager.addSystem(systemPrompt)
    
    // Add user query
    this.messageManager.addHuman(query)
    
    Logging.log('ChatAgent', 'Chat session initialized')
  }

  /**
   * Stream LLM response with or without tools
   */
  private async _streamLLM(opts: { tools: boolean }): Promise<void> {
    const llm = await this.executionContext.getLLM({ temperature: 0.3 })
    
    // Only bind tools in Pass 2
    const llmToUse = opts.tools && llm.bindTools
      ? llm.bindTools(this.toolManager.getAll())
      : llm
    
    // Get current messages
    const messages = this.messageManager.getMessages()
    
    // Start streaming (creates message segment for direct streaming)
    this.eventEmitter.startThinking()
    
    // Stream the response
    const stream = await llmToUse.stream(messages)
    
    // Accumulate chunks for final message
    const chunks: AIMessageChunk[] = []
    let fullContent = ''
    
    // Stream directly to UI without "thinking" state
    for await (const chunk of stream) {
      this._checkAborted()
      chunks.push(chunk)
      
      // Direct streaming to UI
      if (chunk.content) {
        fullContent += chunk.content
        this.eventEmitter.streamThoughtDuringThinking(chunk.content as string)
      }
    }
    
    // Accumulate final message for history
    const finalMessage = this._accumulateMessage(chunks)
    
    // Finish the streaming message
    this.eventEmitter.finishThinking(fullContent)
    
    // Add to message history
    this.messageManager.addAI(finalMessage.content as string || '')
  }

  /**
   * Accumulate message chunks into a single AIMessage
   */
  private _accumulateMessage(chunks: AIMessageChunk[]): AIMessage {
    const content = chunks
      .map(c => c.content)
      .filter(Boolean)
      .join('')
    
    const toolCalls = chunks
      .flatMap(c => c.tool_calls || [])
      .filter(tc => tc.name) // Filter out incomplete tool calls
    
    return new AIMessage({ 
      content, 
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined 
    })
  }

}