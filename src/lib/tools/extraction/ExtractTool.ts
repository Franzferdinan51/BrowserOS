import { DynamicStructuredTool } from '@langchain/core/tools'
import { z } from 'zod'
import { ExecutionContext } from '@/lib/runtime/ExecutionContext'
import { toolError } from '@/lib/tools/Tool.interface'
import { HumanMessage, SystemMessage } from '@langchain/core/messages'
import { generateExtractorSystemPrompt, generateExtractorTaskPrompt } from './ExtractTool.prompt'
import { invokeWithRetry } from '@/lib/utils/retryable'
import { PubSub } from '@/lib/pubsub'
import { TokenCounter } from '@/lib/utils/TokenCounter'
import { Logging } from '@/lib/utils/Logging'
import { DFSParser } from './DFSParser'
import { DFSExtractionOptionsSchema, type DFSExtractionOptions } from './types'
import { getBrowserOSAdapter } from '@/lib/browser/BrowserOSAdapter'

// Input schema for extraction
const ExtractInputSchema = z.object({
  task: z.string(),  // What to extract (e.g., "Extract all product prices")
  tab_id: z.number(),  // Tab ID to extract from
  extract_type: z.enum(['links', 'text', 'semantic', 'products', 'forms', 'navigation', 'main_content']),  // Type of content to extract
  options: DFSExtractionOptionsSchema.optional()  // Advanced options for semantic extraction
})

// Output schema for extracted data
const ExtractedDataSchema = z.object({
  content: z.string(),  // The LLM's extracted/summarized/rephrased output
  reasoning: z.string()  // LLM's explanation of what it did, found, and created
})

type ExtractInput = z.infer<typeof ExtractInputSchema>
type ExtractedData = z.infer<typeof ExtractedDataSchema>

// Factory function to create ExtractTool
export function createExtractTool(executionContext: ExecutionContext): DynamicStructuredTool {
  return new DynamicStructuredTool({
    name: 'extract_tool',
    description: 'Extract specific information from a web page using AI. Supports legacy text/links extraction and new semantic extraction using accessibility tree parsing for products, forms, navigation, and main content.',
    schema: ExtractInputSchema,
    func: async (args: ExtractInput): Promise<string> => {
      try {
        executionContext.getPubSub().publishMessage(PubSub.createMessage(`Extracting information from page ${args.tab_id}`, 'thinking'))
        // Get the page for the specified tab
        const pages = await executionContext.browserContext.getPages([args.tab_id])
        if (!pages || pages.length === 0) {
          return JSON.stringify(toolError(`Tab ${args.tab_id} not found`))
        }
        
        const page = pages[0]
        
        // Get raw content based on extract_type
        let rawContent: string
        if (['semantic', 'products', 'forms', 'navigation', 'main_content'].includes(args.extract_type)) {
          rawContent = await performSemanticExtraction(args, args.tab_id)
        } else if (args.extract_type === 'text') {
          const textSnapshot = await page.getTextSnapshot()
          rawContent = textSnapshot?.sections && textSnapshot.sections.length > 0
            ? textSnapshot.sections.map((section: any) => 
                section.content || section.text || JSON.stringify(section)
              ).join('\n')
            : 'No text content found'
        } else {
          const linksSnapshot = await page.getLinksSnapshot()
          rawContent = linksSnapshot?.sections && linksSnapshot.sections.length > 0
            ? linksSnapshot.sections.map((section: any) => 
                section.content || section.text || JSON.stringify(section)
              ).join('\n')
            : 'No links found'
        }
        
        // Get page metadata
        const url = await page.url()
        const title = await page.title()
        
        // Get LLM instance
        const llm = await executionContext.getLLM({temperature: 0.1})
        
        // Generate prompts
        const systemPrompt = generateExtractorSystemPrompt()
        const taskPrompt = generateExtractorTaskPrompt(
          args.task,
          args.extract_type,
          rawContent,
          { url, title }
        )
        
        // Prepare messages for LLM
        const messages = [
          new SystemMessage(systemPrompt),
          new HumanMessage(taskPrompt)
        ]
        
        // Log token count
        const tokenCount = TokenCounter.countMessages(messages)
        Logging.log('ExtractTool', `Invoking LLM with ${TokenCounter.format(tokenCount)}`, 'info')
        
        // Get structured response from LLM with retry logic
        const structuredLLM = llm.withStructuredOutput(ExtractedDataSchema)
        const extractedData = await invokeWithRetry<ExtractedData>(
          structuredLLM,
          messages,
          3
        )

        executionContext.getPubSub().publishMessage(PubSub.createMessage(`Extracted ${args.extract_type} from page ${title}, generated summary...`, 'thinking'))
        
        // Return success result
        return JSON.stringify({
          ok: true,
          output: extractedData
        })
      } catch (error) {
        // Handle error
        const errorMessage = error instanceof Error ? error.message : String(error)
        executionContext.getPubSub().publishMessage(
          PubSub.createMessageWithId(PubSub.generateId('ToolError'), `Extraction failed: ${errorMessage}`, 'error')
        )
        return JSON.stringify(toolError(errorMessage))  // Return raw error
      }
    }
  })
}

// New semantic extraction method
async function performSemanticExtraction(args: ExtractInput, tabId: number): Promise<string> {
  const browserOSAdapter = getBrowserOSAdapter()
  const accessibilityTree = await browserOSAdapter.getAccessibilityTree(tabId)
  
  const parser = new DFSParser(accessibilityTree)
  
  const options: DFSExtractionOptions = {
    target: args.extract_type as any,
    task: args.task,
    maxDepth: args.options?.maxDepth || 5,
    preserveHierarchy: args.options?.preserveHierarchy ?? true,
    includeInteractive: args.options?.includeInteractive ?? true,
    includeText: args.options?.includeText ?? true,
    minTextLength: args.options?.minTextLength || 3,
    includeHidden: args.options?.includeHidden || false,
    includeRoles: args.options?.includeRoles,
    excludeRoles: args.options?.excludeRoles || ['banner', 'contentinfo', 'complementary', 'definition', 'note']
  }
  
  const extractedContent = await parser.extractContent(options)
  return extractedContent.toStructuredText()
}
