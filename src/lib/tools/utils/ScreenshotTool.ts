import { z } from 'zod'
import { DynamicStructuredTool } from '@langchain/core/tools'
import { ExecutionContext } from '@/lib/runtime/ExecutionContext'
import { Logging } from '@/lib/utils/Logging'
import { toolSuccess, toolError } from '@/lib/tools/Tool.interface'
import { PubSub } from '@/lib/pubsub'

// Input schema for the screenshot tool
const ScreenshotToolInputSchema = z.object({})  // No parameters needed

type ScreenshotToolInput = z.infer<typeof ScreenshotToolInputSchema>;

export function createScreenshotTool(executionContext: ExecutionContext): DynamicStructuredTool {
  return new DynamicStructuredTool({
    name: 'screenshot_tool',
    description: `Capture a screenshot of the current page. Use liberally - screenshots are fast and free!

USE FOR DECISION-MAKING:
• Choosing between multiple options (products, buttons, links)
• Before important actions (Place Order, Submit, Confirm)
• Verifying prices, ratings, or details before proceeding
• Comparing different items or pages

USE FOR DEBUGGING:
• Can't find an element after trying
• Page looks different than expected
• Before calling human_input_tool
• Understanding error messages

Screenshots help you see what's on the page and make better decisions.`,
    schema: ScreenshotToolInputSchema,
    func: async (_args: ScreenshotToolInput): Promise<string> => {
      try {
        // Check if model has enough tokens for screenshots
        const maxTokens = executionContext.messageManager.getMaxTokens()
        const MIN_TOKENS_FOR_SCREENSHOTS = 128000  // 128k minimum
        
        if (maxTokens < MIN_TOKENS_FOR_SCREENSHOTS) {
          Logging.log('ScreenshotTool', 
            `Screenshots disabled: model has ${maxTokens} tokens (minimum: ${MIN_TOKENS_FOR_SCREENSHOTS})`, 
            'info')
          
          return JSON.stringify(toolSuccess(
            `Screenshots are disabled for models with less than 128k tokens. Current model has ${maxTokens} tokens.`
          ))
        }
        
        // TODO(nithin): Add support for multiple screenshot sizes (256x256, 512x512)
        // Currently only supports 1024x1024. Smaller sizes would use less tokens.
        
        // Emit status message
        executionContext.getPubSub().publishMessage(PubSub.createMessage(`Capturing screenshot of current page`, 'thinking'))

        // Get the current page from execution context
        const page = await executionContext.browserContext.getCurrentPage()
        
        if (!page) {
          const error = 'No active page found to take screenshot'
          Logging.log('ScreenshotTool', error, 'error')
          return JSON.stringify(toolError(error))
        }

        // Take the screenshot
        const base64Data = await page.takeScreenshot()
        
        if (!base64Data) {
          const error = 'Failed to capture screenshot - no data returned'
          Logging.log('ScreenshotTool', error, 'error')
          return JSON.stringify(toolError(error))
        }
        
        Logging.log('ScreenshotTool', `Screenshot captured successfully (${base64Data.length} bytes)`, 'info')
        
        
        // Return success with the base64 data in the output message
        return JSON.stringify(toolSuccess(`Captured screenshot of the page.`))
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        Logging.log('ScreenshotTool', `Error capturing screenshot: ${errorMessage}`, 'error')
        
        executionContext.getPubSub().publishMessage(
          PubSub.createMessageWithId(PubSub.generateId('ToolError'), `Screenshot failed: ${errorMessage}`, 'error')
        )
        return JSON.stringify(toolError(errorMessage))  // Return raw error
      }
    }
  })
}
