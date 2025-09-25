diff --git a/chrome/browser/extensions/api/browser_os/browser_os_content_processor.h b/chrome/browser/extensions/api/browser_os/browser_os_content_processor.h
new file mode 100644
index 0000000000000..e553cd8e5ddb9
--- /dev/null
+++ b/chrome/browser/extensions/api/browser_os/browser_os_content_processor.h
@@ -0,0 +1,173 @@
+// Copyright 2024 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef CHROME_BROWSER_EXTENSIONS_API_BROWSER_OS_BROWSER_OS_CONTENT_PROCESSOR_H_
+#define CHROME_BROWSER_EXTENSIONS_API_BROWSER_OS_BROWSER_OS_CONTENT_PROCESSOR_H_
+
+#include <atomic>
+#include <cstdint>
+#include <string>
+#include <unordered_map>
+#include <unordered_set>
+#include <vector>
+
+#include "base/functional/callback.h"
+#include "base/memory/ref_counted.h"
+#include "chrome/common/extensions/api/browser_os.h"
+#include "ui/accessibility/ax_tree_update.h"
+#include "ui/gfx/geometry/rect.h"
+
+namespace ui {
+struct AXNodeData;
+}  // namespace ui
+
+namespace extensions {
+namespace api {
+
+// Result of content processing
+struct ContentProcessingResult {
+  browser_os::Snapshot snapshot;
+  int nodes_processed = 0;
+  int64_t processing_time_ms = 0;
+};
+
+// Processes accessibility trees to extract content (text/links) with parallel processing
+class ContentProcessor {
+ public:
+  // Node information for batch processing
+  struct NodeInfo {
+    NodeInfo();
+    NodeInfo(const NodeInfo&);
+    NodeInfo(NodeInfo&&);
+    NodeInfo& operator=(const NodeInfo&);
+    NodeInfo& operator=(NodeInfo&&);
+    ~NodeInfo();
+
+    int32_t id;
+    std::string role;
+    std::string name;
+    std::string value;
+    std::string url;
+    gfx::Rect bounds;
+    std::vector<int32_t> child_ids;
+    // Additional attributes
+    std::unordered_map<std::string, std::string> attributes;
+  };
+
+  // Section information
+  struct SectionInfo {
+    SectionInfo();
+    SectionInfo(const SectionInfo&) = delete;
+    SectionInfo(SectionInfo&&);
+    SectionInfo& operator=(const SectionInfo&) = delete;
+    SectionInfo& operator=(SectionInfo&&);
+    ~SectionInfo();
+
+    browser_os::SectionType type;
+    std::string label;
+    // Text content for this section
+    std::string text_content;
+    // Links found in this section
+    std::vector<browser_os::LinkInfo> links;
+  };
+
+  ContentProcessor() = default;
+  ~ContentProcessor() = default;
+
+  // Main processing function - handles all threading internally
+  static void ProcessAccessibilityTree(
+      const ui::AXTreeUpdate& tree_update,
+      browser_os::SnapshotType type,
+      browser_os::SnapshotContext context,
+      const std::vector<browser_os::SectionType>& include_sections,
+      const gfx::Size& viewport_size,
+      base::OnceCallback<void(ContentProcessingResult)> callback);
+
+
+ private:
+  // Internal processing context for thread safety
+  struct ProcessingContext : public base::RefCountedThreadSafe<ProcessingContext> {
+    ProcessingContext();
+
+    // Input data
+    ui::AXTreeUpdate tree_update;
+    browser_os::SnapshotType snapshot_type;
+    browser_os::SnapshotContext snapshot_context;
+    std::vector<browser_os::SectionType> include_sections;
+    gfx::Size viewport_size;
+    base::OnceCallback<void(ContentProcessingResult)> callback;
+
+    // Processing state
+    std::atomic<int> pending_batches{0};
+    base::Time start_time;
+    
+    // Thread-safe section management
+    mutable base::Lock sections_lock;
+    std::unordered_map<browser_os::SectionType, std::unique_ptr<SectionInfo>> sections;
+    
+    // Thread-safe caching for section detection
+    mutable base::Lock section_cache_lock;
+    std::unordered_map<int32_t, browser_os::SectionType> node_to_section_cache;
+    std::unordered_map<int32_t, browser_os::SectionType> section_root_nodes;
+    
+    // Node map built from tree_update (read-only after construction)
+    std::unordered_map<int32_t, ui::AXNodeData> node_map;
+
+   private:
+    friend class base::RefCountedThreadSafe<ProcessingContext>;
+    ~ProcessingContext();
+  };
+
+  // Helper functions
+  static browser_os::SectionType GetSectionType(const NodeInfo& node);
+  static bool IsNodeVisible(const NodeInfo& node, const gfx::Rect& viewport_bounds);
+  static std::string ExtractNodeText(const NodeInfo& node);
+  static browser_os::LinkInfo ExtractLinkInfo(const NodeInfo& node);
+  static bool IsLink(const NodeInfo& node);
+  static bool IsTextNode(const NodeInfo& node);
+  
+  // Section detection and caching
+  static browser_os::SectionType DetermineNodeSection(
+      int32_t node_id,
+      const std::unordered_map<int32_t, ui::AXNodeData>& node_map,
+      scoped_refptr<ProcessingContext> context);
+  static void CacheNodeSection(
+      int32_t node_id,
+      browser_os::SectionType section_type,
+      scoped_refptr<ProcessingContext> context);
+  static browser_os::SectionType GetSectionTypeFromNode(
+      const ui::AXNodeData& node);
+  
+  // Thread-safe section content processing
+  static void AddTextToSection(
+      browser_os::SectionType section_type,
+      const std::string& text,
+      scoped_refptr<ProcessingContext> context);
+  static void AddLinkToSection(
+      browser_os::SectionType section_type,
+      browser_os::LinkInfo link,
+      scoped_refptr<ProcessingContext> context);
+  
+  // Batch processing with integrated section detection
+  static void ProcessNodeBatchParallel(
+      const std::vector<ui::AXNodeData>& batch,
+      scoped_refptr<ProcessingContext> context);
+  
+  // Helper functions for parallel processing
+  static std::string ExtractTextFromAXNode(const ui::AXNodeData& node);
+  static bool IsLinkNode(const ui::AXNodeData& node);
+  static browser_os::LinkInfo ExtractLinkFromAXNode(const ui::AXNodeData& node);
+
+  // Batch processing callbacks
+  static void OnBatchProcessed(scoped_refptr<ProcessingContext> context);
+  static void OnAllBatchesComplete(scoped_refptr<ProcessingContext> context);
+
+  ContentProcessor(const ContentProcessor&) = delete;
+  ContentProcessor& operator=(const ContentProcessor&) = delete;
+};
+
+}  // namespace api
+}  // namespace extensions
+
+#endif  // CHROME_BROWSER_EXTENSIONS_API_BROWSER_OS_BROWSER_OS_CONTENT_PROCESSOR_H_
\ No newline at end of file
