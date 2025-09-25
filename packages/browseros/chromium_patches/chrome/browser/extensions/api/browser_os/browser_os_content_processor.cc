diff --git a/chrome/browser/extensions/api/browser_os/browser_os_content_processor.cc b/chrome/browser/extensions/api/browser_os/browser_os_content_processor.cc
new file mode 100644
index 0000000000000..7a35c0fea9de8
--- /dev/null
+++ b/chrome/browser/extensions/api/browser_os/browser_os_content_processor.cc
@@ -0,0 +1,727 @@
+// Copyright 2024 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "chrome/browser/extensions/api/browser_os/browser_os_content_processor.h"
+
+#include <algorithm>
+#include <queue>
+#include <utility>
+
+#include "base/functional/bind.h"
+#include "base/logging.h"
+#include "base/strings/string_util.h"
+#include "base/task/thread_pool.h"
+#include "base/time/time.h"
+#include "ui/accessibility/ax_enum_util.h"
+#include "ui/accessibility/ax_node_data.h"
+#include "ui/accessibility/ax_role_properties.h"
+#include "ui/accessibility/ax_tree_update.h"
+#include "ui/gfx/geometry/rect_conversions.h"
+
+namespace extensions {
+namespace api {
+
+namespace {
+
+// Constants for safety limits
+constexpr size_t kMaxLinksPerSection = 1000;
+constexpr size_t kMaxTextLength = 100000;
+
+// Helper to clean text for output
+std::string CleanTextForOutput(const std::string& text) {
+  std::string cleaned = std::string(base::TrimWhitespaceASCII(text, base::TRIM_ALL));
+  
+  // Replace multiple spaces with single space
+  std::string result;
+  bool prev_space = false;
+  for (char c : cleaned) {
+    if (std::isspace(c)) {
+      if (!prev_space) {
+        result += ' ';
+        prev_space = true;
+      }
+    } else {
+      result += c;
+      prev_space = false;
+    }
+  }
+  
+  return result;
+}
+
+// Helper to determine if URL is external
+bool IsExternalUrl(const std::string& url) {
+  if (url.empty()) return false;
+  
+  // Check for common external URL patterns
+  return url.find("http://") == 0 || 
+         url.find("https://") == 0 ||
+         url.find("//") == 0;
+}
+
+// Convert SectionType enum to string
+std::string SectionTypeToString(browser_os::SectionType type) {
+  switch (type) {
+    case browser_os::SectionType::kMain:
+      return "main";
+    case browser_os::SectionType::kNavigation:
+      return "navigation";
+    case browser_os::SectionType::kFooter:
+      return "footer";
+    case browser_os::SectionType::kHeader:
+      return "header";
+    case browser_os::SectionType::kArticle:
+      return "article";
+    case browser_os::SectionType::kAside:
+      return "aside";
+    case browser_os::SectionType::kComplementary:
+      return "complementary";
+    case browser_os::SectionType::kContentinfo:
+      return "contentinfo";
+    case browser_os::SectionType::kForm:
+      return "form";
+    case browser_os::SectionType::kSearch:
+      return "search";
+    case browser_os::SectionType::kRegion:
+      return "region";
+    case browser_os::SectionType::kOther:
+    default:
+      return "other";
+  }
+}
+
+}  // namespace
+
+// NodeInfo implementation
+ContentProcessor::NodeInfo::NodeInfo() = default;
+ContentProcessor::NodeInfo::NodeInfo(const NodeInfo&) = default;
+ContentProcessor::NodeInfo::NodeInfo(NodeInfo&&) = default;
+ContentProcessor::NodeInfo& ContentProcessor::NodeInfo::operator=(const NodeInfo&) = default;
+ContentProcessor::NodeInfo& ContentProcessor::NodeInfo::operator=(NodeInfo&&) = default;
+ContentProcessor::NodeInfo::~NodeInfo() = default;
+
+// SectionInfo implementation
+ContentProcessor::SectionInfo::SectionInfo() = default;
+ContentProcessor::SectionInfo::SectionInfo(SectionInfo&&) = default;
+ContentProcessor::SectionInfo& ContentProcessor::SectionInfo::operator=(SectionInfo&&) = default;
+ContentProcessor::SectionInfo::~SectionInfo() = default;
+
+// ProcessingContext implementation
+ContentProcessor::ProcessingContext::ProcessingContext() = default;
+ContentProcessor::ProcessingContext::~ProcessingContext() = default;
+
+// ============================================================================
+// Section Detection and Caching Implementation
+// ============================================================================
+
+// Get section type from node attributes (for section roots)
+browser_os::SectionType ContentProcessor::GetSectionTypeFromNode(
+    const ui::AXNodeData& node) {
+  // Check ARIA landmark roles
+  const std::string& role = ui::ToString(node.role);
+  if (role == "navigation") {
+    return browser_os::SectionType::kNavigation;
+  } else if (role == "main") {
+    return browser_os::SectionType::kMain;
+  } else if (role == "complementary" || role == "aside") {
+    return browser_os::SectionType::kAside;
+  } else if (role == "contentinfo" || role == "footer") {
+    return browser_os::SectionType::kFooter;
+  } else if (role == "banner" || role == "header") {
+    return browser_os::SectionType::kHeader;
+  } else if (role == "article") {
+    return browser_os::SectionType::kArticle;
+  } else if (role == "form") {
+    return browser_os::SectionType::kForm;
+  } else if (role == "search") {
+    return browser_os::SectionType::kSearch;
+  } else if (role == "region") {
+    return browser_os::SectionType::kRegion;
+  }
+  
+  // Check HTML tags
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kHtmlTag)) {
+    const std::string& tag = node.GetStringAttribute(ax::mojom::StringAttribute::kHtmlTag);
+    if (tag == "nav") {
+      return browser_os::SectionType::kNavigation;
+    } else if (tag == "main") {
+      return browser_os::SectionType::kMain;
+    } else if (tag == "aside") {
+      return browser_os::SectionType::kAside;
+    } else if (tag == "footer") {
+      return browser_os::SectionType::kFooter;
+    } else if (tag == "header") {
+      return browser_os::SectionType::kHeader;
+    } else if (tag == "article") {
+      return browser_os::SectionType::kArticle;
+    } else if (tag == "form") {
+      return browser_os::SectionType::kForm;
+    }
+  }
+  
+  return browser_os::SectionType::kNone;  // Not a section root
+}
+
+// Cache a node's section for fast lookup
+void ContentProcessor::CacheNodeSection(
+    int32_t node_id,
+    browser_os::SectionType section_type,
+    scoped_refptr<ProcessingContext> context) {
+  base::AutoLock lock(context->section_cache_lock);
+  context->node_to_section_cache[node_id] = section_type;
+}
+
+// Determine which section a node belongs to with caching
+browser_os::SectionType ContentProcessor::DetermineNodeSection(
+    int32_t node_id,
+    const std::unordered_map<int32_t, ui::AXNodeData>& node_map,
+    scoped_refptr<ProcessingContext> context) {
+  
+  // Fast path: check cache first
+  {
+    base::AutoLock lock(context->section_cache_lock);
+    auto cached_it = context->node_to_section_cache.find(node_id);
+    if (cached_it != context->node_to_section_cache.end()) {
+      return cached_it->second;
+    }
+  }
+  
+  // Find the node
+  auto node_it = node_map.find(node_id);
+  if (node_it == node_map.end()) {
+    return browser_os::SectionType::kOther;
+  }
+  
+  // Check if this node itself defines a section
+  browser_os::SectionType node_section = GetSectionTypeFromNode(node_it->second);
+  if (node_section != browser_os::SectionType::kNone) {
+    // This is a section root - cache it
+    CacheNodeSection(node_id, node_section, context);
+    {
+      base::AutoLock lock(context->section_cache_lock);
+      context->section_root_nodes[node_id] = node_section;
+    }
+    return node_section;
+  }
+  
+  // Walk up the tree to find section
+  std::vector<int32_t> path;
+  path.reserve(20);  // Pre-allocate for typical depth
+  
+  int32_t current_id = node_id;
+  const int kMaxDepth = 100;
+  int depth = 0;
+  
+  while (current_id >= 0 && depth < kMaxDepth) {
+    path.push_back(current_id);
+    
+    // Check cache during walk
+    {
+      base::AutoLock lock(context->section_cache_lock);
+      auto cached_it = context->node_to_section_cache.find(current_id);
+      if (cached_it != context->node_to_section_cache.end()) {
+        // Found cached ancestor - cache entire path
+        browser_os::SectionType section = cached_it->second;
+        for (int32_t path_node_id : path) {
+          context->node_to_section_cache[path_node_id] = section;
+        }
+        return section;
+      }
+      
+      // Check if this is a known section root
+      auto root_it = context->section_root_nodes.find(current_id);
+      if (root_it != context->section_root_nodes.end()) {
+        // Found section root - cache entire path
+        browser_os::SectionType section = root_it->second;
+        for (int32_t path_node_id : path) {
+          context->node_to_section_cache[path_node_id] = section;
+        }
+        return section;
+      }
+    }
+    
+    // Move to parent
+    auto current_it = node_map.find(current_id);
+    if (current_it == node_map.end()) {
+      break;
+    }
+    
+    current_id = current_it->second.relative_bounds.offset_container_id;
+    depth++;
+  }
+  
+  // Default to "other" section and cache the path
+  browser_os::SectionType default_section = browser_os::SectionType::kOther;
+  {
+    base::AutoLock lock(context->section_cache_lock);
+    for (int32_t path_node_id : path) {
+      context->node_to_section_cache[path_node_id] = default_section;
+    }
+  }
+  
+  return default_section;
+}
+
+// Helper to get section type from node
+browser_os::SectionType ContentProcessor::GetSectionType(const NodeInfo& node) {
+  // Check ARIA landmark roles
+  if (node.role == "navigation") {
+    return browser_os::SectionType::kNavigation;
+  } else if (node.role == "main") {
+    return browser_os::SectionType::kMain;
+  } else if (node.role == "complementary" || node.role == "aside") {
+    return browser_os::SectionType::kAside;
+  } else if (node.role == "contentinfo" || node.role == "footer") {
+    return browser_os::SectionType::kFooter;
+  } else if (node.role == "banner" || node.role == "header") {
+    return browser_os::SectionType::kHeader;
+  } else if (node.role == "article") {
+    return browser_os::SectionType::kArticle;
+  } else if (node.role == "form") {
+    return browser_os::SectionType::kForm;
+  } else if (node.role == "search") {
+    return browser_os::SectionType::kSearch;
+  } else if (node.role == "region") {
+    return browser_os::SectionType::kRegion;
+  }
+  
+  // Check HTML tags from attributes
+  auto tag_it = node.attributes.find("html-tag");
+  if (tag_it != node.attributes.end()) {
+    const std::string& tag = tag_it->second;
+    if (tag == "nav") {
+      return browser_os::SectionType::kNavigation;
+    } else if (tag == "main") {
+      return browser_os::SectionType::kMain;
+    } else if (tag == "aside") {
+      return browser_os::SectionType::kAside;
+    } else if (tag == "footer") {
+      return browser_os::SectionType::kFooter;
+    } else if (tag == "header") {
+      return browser_os::SectionType::kHeader;
+    } else if (tag == "article") {
+      return browser_os::SectionType::kArticle;
+    } else if (tag == "form") {
+      return browser_os::SectionType::kForm;
+    }
+  }
+  
+  return browser_os::SectionType::kOther;
+}
+
+// ============================================================================
+// Thread-Safe Section Content Management
+// ============================================================================
+
+// Add text content to a section (thread-safe)
+void ContentProcessor::AddTextToSection(
+    browser_os::SectionType section_type,
+    const std::string& text,
+    scoped_refptr<ProcessingContext> context) {
+  
+  if (text.empty()) {
+    return;
+  }
+  
+  base::AutoLock lock(context->sections_lock);
+  
+  // Get or create section
+  auto& section_ptr = context->sections[section_type];
+  if (!section_ptr) {
+    section_ptr = std::make_unique<SectionInfo>();
+    section_ptr->type = section_type;
+  }
+  
+  // Add text with newline separator if needed
+  if (!section_ptr->text_content.empty()) {
+    section_ptr->text_content += "\n";
+  }
+  section_ptr->text_content += text;
+  
+  // Enforce size limit
+  if (section_ptr->text_content.length() > kMaxTextLength) {
+    section_ptr->text_content.resize(kMaxTextLength);
+  }
+}
+
+// Add link to a section (thread-safe)
+void ContentProcessor::AddLinkToSection(
+    browser_os::SectionType section_type,
+    browser_os::LinkInfo link,
+    scoped_refptr<ProcessingContext> context) {
+  
+  base::AutoLock lock(context->sections_lock);
+  
+  // Get or create section
+  auto& section_ptr = context->sections[section_type];
+  if (!section_ptr) {
+    section_ptr = std::make_unique<SectionInfo>();
+    section_ptr->type = section_type;
+  }
+  
+  // Add link with limit check
+  if (section_ptr->links.size() < kMaxLinksPerSection) {
+    section_ptr->links.push_back(std::move(link));
+  }
+}
+
+// Helper to check if node is visible
+bool ContentProcessor::IsNodeVisible(const NodeInfo& node, const gfx::Rect& viewport_bounds) {
+  if (viewport_bounds.IsEmpty()) {
+    return true;  // No viewport restriction
+  }
+  
+  // Check if node bounds intersect with viewport
+  return viewport_bounds.Intersects(node.bounds);
+}
+
+// Helper to extract text from node
+std::string ContentProcessor::ExtractNodeText(const NodeInfo& node) {
+  std::vector<std::string> text_parts;
+  
+  // Get name
+  if (!node.name.empty()) {
+    text_parts.push_back(node.name);
+  }
+  
+  // Get value for input elements
+  if (!node.value.empty()) {
+    text_parts.push_back(node.value);
+  }
+  
+  // Get placeholder
+  auto placeholder_it = node.attributes.find("placeholder");
+  if (placeholder_it != node.attributes.end() && !placeholder_it->second.empty()) {
+    text_parts.push_back(placeholder_it->second);
+  }
+  
+  // Join all text parts
+  std::string result = base::JoinString(text_parts, " ");
+  return CleanTextForOutput(result);
+}
+
+// Helper to extract link info
+browser_os::LinkInfo ContentProcessor::ExtractLinkInfo(const NodeInfo& node) {
+  browser_os::LinkInfo link;
+  
+  // Get URL
+  link.url = node.url;
+  
+  // Get link text (name or inner text)
+  link.text = node.name;
+  
+  // Get title attribute
+  auto title_it = node.attributes.find("title");
+  if (title_it != node.attributes.end()) {
+    link.title = title_it->second;
+  }
+  
+  // Determine if external
+  link.is_external = IsExternalUrl(link.url);
+  
+  // Add additional attributes
+  browser_os::LinkInfo::Attributes attrs;
+  attrs.additional_properties.Set("role", node.role);
+  if (node.attributes.find("html-tag") != node.attributes.end()) {
+    attrs.additional_properties.Set("tag", node.attributes.at("html-tag"));
+  }
+  link.attributes = std::move(attrs);
+  
+  return link;
+}
+
+// Helper to check if node is a link
+bool ContentProcessor::IsLink(const NodeInfo& node) {
+  return (node.role == "link" || !node.url.empty()) &&
+         node.url != "#";  // Skip empty fragment links
+}
+
+// Helper to check if node has text content
+bool ContentProcessor::IsTextNode(const NodeInfo& node) {
+  // Include nodes with text content
+  return !node.name.empty() || !node.value.empty() ||
+         node.attributes.find("placeholder") != node.attributes.end();
+}
+
+
+// ============================================================================
+// Parallel Batch Processing with Integrated Section Detection
+// ============================================================================
+
+// Process a batch of nodes in parallel with section detection
+void ContentProcessor::ProcessNodeBatchParallel(
+    const std::vector<ui::AXNodeData>& batch,
+    scoped_refptr<ProcessingContext> context) {
+  
+  // Process each node in the batch
+  for (const auto& ax_node : batch) {
+    // Skip invisible or ignored nodes
+    if (ax_node.IsInvisibleOrIgnored()) {
+      continue;
+    }
+    
+    // Skip if visibility filtering is enabled and node is not visible
+    if (context->snapshot_context == browser_os::SnapshotContext::kVisible) {
+      gfx::Rect viewport_bounds(context->viewport_size);
+      gfx::Rect node_bounds = gfx::ToEnclosingRect(ax_node.relative_bounds.bounds);
+      if (!viewport_bounds.IsEmpty() && !viewport_bounds.Intersects(node_bounds)) {
+        continue;
+      }
+    }
+    
+    // Determine which section this node belongs to
+    browser_os::SectionType section_type = DetermineNodeSection(
+        ax_node.id, context->node_map, context);
+    
+    // Check if we should include this section
+    if (!context->include_sections.empty()) {
+      bool should_include = false;
+      for (const auto& included : context->include_sections) {
+        if (included == section_type) {
+          should_include = true;
+          break;
+        }
+      }
+      if (!should_include) {
+        continue;
+      }
+    }
+    
+    // Process based on snapshot type
+    if (context->snapshot_type == browser_os::SnapshotType::kText) {
+      // Extract text content
+      std::string text = ExtractTextFromAXNode(ax_node);
+      if (!text.empty()) {
+        AddTextToSection(section_type, text, context);
+      }
+    } else if (context->snapshot_type == browser_os::SnapshotType::kLinks) {
+      // Check if this is a link
+      if (IsLinkNode(ax_node)) {
+        browser_os::LinkInfo link = ExtractLinkFromAXNode(ax_node);
+        // Only add links that have a non-empty URL
+        if (!link.url.empty()) {
+          AddLinkToSection(section_type, std::move(link), context);
+        }
+      }
+    }
+  }
+}
+
+// Helper to extract text from AXNodeData
+std::string ContentProcessor::ExtractTextFromAXNode(const ui::AXNodeData& node) {
+  std::vector<std::string> text_parts;
+  
+  // Get name
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kName)) {
+    text_parts.push_back(node.GetStringAttribute(ax::mojom::StringAttribute::kName));
+  }
+  
+  // Get value for input elements
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kValue)) {
+    text_parts.push_back(node.GetStringAttribute(ax::mojom::StringAttribute::kValue));
+  }
+  
+  // Get placeholder
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kPlaceholder)) {
+    text_parts.push_back(node.GetStringAttribute(ax::mojom::StringAttribute::kPlaceholder));
+  }
+  
+  // Join all text parts
+  std::string result = base::JoinString(text_parts, " ");
+  return CleanTextForOutput(result);
+}
+
+// Helper to check if node is a link
+bool ContentProcessor::IsLinkNode(const ui::AXNodeData& node) {
+  // Use the official IsLink function from ax_role_properties
+  if (!ui::IsLink(node.role)) {
+    return false;
+  }
+  
+  // Also check for valid URL (skip empty fragment links)
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kUrl)) {
+    const std::string& url = node.GetStringAttribute(ax::mojom::StringAttribute::kUrl);
+    return !url.empty() && url != "#";
+  }
+  
+  // Link role without URL is still a valid link (might have onclick handler)
+  return true;
+}
+
+// Helper to extract link info from AXNodeData
+browser_os::LinkInfo ContentProcessor::ExtractLinkFromAXNode(const ui::AXNodeData& node) {
+  browser_os::LinkInfo link;
+  
+  // Get URL
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kUrl)) {
+    link.url = node.GetStringAttribute(ax::mojom::StringAttribute::kUrl);
+  }
+  
+  // Get link text
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kName)) {
+    link.text = node.GetStringAttribute(ax::mojom::StringAttribute::kName);
+  }
+  
+  // Get title attribute
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kTooltip)) {
+    link.title = node.GetStringAttribute(ax::mojom::StringAttribute::kTooltip);
+  }
+  
+  // Determine if external
+  link.is_external = IsExternalUrl(link.url);
+  
+  // Add additional attributes
+  browser_os::LinkInfo::Attributes attrs;
+  attrs.additional_properties.Set("role", ui::ToString(node.role));
+  if (node.HasStringAttribute(ax::mojom::StringAttribute::kHtmlTag)) {
+    attrs.additional_properties.Set("tag", 
+        node.GetStringAttribute(ax::mojom::StringAttribute::kHtmlTag));
+  }
+  link.attributes = std::move(attrs);
+  
+  return link;
+}
+
+
+// Callback when batch is processed
+void ContentProcessor::OnBatchProcessed(
+    scoped_refptr<ProcessingContext> context) {
+  
+  // Decrement pending batches atomically
+  int remaining = context->pending_batches.fetch_sub(1) - 1;
+  
+  // Check if all batches are complete
+  if (remaining == 0) {
+    OnAllBatchesComplete(context);
+  }
+}
+
+// Called when all batches are complete
+void ContentProcessor::OnAllBatchesComplete(scoped_refptr<ProcessingContext> context) {
+  // All processing is already done in parallel batches!
+  // Just need to convert sections to API format
+  
+  // Build result snapshot
+  browser_os::Snapshot snapshot;
+  snapshot.type = context->snapshot_type;
+  snapshot.context = context->snapshot_context;
+  snapshot.timestamp = base::Time::Now().InMillisecondsFSinceUnixEpoch();
+  
+  // Convert sections to API format
+  {
+    base::AutoLock lock(context->sections_lock);
+    for (const auto& [section_type, section_ptr] : context->sections) {
+      if (!section_ptr) continue;
+      
+      browser_os::SnapshotSection api_section;
+      api_section.type = SectionTypeToString(section_type);
+      
+      // Always create both results (one will be empty)
+      browser_os::TextSnapshotResult text_result;
+      browser_os::LinksSnapshotResult links_result;
+      
+      // Populate based on type
+      if (context->snapshot_type == browser_os::SnapshotType::kText) {
+        text_result.text = std::move(section_ptr->text_content);
+        text_result.character_count = text_result.text.length();
+      } else if (context->snapshot_type == browser_os::SnapshotType::kLinks) {
+        links_result.links = std::move(section_ptr->links);
+      }
+      
+      api_section.text_result = std::move(text_result);
+      api_section.links_result = std::move(links_result);
+      
+      snapshot.sections.push_back(std::move(api_section));
+    }
+  }
+  
+  // Calculate processing time
+  base::TimeDelta processing_time = base::Time::Now() - context->start_time;
+  snapshot.processing_time_ms = processing_time.InMilliseconds();
+  
+  LOG(INFO) << "[PERF] Content snapshot processed in " 
+            << processing_time.InMilliseconds() << " ms"
+            << " (sections: " << snapshot.sections.size() << ")";
+  
+  // Create result
+  ContentProcessingResult result;
+  result.snapshot = std::move(snapshot);
+  result.nodes_processed = context->node_map.size();
+  result.processing_time_ms = processing_time.InMilliseconds();
+  
+  // Run callback
+  std::move(context->callback).Run(std::move(result));
+}
+
+// Main processing function
+void ContentProcessor::ProcessAccessibilityTree(
+    const ui::AXTreeUpdate& tree_update,
+    browser_os::SnapshotType type,
+    browser_os::SnapshotContext context,
+    const std::vector<browser_os::SectionType>& include_sections,
+    const gfx::Size& viewport_size,
+    base::OnceCallback<void(ContentProcessingResult)> callback) {
+  
+  // Create processing context
+  auto processing_context = base::MakeRefCounted<ProcessingContext>();
+  processing_context->tree_update = tree_update;
+  processing_context->snapshot_type = type;
+  processing_context->snapshot_context = context;
+  processing_context->include_sections = include_sections;
+  processing_context->viewport_size = viewport_size;
+  processing_context->callback = std::move(callback);
+  processing_context->start_time = base::Time::Now();
+  
+  // Build node map upfront (read-only after this)
+  for (const auto& node : tree_update.nodes) {
+    processing_context->node_map[node.id] = node;
+  }
+  
+  // Pre-identify section roots for faster lookup
+  for (const auto& node : tree_update.nodes) {
+    browser_os::SectionType section_type = GetSectionTypeFromNode(node);
+    if (section_type != browser_os::SectionType::kNone) {
+      base::AutoLock lock(processing_context->section_cache_lock);
+      processing_context->section_root_nodes[node.id] = section_type;
+      processing_context->node_to_section_cache[node.id] = section_type;
+    }
+  }
+  
+  // Handle empty case
+  if (tree_update.nodes.empty()) {
+    ContentProcessingResult result;
+    result.snapshot.type = type;
+    result.snapshot.context = context;
+    result.snapshot.timestamp = base::Time::Now().InMillisecondsFSinceUnixEpoch();
+    result.snapshot.processing_time_ms = 0;
+    result.nodes_processed = 0;
+    std::move(processing_context->callback).Run(std::move(result));
+    return;
+  }
+  
+  // Process nodes in batches
+  const size_t batch_size = 100;
+  size_t num_batches = (tree_update.nodes.size() + batch_size - 1) / batch_size;
+  processing_context->pending_batches = num_batches;
+  
+  for (size_t i = 0; i < tree_update.nodes.size(); i += batch_size) {
+    size_t end = std::min(i + batch_size, tree_update.nodes.size());
+    std::vector<ui::AXNodeData> batch(
+        tree_update.nodes.begin() + i,
+        tree_update.nodes.begin() + end);
+    
+    // Post task to ThreadPool with reply
+    base::ThreadPool::PostTaskAndReply(
+        FROM_HERE,
+        {base::TaskPriority::USER_VISIBLE},
+        base::BindOnce(&ContentProcessor::ProcessNodeBatchParallel,
+                       std::move(batch),
+                       processing_context),
+        base::BindOnce(&ContentProcessor::OnBatchProcessed,
+                       processing_context));
+  }
+}
+
+}  // namespace api
+}  // namespace extensions
\ No newline at end of file
