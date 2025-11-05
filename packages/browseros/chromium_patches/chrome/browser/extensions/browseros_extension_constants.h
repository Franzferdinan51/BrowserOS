diff --git a/chrome/browser/extensions/browseros_extension_constants.h b/chrome/browser/extensions/browseros_extension_constants.h
new file mode 100644
index 0000000000000..17b78fbb99a9f
--- /dev/null
+++ b/chrome/browser/extensions/browseros_extension_constants.h
@@ -0,0 +1,80 @@
+// Copyright 2024 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef CHROME_BROWSER_EXTENSIONS_BROWSEROS_EXTENSION_CONSTANTS_H_
+#define CHROME_BROWSER_EXTENSIONS_BROWSEROS_EXTENSION_CONSTANTS_H_
+
+#include <optional>
+#include <string>
+#include <vector>
+
+namespace extensions {
+namespace browseros {
+
+// AI Agent Extension ID
+inline constexpr char kAISidePanelExtensionId[] =
+    "djhdjhlnljbjgejbndockeedocneiaei";
+
+// Bug Reporter Extension ID
+inline constexpr char kBugReporterExtensionId[] =
+    "adlpneommgkgeanpaekgoaolcpncohkf";
+
+// Controller Extension ID
+inline constexpr char kControllerExtensionId[] =
+    "nlnihljpboknmfagkikhkdblbedophja";
+
+// BrowserOS CDN update manifest URL
+// Used for extensions installed from local .crx files that don't have
+// an update_url in their manifest
+inline constexpr char kBrowserOSUpdateUrl[] =
+    "https://cdn.browseros.com/extensions/update-manifest.xml";
+
+// Allowlist of BrowserOS extension IDs that are permitted to be installed
+// Only extensions with these IDs will be loaded from the config
+constexpr const char* kAllowedExtensions[] = {
+    kAISidePanelExtensionId,  // AI Side Panel extension
+    kBugReporterExtensionId,  // Bug Reporter extension
+    kControllerExtensionId,   // Controller extension
+};
+
+// Check if an extension is a BrowserOS extension
+inline bool IsBrowserOSExtension(const std::string& extension_id) {
+  return extension_id == kAISidePanelExtensionId ||
+         extension_id == kBugReporterExtensionId ||
+         extension_id == kControllerExtensionId;
+}
+
+// Check if an extension can be uninstalled (false for BrowserOS extensions)
+inline bool CanUninstallExtension(const std::string& extension_id) {
+  return !IsBrowserOSExtension(extension_id);
+}
+
+// Get all BrowserOS extension IDs
+inline std::vector<std::string> GetBrowserOSExtensionIds() {
+  return {
+    kAISidePanelExtensionId,
+    kBugReporterExtensionId,
+    kControllerExtensionId
+  };
+}
+
+// Get display name for BrowserOS extensions in omnibox
+// Returns the display name if extension_id is a BrowserOS extension,
+// otherwise returns std::nullopt
+inline std::optional<std::string> GetExtensionDisplayName(
+    const std::string& extension_id) {
+  if (extension_id == kAISidePanelExtensionId) {
+    return "BrowserOS";
+  } else if (extension_id == kBugReporterExtensionId) {
+    return "BrowserOS/bug-reporter";
+  } else if (extension_id == kControllerExtensionId) {
+    return "BrowserOS/controller";
+  }
+  return std::nullopt;
+}
+
+}  // namespace browseros
+}  // namespace extensions
+
+#endif  // CHROME_BROWSER_EXTENSIONS_BROWSEROS_EXTENSION_CONSTANTS_H_
