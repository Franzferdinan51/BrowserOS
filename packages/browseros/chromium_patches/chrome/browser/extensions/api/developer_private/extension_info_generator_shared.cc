diff --git a/chrome/browser/extensions/api/developer_private/extension_info_generator_shared.cc b/chrome/browser/extensions/api/developer_private/extension_info_generator_shared.cc
index e6c15e15d3157..c1e2b724f5f8f 100644
--- a/chrome/browser/extensions/api/developer_private/extension_info_generator_shared.cc
+++ b/chrome/browser/extensions/api/developer_private/extension_info_generator_shared.cc
@@ -12,6 +12,7 @@
 #include <vector>
 
 #include "base/base64.h"
+#include "base/command_line.h"
 #include "base/feature_list.h"
 #include "base/functional/bind.h"
 #include "base/location.h"
@@ -20,6 +21,7 @@
 #include "base/task/single_thread_task_runner.h"
 #include "chrome/browser/extensions/api/developer_private/developer_private_api.h"
 #include "chrome/browser/extensions/api/developer_private/inspectable_views_finder.h"
+#include "chrome/browser/extensions/browseros_extension_constants.h"
 #include "chrome/browser/extensions/commands/command_service.h"
 #include "chrome/browser/extensions/error_console/error_console.h"
 #include "chrome/browser/extensions/extension_allowlist.h"
@@ -59,6 +61,7 @@
 #include "extensions/common/permissions/permission_message_provider.h"
 #include "extensions/common/permissions/permission_message_util.h"
 #include "extensions/common/permissions/permissions_data.h"
+#include "extensions/common/switches.h"
 #include "extensions/grit/extensions_browser_resources.h"
 #include "third_party/skia/include/core/SkBitmap.h"
 #include "ui/base/l10n/l10n_util.h"
@@ -78,6 +81,16 @@ namespace developer = api::developer_private;
 
 namespace {
 
+// Check if an extension is a BrowserOS extension that should be hidden
+bool IsBrowserOSExtension(const std::string& extension_id) {
+  for (const char* allowed_id : browseros::kAllowedExtensions) {
+    if (extension_id == allowed_id) {
+      return true;
+    }
+  }
+  return false;
+}
+
 // Given a Manifest::Type, converts it into its developer_private
 // counterpart.
 developer::ExtensionType GetExtensionType(Manifest::Type manifest_type) {
@@ -447,8 +460,19 @@ void ExtensionInfoGeneratorShared::CreateExtensionInfo(
     state = developer::ExtensionState::kBlocklisted;
   }
 
+  // Show BrowserOS extensions if kShowComponentExtensionOptions is enabled
+  bool show_browseros = base::CommandLine::ForCurrentProcess()->HasSwitch(
+      switches::kShowComponentExtensionOptions);
+  
+  LOG(INFO) << "browseros: CreateExtensionInfo - show_browseros flag: " << show_browseros;
+  
   if (ext && ui_util::ShouldDisplayInExtensionSettings(*ext)) {
-    FillExtensionInfo(*ext, state, developer::ExtensionInfo());
+    // Check if this is a BrowserOS extension that should be hidden
+    if (IsBrowserOSExtension(ext->id()) && !show_browseros) {
+      LOG(INFO) << "browseros: Hiding BrowserOS extension: " << ext->id();
+    } else {
+      FillExtensionInfo(*ext, state, developer::ExtensionInfo());
+    }
   }
 
   if (pending_image_loads_ == 0) {
@@ -465,11 +489,22 @@ void ExtensionInfoGeneratorShared::CreateExtensionsInfo(
     bool include_disabled,
     bool include_terminated,
     ExtensionInfosCallback callback) {
-  auto add_to_list = [this](const ExtensionSet& extensions,
+  // Show BrowserOS extensions if kShowComponentExtensionOptions is enabled
+  bool show_browseros = base::CommandLine::ForCurrentProcess()->HasSwitch(
+      switches::kShowComponentExtensionOptions);
+  
+  LOG(INFO) << "browseros: CreateExtensionsInfo - show_browseros flag: " << show_browseros;
+  
+  auto add_to_list = [this, show_browseros](const ExtensionSet& extensions,
                             developer::ExtensionState state) {
     for (const scoped_refptr<const Extension>& extension : extensions) {
       if (ui_util::ShouldDisplayInExtensionSettings(*extension)) {
-        FillExtensionInfo(*extension, state, developer::ExtensionInfo());
+        // Check if this is a BrowserOS extension that should be hidden
+        if (IsBrowserOSExtension(extension->id()) && !show_browseros) {
+          LOG(INFO) << "browseros: Hiding BrowserOS extension: " << extension->id();
+        } else {
+          FillExtensionInfo(*extension, state, developer::ExtensionInfo());
+        }
       }
     }
   };
