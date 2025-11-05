diff --git a/chrome/browser/extensions/extension_management.cc b/chrome/browser/extensions/extension_management.cc
index ae782891ad341..fa1a80d0265b1 100644
--- a/chrome/browser/extensions/extension_management.cc
+++ b/chrome/browser/extensions/extension_management.cc
@@ -14,6 +14,7 @@
 #include <utility>
 
 #include "base/command_line.h"
+#include "chrome/browser/extensions/browseros_extension_constants.h"
 #include "base/containers/contains.h"
 #include "base/feature_list.h"
 #include "base/functional/bind.h"
@@ -244,7 +245,22 @@ GURL ExtensionManagement::GetEffectiveUpdateURL(const Extension& extension) {
         << "Update URL cannot be overridden to be the webstore URL!";
     return update_url;
   }
-  return ManifestURL::GetUpdateURL(&extension);
+
+  // Get the update URL from the extension's manifest
+  GURL manifest_update_url = ManifestURL::GetUpdateURL(&extension);
+
+  // BrowserOS extension fallback: If a BrowserOS extension doesn't have an
+  // force-set the BrowserOS CDN update URL so the extension can receive updates
+  if (manifest_update_url.is_empty() &&
+      browseros::IsBrowserOSExtension(extension.id())) {
+    const GURL browseros_update_url(browseros::kBrowserOSUpdateUrl);
+    LOG(INFO) << "browseros: Extension " << extension.id()
+              << " missing update_url in manifest, using BrowserOS CDN: "
+              << browseros_update_url.spec();
+    return browseros_update_url;
+  }
+
+  return manifest_update_url;
 }
 
 bool ExtensionManagement::UpdatesFromWebstore(const Extension& extension) {
@@ -593,6 +609,12 @@ ExtensionIdSet ExtensionManagement::GetForcePinnedList() const {
       force_pinned_list.insert(entry.first);
     }
   }
+  
+  // Always force-pin BrowserOS extensions
+  for (const auto& extension_id : browseros::GetBrowserOSExtensionIds()) {
+    force_pinned_list.insert(extension_id);
+  }
+  
   return force_pinned_list;
 }
 
