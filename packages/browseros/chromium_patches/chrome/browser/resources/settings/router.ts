diff --git a/chrome/browser/resources/settings/router.ts b/chrome/browser/resources/settings/router.ts
index 236c564f9b909..393a3c259c2e1 100644
--- a/chrome/browser/resources/settings/router.ts
+++ b/chrome/browser/resources/settings/router.ts
@@ -14,6 +14,8 @@ import {loadTimeData} from './i18n_setup.js';
 export interface SettingsRoutes {
   ABOUT: Route;
   ACCESSIBILITY: Route;
+  NXTSCAPE: Route;
+  BROWSEROS_PREFS: Route;
   ADDRESSES: Route;
   ADVANCED: Route;
   AI: Route;
