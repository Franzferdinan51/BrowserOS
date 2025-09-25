diff --git a/chrome/browser/resources/settings/route.ts b/chrome/browser/resources/settings/route.ts
index 2458ecb3791b0..c8996cc719973 100644
--- a/chrome/browser/resources/settings/route.ts
+++ b/chrome/browser/resources/settings/route.ts
@@ -183,6 +183,8 @@ function createRoutes(): SettingsRoutes {
   // Root pages.
   r.BASIC = new Route('/');
   r.ABOUT = new Route('/help', loadTimeData.getString('aboutPageTitle'));
+  r.NXTSCAPE = new Route('/browseros-ai', 'BrowserOS AI Settings');
+  r.BROWSEROS_PREFS = new Route('/browseros-settings', 'BrowserOS Settings');
 
   r.SEARCH = r.BASIC.createSection(
       '/search', 'search', loadTimeData.getString('searchPageTitle'));
