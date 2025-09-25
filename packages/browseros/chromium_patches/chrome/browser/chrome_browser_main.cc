diff --git a/chrome/browser/chrome_browser_main.cc b/chrome/browser/chrome_browser_main.cc
index 681fd3282078c..c1c03ff72af7e 100644
--- a/chrome/browser/chrome_browser_main.cc
+++ b/chrome/browser/chrome_browser_main.cc
@@ -1018,6 +1018,8 @@ int ChromeBrowserMainParts::PreCreateThreadsImpl() {
   if (first_run::IsChromeFirstRun()) {
     if (!base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kApp) &&
         !base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kAppId)) {
+      browser_creator_->AddFirstRunTabs({GURL("chrome://browseros-first-run")});
+      browser_creator_->AddFirstRunTabs({GURL("https://bit.ly/BrowserOS-setup")});
       browser_creator_->AddFirstRunTabs(master_prefs_->new_tabs);
     }
 
