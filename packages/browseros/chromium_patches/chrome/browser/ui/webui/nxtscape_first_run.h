diff --git a/chrome/browser/ui/webui/nxtscape_first_run.h b/chrome/browser/ui/webui/nxtscape_first_run.h
new file mode 100644
index 0000000000000..ceaa893d34c69
--- /dev/null
+++ b/chrome/browser/ui/webui/nxtscape_first_run.h
@@ -0,0 +1,194 @@
+#ifndef CHROME_BROWSER_UI_WEBUI_NXTSCAPE_FIRST_RUN_H_
+#define CHROME_BROWSER_UI_WEBUI_NXTSCAPE_FIRST_RUN_H_
+
+#include "base/memory/ref_counted_memory.h"
+#include "chrome/browser/profiles/profile.h"
+#include "content/public/browser/url_data_source.h"
+#include "content/public/browser/web_ui.h"
+#include "content/public/browser/web_ui_controller.h"
+#include "content/public/browser/webui_config.h"
+#include "services/network/public/mojom/content_security_policy.mojom.h"
+
+class UFRDataSource : public content::URLDataSource {
+ public:
+  UFRDataSource() {}
+  UFRDataSource(const UFRDataSource&) = delete;
+  UFRDataSource& operator=(const UFRDataSource&) = delete;
+
+  // URLDataSource implementation:
+  std::string GetSource() override;
+  std::string GetMimeType(const GURL& url) override;
+  std::string GetContentSecurityPolicy(network::mojom::CSPDirectiveName directive) override;
+  void StartDataRequest(const GURL& url,
+                        const content::WebContents::Getter& wc_getter,
+                        GotDataCallback callback) override;
+};
+
+// Implementation of UFRDataSource
+std::string UFRDataSource::GetSource() {
+  return "browseros-first-run";
+}
+
+std::string UFRDataSource::GetMimeType(const GURL& url) {
+  return "text/html";
+}
+
+std::string UFRDataSource::GetContentSecurityPolicy(network::mojom::CSPDirectiveName directive) {
+  if (directive == network::mojom::CSPDirectiveName::ScriptSrc)
+    return "script-src 'unsafe-inline'";
+  return std::string();
+}
+
+void UFRDataSource::StartDataRequest(const GURL& url,
+                                    const content::WebContents::Getter& wc_getter,
+                                    GotDataCallback callback) {
+  std::string source = R"(<!DOCTYPE html>
+<html lang="en">
+<head>
+<title>BrowserOS First Run</title>
+<meta charset="UTF-8">
+<meta name="color-scheme" content="light dark">
+<style>
+ @import url(chrome://resources/css/text_defaults_md.css);
+ html{color:#202124; background:white; line-height:1.2em; font-family: sans-serif; font-size: 1.1em;}
+ a{color:#1967d2; text-decoration: none;}
+ a:hover{text-decoration: underline;}
+ h2{margin:0; padding:0.8em 1.33em; font-size: 1.5em;}
+ p,details{border-top:.063em solid #f0f0f0; margin:0; padding:1.2em 2em;}
+ ul,ol{padding-left:2.5em; margin-top: 0.5em; margin-bottom: 0.5em;}
+ code{background:rgba(128 128 128 / .2); padding:0.2em 0.5em; border-radius:0.25em; font-size: 0.9em;}
+ summary{cursor:pointer; font-weight: bold; padding: 0.5em 0;}
+ section{width:60em; max-width: 90%; margin:3.5em auto; padding:2em 2.5em; border-radius:.75em;
+         background:white; box-shadow:0 .1em .2em 0 rgba(0,0,0,0.1), 0 .2em .5em 0 rgba(0,0,0,0.1);}
+ .hero {text-align: center; padding-bottom: 1em;}
+ .hero h1 {font-size: 2.5em; margin-bottom: 0.2em; color: #333;}
+ .hero p {font-size: 1.1em; color: #555; border-top: none; padding-top: 0;}
+ .section-title { font-size: 1.8em; margin-bottom: 0.5em; color: #444;}
+ .feature-list li { margin-bottom: 0.5em; }
+ .community-links a { display: inline-block; margin: 0.5em; padding: 0.5em 1em; background-color: #f0f0f0; border-radius: 0.3em; color: #333; }
+ .community-links a:hover { background-color: #e0e0e0; }
+ .sub-headline {
+  display: block;
+  margin-top: 1.0em;
+ }
+
+ @media(prefers-color-scheme:dark){
+  html{color:#e8eaed; background:#202124}
+  a{color:#8ab4f8}
+  p,details{border-top:.063em solid #3f4042}
+  section{background:#292a2d; box-shadow:0 .1em .2em 0 rgba(0,0,0,0.3), 0 .2em .5em 0 rgba(0,0,0,0.3);}
+  .hero h1 {color: #f1f1f1;}
+  .hero p {color: #ccc;}
+  .section-title { color: #ddd;}
+  .community-links a { background-color: #3a3b3d; color: #e8eaed; }
+  .community-links a:hover { background-color: #4a4b4d; }
+ }
+</style>
+<base target="_blank">
+</head>
+<body>
+<section class="hero">
+ <h1>The Open-Source Agentic Browser 🦊</h1>
+ <p class="sub-headline">Your Browser, Reimagined. ✨</p>
+ <p>We believe browsers must be open source, not owned by search or ad companies. And the future is AI agents automating your work locally and securely. We're building the best browser for that future. 🚀</p>
+ <p style="font-size:0.9em; color: #777;">This page can always be accessed again at <a href="chrome://browseros-first-run"><code>chrome://browseros-first-run</code></a></p>
+</section>
+
+<section>
+ <h2 class="section-title">🚀 Getting Started</h2>
+ <p style="text-align: center; margin: 1em 0; padding: 0.8em; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 0.5em;">
+  <a href="https://bit.ly/BrowserOS-setup" target="_blank" style="color: white; font-weight: bold; font-size: 1.1em;">
+   📖 Quick Start Guide - bit.ly/BrowserOS-setup
+  </a>
+ </p>
+ <details open>
+  <summary><b>📥 Import your data from Chrome</b></summary>
+  <ol>
+   <li>Navigate to <a href="chrome://settings/importData"><code>chrome://settings/importData</code></a></li>
+   <li>Click "Import"</li>
+   <li>Follow the on-screen prompts and click "Always allow" when prompted to import all your data at once</li>
+  </ol>
+ </details>
+ <details>
+  <summary><b>🔑 BYOK (Bring Your Own Keys)</b></summary>
+  <p style="padding: 1em 2em;">
+   You have full control over your AI models! Navigate to <a href="chrome://settings/browseros"><code>chrome://settings/browseros</code></a> to configure your own API keys for various providers.
+  </p>
+  <p style="padding: 0.5em 2em 1em 2em;">
+   <strong>Note:</strong> You can even run everything locally using <a href="https://ollama.com">Ollama</a>! 🔒
+  </p>
+ </details>
+ <details>
+  <summary><b>⌨️ Keyboard Shortcuts</b></summary>
+  <p style="padding: 1em 2em;">
+   <strong>Toggle AI Agent:</strong> Press <code>Cmd+E</code> to quickly open or close the AI agent sidebar. 🤖
+  </p>
+ </details>
+</section>
+
+<section>
+ <h2 class="section-title">✨ Key Features</h2>
+ <ul class="feature-list">
+  <li>🤖 <strong>BrowserOS Agent:</strong> Your productivity agent that can manage your tabs and browsing sessions. For example:
+   <ul>
+    <li>"list tabs I have open"</li>
+    <li>"close duplicate tabs"</li>
+    <li>"group tabs by topic"</li>
+    <li>"switch to Bookface tab"</li>
+    <li>"save my current browsing session as XYZ-Research"</li>
+    <li>"resume XYZ-Research browsing session"</li>
+    <li>"search my browser history for all github pages I visited"</li>
+    <li>"organize my entire bookmark collection"</li>
+   </ul>
+  </li>
+  <li>🧭 <strong>BrowserOS Navigator:</strong> Performs agentic tasks for you on web pages. For example:
+   <ul>
+    <li>Go to amazon.com and search for "hard disk"</li>
+    <li>Navigate to specific pages and interact with content</li>
+    <li>Automate repetitive browsing tasks</li>
+   </ul>
+  </li>
+ </ul>
+</section>
+
+<section>
+ <h2 class="section-title">🤝 Join Our Community & Explore</h2>
+ <p class="community-links">
+  <a href="https://discord.gg/YKwjt5vuKr">💬 Discord</a>
+  <a href="https://github.com/browseros-ai/BrowserOS">💻 GitHub</a>
+  <a href="https://x.com/browseros_ai">🐦 X (Twitter)</a>
+ </p>
+ <p style="font-size:0.9em; text-align:center;">Have questions or want to contribute? We'd love to hear from you!</p>
+</section>
+
+<script>
+ document.getElementById("bdic").onchange = function(e){
+  var f = new FileReader;
+  f.onload = function(){
+   var a = document.createElement("a");
+   a.setAttribute("href", "data:application/octet-stream;base64, " + f.result);
+   a.setAttribute("download", e.target.files[0].name.replace(/\.[^/.]+$/, ".bdic"));
+   a.click()
+  }, f.readAsText(this.files[0])};
+</script>
+</body>
+</html>)";
+  std::move(callback).Run(base::MakeRefCounted<base::RefCountedString>(std::move(source)));
+}
+
+class NxtscapeFirstRun;
+class NxtscapeFirstRunUIConfig : public content::DefaultWebUIConfig<NxtscapeFirstRun> {
+  public:
+   NxtscapeFirstRunUIConfig() : DefaultWebUIConfig("chrome", "browseros-first-run") {}
+};
+
+class NxtscapeFirstRun : public content::WebUIController {
+ public:
+  NxtscapeFirstRun(content::WebUI* web_ui) : content::WebUIController(web_ui) {
+    content::URLDataSource::Add(Profile::FromWebUI(web_ui), std::make_unique<UFRDataSource>());
+  }
+  NxtscapeFirstRun(const NxtscapeFirstRun&) = delete;
+  NxtscapeFirstRun& operator=(const NxtscapeFirstRun&) = delete;
+};
+
+#endif  // CHROME_BROWSER_UI_WEBUI_NXTSCAPE_FIRST_RUN_H_
