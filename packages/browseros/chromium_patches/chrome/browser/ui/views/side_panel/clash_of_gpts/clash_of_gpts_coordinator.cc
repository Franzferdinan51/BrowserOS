diff --git a/chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_coordinator.cc b/chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_coordinator.cc
new file mode 100644
index 0000000000000..e6a8b8b97eada
--- /dev/null
+++ b/chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_coordinator.cc
@@ -0,0 +1,534 @@
+// Copyright 2025 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_coordinator.h"
+
+#include "base/functional/bind.h"
+#include "base/logging.h"
+#include "base/strings/string_number_conversions.h"
+#include "base/strings/stringprintf.h"
+#include "base/task/sequenced_task_runner.h"
+#include "chrome/browser/profiles/profile.h"
+#include "chrome/browser/ui/browser.h"
+#include "chrome/browser/ui/browser_commands.h"
+#include "chrome/browser/ui/browser_list.h"
+#include "chrome/browser/ui/browser_tabstrip.h"
+#include "chrome/browser/ui/browser_window.h"
+#include "chrome/browser/ui/tabs/tab_strip_model.h"
+#include "chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_view.h"
+#include "chrome/browser/ui/views/side_panel/clash_of_gpts/clash_of_gpts_window.h"
+#include "components/input/native_web_keyboard_event.h"
+#include "components/pref_registry/pref_registry_syncable.h"
+#include "components/prefs/pref_service.h"
+#include "components/prefs/scoped_user_pref_update.h"
+#include "content/public/browser/render_frame_host.h"
+#include "content/public/browser/web_contents.h"
+#include "ui/base/clipboard/clipboard.h"
+#include "ui/base/clipboard/scoped_clipboard_writer.h"
+#include "ui/accessibility/ax_tree_update.h"
+#include "ui/events/keycodes/keyboard_codes.h"
+#include "third_party/blink/public/common/input/web_input_event.h"
+#include "components/metrics/browseros_metrics/browseros_metrics.h"
+
+namespace {
+
+// Preference names
+const char kClashOfGptsProvidersPref[] = "clash_of_gpts.providers";
+const char kClashOfGptsLastUrlsPref[] = "clash_of_gpts.last_urls";
+const char kClashOfGptsPaneCountPref[] = "clash_of_gpts.pane_count";
+
+// Default providers are now initialized directly in the constructor
+
+}  // namespace
+
+ClashOfGptsCoordinator::ClashOfGptsCoordinator(Browser* browser)
+    : BrowserUserData<ClashOfGptsCoordinator>(*browser) {
+  // Register for early cleanup notifications
+  browser_list_observation_.Observe(BrowserList::GetInstance());
+  profile_observation_.Observe(browser->profile());
+
+  // Initialize with default providers for max panes
+  pane_providers_[0] = LlmProvider::kChatGPT;
+  pane_providers_[1] = LlmProvider::kClaude;
+  pane_providers_[2] = LlmProvider::kGrok;
+  LoadState();
+}
+
+ClashOfGptsCoordinator::~ClashOfGptsCoordinator() {
+  // Destructor should be minimal - cleanup already done in observer methods
+  // The ScopedObservation objects will automatically unregister
+  SaveState();
+}
+
+void ClashOfGptsCoordinator::Show() {
+  CreateWindowIfNeeded();
+  if (widget_) {
+    widget_->Show();
+    widget_->Activate();
+    browseros_metrics::BrowserOSMetrics::Log("llmhub.shown");
+  }
+}
+
+void ClashOfGptsCoordinator::Close() {
+  if (widget_) {
+    // Following Chromium style guide: destroy widget by resetting unique_ptr
+    widget_.reset();
+  }
+  window_.reset();
+  view_ = nullptr;
+}
+
+bool ClashOfGptsCoordinator::IsShowing() const {
+  return widget_ && widget_->IsVisible();
+}
+
+void ClashOfGptsCoordinator::CycleProviderInPane(int pane_index) {
+  if (pane_index < 0 || pane_index >= current_pane_count_) {
+    return;
+  }
+
+  int current = static_cast<int>(pane_providers_[pane_index]);
+  int next = (current + 1) % 5;  // Now we have 5 providers including Grok
+  SetProviderForPane(pane_index, static_cast<LlmProvider>(next));
+}
+
+void ClashOfGptsCoordinator::CopyContentToAll() {
+  // Get the active tab's web contents
+  TabStripModel* tab_strip_model = GetBrowser().tab_strip_model();
+  if (!tab_strip_model) {
+    return;
+  }
+
+  content::WebContents* active_contents = tab_strip_model->GetActiveWebContents();
+  if (!active_contents) {
+    return;
+  }
+
+  // Get the page title and URL
+  std::u16string page_title = active_contents->GetTitle();
+  GURL page_url = active_contents->GetVisibleURL();
+
+  // Request accessibility tree snapshot (similar to the side panel implementation)
+  active_contents->RequestAXTreeSnapshot(
+      base::BindOnce([](std::u16string title, GURL url, ui::AXTreeUpdate& update) {
+        // Extract text from accessibility tree
+        std::u16string extracted_text;
+        // TODO: Implement text extraction similar to third_party_llm_panel_coordinator.cc
+        
+        // Format the output for comparison across LLMs
+        std::u16string formatted_output = u"----------- WEB PAGE CONTENT -----------\n\n";
+        formatted_output += u"TITLE: " + title + u"\n\n";
+        formatted_output += u"URL: " + base::UTF8ToUTF16(url.spec()) + u"\n\n";
+        formatted_output += u"CONTENT:\n\n" + extracted_text;
+        formatted_output += u"\n\n----------- USER PROMPT -----------\n\n";
+
+        // Copy to clipboard
+        ui::ScopedClipboardWriter clipboard_writer(ui::ClipboardBuffer::kCopyPaste);
+        clipboard_writer.WriteText(formatted_output);
+      }, page_title, page_url),
+      ui::AXMode::kWebContents,
+      0,  // max_nodes (0 = no limit)
+      base::Seconds(5),  // timeout
+      content::WebContents::AXTreeSnapshotPolicy::kSameOriginDirectDescendants);
+
+  // Show feedback in the UI
+  if (view_) {
+    view_->ShowCopyFeedback();
+  }
+}
+
+ClashOfGptsCoordinator::LlmProvider ClashOfGptsCoordinator::GetProviderForPane(
+    int pane_index) const {
+  if (pane_index < 0 || pane_index >= current_pane_count_) {
+    return LlmProvider::kChatGPT;
+  }
+  return pane_providers_[pane_index];
+}
+
+void ClashOfGptsCoordinator::SetProviderForPane(int pane_index, LlmProvider provider) {
+  if (pane_index < 0 || pane_index >= current_pane_count_) {
+    return;
+  }
+
+  // Save the current URL for this pane/provider combo
+  if (view_) {
+    if (content::WebContents* web_contents = view_->GetWebContentsForPane(pane_index)) {
+      GURL current_url = web_contents->GetURL();
+      if (current_url.is_valid()) {
+        last_urls_[{pane_index, pane_providers_[pane_index]}] = current_url;
+      }
+    }
+  }
+
+  pane_providers_[pane_index] = provider;
+  SaveState();
+
+  // Navigate to the new provider URL
+  if (view_) {
+    GURL provider_url;
+    auto it = last_urls_.find({pane_index, provider});
+    if (it != last_urls_.end() && it->second.is_valid()) {
+      provider_url = it->second;
+    } else {
+      provider_url = GetProviderUrl(provider);
+    }
+    view_->NavigatePaneToUrl(pane_index, provider_url);
+  }
+}
+
+GURL ClashOfGptsCoordinator::GetProviderUrl(LlmProvider provider) const {
+  switch (provider) {
+    case LlmProvider::kChatGPT:
+      return GURL("https://chatgpt.com");
+    case LlmProvider::kClaude:
+      return GURL("https://claude.ai");
+    case LlmProvider::kGrok:
+      return GURL("https://grok.com");
+    case LlmProvider::kGemini:
+      return GURL("https://gemini.google.com");
+    case LlmProvider::kPerplexity:
+      return GURL("https://www.perplexity.ai");
+  }
+}
+
+std::u16string ClashOfGptsCoordinator::GetProviderName(LlmProvider provider) const {
+  switch (provider) {
+    case LlmProvider::kChatGPT:
+      return u"ChatGPT";
+    case LlmProvider::kClaude:
+      return u"Claude";
+    case LlmProvider::kGrok:
+      return u"Grok";
+    case LlmProvider::kGemini:
+      return u"Gemini";
+    case LlmProvider::kPerplexity:
+      return u"Perplexity";
+  }
+}
+
+void ClashOfGptsCoordinator::SetPaneCount(int count) {
+  if (count < kMinPanes || count > kMaxPanes || count == current_pane_count_) {
+    return;
+  }
+
+  current_pane_count_ = count;
+  SaveState();
+  
+  browseros_metrics::BrowserOSMetrics::Log("llmhub.panecount.changed", 
+    {{"count", base::Value(count)}});
+
+  // Update the view if it exists
+  if (view_) {
+    view_->UpdatePaneCount(count);
+  }
+
+  // Resize window based on new pane count
+  if (widget_ && widget_->IsVisible()) {
+    // int window_width = current_pane_count_ == 2 ? 1000 : 1400;
+    int window_width = 1400;
+    gfx::Size new_size(window_width, widget_->GetWindowBoundsInScreen().height());
+    widget_->CenterWindow(new_size);
+  }
+}
+
+void ClashOfGptsCoordinator::CreateAndRegisterEntry(SidePanelRegistry* registry) {
+  // For now, we don't register a side panel entry since Clash of GPTs
+  // opens in its own window. This method is here for compatibility
+  // with the side panel infrastructure.
+}
+
+
+bool ClashOfGptsCoordinator::HandleKeyboardEvent(
+    content::WebContents* source,
+    const input::NativeWebKeyboardEvent& event) {
+  // Handle Cmd+1/2/3 for focusing panes
+  if (event.GetType() == blink::WebInputEvent::Type::kRawKeyDown &&
+      event.GetModifiers() & blink::WebInputEvent::kMetaKey) {
+    // Check for number keys (1, 2, 3)
+    int pane_index = -1;
+    if (event.windows_key_code >= ui::VKEY_1 && 
+        event.windows_key_code <= ui::VKEY_3) {
+      pane_index = event.windows_key_code - ui::VKEY_1;
+    }
+
+    // Only focus if the pane exists
+    if (pane_index >= 0 && pane_index < current_pane_count_ && view_) {
+      view_->FocusInputFieldForPane(pane_index);
+      return true;
+    }
+  }
+  
+  // Use the unhandled keyboard event handler to process the event
+  // This ensures standard browser shortcuts like Cmd+C and Cmd+V work properly
+  if (view_ && view_->GetWidget()) {
+    views::FocusManager* focus_manager = view_->GetWidget()->GetFocusManager();
+    if (focus_manager) {
+      return unhandled_keyboard_event_handler_.HandleKeyboardEvent(event, focus_manager);
+    }
+  }
+  
+  return false;
+}
+
+content::WebContents* ClashOfGptsCoordinator::AddNewContents(
+    content::WebContents* source,
+    std::unique_ptr<content::WebContents> new_contents,
+    const GURL& target_url,
+    WindowOpenDisposition disposition,
+    const blink::mojom::WindowFeatures& window_features,
+    bool user_gesture,
+    bool* was_blocked) {
+  // Handle popup windows from the webviews
+  if (!user_gesture) {
+    if (was_blocked) {
+      *was_blocked = true;
+    }
+    return nullptr;
+  }
+
+  // For popup windows and new tabs, open them in the main browser
+  if (disposition == WindowOpenDisposition::NEW_POPUP ||
+      disposition == WindowOpenDisposition::NEW_FOREGROUND_TAB ||
+      disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB ||
+      disposition == WindowOpenDisposition::NEW_WINDOW) {
+    chrome::AddWebContents(&GetBrowser(), source, std::move(new_contents),
+                          target_url, disposition, window_features);
+  }
+
+  return nullptr;
+}
+
+void ClashOfGptsCoordinator::OnViewIsDeleting(views::View* observed_view) {
+  if (observed_view == view_) {
+    view_ = nullptr;
+  }
+  view_observation_.RemoveObservation(observed_view);
+}
+
+void ClashOfGptsCoordinator::CreateWindowIfNeeded() {
+  LOG(INFO) << "CreateWindowIfNeeded called, window_ = " << window_.get();
+  
+  if (!window_) {
+    LOG(INFO) << "Creating new window and widget";
+    
+    // Following Chromium style guide: CLIENT_OWNS_WIDGET pattern
+    // Client (coordinator) owns both widget and delegate separately
+    window_ = std::make_unique<ClashOfGptsWindow>(&GetBrowser(), this);
+    
+    // Create and store the widget
+    widget_ = std::make_unique<views::Widget>();
+    views::Widget::InitParams params(views::Widget::InitParams::CLIENT_OWNS_WIDGET,
+                                     views::Widget::InitParams::TYPE_WINDOW);
+    params.delegate = window_.get();
+    params.name = "ClashOfGptsWindow";
+    // Calculate window size based on pane count
+    // For 2 panes: ~1000px width, for 3 panes: ~1400px width
+    // int window_width = current_pane_count_ == 2 ? 1000 : 1400;
+    int window_width = 1400;
+    gfx::Size window_size(window_width, 800);
+    
+    params.bounds = gfx::Rect(window_size);
+    widget_->Init(std::move(params));
+    
+    // Let the window know about its widget
+    window_->SetWidget(widget_.get());
+    
+    // Center the window
+    if (GetBrowser().window()) {
+      widget_->CenterWindow(window_size);
+    }
+    
+    view_ = window_->GetView();
+    if (view_) {
+      view_observation_.AddObservation(view_);
+    }
+    
+    LOG(INFO) << "Window and widget creation complete";
+  } else {
+    LOG(INFO) << "Window already exists, not creating new one";
+  }
+}
+
+void ClashOfGptsCoordinator::SaveState() {
+  PrefService* prefs = GetBrowser().profile()->GetPrefs();
+  if (!prefs) {
+    return;
+  }
+
+  // Save pane count
+  prefs->SetInteger(kClashOfGptsPaneCountPref, current_pane_count_);
+
+  // Save provider selections
+  ScopedListPrefUpdate providers_update(prefs, kClashOfGptsProvidersPref);
+  providers_update->clear();
+  for (int i = 0; i < current_pane_count_; ++i) {
+    providers_update->Append(static_cast<int>(pane_providers_[i]));
+  }
+
+  // Save last URLs
+  ScopedDictPrefUpdate urls_update(prefs, kClashOfGptsLastUrlsPref);
+  urls_update->clear();
+  for (const auto& [key, url] : last_urls_) {
+    std::string dict_key = base::StringPrintf("%d_%d", key.first, static_cast<int>(key.second));
+    urls_update->Set(dict_key, url.spec());
+  }
+}
+
+void ClashOfGptsCoordinator::LoadState() {
+  PrefService* prefs = GetBrowser().profile()->GetPrefs();
+  if (!prefs) {
+    // Use defaults - already initialized in constructor
+    return;
+  }
+
+  // Load pane count
+  current_pane_count_ = prefs->GetInteger(kClashOfGptsPaneCountPref);
+  if (current_pane_count_ < kMinPanes || current_pane_count_ > kMaxPanes) {
+    current_pane_count_ = kDefaultPaneCount;
+  }
+
+  // Load provider selections
+  const base::Value::List& providers_list = prefs->GetList(kClashOfGptsProvidersPref);
+  if (providers_list.size() > 0) {
+    for (size_t i = 0; i < providers_list.size() && i < kMaxPanes; ++i) {
+      if (providers_list[i].is_int()) {
+        int provider_int = providers_list[i].GetInt();
+        if (provider_int >= 0 && provider_int <= 4) {  // Now includes kPerplexity = 4
+          pane_providers_[i] = static_cast<LlmProvider>(provider_int);
+        }
+      }
+    }
+  }
+
+  // Load last URLs
+  const base::Value::Dict& urls_dict = prefs->GetDict(kClashOfGptsLastUrlsPref);
+  for (const auto [key, value] : urls_dict) {
+    if (const std::string* url_str = value.GetIfString()) {
+      // Parse key format "pane_provider" safely without sscanf
+      size_t underscore_pos = key.find('_');
+      if (underscore_pos != std::string::npos && underscore_pos > 0 && 
+          underscore_pos < key.length() - 1) {
+        int pane_index, provider_int;
+        if (base::StringToInt(key.substr(0, underscore_pos), &pane_index) &&
+            base::StringToInt(key.substr(underscore_pos + 1), &provider_int)) {
+          if (pane_index >= 0 && pane_index < kMaxPanes &&
+              provider_int >= 0 && provider_int <= 4) {  // Now includes kPerplexity = 4
+            GURL url(*url_str);
+            if (url.is_valid()) {
+              last_urls_[{pane_index, static_cast<LlmProvider>(provider_int)}] = url;
+            }
+          }
+        }
+      }
+    }
+  }
+}
+
+// static
+void ClashOfGptsCoordinator::RegisterProfilePrefs(
+    user_prefs::PrefRegistrySyncable* registry) {
+  registry->RegisterListPref(kClashOfGptsProvidersPref);
+  registry->RegisterDictionaryPref(kClashOfGptsLastUrlsPref);
+  registry->RegisterIntegerPref(kClashOfGptsPaneCountPref, kDefaultPaneCount);
+}
+
+
+// PaneWebContentsObserver implementation
+ClashOfGptsCoordinator::PaneWebContentsObserver::PaneWebContentsObserver(
+    ClashOfGptsCoordinator* coordinator, int pane_index, content::WebContents* web_contents)
+    : content::WebContentsObserver(web_contents),
+      coordinator_(coordinator),
+      pane_index_(pane_index) {}
+
+ClashOfGptsCoordinator::PaneWebContentsObserver::~PaneWebContentsObserver() = default;
+
+void ClashOfGptsCoordinator::PaneWebContentsObserver::DidFinishLoad(
+    content::RenderFrameHost* render_frame_host,
+    const GURL& validated_url) {
+  // Focus the input field when the page finishes loading
+  if (render_frame_host && render_frame_host->IsInPrimaryMainFrame()) {
+    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
+        FROM_HERE,
+        base::BindOnce([](base::WeakPtr<ClashOfGptsCoordinator> coordinator,
+                         int pane_index) {
+          if (!coordinator || !coordinator->view_) {
+            return;
+          }
+          coordinator->view_->FocusInputFieldForPane(pane_index);
+        }, coordinator_->weak_factory_.GetWeakPtr(), pane_index_),
+        base::Seconds(1));
+  }
+}
+
+content::WebContents* ClashOfGptsCoordinator::GetOrCreateWebContentsForPane(int pane_index) {
+  if (pane_index < 0 || pane_index >= kMaxPanes) {
+    return nullptr;
+  }
+
+  if (!owned_web_contents_[pane_index]) {
+    content::WebContents::CreateParams params(GetBrowser().profile());
+    owned_web_contents_[pane_index] = content::WebContents::Create(params);
+
+    // Set this as the delegate to handle keyboard events
+    owned_web_contents_[pane_index]->SetDelegate(this);
+
+    // Create observer for this pane
+    pane_observers_[pane_index] = std::make_unique<PaneWebContentsObserver>(
+        this, pane_index, owned_web_contents_[pane_index].get());
+  }
+
+  return owned_web_contents_[pane_index].get();
+}
+
+void ClashOfGptsCoordinator::CleanupWebContents() {
+  // Save any URLs before cleanup
+  if (view_) {
+    for (int i = 0; i < current_pane_count_; ++i) {
+      if (content::WebContents* web_contents = view_->GetWebContentsForPane(i)) {
+        GURL current_url = web_contents->GetURL();
+        if (current_url.is_valid()) {
+          last_urls_[{i, pane_providers_[i]}] = current_url;
+        }
+      }
+    }
+  }
+
+  // Clear all WebContents first
+  for (int i = 0; i < kMaxPanes; ++i) {
+    // Clear the observer first
+    pane_observers_[i].reset();
+
+    // Then destroy the WebContents
+    owned_web_contents_[i].reset();
+  }
+
+  // Remove view observation before widget cleanup
+  if (view_) {
+    view_observation_.RemoveObservation(view_);
+    view_ = nullptr;
+  }
+
+  // Close the window if it exists
+  if (widget_ && !widget_->IsClosed()) {
+    widget_->CloseNow();
+  }
+  widget_.reset();
+  window_.reset();
+}
+
+void ClashOfGptsCoordinator::OnBrowserRemoved(Browser* browser) {
+  if (browser == &GetBrowser()) {
+    // Browser is being removed - clean up WebContents early
+    CleanupWebContents();
+  }
+}
+
+void ClashOfGptsCoordinator::OnProfileWillBeDestroyed(Profile* profile) {
+  if (profile == GetBrowser().profile()) {
+    // Profile is being destroyed - clean up WebContents if not already done
+    CleanupWebContents();
+  }
+}
+
+BROWSER_USER_DATA_KEY_IMPL(ClashOfGptsCoordinator);
