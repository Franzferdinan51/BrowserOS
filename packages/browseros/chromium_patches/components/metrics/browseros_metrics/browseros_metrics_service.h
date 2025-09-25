diff --git a/components/metrics/browseros_metrics/browseros_metrics_service.h b/components/metrics/browseros_metrics/browseros_metrics_service.h
new file mode 100644
index 0000000000000..db124fd11382a
--- /dev/null
+++ b/components/metrics/browseros_metrics/browseros_metrics_service.h
@@ -0,0 +1,81 @@
+// Copyright 2025 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef COMPONENTS_METRICS_BROWSEROS_METRICS_BROWSEROS_METRICS_SERVICE_H_
+#define COMPONENTS_METRICS_BROWSEROS_METRICS_BROWSEROS_METRICS_SERVICE_H_
+
+#include <memory>
+#include <string>
+
+#include "base/functional/callback.h"
+#include "base/memory/weak_ptr.h"
+#include "base/values.h"
+#include "components/keyed_service/core/keyed_service.h"
+#include "services/network/public/cpp/simple_url_loader.h"
+#include "url/gurl.h"
+
+class PrefService;
+
+namespace network {
+class SharedURLLoaderFactory;
+}  // namespace network
+
+namespace browseros_metrics {
+
+// Service for capturing and sending analytics events to PostHog.
+// This service manages a stable client ID and sends events to the PostHog API.
+class BrowserOSMetricsService : public KeyedService {
+ public:
+  explicit BrowserOSMetricsService(
+      PrefService* pref_service,
+      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory);
+
+  BrowserOSMetricsService(const BrowserOSMetricsService&) = delete;
+  BrowserOSMetricsService& operator=(const BrowserOSMetricsService&) = delete;
+
+  ~BrowserOSMetricsService() override;
+
+  // Captures a single event with the given name and properties.
+  // Properties should not contain PII. Common properties like client_id,
+  // browser version, and OS are added automatically.
+  void CaptureEvent(const std::string& event_name,
+                    base::Value::Dict properties);
+
+  // Returns the stable client ID for this browser instance.
+  std::string GetClientId() const;
+
+  // KeyedService:
+  void Shutdown() override;
+
+ private:
+  // Initializes or retrieves the stable client ID from preferences.
+  void InitializeClientId();
+
+  // Sends the event to PostHog API.
+  void SendEventToPostHog(const std::string& event_name,
+                          base::Value::Dict properties);
+
+  // Handles the response from PostHog API.
+  void OnPostHogResponse(std::unique_ptr<network::SimpleURLLoader> loader,
+                         std::unique_ptr<std::string> response_body);
+
+  // Adds default properties to the event.
+  void AddDefaultProperties(base::Value::Dict& properties);
+
+  // PrefService for storing the stable client ID.
+  raw_ptr<PrefService> pref_service_;
+
+  // Factory for creating URL loaders.
+  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
+
+  // Stable client ID for this browser instance.
+  std::string client_id_;
+
+  // Weak pointer factory for callbacks.
+  base::WeakPtrFactory<BrowserOSMetricsService> weak_factory_{this};
+};
+
+}  // namespace browseros_metrics
+
+#endif  // COMPONENTS_METRICS_BROWSEROS_METRICS_BROWSEROS_METRICS_SERVICE_H_
\ No newline at end of file
