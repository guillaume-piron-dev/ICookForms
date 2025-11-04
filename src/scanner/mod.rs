//! Cookie scanner for web applications
//!
//! This module implements a complete HTTP cookie scanner using reqwest.
//! It can scan single URLs or crawl entire websites to find cookies.

use crate::types::config::ScanConfig;
use crate::types::report::{ScanResult, ScanStatus};
use crate::types::{Cookie, Error, Result};
use reqwest::{header, Client, Response};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use url::Url;

/// HTTP cookie scanner
pub struct Scanner {
    config: ScanConfig,
    client: Client,
}

impl Scanner {
    /// Create a new scanner with configuration
    pub fn new(config: ScanConfig) -> Result<Self> {
        let client = build_http_client(&config)?;

        Ok(Self { config, client })
    }

    /// Scan a single URL for cookies
    pub async fn scan(&self, url: &str) -> Result<ScanResult> {
        info!("Starting cookie scan for: {}", url);

        let mut result = ScanResult::new(url);
        result.status = ScanStatus::InProgress;
        result.config = serde_json::to_value(&self.config).unwrap_or(serde_json::Value::Null);

        // Validate URL
        let parsed_url =
            Url::parse(url).map_err(|e| Error::scanner(format!("Invalid URL: {e}")))?;

        // Scan the page
        match self.scan_url(&parsed_url).await {
            Ok(cookies) => {
                result.cookies.extend(cookies);
                result.pages_scanned = 1;
                result.requests_made = 1;
            }
            Err(e) => {
                result.errors.push(format!("Failed to scan URL: {e}"));
                result.status = ScanStatus::Failed;
                return Ok(result);
            }
        }

        result.complete();
        info!("Scan completed. Found {} cookies", result.cookies.len());

        Ok(result)
    }

    /// Crawl a website and scan all pages for cookies
    pub async fn crawl(&self, start_url: &str) -> Result<ScanResult> {
        info!("Starting website crawl from: {}", start_url);

        let mut result = ScanResult::new(start_url);
        result.status = ScanStatus::InProgress;
        result.config = serde_json::to_value(&self.config).unwrap_or(serde_json::Value::Null);

        let start =
            Url::parse(start_url).map_err(|e| Error::scanner(format!("Invalid start URL: {e}")))?;

        let mut visited = HashSet::new();
        let mut to_visit = vec![start.clone()];
        let mut all_cookies = HashMap::new();

        while !to_visit.is_empty() && visited.len() < self.config.max_pages {
            let url = to_visit.pop().unwrap();

            if visited.contains(&url) {
                continue;
            }

            // Check domain restrictions
            if !self.should_scan_url(&url, &start) {
                continue;
            }

            info!("Scanning page: {}", url);
            visited.insert(url.clone());
            result.pages_scanned += 1;

            // Scan the URL
            match self.scan_url(&url).await {
                Ok(cookies) => {
                    result.requests_made += 1;

                    // Store unique cookies
                    for cookie in cookies {
                        let key =
                            format!("{}:{}", cookie.name, cookie.domain.as_deref().unwrap_or(""));
                        all_cookies.insert(key, cookie);
                    }

                    // Extract links for crawling
                    if visited.len() < self.config.max_pages {
                        match self.extract_links(&url).await {
                            Ok(links) => {
                                for link in links {
                                    if !visited.contains(&link) && to_visit.len() < 1000 {
                                        to_visit.push(link);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to extract links from {}: {}", url, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Failed to scan {url}: {e}"));
                }
            }

            // Rate limiting
            if let Some(rate_limit) = self.config.rate_limit {
                let delay = Duration::from_millis(1000 / u64::from(rate_limit));
                tokio::time::sleep(delay).await;
            }
        }

        // Convert HashMap to Vec
        result.cookies = all_cookies.into_values().collect();

        result.complete();
        info!(
            "Crawl completed. Scanned {} pages, found {} cookies",
            result.pages_scanned,
            result.cookies.len()
        );

        Ok(result)
    }

    /// Scan a single URL and extract cookies
    async fn scan_url(&self, url: &Url) -> Result<Vec<Cookie>> {
        debug!("Fetching URL: {}", url);

        // Make request with timeout
        let response = timeout(self.config.timeout, self.client.get(url.as_str()).send())
            .await
            .map_err(|_| Error::timeout(format!("Request timeout for {url}")))?
            .map_err(Error::Http)?;

        // Extract cookies from response
        Ok(Self::extract_cookies(url, &response))
    }

    /// Extract cookies from HTTP response
    fn extract_cookies(url: &Url, response: &Response) -> Vec<Cookie> {
        let mut cookies = Vec::new();

        // Extract Set-Cookie headers
        for value in response.headers().get_all(header::SET_COOKIE) {
            if let Ok(header_str) = value.to_str() {
                // Parse with strict=false for maximum compatibility
                match crate::parser::parse_set_cookie(header_str, false) {
                    Ok(mut cookie) => {
                        // Set source URL
                        cookie.source_url = Some(url.to_string());

                        // Determine if third-party
                        cookie.is_third_party = is_third_party_cookie(url, &cookie);

                        cookies.push(cookie);
                    }
                    Err(e) => {
                        warn!("Failed to parse cookie: {}", e);
                    }
                }
            }
        }

        debug!("Extracted {} cookies from {}", cookies.len(), url);
        cookies
    }

    /// Extract links from a page for crawling
    async fn extract_links(&self, url: &Url) -> Result<Vec<Url>> {
        use scraper::{Html, Selector};

        let client = &self.client;
        let timeout = self.config.timeout;

        let response = tokio::time::timeout(timeout, client.get(url.clone()).send())
            .await
            .map_err(|_| Error::timeout("Link extraction timeout"))?
            .map_err(Error::Http)?;

        let body = response.text().await.map_err(Error::Http)?;

        // Simple link extraction using scraper
        let document = Html::parse_document(&body);
        let selector = Selector::parse("a[href]").unwrap();

        let mut links = Vec::new();

        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(absolute_url) = url.join(href) {
                    links.push(absolute_url);
                }
            }
        }

        debug!("Extracted {} links from {}", links.len(), url);
        Ok(links)
    }

    /// Check if URL should be scanned based on domain restrictions
    fn should_scan_url(&self, url: &Url, start: &Url) -> bool {
        // Check include domains
        if !self.config.include_domains.is_empty() {
            let domain = url.domain().unwrap_or("");
            if !self
                .config
                .include_domains
                .iter()
                .any(|d| domain.contains(d))
            {
                return false;
            }
        }

        // Check exclude domains
        if !self.config.exclude_domains.is_empty() {
            let domain = url.domain().unwrap_or("");
            if self
                .config
                .exclude_domains
                .iter()
                .any(|d| domain.contains(d))
            {
                return false;
            }
        }

        // Stay on same domain by default
        if url.domain() != start.domain() {
            return false;
        }

        true
    }
}

/// Build HTTP client with configuration
fn build_http_client(config: &ScanConfig) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .cookie_store(true); // Enable cookie jar

    // Configure redirects
    if config.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(config.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    // Configure SSL verification
    if !config.verify_ssl {
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Configure proxy
    if let Some(ref proxy_url) = config.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| Error::config(format!("Invalid proxy URL: {e}")))?;
        builder = builder.proxy(proxy);
    }

    // Add custom headers
    let mut headers = header::HeaderMap::new();
    for (name, value) in &config.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            header::HeaderName::from_bytes(name.as_bytes()),
            header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
    builder = builder.default_headers(headers);

    builder
        .build()
        .map_err(|e| Error::scanner(format!("Failed to build HTTP client: {e}")))
}

/// Check if cookie is third-party relative to the URL
fn is_third_party_cookie(url: &Url, cookie: &Cookie) -> bool {
    let page_domain = url.domain().unwrap_or("");

    if let Some(ref cookie_domain) = cookie.domain {
        // Remove leading dot from cookie domain
        let cookie_domain = cookie_domain.trim_start_matches('.');

        // Check if domains match
        !page_domain.ends_with(cookie_domain) && !cookie_domain.ends_with(page_domain)
    } else {
        false
    }
}

/// Scanner builder for convenient configuration
pub struct ScannerBuilder {
    config: ScanConfig,
}

impl ScannerBuilder {
    /// Create a new scanner builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ScanConfig::default(),
        }
    }

    /// Set maximum pages to scan
    #[must_use]
    pub fn max_pages(mut self, max: usize) -> Self {
        self.config.max_pages = max;
        self
    }

    /// Set request timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set user agent
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config.user_agent = ua.into();
        self
    }

    /// Enable/disable SSL verification
    #[must_use]
    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.config.verify_ssl = verify;
        self
    }

    /// Set HTTP proxy
    #[must_use]
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.config.proxy = Some(proxy.into());
        self
    }

    /// Set rate limit (requests per second)
    #[must_use]
    pub fn rate_limit(mut self, rps: u32) -> Self {
        self.config.rate_limit = Some(rps);
        self
    }

    /// Build the scanner
    pub fn build(self) -> Result<Scanner> {
        Scanner::new(self.config)
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_builder() {
        let scanner = ScannerBuilder::new()
            .max_pages(50)
            .timeout(Duration::from_secs(10))
            .user_agent("TestBot/1.0")
            .verify_ssl(false)
            .build();

        assert!(scanner.is_ok());
    }

    #[test]
    fn test_is_third_party() {
        let url = Url::parse("https://example.com/page").unwrap();
        let mut cookie = Cookie::new("test".to_string(), "value".to_string());

        cookie.domain = Some("example.com".to_string());
        assert!(!is_third_party_cookie(&url, &cookie));

        cookie.domain = Some("thirdparty.com".to_string());
        assert!(is_third_party_cookie(&url, &cookie));
    }

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = Scanner::new(ScanConfig::default());
        assert!(scanner.is_ok());
    }
}
