//! SAML browser authentication via an embedded WebKitGTK WebView.
//!
//! Flow:
//!
//! 1. Prelogin returns either a SAML URL (`REDIRECT` method) or a base64-
//!    encoded HTML form (`POST` method).
//! 2. We open a GTK window with a WebView and load that URL/HTML. The user
//!    completes auth with their IdP in the embedded browser.
//! 3. We hook `resource-load-started` on the WebView and inspect every
//!    response's HTTP headers. When a response contains
//!    `saml-auth-status: 1`, we grab `saml-username` and `prelogin-cookie`
//!    (and `portal-userauthcookie` for logging) from the same response.
//! 4. Close the window, return a [`Credential::Password`] where the
//!    "password" is actually the prelogin-cookie — this is how GP's
//!    subsequent portal-login accepts it (see openconnect's
//!    `auth-globalprotect.c`).

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use gp_proto::prelogin::{PreloginResponse, SamlPrelogin};
use gp_proto::Credential;
use gtk::prelude::*;
use webkit2gtk::{
    NavigationPolicyDecisionExt, PolicyDecisionType, ResponsePolicyDecisionExt, URIRequestExt,
    URIResponseExt, WebResourceExt, WebViewExt,
};

use crate::context::AuthContext;
use crate::error::AuthError;
use crate::saml_common::{parse_globalprotect_callback, SamlCapture};
use crate::AuthProvider;

/// SAML provider that drives an embedded WebKitGTK browser.
pub struct SamlBrowserAuthProvider;

#[async_trait]
impl AuthProvider for SamlBrowserAuthProvider {
    fn name(&self) -> &str {
        "saml-webview"
    }

    fn can_handle(&self, prelogin: &PreloginResponse) -> bool {
        matches!(prelogin, PreloginResponse::Saml(_))
    }

    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        _ctx: &AuthContext,
    ) -> Result<Credential, AuthError> {
        let saml = match prelogin {
            PreloginResponse::Saml(s) => s.clone(),
            _ => return Err(AuthError::Failed("not a SAML prelogin response".into())),
        };

        // GTK must run on a dedicated OS thread — it's thread-local and we
        // don't want to block the tokio runtime. spawn_blocking uses a
        // worker thread from the blocking pool.
        let capture = tokio::task::spawn_blocking(move || run_saml_webview(&saml))
            .await
            .map_err(|e| AuthError::Failed(format!("saml webview join error: {e}")))??;

        tracing::info!("saml capture: user={}", capture.username);
        if let Some(puac) = &capture.portal_user_auth_cookie {
            tracing::debug!("portal-userauthcookie captured ({} bytes)", puac.len());
        }

        Ok(capture.into_credential())
    }
}

/// Run the GTK main loop with a WebView and block until we've captured the
/// SAML cookie or the window is closed.
fn run_saml_webview(saml: &SamlPrelogin) -> Result<SamlCapture, AuthError> {
    gtk::init().map_err(|e| AuthError::Failed(format!("gtk init: {e}")))?;

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("Pangolin — SAML authentication");
    window.set_default_size(900, 700);

    let webview = webkit2gtk::WebView::new();
    window.add(&webview);

    // Shared slot for the captured cookie. RefCell is fine because GTK is
    // single-threaded on this thread.
    let captured: Rc<RefCell<Option<SamlCapture>>> = Rc::new(RefCell::new(None));

    // `decide-policy` is our primary capture point. It fires twice for
    // every navigation:
    //
    // 1. `NavigationAction`: before the request goes out. We use this to
    //    intercept `globalprotectcallback:` URIs — Prisma Access portals
    //    redirect to this custom scheme with the CAS JWT embedded in the
    //    query string instead of returning the classic
    //    `saml-auth-status: 1` headers.
    //
    // 2. `Response`: as soon as WebKit has HTTP headers but before it
    //    tries to render the body. This catches the classic on-prem GP
    //    flow where the portal returns those headers directly.
    {
        let captured = Rc::clone(&captured);
        let window_clone = window.clone();
        webview.connect_decide_policy(move |_wv, decision, decision_type| match decision_type {
            PolicyDecisionType::NavigationAction | PolicyDecisionType::NewWindowAction => {
                let Ok(nav) = decision
                    .clone()
                    .downcast::<webkit2gtk::NavigationPolicyDecision>()
                else {
                    return false;
                };
                let Some(action) = nav.navigation_action() else {
                    return false;
                };
                let Some(req) = action.request() else {
                    return false;
                };
                let uri = req.uri().unwrap_or_default();
                if let Some(cap) = parse_globalprotect_callback(&uri) {
                    tracing::info!("captured globalprotectcallback for {}", cap.username);
                    *captured.borrow_mut() = Some(cap);
                    window_clone.close();
                    return true;
                }
                false
            }
            PolicyDecisionType::Response => {
                let Ok(response_decision) = decision
                    .clone()
                    .downcast::<webkit2gtk::ResponsePolicyDecision>()
                else {
                    return false;
                };
                let Some(response) = response_decision.response() else {
                    return false;
                };
                if let Some(cap) = extract_from_response(&response) {
                    tracing::info!("SAML auth completed for {}", cap.username);
                    *captured.borrow_mut() = Some(cap);
                    window_clone.close();
                    return true;
                }
                false
            }
            _ => false,
        });
    }

    // Secondary capture path: some GP portals send the final auth headers
    // on a sub-resource (e.g. an image or XHR) rather than the main
    // navigation. `resource-load-started` catches those too.
    {
        let captured = Rc::clone(&captured);
        let window_clone = window.clone();
        webview.connect_resource_load_started(move |_wv, resource, _request| {
            let captured = Rc::clone(&captured);
            let window = window_clone.clone();
            resource.connect_finished(move |res| {
                if captured.borrow().is_some() {
                    return;
                }
                if let Some(cap) = extract_from_resource(res) {
                    tracing::info!("SAML auth completed (sub-resource) for {}", cap.username);
                    *captured.borrow_mut() = Some(cap);
                    window.close();
                }
            });
        });
    }

    // Fallback capture: if decide-policy didn't catch the callback (older
    // webkit2gtk, some edge cases), load-failed will still fire for the
    // unknown `globalprotectcallback:` scheme.
    {
        let captured = Rc::clone(&captured);
        let window_clone = window.clone();
        webview.connect_load_failed(move |_wv, _event, uri, _err| {
            tracing::debug!("webview load-failed: {}", uri);
            if captured.borrow().is_some() {
                return false;
            }
            if let Some(cap) = parse_globalprotect_callback(uri) {
                tracing::info!(
                    "captured globalprotectcallback (load-failed) for {}",
                    cap.username
                );
                *captured.borrow_mut() = Some(cap);
                window_clone.close();
                return true;
            }
            false
        });
    }

    // Close button => exit main loop with no capture.
    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::glib::Propagation::Proceed
    });

    // Kick off navigation.
    match saml.saml_auth_method.as_str() {
        "REDIRECT" => {
            tracing::debug!("SAML REDIRECT: loading {}", saml.saml_request);
            webview.load_uri(&saml.saml_request);
        }
        "POST" => {
            // saml_request is a base64-encoded HTML body that auto-submits
            // a form to the IdP. We decode and feed it to load_html; the
            // base_uri lets the form submit to the absolute IdP URL.
            let decoded = BASE64
                .decode(saml.saml_request.as_bytes())
                .map_err(|e| AuthError::Failed(format!("decode saml-request base64: {e}")))?;
            let html = String::from_utf8(decoded)
                .map_err(|e| AuthError::Failed(format!("saml-request not utf8: {e}")))?;
            tracing::debug!("SAML POST: loading {} bytes of html", html.len());
            webview.load_html(&html, None);
        }
        other => {
            return Err(AuthError::Failed(format!(
                "unknown saml-auth-method: {other}"
            )));
        }
    }

    window.show_all();

    // Main loop runs until capture fires window.close() or the user closes
    // the window manually.
    gtk::main();

    let result = captured.borrow_mut().take();
    match result {
        Some(cap) => Ok(cap),
        None => Err(AuthError::Failed(
            "SAML window closed before authentication completed".into(),
        )),
    }
}

/// Pull `saml-auth-status`, `saml-username`, `prelogin-cookie`, and
/// `portal-userauthcookie` out of a response's HTTP headers.
fn extract_from_response(response: &webkit2gtk::URIResponse) -> Option<SamlCapture> {
    let headers = response.http_headers()?;

    let status = headers.one("saml-auth-status").unwrap_or_default();
    tracing::trace!(
        "decide-policy response {} — saml-auth-status={:?}",
        response.uri().unwrap_or_default(),
        status
    );
    if status != "1" {
        return None;
    }

    let username = headers.one("saml-username")?.to_string();
    let prelogin_cookie = headers.one("prelogin-cookie")?.to_string();
    let portal_user_auth_cookie = headers.one("portal-userauthcookie").map(|s| s.to_string());

    Some(SamlCapture {
        username,
        prelogin_cookie,
        portal_user_auth_cookie,
    })
}

fn extract_from_resource(resource: &webkit2gtk::WebResource) -> Option<SamlCapture> {
    extract_from_response(&resource.response()?)
}
