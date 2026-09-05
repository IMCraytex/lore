// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use lore_base::error::Disconnected;
use lore_base::lore_debug;
use lore_base::error::NotAuthorized;
use lore_base::error::NotSupported;
use lore_base::types::RepositoryId;
use serde::Deserialize;

use crate::error::ProtocolError;
use crate::traits::Authentication;
use crate::types::*;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_SCOPES: &str = "openid profile";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An issuer address and the client parameters to present to it.
///
/// The auth URL carries both: `oidc://host/path?client_id=lore&scopes=openid+profile`
/// addresses an issuer over HTTPS, and `oidc-http` addresses one over plaintext.
struct Endpoint {
    issuer: String,
    client_id: String,
    scopes: String,
}

/// Splits an auth URL into the issuer URL and the client parameters in its query.
///
/// The scheme selects the transport because the registry dispatches on it, so it
/// is the only place the issuer's own scheme can be carried.
fn parse_endpoint(auth_url: &str) -> Result<Endpoint, ProtocolError> {
    let (scheme, rest) = auth_url.split_once("://").ok_or_else(|| {
        ProtocolError::internal(format!("invalid auth URL (missing scheme): '{auth_url}'"))
    })?;

    let transport = match scheme {
        "oidc" => "https",
        "oidc-http" => "http",
        other => {
            return Err(ProtocolError::internal(format!(
                "'{other}' is not an OIDC auth URL scheme"
            )));
        }
    };

    let mut url = url::Url::parse(&format!("{transport}://{rest}"))
        .map_err(|e| ProtocolError::internal(format!("invalid auth URL '{auth_url}': {e}")))?;

    let mut client_id = None;
    let mut scopes = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            "scopes" => scopes = Some(value.replace('+', " ")),
            _ => {}
        }
    }
    url.set_query(None);

    let client_id = client_id.ok_or_else(|| {
        ProtocolError::internal(format!("auth URL '{auth_url}' names no client_id"))
    })?;

    Ok(Endpoint {
        issuer: url.as_str().trim_end_matches('/').to_string(),
        client_id,
        scopes: scopes.unwrap_or_else(|| DEFAULT_SCOPES.to_string()),
    })
}

/// The subset of an OpenID provider's metadata this client uses.
#[derive(Deserialize)]
struct ProviderMetadata {
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
}

fn http_client() -> Result<&'static reqwest::Client, ProtocolError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| ProtocolError::internal(format!("constructing HTTP client: {e}")))?;
    Ok(CLIENT.get_or_init(|| client))
}

async fn discover(issuer: &str) -> Result<ProviderMetadata, ProtocolError> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let body = http_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            lore_debug!("Discovery request to {url} failed: {e}");
            ProtocolError::from(Disconnected)
        })?
        .text()
        .await
        .map_err(|e| ProtocolError::internal(format!("reading discovery document: {e}")))?;

    serde_json::from_str(&body)
        .map_err(|e| ProtocolError::internal(format!("parsing discovery document at {url}: {e}")))
}

/// Posts a form to a token or device endpoint and returns the response body.
///
/// The body is returned unparsed because the token endpoint reports a pending
/// authorization as an HTTP 400 carrying a JSON error code, so a failing status
/// still holds the answer.
async fn post_form(url: &str, form: &[(&str, &str)]) -> Result<String, ProtocolError> {
    http_client()?
        .post(url)
        .form(form)
        .send()
        .await
        .map_err(|e| {
            lore_debug!("Request to {url} failed: {e}");
            ProtocolError::from(Disconnected)
        })?
        .text()
        .await
        .map_err(|e| ProtocolError::internal(format!("reading response from {url}: {e}")))
}

/// Reads the identity out of an access token.
///
/// The subject claim is the identity, and `preferred_username` the display name
/// where the token carries one.
fn authentication_token(
    access_token: String,
    refresh_token: Option<String>,
) -> Result<AuthenticationToken, ProtocolError> {
    let info = lore_credential::user_info_from_token(access_token)
        .ok_or_else(|| ProtocolError::internal("access token is not a readable JWT"))?;

    let user_name = if info.preferred_username.is_empty() {
        info.name
    } else {
        info.preferred_username
    };

    Ok(AuthenticationToken {
        token: info.token,
        user_id: info.id,
        user_name,
        expires_ms: info.expires,
        acceptable_root_domains: Vec::new(),
        refresh_token,
    })
}

/// Authentication implementation for OpenID Connect providers.
///
/// Registered under the `oidc` and `oidc-http` schemes. Login uses the device
/// authorization grant, which covers the browser and headless cases alike.
///
/// The access token authorizes on its own: an exchange returns it unchanged,
/// because narrowing one to a single repository needs a grant a provider is not
/// assumed to offer.
#[derive(Default)]
pub struct OidcAuthentication;

#[async_trait]
impl Authentication for OidcAuthentication {
    async fn start_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        let endpoint = parse_endpoint(auth_url)?;
        let metadata = discover(&endpoint.issuer).await?;

        let device_endpoint = metadata.device_authorization_endpoint.ok_or_else(|| {
            ProtocolError::from(NotSupported {
                operation: format!(
                    "{} advertises no device authorization endpoint",
                    endpoint.issuer
                ),
            })
        })?;

        let body = post_form(
            &device_endpoint,
            &[
                ("client_id", endpoint.client_id.as_str()),
                ("scope", endpoint.scopes.as_str()),
            ],
        )
        .await?;

        let response: DeviceAuthorization = serde_json::from_str(&body).map_err(|e| {
            ProtocolError::internal(format!("parsing device authorization response: {e}"))
        })?;

        Ok(AuthSession {
            session_code: response.device_code,
            login_url: response
                .verification_uri_complete
                .unwrap_or(response.verification_uri),
        })
    }

    async fn poll_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        let endpoint = parse_endpoint(auth_url)?;
        let metadata = discover(&endpoint.issuer).await?;

        let body = post_form(
            &metadata.token_endpoint,
            &[
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", session_code),
                ("client_id", endpoint.client_id.as_str()),
            ],
        )
        .await?;

        // An error code is the answer while the user is still at the login
        // screen, so it is read before the success shape is attempted.
        if let Ok(failure) = serde_json::from_str::<TokenErrorResponse>(&body) {
            return match failure.error.as_str() {
                "authorization_pending" | "slow_down" => Ok(None),
                "access_denied" => Err(NotAuthorized.into()),
                "expired_token" => Err(ProtocolError::from(NotSupported {
                    operation: "login session expired before it was approved".to_string(),
                })),
                other => Err(ProtocolError::internal(format!(
                    "device grant failed: {other}"
                ))),
            };
        }

        let response: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| ProtocolError::internal(format!("parsing token response: {e}")))?;

        authentication_token(response.access_token, response.refresh_token).map(Some)
    }

    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        _token: &str,
        token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: format!("exchanging a '{token_type}' token"),
        }))
    }

    async fn refresh_authentication(
        &self,
        auth_url: &str,
        refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let endpoint = parse_endpoint(auth_url)?;
        let metadata = discover(&endpoint.issuer).await?;

        let body = post_form(
            &metadata.token_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", endpoint.client_id.as_str()),
            ],
        )
        .await?;

        if let Ok(failure) = serde_json::from_str::<TokenErrorResponse>(&body) {
            lore_debug!("Refresh grant failed: {}", failure.error);
            return Err(NotAuthorized.into());
        }

        let response: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| ProtocolError::internal(format!("parsing refresh response: {e}")))?;

        authentication_token(response.access_token, response.refresh_token)
    }

    async fn exchange_for_repository(
        &self,
        auth_url: &str,
        authn_token: &str,
        _repository: RepositoryId,
        correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.exchange_for_custom_resource(auth_url, authn_token, "", correlation_id)
            .await
    }

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        let info = lore_credential::user_info_from_token(authn_token.to_string())
            .ok_or_else(|| ProtocolError::internal("access token is not a readable JWT"))?;

        Ok(AuthorizationToken {
            token: info.token,
            expires_ms: info.expires,
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn get_user_info(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        user_ids: &[String],
        _correlation_id: &str,
    ) -> Result<Vec<ResolvedUser>, ProtocolError> {
        // OpenID Connect resolves the bearer's own identity and no other, so an
        // id resolves to itself and the caller displays it raw.
        Ok(user_ids
            .iter()
            .map(|user_id| ResolvedUser {
                user_id: user_id.clone(),
                user_name: user_id.clone(),
            })
            .collect())
    }

    async fn get_user_id(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        display_name: &str,
        _correlation_id: &str,
    ) -> Result<Option<ResolvedUser>, ProtocolError> {
        Ok(Some(ResolvedUser {
            user_id: display_name.to_string(),
            user_name: display_name.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_scheme_addresses_the_issuer_over_tls() {
        let endpoint = parse_endpoint("oidc://auth.example.com/application/o/lore/?client_id=lore")
            .expect("a well-formed auth URL");
        assert_eq!(endpoint.issuer, "https://auth.example.com/application/o/lore");
        assert_eq!(endpoint.client_id, "lore");
        assert_eq!(endpoint.scopes, DEFAULT_SCOPES);
    }

    #[test]
    fn plaintext_scheme_addresses_the_issuer_over_http() {
        let endpoint = parse_endpoint("oidc-http://127.0.0.1:9000/o/lore?client_id=lore")
            .expect("a well-formed auth URL");
        assert_eq!(endpoint.issuer, "http://127.0.0.1:9000/o/lore");
    }

    #[test]
    fn scopes_are_read_from_the_query() {
        let endpoint =
            parse_endpoint("oidc://auth.example.com/?client_id=lore&scopes=openid+groups")
                .expect("a well-formed auth URL");
        assert_eq!(endpoint.scopes, "openid groups");
    }

    #[test]
    fn an_auth_url_without_a_client_id_is_refused() {
        assert!(parse_endpoint("oidc://auth.example.com/").is_err());
    }

    #[test]
    fn a_foreign_scheme_is_refused() {
        assert!(parse_endpoint("ucs-auth://auth.example.com").is_err());
        assert!(parse_endpoint("auth.example.com").is_err());
    }
}
