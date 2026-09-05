// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_proto::auth::CheckUserPermissionRequest;
use tonic::Code;
use tonic::Status;

use super::auth::grpc_get_auth_client;
use super::common::create_request_with_authorization;
use crate::grpc::ServerResultExt;

#[async_trait]
pub trait RepositoryAuthorizer: Send + Sync {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status>;
}

/// Always allows access. Used when no auth URL is configured.
pub struct AllowAllRepositoryAuthorizer;

#[async_trait]
impl RepositoryAuthorizer for AllowAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        _authorization: Option<String>,
        _repository_id: RepositoryId,
    ) -> Result<(), Status> {
        Ok(())
    }
}

/// Checks repository access against the Lore auth service.
pub struct AuthClientAuthorizer {
    auth_url: String,
}

impl AuthClientAuthorizer {
    pub fn new(auth_url: String) -> Self {
        Self { auth_url }
    }
}

#[async_trait]
impl RepositoryAuthorizer for AuthClientAuthorizer {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status> {
        let mut client = grpc_get_auth_client(self.auth_url.clone()).await?;
        let resource_id = format!("urc-{repository_id}");
        let request = create_request_with_authorization(
            CheckUserPermissionRequest {
                resource_id: vec![resource_id.clone()],
                target_user: None,
            },
            authorization,
        )?;

        let permissions = client
            .check_user_permission(request)
            .await
            .warn_map_err(|err| {
                if err.code() == Code::PermissionDenied {
                    return Status::permission_denied("Query resource denied");
                } else if err.code() == Code::Unauthenticated {
                    return Status::unauthenticated("Query resource failed - unauthenticated");
                }
                Status::internal(format!("Failed to call auth check_user_permission: {err}"))
            })?;

        if permissions
            .into_inner()
            .allowed_resource_permission
            .first()
            .ok_or(Status::internal("No permissions for resource"))?
            .resource_id
            == resource_id
        {
            Ok(())
        } else {
            Err(Status::internal("Unexpected resource_id"))
        }
    }
}

/// Whether an auth URL addresses a `UrcAuthApi` service that can answer a
/// permission query.
///
/// An OIDC issuer cannot: the standards put the grant in the token and leave
/// the resource server to decide locally against it, so there is no permission
/// RPC to call.
pub fn is_auth_service(auth_url: &str) -> bool {
    !matches!(
        auth_url.split_once("://").map(|(scheme, _)| scheme),
        Some("oidc") | Some("oidc-http")
    )
}

/// Creates the appropriate authorizer from an optional auth URL.
/// Returns `AllowAllRepositoryAuthorizer` when no URL is configured, and when
/// the URL names an issuer rather than an auth service.
pub fn repository_authorizer(auth_url: Option<String>) -> Arc<dyn RepositoryAuthorizer> {
    match auth_url {
        Some(url) if is_auth_service(&url) => Arc::new(AuthClientAuthorizer::new(url)),
        _ => Arc::new(AllowAllRepositoryAuthorizer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issuer_url_is_not_an_auth_service() {
        assert!(!is_auth_service("oidc://auth.example.com/o/lore?client_id=lore"));
        assert!(!is_auth_service("oidc-http://127.0.0.1:9000/o/lore?client_id=lore"));
    }

    #[test]
    fn a_grpc_auth_url_is_an_auth_service() {
        assert!(is_auth_service("ucs-auth://auth.example.com"));
        assert!(is_auth_service("https://auth.example.com"));
    }
}
