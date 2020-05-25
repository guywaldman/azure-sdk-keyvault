use crate::KeyVaultError;
use anyhow::Context;
use anyhow::Result;
use azure_sdk_auth_aad::authorize_non_interactive;
use chrono::{DateTime, Utc};
use oauth2::{AccessToken, ClientId, ClientSecret};
use std::sync::Arc;

const PUBLIC_ENDPOINT_SUFFIX: &str = "vault.azure.net";

/// Client for Key Vault operations - getting a secret, listing secrets, etc.
/// 
/// # Examples
/// 
/// ```
/// use azure_sdk_keyvault::KeyVaultClient;
/// let client = KeyVaultClient::new(&"{client_id}", &"{client_secret}", &"{tenant_id}", &"test-keyvault");
/// ```
#[derive(Debug)]
pub struct KeyVaultClient<'a> {
    pub(crate) aad_client_id: &'a str,
    pub(crate) aad_client_secret: &'a str,
    pub(crate) aad_tenant_id: &'a str,
    pub(crate) keyvault_name: &'a str,
    pub(crate) endpoint_suffix: &'a str,
    pub(crate) token: Option<AccessToken>,
    pub(crate) token_expiration: Option<DateTime<Utc>>,
}

impl<'a> KeyVaultClient<'a> {
    /// Creates a new `KeyVaultClient` with an endpoint suffix. Useful for non-public Azure clouds.
    /// For the default public environment, use `KeyVaultClient::new`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let client = KeyVaultClient::new_with_endpoint_suffix(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault", &"vault.foobar.net");
    /// ```
    pub fn new_with_endpoint_suffix(
        aad_client_id: &'a str,
        aad_client_secret: &'a str,
        aad_tenant_id: &'a str,
        keyvault_name: &'a str,
        endpoint_suffix: &'a str,
    ) -> Self {
        Self {
            aad_client_id,
            aad_client_secret,
            aad_tenant_id,
            keyvault_name,
            endpoint_suffix: endpoint_suffix,
            token: None,
            token_expiration: None,
        }
    }

    /// Creates a new `KeyVaultClient`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");
    /// ```
    pub fn new(
        aad_client_id: &'a str,
        aad_client_secret: &'a str,
        aad_tenant_id: &'a str,
        keyvault_name: &'a str,
    ) -> Self {
        KeyVaultClient::new_with_endpoint_suffix(
            aad_client_id,
            aad_client_secret,
            aad_tenant_id,
            keyvault_name,
            PUBLIC_ENDPOINT_SUFFIX,
        )
    }

    pub(crate) async fn refresh_token(&mut self) -> Result<(), KeyVaultError> {
        if matches!(self.token_expiration, Some(exp) if exp > chrono::Utc::now()) {
            // Token is valid, return it.
            return Ok(());
        }
        let aad_client_id = ClientId::new(self.aad_client_id.to_owned());
        let aad_client_secret = ClientSecret::new(self.aad_client_secret.to_owned());
        let token = authorize_non_interactive(
            Arc::new(reqwest::Client::new()),
            &aad_client_id,
            &aad_client_secret,
            "https://vault.azure.net",
            self.aad_tenant_id,
        )
        .await
        .with_context(|| "Failed to authenticate to Azure Active Directory")
        .map_err(|e| KeyVaultError::AuthorizationError(e))?;
        self.token = Some(token.access_token().clone());
        self.token_expiration = Some(token.expires_on);
        Ok(())
    }

    pub(crate) async fn get_authed(&mut self, uri: String) -> Result<String, KeyVaultError> {
        self.refresh_token().await?;

        let resp = reqwest::Client::new()
            .get(&uri)
            .header(
                "Authorization",
                format!("Bearer {}", self.token.as_ref().unwrap().secret()),
            )
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        Ok(body)
    }

    pub(crate) async fn put_authed(&mut self, uri: String, body: String) -> Result<String, KeyVaultError> {
        self.refresh_token().await?;

        let resp = reqwest::Client::new()
            .put(&uri)
            .header(
                "Authorization",
                format!("Bearer {}", self.token.as_ref().unwrap().secret()),
            )
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        let body = resp.text().await.unwrap();
        Ok(body)
    }
}
