use crate::KeyVaultClient;
use crate::KeyVaultError;
use anyhow::Result;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use getset::Getters;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Map, Value};

const API_VERSION: &str = "7.0";

#[derive(Debug)]
pub struct KeyVaultSecretBaseIdentifier {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
pub struct KeyVaultSecretBaseIdentifierRaw {
    id: String,
}

#[derive(Deserialize, Debug)]
pub struct KeyVaultGetSecretsResponse {
    value: Vec<KeyVaultSecretBaseIdentifierRaw>,
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KeyVaultSecret {
    id: String,
    value: String,
    enabled: bool,
    time_created: DateTime<Utc>,
    time_updated: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct KeyVaultGetSecretResponse {
    value: String,
    id: String,
    attributes: KeyVaultGetSecretResponseAttributes,
}

#[derive(Deserialize, Debug)]
pub(crate) struct KeyVaultGetSecretResponseAttributes {
    enabled: bool,
    #[serde(with = "ts_seconds")]
    created: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    updated: DateTime<Utc>,
    #[serde(rename = "recoveryLevel")]
    recovery_level: String,
}

impl<'a> KeyVaultClient<'a> {
    /// Gets a secret from the Key Vault.
    /// Note that the latest version is fetched. For a specific version, use `get_version_with_version`.
    /// 
    /// # Example
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let mut client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");
    /// client.get_secret(&"secret_name");
    /// ```
    pub async fn get_secret(&mut self, secret_name: &'a str) -> Result<KeyVaultSecret, KeyVaultError> {
        Ok(self.get_secret_with_version(secret_name, "").await?)
    }

    /// Gets a secret from the Key Vault with a specific version.
    /// If you need the latest version, use `get_secret`.
    /// 
    /// # Example
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let mut client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");
    /// client.get_secret_with_version(&"secret_name", &"3c9aa4f2-8a1a-4248-9bc9-78bb1a78f5d1");
    /// ```
    pub async fn get_secret_with_version(
        &mut self,
        secret_name: &'a str,
        secret_version_name: &'a str,
    ) -> Result<KeyVaultSecret, KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!(
                "https://{}.vault.azure.net/secrets/{}/{}",
                self.keyvault_name, secret_name, secret_version_name
            ),
            &[("api-version", API_VERSION)],
        )
        .unwrap();
        let resp_body = self.get_authed(uri.to_string()).await?;
        let response = serde_json::from_str::<KeyVaultGetSecretResponse>(&resp_body).unwrap();
        Ok(KeyVaultSecret {
            enabled: response.attributes.enabled,
            value: response.value,
            time_created: response.attributes.created,
            time_updated: response.attributes.updated,
            id: response.id,
        })
    }

    /// Lists all secrets in the Key Vault.
    /// 
    /// # Example
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let mut client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");
    /// client.list_secrets(100);
    /// ```
    pub async fn list_secrets(
        &mut self,
        max_secrets: usize,
    ) -> Result<Vec<KeyVaultSecretBaseIdentifier>, KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!("https://{}.vault.azure.net/secrets", self.keyvault_name),
            &[("api-version", API_VERSION), ("maxresults", &max_secrets.to_string())],
        )
        .unwrap();

        let resp_body = self.get_authed(uri.to_string()).await?;
        let response = serde_json::from_str::<KeyVaultGetSecretsResponse>(&resp_body).unwrap();

        Ok(response
            .value
            .into_iter()
            .map(|s| KeyVaultSecretBaseIdentifier {
                id: s.id.to_owned(),
                name: s.id.to_owned().split("/").last().unwrap().to_owned(),
            })
            .collect())
    }

    /// Sets a secret in the Key Vault.
    /// 
    /// # Example
    /// 
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let mut client = KeyVaultClient::new(&"c1a6d79b-082b-4798-b362-a77e96de50db", &"SUPER_SECRET_KEY", &"bc598e67-03d8-44d5-aa46-8289b9a39a14", &"test-keyvault");
    /// client.set_secret(&"some_secret", &"42");
    /// ```
    pub async fn set_secret(&mut self, secret_name: &'a str, new_secret_value: &'a str) -> Result<(), KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!("https://{}.vault.azure.net/secrets/{}", self.keyvault_name, secret_name),
            &[("api-version", API_VERSION)],
        )
        .unwrap();

        let mut request_body = Map::new();
        request_body.insert("value".to_owned(), Value::String(new_secret_value.to_owned()));

        self.put_authed(uri.to_string(), Value::Object(request_body).to_string())
            .await?;

        Ok(())
    }
}
