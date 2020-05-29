use crate::KeyVaultClient;
use crate::{client::API_VERSION, KeyVaultError};
use anyhow::{Context, Result};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use getset::Getters;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fmt;

const DEFAULT_GET_VERISONS_MAX_RESULTS: usize = 25;

/// Reflects the deletion recovery level currently in effect for keys in the current Key Vault.
/// If it contains 'Purgeable' the key can be permanently deleted by a privileged user;
/// otherwise, only the system can purge the key, at the end of the retention interval.
pub enum RecoveryLevel {
    Purgeable,
    Recoverable,
    RecoverableAndProtectedSubscription,
    RecoverableAndPurgeable,
}

impl fmt::Display for RecoveryLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecoveryLevel::Purgeable => write!(f, "Purgeable"),
            RecoveryLevel::Recoverable => write!(f, "Recoverable"),
            RecoveryLevel::RecoverableAndProtectedSubscription => write!(f, "Recoverable+ProtectedSubscription"),
            RecoveryLevel::RecoverableAndPurgeable => write!(f, "Recoverable+Purgeable"),
        }
    }
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KeyVaultSecretBaseIdentifier {
    id: String,
    name: String,
    enabled: bool,
    time_created: DateTime<Utc>,
    time_updated: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct KeyVaultSecretBaseIdentifierAttributedRaw {
    enabled: bool,
    #[serde(with = "ts_seconds")]
    created: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    updated: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct KeyVaultSecretBaseIdentifierRaw {
    id: String,
    attributes: KeyVaultSecretBaseIdentifierAttributedRaw,
}

#[derive(Deserialize, Debug)]
pub(crate) struct KeyVaultGetSecretsResponse {
    value: Vec<KeyVaultSecretBaseIdentifierRaw>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
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
                "{}/secrets/{}/{}",
                self.keyvault_endpoint, secret_name, secret_version_name
            ),
            &[("api-version", API_VERSION)],
        )
        .unwrap();
        let resp_body = self.get_authed(uri.to_string()).await?;
        let response = serde_json::from_str::<KeyVaultGetSecretResponse>(&resp_body)
            .with_context(|| format!("Failed to parse response from Key Vault: {}", resp_body))?;
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
            &format!("{}/secrets", self.keyvault_endpoint),
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
                enabled: s.attributes.enabled,
                time_created: s.attributes.created,
                time_updated: s.attributes.updated,
            })
            .collect())
    }

    pub async fn get_secret_versions(
        &mut self,
        secret_name: &'a str,
    ) -> Result<Vec<KeyVaultSecretBaseIdentifier>, KeyVaultError> {
        let mut secret_versions = Vec::<KeyVaultSecretBaseIdentifier>::new();
        let mut uri = Url::parse_with_params(
            &format!("{}/secrets/{}/versions", self.keyvault_endpoint, secret_name),
            &[
                ("api-version", API_VERSION),
                ("maxresults", &DEFAULT_GET_VERISONS_MAX_RESULTS.to_string()),
            ],
        )
        .unwrap();

        loop {
            let resp_body = self.get_authed(uri.to_string()).await?;
            let response = serde_json::from_str::<KeyVaultGetSecretsResponse>(&resp_body).unwrap();

            secret_versions.extend(
                response
                    .value
                    .into_iter()
                    .map(|s| KeyVaultSecretBaseIdentifier {
                        id: s.id.to_owned(),
                        name: s.id.to_owned().split("/").last().unwrap().to_owned(),
                        enabled: s.attributes.enabled,
                        time_created: s.attributes.created,
                        time_updated: s.attributes.updated,
                    })
                    .collect::<Vec<KeyVaultSecretBaseIdentifier>>(),
            );
            match response.next_link {
                None => break,
                Some(u) => uri = Url::parse(&u).unwrap(),
            }
        }

        // Return the secret versions sorted by the time modified in descending order.
        secret_versions.sort_by(|a, b| {
            if a.time_updated > b.time_updated {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        Ok(secret_versions)
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
            &format!("{}/secrets/{}", self.keyvault_endpoint, secret_name),
            &[("api-version", API_VERSION)],
        )
        .unwrap();

        let mut request_body = Map::new();
        request_body.insert("value".to_owned(), Value::String(new_secret_value.to_owned()));

        self.put_authed(uri.to_string(), Value::Object(request_body).to_string())
            .await?;

        Ok(())
    }

    /// Changes whether a secret is enabled or not.
    ///
    /// # Example
    ///
    /// ```
    /// use azure_sdk_keyvault::KeyVaultClient;
    /// let mut client = KeyVaultClient::new(&"...", &"...", &"...", &"test-keyvault");
    /// client.update_secret_enabled(&"some_secret", &"...", false);
    /// ```
    pub async fn update_secret_enabled(
        &mut self,
        secret_name: &'a str,
        secret_version: &'a str,
        enabled: bool,
    ) -> Result<(), KeyVaultError> {
        let mut attributes = Map::new();
        attributes.insert("enabled".to_owned(), Value::Bool(enabled));

        self.update_secret(secret_name, secret_version, attributes).await?;

        Ok(())
    }

    /// Changes a secret's [Recovery Level](RecoveryLevel).
    ///
    /// # Example
    ///
    /// ```
    /// use azure_sdk_keyvault::{KeyVaultClient, RecoveryLevel};
    /// let mut client = KeyVaultClient::new(&"...", &"...", &"...", &"test-keyvault");
    /// client.update_secret_recovery_level(&"some_secret", &"...", RecoveryLevel::Purgeable);
    /// ```
    pub async fn update_secret_recovery_level(
        &mut self,
        secret_name: &'a str,
        secret_version: &'a str,
        recovery_level: RecoveryLevel,
    ) -> Result<(), KeyVaultError> {
        let mut attributes = Map::new();
        attributes.insert("enabled".to_owned(), Value::String(recovery_level.to_string()));

        self.update_secret(secret_name, secret_version, attributes).await?;

        Ok(())
    }

    /// Changes a secret's [Recovery Level](RecoveryLevel).
    ///
    /// # Example
    ///
    /// ```
    /// use azure_sdk_keyvault::{KeyVaultClient, RecoveryLevel};
    /// let mut client = KeyVaultClient::new(&"...", &"...", &"...", &"test-keyvault");
    /// client.update_secret_recovery_level(&"some_secret", &"...", RecoveryLevel::Purgeable);
    /// ```
    pub async fn update_secret_expiration_time(
        &mut self,
        secret_name: &'a str,
        secret_version: &'a str,
        expiration_time: DateTime<Utc>,
    ) -> Result<(), KeyVaultError> {
        let mut attributes = Map::new();
        attributes.insert(
            "exp".to_owned(),
            Value::Number(serde_json::Number::from(expiration_time.timestamp())),
        );

        self.update_secret(secret_name, secret_version, attributes).await?;

        Ok(())
    }

    async fn update_secret(
        &mut self,
        secret_name: &'a str,
        secret_version: &'a str,
        attributes: Map<String, Value>,
    ) -> Result<(), KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!("{}/secrets/{}/{}", self.keyvault_endpoint, secret_name, secret_version),
            &[("api-version", API_VERSION)],
        )
        .unwrap();

        let mut request_body = Map::new();
        request_body.insert("attributes".to_owned(), Value::Object(attributes));

        self.patch_authed(uri.to_string(), Value::Object(request_body).to_string())
            .await?;

        Ok(())
    }
}
