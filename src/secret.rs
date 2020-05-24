use crate::KeyVaultClient;
use crate::KeyVaultError;
use anyhow::Result;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use getset::Getters;
use reqwest::Url;
use serde::Deserialize;
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
    pub async fn get_secret(
        &mut self,
        secret_name: &'a str,
    ) -> Result<KeyVaultSecret, KeyVaultError> {
        Ok(self.get_secret_with_version(secret_name, "").await?)
    }

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
            &[("api-version", "7.0")],
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
}
