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

    pub async fn list_secrets(
        &mut self,
        max_secrets: usize,
    ) -> Result<Vec<KeyVaultSecretBaseIdentifier>, KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!("https://{}.vault.azure.net/secrets", self.keyvault_name),
            &[
                ("api-version", API_VERSION),
                ("maxresults", &max_secrets.to_string()),
            ],
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

    pub async fn set_secret(
        &mut self,
        secret_name: &'a str,
        new_secret_value: &'a str
    ) -> Result<(), KeyVaultError> {
        let uri = Url::parse_with_params(
            &format!("https://{}.vault.azure.net/secrets/{}", self.keyvault_name, secret_name),
            &[
                ("api-version", API_VERSION)
            ],
        )
        .unwrap();

        let mut request_body = Map::new();
        request_body.insert("value".to_owned(), Value::String(new_secret_value.to_owned()));

        self.put_authed(uri.to_string(), Value::Object(request_body).to_string()).await?;

        Ok(())
    }
}
