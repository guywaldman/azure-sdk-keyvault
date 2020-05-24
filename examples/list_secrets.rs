use azure_sdk_keyvault::KeyVaultClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = "...";
    let client_secret = "...";
    let tenant_id = "...";
    let keyvault_name = "guywald-personal";

    let mut client = KeyVaultClient::new(client_id, client_secret, tenant_id, keyvault_name);

    let secrets = client.list_secrets(25).await?;
    dbg!(&secrets);

    Ok(())
}
