using System;
using System.Configuration;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;

namespace PhoenixRising.Website
{
    public class WebUtils
    {
        public static string GetVaultSecret(string keyName)
        {
            KeyVaultClient KeyVault;
            try
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var _token = azureServiceTokenProvider.GetAccessTokenAsync("https://vault.azure.net").Result;
                KeyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            }
            catch (Exception e)
            {
                throw e;
            }

            string vaultURL = ConfigurationManager.AppSettings["AzureVaultURL"] + keyName;
            return KeyVault.GetSecretAsync(vaultURL).Result.Value;
        }
    }
}