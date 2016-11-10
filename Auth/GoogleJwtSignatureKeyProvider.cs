namespace ASP.Core.GoogleJwt.Auth
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Logging;

    using Newtonsoft.Json;

    public class GoogleJwtSignatureKeyProvider
    {
        private const string KeysCacheKey = "GooglePublicKeys";
        private const string PublicKeysEndpoint = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

        private readonly ILogger<GoogleJwtSignatureKeyProvider> logger;

        private readonly IMemoryCache cache;

        public GoogleJwtSignatureKeyProvider(ILogger<GoogleJwtSignatureKeyProvider> logger, IMemoryCache cache)
        {
            this.logger = logger;
            this.cache = cache;
        }

        public async Task<X509Certificate2> GetCertificateAsync(string jwtKid)
        {
            if (string.IsNullOrEmpty(jwtKid))
            {
                throw new ArgumentException("No JWT KID was provided!", nameof(jwtKid));
            }

            var certString = await GetCertificateStringAsync(jwtKid);
            certString = RemoveInvalidBase64Chars(certString);

            var certificateBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certificateBytes);
        }

        private async Task<string> GetCertificateStringAsync(string kid)
        {
            IDictionary<string, string> keys;

            if (cache.TryGetValue(KeysCacheKey, out keys))
            {
                if (keys.ContainsKey(kid))
                {
                    return keys[kid];
                }
            }

            keys = await GetAllPublicTokenCertificatesAsync();
            return keys?[kid];
        }

        private async Task<IDictionary<string, string>> GetAllPublicTokenCertificatesAsync()
        {
            var httpClient = new HttpClient();

            try
            {
                var response = await httpClient.GetAsync(new Uri(PublicKeysEndpoint));
                var content = await response.Content.ReadAsStringAsync();
                var keys = JsonConvert.DeserializeObject<IDictionary<string, string>>(content);

                var cacheControl = response.Headers.CacheControl;

                if (cacheControl.MaxAge.HasValue)
                {
                    cache.Set(KeysCacheKey, keys, new MemoryCacheEntryOptions().SetAbsoluteExpiration(cacheControl.MaxAge.Value));
                }

                return keys;
            }
            catch (Exception ex)
            {
                logger.LogWarning("Call to get GOOGLE JWT public keys failed.", ex);
                throw;
            }
        }

        private string RemoveInvalidBase64Chars(string certificateString)
        {
            certificateString = certificateString.Replace("-----BEGIN CERTIFICATE-----", string.Empty);
            certificateString = certificateString.Replace("-----END CERTIFICATE-----", string.Empty);
            certificateString = certificateString.Replace(Environment.NewLine, string.Empty);

            return certificateString.Trim();
        }
    }
}