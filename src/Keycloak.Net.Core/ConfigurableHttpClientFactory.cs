using System.Net.Http;
using Flurl.Http.Configuration;

namespace Keycloak.Net
{
    internal class ConfigurableHttpClientFactory : DefaultHttpClientFactory
    {
        // Values for client configuration
        private HttpMessageHandler _clientHandler;

        public ConfigurableHttpClientFactory()
        {
            _clientHandler = base.CreateMessageHandler();
        }

        public void SetHttpClientHandler(HttpClientHandler clientHandler)
        {
            _clientHandler = clientHandler;
        }

        public override HttpMessageHandler CreateMessageHandler()
        {
            return _clientHandler;
        }
    }
}