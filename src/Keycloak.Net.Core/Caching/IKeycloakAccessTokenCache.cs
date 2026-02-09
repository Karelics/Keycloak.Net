using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keycloak.Net.Core.Caching;

public interface IKeycloakAccessTokenCache
{
    Task<string> GetFromCacheAsync(string key, CancellationToken cancellationToken = default);
    Task AddToCacheAsync(string key, string accessToken, CancellationToken cancellationToken = default);
    Task<bool> RemoveFromCacheAsync(string key, CancellationToken cancellationToken = default);
    Task ClearCacheAsync(CancellationToken cancellationToken = default);

    TimeSpan FlushPeriod { get; }
}
