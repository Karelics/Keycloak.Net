using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keycloak.Net.Core.Caching;

public sealed class InMemoryKeycloakAccessTokenCache : IKeycloakAccessTokenCache
{
    private static readonly ReaderWriterLockSlim _locker;
    private static readonly IDictionary<string, (string, DateTime)> _cache;
    private static DateTime _lastFlush;

    static InMemoryKeycloakAccessTokenCache()
    {
        _locker = new ReaderWriterLockSlim();
        _cache = new Dictionary<string, (string, DateTime)>(StringComparer.OrdinalIgnoreCase);
        _lastFlush = DateTime.UtcNow;
    }

    public Task<string> GetFromCacheAsync(string key, CancellationToken cancellationToken)
    {
        _locker.EnterUpgradeableReadLock();

        try
        {
            if (!_cache.TryGetValue(key, out var cachedToken))
            {
                return Task.FromResult(string.Empty);
            }

            if (cachedToken.Item2 < DateTime.UtcNow)
            {
                _locker.EnterWriteLock();

                try
                {
                    _cache.Remove(key);

                    return Task.FromResult(string.Empty);
                }
                finally
                {
                    _locker.ExitWriteLock();
                }
            }

            return Task.FromResult(cachedToken.Item1);
        }
        finally
        {
            _locker.ExitUpgradeableReadLock();
        }
    }

    public async Task AddToCacheAsync(string key, string accessToken, CancellationToken cancellationToken)
    {
        JwtSecurityToken token;

        try
        {
            token = GetAccessToken(accessToken);
        }
        catch
        {
            // Do we care anything went wrong?

            return;
        }

        var expires = token.ValidTo.ToUniversalTime();

        if (expires < DateTime.UtcNow)
        {
            return;
        }

        var shouldFlush = false;

        _locker.EnterWriteLock();

        try
        {
            _cache[key] = (accessToken, expires);

            var ts = DateTime.UtcNow - _lastFlush;

            if (ts >= FlushPeriod)
            {
                shouldFlush = true;
            }
        }
        finally
        {
            _locker.ExitWriteLock();
        }

        if (shouldFlush)
        {
            await FlushCacheAsync(cancellationToken);
        }
    }

    public Task<bool> RemoveFromCacheAsync(string key, CancellationToken cancellationToken)
    {
        _locker.EnterUpgradeableReadLock();

        try
        {
            if (_cache.TryGetValue(key, out _))
            {
                _locker.EnterWriteLock();

                try
                {
                    _cache.Remove(key);

                    return Task.FromResult(true);
                }
                finally
                {
                    _locker.ExitWriteLock();
                }
            }

            return Task.FromResult(false);
        }
        finally
        {
            _locker.ExitUpgradeableReadLock();
        }
    }

    public Task ClearCacheAsync(CancellationToken cancellationToken)
    {
        _locker.EnterWriteLock();

        try
        {
            _cache.Clear();

            _lastFlush = DateTime.UtcNow;
        }
        finally
        {
            _locker.ExitWriteLock();
        }

        return Task.CompletedTask;
    }

    private async Task FlushCacheAsync(CancellationToken cancellationToken)
    {
        _locker.EnterWriteLock();

        try
        {
            var expiredKeys = new List<string>(_cache.Count);

            foreach (var kvp in _cache)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (kvp.Value.Item2 < DateTime.UtcNow)
                {
                    expiredKeys.Add(kvp.Key);
                }
            }

            foreach (var key in expiredKeys)
            {
                cancellationToken.ThrowIfCancellationRequested();

                _cache.Remove(key);
            }

            _lastFlush = DateTime.UtcNow;
        }
        finally
        {
            _locker.ExitWriteLock();
        }
    }

    private JwtSecurityToken GetAccessToken(string accessToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(accessToken);

        return token;
    }

    public TimeSpan FlushPeriod { get; } = TimeSpan.FromMinutes(20);
}
