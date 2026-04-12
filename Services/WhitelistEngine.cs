using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Manages whitelist rules and provides fast domain/IP matching.
/// Rules are loaded from SQLite and cached in memory.
/// </summary>
public class WhitelistEngine
{
    private readonly DatabaseService _db;
    private List<WhitelistRule> _rules = new();
    private DateTime _lastLoad = DateTime.MinValue;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public WhitelistEngine(DatabaseService db) => _db = db;

    // ── Public API ────────────────────────────────────────────

    public async Task<bool> IsDomainWhitelistedAsync(string domain)
    {
        await EnsureLoadedAsync();
        return _rules
            .Where(r => r.Type == RuleType.Domain && r.IsEnabled)
            .Any(r => r.Matches(domain));
    }

    public async Task<bool> IsIpWhitelistedAsync(string ip)
    {
        await EnsureLoadedAsync();
        return _rules
            .Where(r => r.Type == RuleType.Ip && r.IsEnabled)
            .Any(r => r.Matches(ip));
    }

    public async Task<bool> IsProcessWhitelistedAsync(string processName)
    {
        await EnsureLoadedAsync();
        return _rules
            .Where(r => r.Type == RuleType.ProcessName && r.IsEnabled)
            .Any(r => r.Matches(processName));
    }

    public async Task<List<WhitelistRule>> GetAllRulesAsync()
    {
        await EnsureLoadedAsync();
        return _rules.ToList();
    }

    public async Task AddRuleAsync(WhitelistRule rule)
    {
        rule.Id = await _db.AddRuleAsync(rule);
        _rules.Add(rule);
    }

    public async Task UpdateRuleAsync(WhitelistRule rule)
    {
        await _db.UpdateRuleAsync(rule);
        var idx = _rules.FindIndex(r => r.Id == rule.Id);
        if (idx >= 0) _rules[idx] = rule;
    }

    public async Task DeleteRuleAsync(int id)
    {
        await _db.DeleteRuleAsync(id);
        _rules.RemoveAll(r => r.Id == id);
    }

    public void InvalidateCache() => _lastLoad = DateTime.MinValue;

    // ── Private ───────────────────────────────────────────────
    private async Task EnsureLoadedAsync()
    {
        if (DateTime.UtcNow - _lastLoad < TimeSpan.FromMinutes(5)) return;
        await _lock.WaitAsync();
        try
        {
            if (DateTime.UtcNow - _lastLoad < TimeSpan.FromMinutes(5)) return;
            _rules    = await _db.GetRulesAsync();
            _lastLoad = DateTime.UtcNow;
        }
        finally { _lock.Release(); }
    }
}
