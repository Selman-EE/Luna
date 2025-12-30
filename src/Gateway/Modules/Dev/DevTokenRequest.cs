namespace Gateway.Modules.Dev;
public sealed record DevTokenRequest(
    string? Sub,
    int TtlMinutes,
    string[]? Roles,
    string[]? Permissions
);