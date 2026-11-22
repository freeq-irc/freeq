using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Freeq.WinUI.Models;

public enum MemberRole
{
    Operator,
    HalfOp,
    Voiced,
    Regular
}

public enum PresenceStatus
{
    Online,
    Away,
    Offline
}

public class MemberModel
{
    public string Nick { get; set; } = string.Empty;
    public string? Did { get; set; }
    public string? AwayMessage { get; set; }
    public MemberRole Role { get; set; } = MemberRole.Regular;
    public PresenceStatus Status { get; set; } = PresenceStatus.Online;
    /// <summary>"agent" / "external_agent" when the server said so; null is a person.</summary>
    public string? ActorClass { get; set; }
    /// <summary>Last structured PRESENCE state (agents only), e.g. "executing".</summary>
    public string? PresenceState { get; set; }
    /// <summary>Last structured PRESENCE status text, raw (key=value pairs).</summary>
    public string? PresenceText { get; set; }

    public bool IsVerified => !string.IsNullOrEmpty(Did);
    public bool IsAgent => ActorClass is "agent" or "external_agent";
    public string AgentBadge => ActorClass == "external_agent" ? "EXT AGENT" : "AGENT";
    public string AgentBadgeTooltip => ActorClass == "external_agent" ? "External agent" : "Agent";

    /// <summary>A working agent: its AWAY is its work, so it is not "away".</summary>
    public bool IsWorking => AgentStatus.IsWorking(IsAgent, PresenceState, AwayMessage);
    public bool ShowsAway => AgentStatus.ShowsAway(IsAgent, PresenceState, AwayMessage, Status == PresenceStatus.Away);

    /// <summary>One line under the nick: "Working · answering chad in #phoenix", or a person's away message.</summary>
    public string? StatusLine => AgentStatus.MemberLine(IsAgent, PresenceState, PresenceText, AwayMessage);
    public bool HasStatusLine => !string.IsNullOrEmpty(StatusLine);

    public Brush RoleBrush => Resource(Role == MemberRole.Voiced ? "WarningBrush" : "SuccessBrush");
    public Brush StatusLineBrush => Resource(IsAgent ? "BlueBrush" : "FgDimBrush");
    public Brush PresenceDotBrush => Resource(IsWorking ? "BlueBrush" : ShowsAway ? "WarningBrush" : "SuccessBrush");

    // Same lookup as MessageContentView: the indexer searches the merged theme dictionaries.
    private static Brush Resource(string key)
    {
        try
        {
            if (Application.Current?.Resources[key] is Brush brush) return brush;
        }
        catch { /* missing key: fall through */ }
        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }
    public string NickInitial => string.IsNullOrEmpty(Nick) ? "?" : Nick[..1].ToUpper();

    public string RoleBadge => Role switch
    {
        MemberRole.Operator => "@",
        MemberRole.HalfOp => "%",
        MemberRole.Voiced => "+",
        _ => ""
    };

    // Design system: hash-assigned nick color from the 5-hue palette
    public SolidColorBrush NickBrush => NickColor.ForNick(Nick);
    public SolidColorBrush AvatarBackgroundBrush => NickColor.AvatarBackgroundForNick(Nick);
}
