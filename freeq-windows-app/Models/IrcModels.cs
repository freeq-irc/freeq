namespace Freeq.Windows.Models;

public class IrcMessage
{
    public string Id { get; set; } = "";
    public string From { get; set; } = "";
    public string Target { get; set; } = "";
    public string Text { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool IsAction { get; set; }
    public bool IsSelf { get; set; }
    public bool IsSystem { get; set; }
    public string? ReplyTo { get; set; }
    public string? ReplyPreview { get; set; }
    public string? EditOf { get; set; }
    public bool IsEdited { get; set; }
    public bool Deleted { get; set; }
    public bool IsBatchMessage { get; set; }

    /// <summary>
    /// Reactions: emoji → list of nicks who reacted.
    /// </summary>
    public Dictionary<string, List<string>> Reactions { get; set; } = new();

    public bool HasReactions => Reactions.Count > 0;

    public string ReactionsDisplay
    {
        get
        {
            if (Reactions.Count == 0) return "";
            return string.Join("  ", Reactions.Select(r => $"{r.Key} {r.Value.Count}"));
        }
    }

    public void AddReaction(string emoji, string nick)
    {
        if (!Reactions.ContainsKey(emoji))
            Reactions[emoji] = new List<string>();
        if (!Reactions[emoji].Contains(nick, StringComparer.OrdinalIgnoreCase))
            Reactions[emoji].Add(nick);
    }
}

/// <summary>
/// A channel member. Observable so the row repaints in place when its away,
/// presence or actor class changes — the record is mutated, never rebuilt, so
/// a mode change, rename or NAMES refresh keeps the agent's class and status.
/// </summary>
public class IrcMember : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
{
    private string _nick = "";
    private bool _isOp, _isHalfOp, _isVoiced;
    private string? _awayMsg, _awayText, _actorClass, _presenceState, _presenceText;
    private bool _awayIsAgentStatus;

    public string Nick { get => _nick; set { if (SetProperty(ref _nick, value)) OnPropertyChanged(nameof(PrefixedNick)); } }
    public bool IsOp { get => _isOp; set { if (SetProperty(ref _isOp, value)) Changed(); } }
    public bool IsHalfOp { get => _isHalfOp; set { if (SetProperty(ref _isHalfOp, value)) Changed(); } }
    public bool IsVoiced { get => _isVoiced; set { if (SetProperty(ref _isVoiced, value)) Changed(); } }

    /// <summary>The AWAY reason as sent; null when not away.</summary>
    public string? AwayMsg { get => _awayMsg; set { if (SetProperty(ref _awayMsg, value)) Changed(); } }
    /// <summary>The AWAY reason for display, decoded by the core when it is an agent status.</summary>
    public string? AwayText { get => _awayText; set { if (SetProperty(ref _awayText, value)) Changed(); } }
    /// <summary>The AWAY reason is an agent's key=value status, not a person's away message.</summary>
    public bool AwayIsAgentStatus { get => _awayIsAgentStatus; set { if (SetProperty(ref _awayIsAgentStatus, value)) Changed(); } }

    /// <summary>"agent" / "external_agent" when the server said so; null is a person.</summary>
    public string? ActorClass { get => _actorClass; set { if (SetProperty(ref _actorClass, value)) Changed(); } }
    /// <summary>Last structured PRESENCE state (agents only), e.g. "executing".</summary>
    public string? PresenceState { get => _presenceState; set { if (SetProperty(ref _presenceState, value)) Changed(); } }
    /// <summary>Last PRESENCE as one display line, decoded by the core.</summary>
    public string? PresenceText { get => _presenceText; set { if (SetProperty(ref _presenceText, value)) Changed(); } }

    public string PrefixedNick =>
        IsOp ? $"@{Nick}" :
        IsHalfOp ? $"%{Nick}" :
        IsVoiced ? $"+{Nick}" :
        Nick;

    public bool IsAgent => ActorClass is "agent" or "external_agent";
    public string AgentBadge => ActorClass == "external_agent" ? "EXT AGENT" : "AGENT";
    public string AgentBadgeTooltip => ActorClass == "external_agent" ? "External agent" : "Agent";

    /// <summary>An agent at work: presence says so, or (with none) its AWAY is its status.</summary>
    public bool IsWorking => IsAgent && (PresenceState == "executing" || (PresenceState == null && AwayIsAgentStatus));

    /// <summary>Label "away" only for real absence — never for an agent whose AWAY is its status.</summary>
    public bool ShowsAway => AwayMsg != null && !IsWorking && !(IsAgent && AwayIsAgentStatus);

    /// <summary>One line under the nick: "Working · answering chad in #phoenix", or a person's away message.</summary>
    public string? StatusLine => IsAgent && !string.IsNullOrEmpty(PresenceText) ? PresenceText : AwayText;

    /// <summary>List group: regular-rank agents after the people; ops and voiced keep their rank.</summary>
    public string Group => IsAgent && !IsOp && !IsHalfOp && !IsVoiced ? "Agents" : "Members";

    private void Changed()
    {
        OnPropertyChanged(nameof(PrefixedNick));
        OnPropertyChanged(nameof(IsAgent));
        OnPropertyChanged(nameof(AgentBadge));
        OnPropertyChanged(nameof(AgentBadgeTooltip));
        OnPropertyChanged(nameof(IsWorking));
        OnPropertyChanged(nameof(ShowsAway));
        OnPropertyChanged(nameof(StatusLine));
        OnPropertyChanged(nameof(Group));
    }
}

public class IrcChannel
{
    public string Name { get; set; } = "";
    public string Topic { get; set; } = "";
    public string? TopicSetBy { get; set; }
    public int UnreadCount { get; set; }
    public bool IsJoined { get; set; }
}
