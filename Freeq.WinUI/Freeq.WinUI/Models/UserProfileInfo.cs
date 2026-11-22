namespace Freeq.WinUI.Models;

public class UserProfileInfo
{
    public string Nick { get; set; } = string.Empty;
    public string? Did { get; set; }
    public string? BlueskyHandle { get; set; }
    public bool CanModerate { get; set; }
    public string? ActorClass { get; set; }
    public bool IsAway { get; set; }
    public string? AwayMessage { get; set; }
    public string? PresenceState { get; set; }
    public string? PresenceText { get; set; }

    public bool IsAgent => ActorClass is "agent" or "external_agent";
    public string? ActorLabel => ActorClass switch
    {
        "agent" => "Agent",
        "external_agent" => "External agent",
        _ => null,
    };

    /// <summary>The agent's decoded status (presence first, then AWAY); null for a person.</summary>
    public AgentStatus? Agent => AgentStatus.ForMember(IsAgent, PresenceState, PresenceText, AwayMessage);

    /// <summary>
    /// The status line for the profile: "Working" (agents — never "Away"),
    /// "Away: lunch" for a person, or "Online".
    /// </summary>
    public string StatusText =>
        AgentStatus.ProfileStatus(IsAgent, PresenceState, PresenceText, AwayMessage, IsAway);

    public string DisplayDid => string.IsNullOrWhiteSpace(Did) ? "Guest" : Did!;
    public string DisplayHandle => string.IsNullOrWhiteSpace(BlueskyHandle) ? "Unavailable" : BlueskyHandle!;
}
