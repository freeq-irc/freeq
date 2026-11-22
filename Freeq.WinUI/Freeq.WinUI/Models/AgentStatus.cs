using System.Text.RegularExpressions;

namespace Freeq.WinUI.Models;

/// <summary>
/// An agent's presence status, decoded.
///
/// Agents built on harness-kit publish their status as space-separated
/// <c>key=value</c> pairs, with the prose <c>doing</c> field's spaces sent as <c>+</c>:
///
/// <code>project=phoenix-agent model=opus doing=answering+chad+in+#phoenix+·+0s</code>
///
/// Carried in an AWAY reason it is prefixed with the presence state
/// (<c>executing: project=…</c>). Shown raw it is unreadable, so every surface
/// decodes it with this first. Mirrors freeq-app/src/lib/status.ts and
/// freeq-macos/…/Models/AgentStatus.swift — keep the wording in step.
///
/// Pure: no WinUI dependencies, so the test project links it directly.
/// </summary>
public sealed record AgentStatus
{
    /// <summary>Presence state when the text carried one (<c>executing</c>, …).</summary>
    public string? State { get; init; }
    /// <summary>What the agent is doing right now, as prose.</summary>
    public string? Doing { get; init; }
    public string? Project { get; init; }
    public string? Branch { get; init; }
    public string? Repo { get; init; }
    public string? Model { get; init; }

    private static readonly HashSet<string> Known =
        ["project", "branch", "repo", "model", "session", "doing"];

    private static readonly Regex Pair = new(@"^[a-z_]+=\S*$", RegexOptions.CultureInvariant);
    private static readonly Regex StatePrefix = new(@"^([a-z_]+):\s+(.*)$", RegexOptions.CultureInvariant | RegexOptions.Singleline);
    private static readonly char[] Whitespace = [' ', '\t', '\r', '\n'];

    /// <summary>
    /// Decode an agent's status string, or null when it is not one (free text
    /// from a person, JSON, empty). Never throws.
    /// </summary>
    public static AgentStatus? Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var text = raw.Trim();
        string? state = null;

        // "executing: project=…" — a state prefix, but only in front of pairs,
        // so a person's "lunch: back at 2" is left alone.
        var prefixed = StatePrefix.Match(text);
        if (prefixed.Success)
        {
            var rest = prefixed.Groups[2].Value;
            var first = rest.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            if (Pair.IsMatch(first))
            {
                state = prefixed.Groups[1].Value;
                text = rest;
            }
        }

        var tokens = text.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0 || !tokens.All(t => Pair.IsMatch(t))) return null;

        var known = 0;
        string? doing = null, project = null, branch = null, repo = null, model = null;
        foreach (var token in tokens)
        {
            var eq = token.IndexOf('=');
            var key = token[..eq];
            var value = token[(eq + 1)..];
            if (!Known.Contains(key)) continue;
            known++;
            if (value.Length == 0) continue;
            switch (key)
            {
                case "doing": doing = value.Replace('+', ' '); break;
                case "project": project = value; break;
                case "branch": branch = value; break;
                case "repo": repo = value; break;
                case "model": model = value; break;
                // "session" is an internal id: recognised, never shown.
            }
        }
        if (known == 0) return null;

        return new AgentStatus
        {
            State = state,
            Doing = doing,
            Project = project,
            Branch = branch,
            Repo = repo,
            Model = model,
        };
    }

    /// <summary>Words for an agent presence state.</summary>
    public static string? LabelForState(string? state)
    {
        if (string.IsNullOrEmpty(state)) return null;
        return state switch
        {
            "executing" => "Working",
            "active" or "online" => "Available",
            "idle" => "Idle",
            "waiting_for_input" => "Waiting for input",
            "blocked_on_permission" => "Needs approval",
            "blocked_on_budget" => "Out of budget",
            "rate_limited" => "Rate limited",
            "degraded" => "Degraded",
            "paused" => "Paused",
            "sandboxed" => "Sandboxed",
            "revoked" => "Revoked",
            "offline" => "Offline",
            _ => state.Replace('_', ' '),
        };
    }

    /// <summary>"phoenix-agent @main · opus": where the agent is working, in one line.</summary>
    public string? Context
    {
        get
        {
            var where = string.Join(" ", new[] { Project, Branch is null ? null : $"@{Branch}" }
                .Where(s => !string.IsNullOrEmpty(s)));
            var parts = new[] { where, Model }.Where(s => !string.IsNullOrEmpty(s)).ToArray();
            return parts.Length == 0 ? null : string.Join(" · ", parts);
        }
    }

    /// <summary>One line: "Working · answering chad in #phoenix".</summary>
    public string? Summary
    {
        get
        {
            var parts = new[] { LabelForState(State), Doing ?? Context }
                .Where(s => !string.IsNullOrEmpty(s)).ToArray();
            return parts.Length == 0 ? null : string.Join(" · ", parts);
        }
    }

    /// <summary>The labelled facts a detail view lists under the activity.</summary>
    public IReadOnlyList<(string Label, string Value)> Facts =>
        new (string, string?)[] { ("Project", Project), ("Branch", Branch), ("Repo", Repo), ("Model", Model) }
            .Where(f => !string.IsNullOrEmpty(f.Item2))
            .Select(f => (f.Item1, f.Item2!))
            .ToList();

    /// <summary>An AWAY reason as display text: an agent's decoded, anyone else's as is.</summary>
    public static string? DisplayAway(string? away)
    {
        if (string.IsNullOrEmpty(away)) return null;
        return Parse(away) is { } agent ? agent.Summary : away;
    }

    // ── Member-level rules, shared by the member list and the profile view ──

    /// <summary>
    /// A member's agent status: from its live PRESENCE status when it is an
    /// agent that publishes one (its state filling in when the text has none),
    /// else from its AWAY reason. Null for a person.
    /// </summary>
    public static AgentStatus? ForMember(bool isAgent, string? presenceState, string? presenceStatus, string? awayMessage)
    {
        if (isAgent && Parse(presenceStatus) is { } live)
            return live.State is null ? live with { State = presenceState } : live;
        if (isAgent && Parse(awayMessage) is { } away)
            return away;
        return null;
    }

    /// <summary>
    /// An agent at work: it says so in presence, or (with no presence) its
    /// AWAY is an agent status rather than a person's away message. A working
    /// agent is not "Away", whatever the IRC AWAY flag says.
    /// </summary>
    public static bool IsWorking(bool isAgent, string? presenceState, string? awayMessage)
    {
        if (!isAgent) return false;
        if (presenceState == "executing") return true;
        return presenceState is null && Parse(awayMessage) is not null;
    }

    /// <summary>
    /// Whether to label a member "Away". Never for an agent whose AWAY is an
    /// agent status (it is working, or blocked — its status line says which),
    /// nor for one whose presence says it is executing.
    /// </summary>
    public static bool ShowsAway(bool isAgent, string? presenceState, string? awayMessage, bool isAway) =>
        isAway
        && !IsWorking(isAgent, presenceState, awayMessage)
        && !(isAgent && Parse(awayMessage) is not null);

    /// <summary>
    /// The status a profile or DM view shows: the agent's state in words
    /// ("Working", "Needs approval", "Available") — never "Away" for an agent
    /// whose AWAY is its status — else "Away: …" for a person, else "Online".
    /// </summary>
    public static string ProfileStatus(bool isAgent, string? presenceState, string? presenceStatus, string? awayMessage, bool isAway)
    {
        if (isAgent)
        {
            var away = ShowsAway(true, presenceState, awayMessage, isAway);
            var state = ForMember(true, presenceState, presenceStatus, awayMessage)?.State ?? presenceState;
            if (!away && LabelForState(state) is { } label) return label;
            if (IsWorking(true, presenceState, awayMessage)) return "Working";
        }
        if (isAway)
            return string.IsNullOrEmpty(awayMessage) ? "Away" : $"Away: {DisplayAway(awayMessage)}";
        return "Online";
    }

    /// <summary>
    /// The one line under a member's nick: an agent's decoded status, a
    /// person's away message, or null for nothing to show.
    /// </summary>
    public static string? MemberLine(bool isAgent, string? presenceState, string? presenceStatus, string? awayMessage)
    {
        if (isAgent)
        {
            if (ForMember(true, presenceState, presenceStatus, awayMessage) is { } s && s.Summary is { } summary)
                return summary;
            // An agent with a state and nothing else still says what it is doing.
            if (LabelForState(presenceState) is { } label)
                return label;
        }
        return DisplayAway(awayMessage);
    }
}
