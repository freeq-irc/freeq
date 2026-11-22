using Freeq.WinUI.Models;
using Freeq.WinUI.Services;

namespace Freeq.WinUI.Tests;

/// <summary>
/// The agent status decoder. Mirrors freeq-app/src/lib/status.test.ts so the
/// Windows client reads an agent's status in the same words as web and macOS.
/// </summary>
public class AgentStatusTests
{
    private const string Raw = "project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s";

    [Fact]
    public void Parse_DecodesHarnessKitStatus()
    {
        var s = AgentStatus.Parse(Raw);
        Assert.NotNull(s);
        Assert.Equal("phoenix-agent", s!.Project);
        Assert.Equal("answering chad-bot-phoenix in #phoenix · 0s", s.Doing);
        Assert.Null(s.State);
    }

    [Fact]
    public void Parse_TakesPresenceStateOffAwayReason()
    {
        var s = AgentStatus.Parse($"executing: {Raw} model=opus branch=main");
        Assert.NotNull(s);
        Assert.Equal("executing", s!.State);
        Assert.Equal("phoenix-agent", s.Project);
        Assert.Equal("opus", s.Model);
        Assert.Equal("main", s.Branch);
    }

    [Fact]
    public void Parse_NeverShowsSession()
    {
        var s = AgentStatus.Parse("session=abc123 model=opus");
        Assert.NotNull(s);
        Assert.Equal("opus", s!.Context);
        Assert.Equal("opus", s.Summary);
    }

    [Theory]
    [InlineData("out to lunch")]
    [InlineData("back at 3: see you")]
    [InlineData("{\"status\":\"lunch\"}")]
    [InlineData("a=b c=d")]
    [InlineData("project=x and some words")]
    [InlineData("Project=x")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Parse_LeavesNonAgentTextAlone(string? text)
        => Assert.Null(AgentStatus.Parse(text));

    [Fact]
    public void Parse_StatePrefixOnlyInFrontOfPairs()
    {
        Assert.Equal("blocked_on_budget", AgentStatus.Parse("blocked_on_budget: model=opus")!.State);
        Assert.Null(AgentStatus.Parse("lunch: back at 2"));
    }

    [Fact]
    public void DisplayAway_ReadsAgentAwayAsWords()
    {
        Assert.Equal("Working · answering chad-bot-phoenix in #phoenix · 0s", AgentStatus.DisplayAway($"executing: {Raw}"));
        Assert.Equal("Working · x · m", AgentStatus.DisplayAway("executing: project=x model=m"));
        Assert.Equal("Working · x @main · m", AgentStatus.DisplayAway("executing: project=x branch=main model=m"));
    }

    [Fact]
    public void DisplayAway_KeepsPeopleAsTheyWere()
    {
        Assert.Equal("lunch", AgentStatus.DisplayAway("lunch"));
        Assert.Equal("{\"status\":\"lunch\"}", AgentStatus.DisplayAway("{\"status\":\"lunch\"}"));
        Assert.Null(AgentStatus.DisplayAway(""));
        Assert.Null(AgentStatus.DisplayAway(null));
    }

    [Theory]
    [InlineData("executing", "Working")]
    [InlineData("active", "Available")]
    [InlineData("online", "Available")]
    [InlineData("idle", "Idle")]
    [InlineData("waiting_for_input", "Waiting for input")]
    [InlineData("blocked_on_permission", "Needs approval")]
    [InlineData("blocked_on_budget", "Out of budget")]
    [InlineData("rate_limited", "Rate limited")]
    [InlineData("degraded", "Degraded")]
    [InlineData("paused", "Paused")]
    [InlineData("sandboxed", "Sandboxed")]
    [InlineData("revoked", "Revoked")]
    [InlineData("offline", "Offline")]
    [InlineData("something_new", "something new")]
    public void LabelForState_NamesStates(string state, string label) =>
        Assert.Equal(label, AgentStatus.LabelForState(state));

    [Fact]
    public void Context_ProjectBranchModel() =>
        Assert.Equal("p @b · m", new AgentStatus { Project = "p", Branch = "b", Model = "m" }.Context);

    // ── Member-level rules ──

    [Fact]
    public void WorkingAgent_IsNotAway()
    {
        var away = $"executing: {Raw}";
        Assert.True(AgentStatus.IsWorking(isAgent: true, presenceState: null, awayMessage: away));
        Assert.False(AgentStatus.ShowsAway(true, null, away, isAway: true));
        Assert.Equal("Working", AgentStatus.ProfileStatus(true, null, null, away, isAway: true));
    }

    [Fact]
    public void BlockedAgent_IsNotAwayEither_ItsStateSaysWhy()
    {
        var away = "blocked_on_permission: project=x doing=editing+files";
        Assert.False(AgentStatus.ShowsAway(true, "blocked_on_permission", away, isAway: true));
        Assert.Equal("Needs approval", AgentStatus.ProfileStatus(true, "blocked_on_permission", null, away, true));
        Assert.Equal("Needs approval · editing files", AgentStatus.MemberLine(true, "blocked_on_permission", null, away));
    }

    [Fact]
    public void Person_WithAgentShapedAway_IsStillAway()
    {
        // Only a member the server classed as an agent is read as one.
        Assert.True(AgentStatus.ShowsAway(false, null, "lunch", isAway: true));
        Assert.Equal("Away: lunch", AgentStatus.ProfileStatus(false, null, null, "lunch", isAway: true));
        Assert.Equal("Online", AgentStatus.ProfileStatus(false, null, null, null, isAway: false));
    }

    [Fact]
    public void AgentAwayInFreeText_IsAway()
    {
        Assert.True(AgentStatus.ShowsAway(true, null, "gone fishing", isAway: true));
        Assert.Equal("gone fishing", AgentStatus.MemberLine(true, null, null, "gone fishing"));
    }

    [Fact]
    public void LivePresence_WinsOverAway_AndLendsItsState()
    {
        var s = AgentStatus.ForMember(true, "active", "project=freeq doing=reviewing+a+PR", null);
        Assert.NotNull(s);
        Assert.Equal("active", s!.State);
        Assert.Equal("Available · reviewing a PR", s.Summary);
        Assert.Equal("Available · reviewing a PR", AgentStatus.MemberLine(true, "active", "project=freeq doing=reviewing+a+PR", null));
        Assert.Equal("Available", AgentStatus.ProfileStatus(true, "active", "project=freeq doing=reviewing+a+PR", null, false));
    }

    [Fact]
    public void AgentWithStateOnly_SaysTheState() =>
        Assert.Equal("Idle", AgentStatus.MemberLine(true, "idle", null, null));

    [Fact]
    public void ForMember_NullForPeople() =>
        Assert.Null(AgentStatus.ForMember(false, null, Raw, $"executing: {Raw}"));
}

/// <summary>
/// The client keeps an agent's class and presence across the events that used
/// to drop them (rename, quit), and learns them from every source the server uses.
/// </summary>
public class ActorInfoTests
{
    [Fact]
    public void JoinTag_MarksAgent()
    {
        var irc = new IrcClient();
        irc.ProcessLine("@+freeq.at/actor-class=agent :bot!u@h JOIN #lobby did:key:z6Mk :Bot");
        irc.ProcessLine(":carol!u@h JOIN #lobby * :Carol");
        Assert.Equal("agent", irc.GetActorClass("bot"));
        Assert.Null(irc.GetActorClass("carol"));
    }

    [Fact]
    public void Roster674_MarksAgents_HumansStayUnmarked()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":irc.freeq.at 674 me #lobby :worker=agent bridge=external_agent dana=human junk");
        Assert.Equal("agent", irc.GetActorClass("worker"));
        Assert.Equal("external_agent", irc.GetActorClass("bridge"));
        Assert.Null(irc.GetActorClass("dana"));
    }

    [Fact]
    public void Presence_IsStored_AndProvesAgent()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":bot!u@h PRESENCE :state=executing;status=project=freeq doing=building+it;task=01JQ");
        var p = irc.GetPresence("bot");
        Assert.NotNull(p);
        Assert.Equal("executing", p!.State);
        Assert.Equal("project=freeq doing=building+it", p.Status);
        Assert.Equal("agent", irc.GetActorClass("bot"));
    }

    [Fact]
    public void Presence_WithoutState_IsIgnored()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":bot!u@h PRESENCE :status=hello");
        Assert.Null(irc.GetPresence("bot"));
    }

    [Fact]
    public void NickChange_CarriesClassAndPresence()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":irc.freeq.at 674 me #lobby :bot=agent");
        irc.ProcessLine(":bot!u@h PRESENCE :state=idle");
        irc.ProcessLine(":bot!u@h NICK bot2");
        Assert.Null(irc.GetActorClass("bot"));
        Assert.Equal("agent", irc.GetActorClass("bot2"));
        Assert.Equal("idle", irc.GetPresence("bot2")!.State);
    }

    [Fact]
    public void Quit_ForgetsClass()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":irc.freeq.at 674 me #lobby :bot=agent");
        irc.ProcessLine(":bot!u@h QUIT :bye");
        Assert.Null(irc.GetActorClass("bot"));
    }

    [Fact]
    public void Whois673_MarksAgent()
    {
        var irc = new IrcClient();
        irc.ProcessLine(":irc.freeq.at 673 me bot :actor_class=external_agent");
        Assert.Equal("external_agent", irc.GetActorClass("bot"));
    }
}
