using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Freeq.Windows.Models;

namespace Freeq.Windows.ViewModels;

/// <summary>
/// ViewModel for a single channel or DM conversation.
/// </summary>
public partial class ChannelViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _topic = "";

    [ObservableProperty]
    private bool _isJoined;

    [ObservableProperty]
    private int _unreadCount;

    [ObservableProperty]
    private bool _scrollToBottom;

    [ObservableProperty]
    private bool _isServerChannel;

    // ── History ──

    [ObservableProperty]
    private bool _isLoadingHistory;

    [ObservableProperty]
    private bool _hasMoreHistory = true;

    [ObservableProperty]
    private string? _oldestMsgId;

    // ── Typing ──

    [ObservableProperty]
    private string? _typingIndicator;

    private readonly Dictionary<string, DateTime> _typingUsers = new();
    private System.Timers.Timer? _typingCleanupTimer;

    // ── Pinned ──

    public ObservableCollection<IrcMessage> PinnedMessages { get; } = new();

    public ObservableCollection<IrcMessage> Messages { get; } = new();
    public ObservableCollection<IrcMember> Members { get; } = new();

    public ChannelViewModel()
    {
        // People first, then a separate "Agents" group. Live grouping, so a
        // member regroups the moment its actor class arrives (674 / JOIN tag
        // land after NAMES / the join itself).
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Members);
        view.GroupDescriptions.Add(new System.Windows.Data.PropertyGroupDescription(nameof(IrcMember.Group)));
        if (view is System.ComponentModel.ICollectionViewLiveShaping live && live.CanChangeLiveGrouping)
        {
            live.LiveGroupingProperties.Add(nameof(IrcMember.Group));
            live.IsLiveGrouping = true;
        }
    }

    public string DisplayName => IsServerChannel ? "Server" : Name.StartsWith('#') ? Name : $"@ {Name}";
    public bool IsChannel => Name.StartsWith('#');

    public int MemberCount => Members.Count;

    public void AddMember(IrcMember member)
    {
        var existing = FindMember(member.Nick);
        if (existing != null)
        {
            existing.IsOp = member.IsOp;
            existing.IsHalfOp = member.IsHalfOp;
            existing.IsVoiced = member.IsVoiced;
            RefreshMembers();
        }
        else
        {
            // Insert sorted: ops first, then halfops, then voiced, then regular
            var idx = 0;
            for (; idx < Members.Count; idx++)
            {
                if (CompareMemberRank(member, Members[idx]) < 0) break;
            }
            Members.Insert(idx, member);
            OnPropertyChanged(nameof(MemberCount));
        }
    }

    public void RemoveMember(string nick)
    {
        var m = FindMember(nick);
        if (m != null)
        {
            Members.Remove(m);
            OnPropertyChanged(nameof(MemberCount));
        }
    }

    public IrcMember? FindMember(string nick)
    {
        return Members.FirstOrDefault(m =>
            string.Equals(m.Nick, nick, StringComparison.OrdinalIgnoreCase));
    }

    public void RefreshMembers()
    {
        // Re-sort members by rank
        var sorted = Members.OrderBy(m => m, MemberRankComparer.Instance).ToList();
        for (int i = 0; i < sorted.Count; i++)
        {
            if (Members[i] != sorted[i])
            {
                Members.Move(Members.IndexOf(sorted[i]), i);
            }
        }
    }

    public void AddTypingUser(string nick)
    {
        _typingUsers[nick] = DateTime.UtcNow;
        UpdateTypingIndicator();
        EnsureTypingCleanup();
    }

    public void RemoveTypingUser(string nick)
    {
        _typingUsers.Remove(nick);
        UpdateTypingIndicator();
    }

    private void UpdateTypingIndicator()
    {
        // Remove stale entries (>8s)
        var stale = _typingUsers.Where(kv => (DateTime.UtcNow - kv.Value).TotalSeconds > 8).Select(kv => kv.Key).ToList();
        foreach (var s in stale) _typingUsers.Remove(s);

        var users = _typingUsers.Keys.ToList();
        TypingIndicator = users.Count switch
        {
            0 => null,
            1 => $"{users[0]} is typing...",
            2 => $"{users[0]} and {users[1]} are typing...",
            _ => $"{users[0]}, {users[1]} and {users.Count - 2} more are typing..."
        };
    }

    private void EnsureTypingCleanup()
    {
        if (_typingCleanupTimer != null) return;
        _typingCleanupTimer = new System.Timers.Timer(3000) { AutoReset = true };
        _typingCleanupTimer.Elapsed += (_, _) =>
        {
            System.Windows.Application.Current?.Dispatcher?.BeginInvoke(UpdateTypingIndicator);
        };
        _typingCleanupTimer.Start();
    }

    private static int CompareMemberRank(IrcMember a, IrcMember b)
    {
        return MemberRankComparer.Instance.Compare(a, b);
    }

    private class MemberRankComparer : IComparer<IrcMember>
    {
        public static readonly MemberRankComparer Instance = new();

        public int Compare(IrcMember? a, IrcMember? b)
        {
            if (a == null || b == null) return 0;
            var ra = GetRank(a);
            var rb = GetRank(b);
            if (ra != rb) return ra.CompareTo(rb);
            return string.Compare(a.Nick, b.Nick, StringComparison.OrdinalIgnoreCase);
        }

        // Regular agents after regular people, matching the "Agents" group.
        private static int GetRank(IrcMember m) =>
            m.IsOp ? 0 : m.IsHalfOp ? 1 : m.IsVoiced ? 2 : m.IsAgent ? 4 : 3;
    }
}
