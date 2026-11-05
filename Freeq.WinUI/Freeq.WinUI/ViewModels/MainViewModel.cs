using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Freeq.WinUI.Models;
using Freeq.WinUI.Services;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using System.Security.Cryptography;
using System.Text;
using System.Collections.ObjectModel;

namespace Freeq.WinUI.ViewModels;

#pragma warning disable MVVMTK0045 // AOT compatibility - not needed for desktop WinUI

public partial class MainViewModel : ObservableObject
{
    private readonly IrcClient _irc = new();
    private readonly DispatcherQueue _dispatcher;
    private readonly AppSettings _settings = new();

    [ObservableProperty] private string _serverUrl = "wss://irc.freeq.at/irc";
    [ObservableProperty] private string _nickname = "";
    [ObservableProperty] private string _connectionStatus = "Disconnected";
    [ObservableProperty] private ConnectionState _connectionState = ConnectionState.Disconnected;
    [ObservableProperty] private ChannelModel? _selectedChannel;
    [ObservableProperty] private string _composeText = "";
    [ObservableProperty] private string _currentTopic = "";
    [ObservableProperty] private bool _isConnected;
    [ObservableProperty] private bool _showConnectDialog = true;
    [ObservableProperty] private bool _isMemberListVisible = true;
    [ObservableProperty] private string? _errorMessage;

    // Edit mode: non-null when the user is editing an existing message
    [ObservableProperty] private string? _editingMessageId;
    [ObservableProperty] private bool _isEditing;

    // Typing indicator text shown above compose box, e.g. "Alice is typing…"
    [ObservableProperty] private string _typingText = "";
    [ObservableProperty] private bool _showReconnectBanner;
    [ObservableProperty] private string _reconnectBannerText = "";
    [ObservableProperty] private bool _showMotdBanner;
    [ObservableProperty] private string _motdText = "";
    [ObservableProperty] private bool _isAway;
    [ObservableProperty] private string _awayMessage = "";
    [ObservableProperty] private bool _isAppForeground = true;
    [ObservableProperty] private int _unreadMentionCount;
    [ObservableProperty] private ThemeMode _themeMode = ThemeMode.System;
    [ObservableProperty] private MessageDensity _messageDensity = MessageDensity.Default;
    [ObservableProperty] private JoinPartDisplay _joinPartDisplay = JoinPartDisplay.Hidden;
    [ObservableProperty] private bool _autoLoadExternalMedia = true;
    [ObservableProperty] private bool _enableWindowsNotifications = true;
    [ObservableProperty] private bool _enableNotificationSounds;
    [ObservableProperty] private bool _isChannelInviteOnly;
    [ObservableProperty] private bool _isChannelTopicProtected;
    [ObservableProperty] private bool _isChannelModerated;
    [ObservableProperty] private bool _isChannelNoExternal;
    [ObservableProperty] private bool _isChannelEncrypted;
    [ObservableProperty] private string _selectedChannelSafetyText = "";

    public ObservableCollection<ChannelModel> Channels { get; } = [];
    public ObservableCollection<ChannelModel> FavoriteChannels { get; } = [];
    public ObservableCollection<ChannelModel> DirectMessages { get; } = [];
    public ObservableCollection<MessageModel> Messages { get; } = [];
    public ObservableCollection<MemberModel> Operators { get; } = [];
    public ObservableCollection<MemberModel> Voiced { get; } = [];
    public ObservableCollection<MemberModel> Members { get; } = [];
    public ObservableCollection<ChannelListEntry> ServerChannels { get; } = [];
    public ObservableCollection<PinEntry> PinnedMessages { get; } = [];
    public ObservableCollection<MessageSearchResult> SearchResults { get; } = [];
    public ObservableCollection<GovernanceEvent> AuditTimeline { get; } = [];
    public ObservableCollection<ChannelMaskEntry> ChannelBans { get; } = [];
    public ObservableCollection<ChannelMaskEntry> ChannelInvites { get; } = [];
    public ObservableCollection<BookmarkEntry> Bookmarks { get; } = [];

    public event Action<string>? ToastRequested;
    public event Action<string>? WindowsToastRequested;
    public event Action<ThemeMode>? ThemeChanged;

    private readonly Dictionary<string, List<MessageModel>> _messagesByChannel = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _membersByChannel = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _pendingJoinChannels = [];
    private string? _desiredNickname;

    // Tracks who is currently typing per channel: channel → (nick → expiry timer)
    private readonly Dictionary<string, Dictionary<string, System.Threading.Timer>> _typingTimers = new(StringComparer.OrdinalIgnoreCase);

    // Outbound typing: timer to send "done" after 10 s of no input
    private System.Threading.Timer? _outboundTypingTimer;
    private bool _outboundTypingActive;
    private readonly Dictionary<string, string?> _awayByNick = new(StringComparer.OrdinalIgnoreCase);
    private bool _hasShownMotd;
    private string? _lastAuthenticatedDid;
    private bool _wasConnected;
    private readonly Dictionary<string, HashSet<char>> _channelModes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<ChannelMaskEntry>> _bansByChannel = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<ChannelMaskEntry>> _invitesByChannel = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<GovernanceEvent>> _auditByChannel = new(StringComparer.OrdinalIgnoreCase);

    public MainViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;

        // Load persisted UI and notification preferences.
        if (Enum.TryParse<ThemeMode>(_settings.ThemeMode, true, out var loadedTheme))
            ThemeMode = loadedTheme;
        if (Enum.TryParse<MessageDensity>(_settings.MessageDensity, true, out var loadedDensity))
            MessageDensity = loadedDensity;
        if (Enum.TryParse<JoinPartDisplay>(_settings.JoinPartDisplay, true, out var loadedJoinPart))
            JoinPartDisplay = loadedJoinPart;
        AutoLoadExternalMedia = _settings.AutoLoadExternalMedia;
        EnableWindowsNotifications = _settings.EnableWindowsNotifications;
        EnableNotificationSounds = _settings.EnableNotificationSounds;
        foreach (var bookmark in _settings.Bookmarks.OrderByDescending(b => b.BookmarkedAt))
            Bookmarks.Add(bookmark);

        _irc.StateChanged += OnStateChanged;
        _irc.MessageReceived += OnMessageReceived;
        _irc.MessageEdited += OnMessageEdited;
        _irc.MessageDeleted += OnMessageDeleted;
        _irc.ReactionReceived += OnReactionReceived;
        _irc.TypingChanged += OnTypingChanged;
        _irc.JoinReceived += OnJoinReceived;
        _irc.PartReceived += OnPartReceived;
        _irc.QuitReceived += OnQuitReceived;
        _irc.AwayChanged += OnAwayChanged;
        _irc.SelfAwayStateChanged += OnSelfAwayStateChanged;
        _irc.TopicReceived += OnTopicReceived;
        _irc.NamesReceived += OnNamesReceived;
        _irc.NickChanged += OnNickChanged;
        _irc.AccountChanged += OnAccountChanged;
        _irc.ListEntryReceived += OnListEntryReceived;
        _irc.PinEntryReceived += OnPinEntryReceived;
        _irc.MotdReceived += OnMotdReceived;
        _irc.RawReceived += OnRawReceived;
        _irc.ErrorReceived += OnError;
    }

    partial void OnSelectedChannelChanged(ChannelModel? value)
    {
        if (value == null) return;

        Messages.Clear();
        if (_messagesByChannel.TryGetValue(value.Name, out var msgs))
        {
            foreach (var m in msgs)
                Messages.Add(m);
        }

        CurrentTopic = value.Topic;
        RefreshMemberList(value.Name);
        RefreshGovernancePanels(value.Name);
        if (value.Name.StartsWith('#'))
        {
            _irc.Send($"MODE {value.Name}");
            _irc.Send($"MODE {value.Name} b");
            _irc.Send($"MODE {value.Name} I");
        }

        value.UnreadCount = 0;
        if (value.MentionCount > 0)
            UnreadMentionCount = Math.Max(0, UnreadMentionCount - value.MentionCount);
        value.MentionCount = 0;

        // Cancel any edit in progress when switching channels
        CancelEdit();
    }

    [RelayCommand]
    private async Task Connect()
    {
        if (string.IsNullOrWhiteSpace(Nickname))
        {
            ErrorMessage = "Please enter a nickname";
            return;
        }

        ErrorMessage = null;
        _desiredNickname = Nickname;
        await _irc.ConnectAsync(ServerUrl, Nickname);
    }

    [RelayCommand]
    private void Disconnect()
    {
        _irc.Disconnect();
        Channels.Clear();
        FavoriteChannels.Clear();
        DirectMessages.Clear();
        Messages.Clear();
        Operators.Clear();
        Voiced.Clear();
        Members.Clear();
        _messagesByChannel.Clear();
        _presenceRuns.Clear();
        _membersByChannel.Clear();
        _pendingJoinChannels.Clear();
        _typingTimers.Clear();
        _awayByNick.Clear();
        _channelModes.Clear();
        _bansByChannel.Clear();
        _invitesByChannel.Clear();
        _auditByChannel.Clear();
        AuditTimeline.Clear();
        ChannelBans.Clear();
        ChannelInvites.Clear();
        SelectedChannel = null;
        ShowConnectDialog = true;
        IsConnected = false;
        IsAway = false;
        AwayMessage = "";
        UnreadMentionCount = 0;
        ShowReconnectBanner = false;
        ShowMotdBanner = false;
        _hasShownMotd = false;
        CancelEdit();
    }

    [RelayCommand]
    private void SendMessage()
    {
        if (string.IsNullOrWhiteSpace(ComposeText) || SelectedChannel == null) return;

        var text = ComposeText.Trim();

        // Stop outbound typing indicator
        StopOutboundTyping();

        // Editing an existing message
        if (IsEditing && EditingMessageId != null)
        {
            _irc.SendEditMessage(SelectedChannel.Name, EditingMessageId, text);
            CancelEdit();
            return;
        }

        // Slash commands
        if (text.StartsWith('/'))
        {
            HandleSlashCommand(text);
            ComposeText = "";
            return;
        }

        // Regular message
        _irc.SendMessage(SelectedChannel.Name, text);

        // When echo-message is acked, the server echoes back with the real msgid.
        // When not acked, add a local message immediately.
        if (!_irc.IsEchoMessageAcked)
        {
            var msg = new MessageModel
            {
                Id = Guid.NewGuid().ToString(),
                Nick = _irc.Nick,
                Content = text,
                Timestamp = DateTimeOffset.Now,
            };
            AddMessage(SelectedChannel.Name, msg);
        }

        ComposeText = "";
    }

    /// <summary>Called by ComposeBox on every keystroke to send outbound typing indicators.</summary>
    public void NotifyTyping()
    {
        if (SelectedChannel == null) return;

        if (!_outboundTypingActive)
        {
            _outboundTypingActive = true;
            _irc.SendTyping(SelectedChannel.Name, true);
        }

        // Reset the 10-second done timer
        _outboundTypingTimer?.Dispose();
        _outboundTypingTimer = new System.Threading.Timer(_ =>
        {
            StopOutboundTyping();
        }, null, TimeSpan.FromSeconds(10), Timeout.InfiniteTimeSpan);
    }

    private void StopOutboundTyping()
    {
        _outboundTypingTimer?.Dispose();
        _outboundTypingTimer = null;
        if (_outboundTypingActive && SelectedChannel != null)
        {
            _outboundTypingActive = false;
            _irc.SendTyping(SelectedChannel.Name, false);
        }
    }

    /// <summary>Load a sent message into the compose box for editing.</summary>
    public void BeginEditMessage(MessageModel msg)
    {
        EditingMessageId = msg.Id;
        IsEditing = true;
        ComposeText = msg.Content;
    }

    [RelayCommand]
    public void CancelEdit()
    {
        EditingMessageId = null;
        IsEditing = false;
        ComposeText = "";
    }

    /// <summary>Send a soft-delete request for a message.</summary>
    public void DeleteMessage(MessageModel msg)
    {
        if (SelectedChannel == null) return;
        _irc.SendDeleteMessage(SelectedChannel.Name, msg.Id);
        NotifyToast("Message deleted");
    }

    public void ReactToMessage(MessageModel msg, string emoji)
    {
        if (SelectedChannel == null || string.IsNullOrWhiteSpace(emoji)) return;
        _irc.Send($"@+react={emoji};+reply={msg.Id} TAGMSG {SelectedChannel.Name} :");
        msg.ToggleReaction(emoji, _irc.Nick);
    }

    public void SetForeground(bool isForeground)
    {
        IsAppForeground = isForeground;
    }

    public async Task<string> UploadAndSendFileAsync(string filePath, string? caption = null)
    {
        if (SelectedChannel == null || string.IsNullOrWhiteSpace(filePath))
            throw new InvalidOperationException("Select a channel before uploading");

        var token = _settings.ApiBearerToken;
        var result = await UploadService.UploadAsync(ServerUrl, filePath, token, SelectedChannel.Name, caption);
        var text = string.IsNullOrWhiteSpace(caption) ? result.Url : $"{caption} {result.Url}";
        _irc.SendMessage(SelectedChannel.Name, text);
        NotifyToast($"Uploaded {Path.GetFileName(filePath)}");
        return result.Url;
    }

    public void UpdatePreferences(
        ThemeMode themeMode,
        MessageDensity messageDensity,
        JoinPartDisplay joinPartDisplay,
        bool autoLoadExternalMedia,
        bool enableWindowsNotifications,
        bool enableNotificationSounds)
    {
        ThemeMode = themeMode;
        MessageDensity = messageDensity;
        JoinPartDisplay = joinPartDisplay;
        AutoLoadExternalMedia = autoLoadExternalMedia;
        EnableWindowsNotifications = enableWindowsNotifications;
        EnableNotificationSounds = enableNotificationSounds;

        _settings.ThemeMode = themeMode.ToString();
        _settings.MessageDensity = messageDensity.ToString();
        _settings.JoinPartDisplay = joinPartDisplay.ToString();
        _settings.AutoLoadExternalMedia = autoLoadExternalMedia;
        _settings.EnableWindowsNotifications = enableWindowsNotifications;
        _settings.EnableNotificationSounds = enableNotificationSounds;
        _settings.Save();

        ThemeChanged?.Invoke(themeMode);
    }

    public UserProfileInfo GetUserProfile(string nick)
    {
        var did = _irc.GetAccount(nick);
        string? handle = null;
        if (!string.IsNullOrWhiteSpace(did) && did!.Contains('.') && !did.StartsWith("did:", StringComparison.OrdinalIgnoreCase))
            handle = did;

        return new UserProfileInfo
        {
            Nick = nick,
            Did = did,
            BlueskyHandle = handle,
            CanModerate = IsCurrentUserOperator(),
        };
    }

    public bool IsCurrentUserOperator()
    {
        return Operators.Any(m => m.Nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase));
    }

    public void SetMemberOperator(string nick, bool isOperator)
    {
        if (SelectedChannel == null) return;
        _irc.Send($"MODE {SelectedChannel.Name} {(isOperator ? "+o" : "-o")} {nick}");
        NotifyToast(isOperator ? $"Granted op to {nick}" : $"Removed op from {nick}");
    }

    public void SetMemberVoice(string nick, bool isVoiced)
    {
        if (SelectedChannel == null) return;
        _irc.Send($"MODE {SelectedChannel.Name} {(isVoiced ? "+v" : "-v")} {nick}");
        NotifyToast(isVoiced ? $"Granted voice to {nick}" : $"Removed voice from {nick}");
    }

    public void ToggleAwayStatus(string? message = null)
    {
        if (IsAway)
            _irc.Send("AWAY");
        else
            _irc.Send(string.IsNullOrWhiteSpace(message) ? "AWAY :Away" : $"AWAY :{message}");
    }

    public void DismissReconnectBanner() => ShowReconnectBanner = false;
    public void DismissMotdBanner() => ShowMotdBanner = false;
    public void ShowToast(string text) => NotifyToast(text);

    public void JumpToMessage(string channel, string messageId)
    {
        var target = FindChannel(channel);
        if (target != null)
            SelectedChannel = target;

        var msg = Messages.FirstOrDefault(m => m.Id == messageId);
        if (msg != null)
            NotifyToast($"Jumped to message from {msg.Nick}");
    }

    public void SearchMessages(string query)
    {
        SearchResults.Clear();
        if (string.IsNullOrWhiteSpace(query)) return;

        foreach (var channel in _messagesByChannel)
        {
            foreach (var msg in channel.Value)
            {
                if (msg.IsDeleted) continue;
                if (!msg.Content.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;

                SearchResults.Add(new MessageSearchResult
                {
                    Channel = channel.Key,
                    MessageId = msg.Id,
                    Nick = msg.Nick,
                    Content = msg.Content,
                    Timestamp = msg.Timestamp,
                });
            }
        }
    }

    /// <summary>Returns all nicks in the current channel for Tab autocomplete.</summary>
    public IEnumerable<string> GetCurrentChannelNicks()
    {
        return Operators.Select(m => m.Nick)
            .Concat(Voiced.Select(m => m.Nick))
            .Concat(Members.Select(m => m.Nick));
    }

    /// <summary>Returns the last message sent by the current user in the active channel.</summary>
    public MessageModel? GetLastOwnMessage()
    {
        if (SelectedChannel == null) return null;
        if (!_messagesByChannel.TryGetValue(SelectedChannel.Name, out var msgs)) return null;
        return msgs.LastOrDefault(m =>
            m.Nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase) && !m.IsDeleted);
    }

    private void HandleSlashCommand(string text)
    {
        var space = text.IndexOf(' ');
        var cmd = (space < 0 ? text[1..] : text[1..space]).ToLowerInvariant();
        var args = space >= 0 ? text[(space + 1)..].Trim() : "";

        switch (cmd)
        {
            case "me":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"PRIVMSG {SelectedChannel.Name} :\x01ACTION {args}\x01");
                break;

            case "join":
                if (!string.IsNullOrWhiteSpace(args))
                    JoinChannelCommand.Execute(args.Split(' ')[0]);
                break;

            case "part":
                if (SelectedChannel != null)
                    _irc.PartChannel(SelectedChannel.Name, string.IsNullOrWhiteSpace(args) ? null : args);
                break;

            case "topic":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"TOPIC {SelectedChannel.Name} :{args}");
                break;

            case "invite":
            {
                var parts = args.Split(' ', 2);
                if (parts.Length >= 1 && SelectedChannel != null)
                {
                    var target = parts.Length >= 2 ? parts[1] : SelectedChannel.Name;
                    _irc.Send($"INVITE {parts[0]} {target}");
                }
                break;
            }

            case "kick":
            {
                var parts = args.Split(' ', 2);
                if (parts.Length >= 1 && SelectedChannel != null)
                {
                    var reason = parts.Length >= 2 ? parts[1] : "";
                    _irc.Send(string.IsNullOrEmpty(reason)
                        ? $"KICK {SelectedChannel.Name} {parts[0]}"
                        : $"KICK {SelectedChannel.Name} {parts[0]} :{reason}");
                }
                break;
            }

            case "op":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"MODE {SelectedChannel.Name} +o {args}");
                break;

            case "deop":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"MODE {SelectedChannel.Name} -o {args}");
                break;

            case "voice":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"MODE {SelectedChannel.Name} +v {args}");
                break;

            case "mode":
                if (!string.IsNullOrWhiteSpace(args) && SelectedChannel != null)
                    _irc.Send($"MODE {SelectedChannel.Name} {args}");
                break;

            case "msg":
            {
                var parts = args.Split(' ', 2);
                if (parts.Length >= 2)
                    _irc.Send($"PRIVMSG {parts[0]} :{parts[1]}");
                break;
            }

            case "whois":
                if (!string.IsNullOrWhiteSpace(args))
                    _irc.Send($"WHOIS {args}");
                break;

            case "away":
                _irc.Send(string.IsNullOrWhiteSpace(args) ? "AWAY" : $"AWAY :{args}");
                break;

            case "pins":
                if (SelectedChannel != null)
                    _irc.RequestPins(SelectedChannel.Name);
                break;

            case "raw":
                if (!string.IsNullOrWhiteSpace(args))
                    _irc.Send(args);
                break;

            case "help":
                if (SelectedChannel != null)
                    AddSystemMessage(SelectedChannel.Name,
                        "Commands: /me /join /part /topic /invite /kick /op /deop /voice /mode /msg /whois /away /pins /raw /help");
                break;

            default:
                if (SelectedChannel != null)
                    AddSystemMessage(SelectedChannel.Name, $"Unknown command: /{cmd}");
                break;
        }
    }

    /// <summary>
    /// Queue channels to join. They will be sent to the server once registration completes (001).
    /// </summary>
    public void QueueJoinChannels(IEnumerable<string> channels)
    {
        foreach (var raw in channels)
        {
            var channel = raw.Trim();
            if (string.IsNullOrWhiteSpace(channel)) continue;
            if (!channel.StartsWith('#')) channel = "#" + channel;

            if (!_pendingJoinChannels.Contains(channel, StringComparer.OrdinalIgnoreCase))
                _pendingJoinChannels.Add(channel);
        }
    }

    [RelayCommand]
    private void JoinChannel(string channel)
    {
        if (string.IsNullOrWhiteSpace(channel)) return;
        if (!channel.StartsWith('#')) channel = "#" + channel;

        if (_irc.State == ConnectionState.Authenticated)
        {
            _irc.JoinChannel(channel);
        }
        else
        {
            if (!_pendingJoinChannels.Contains(channel, StringComparer.OrdinalIgnoreCase))
                _pendingJoinChannels.Add(channel);
        }
    }

    [RelayCommand]
    private void SelectPreviousChannel()
    {
        var all = Channels.Concat(DirectMessages).ToList();
        if (all.Count == 0) return;
        var idx = SelectedChannel == null ? 0 : all.FindIndex(c => c.Name.Equals(SelectedChannel.Name, StringComparison.OrdinalIgnoreCase));
        if (idx < 0) idx = 0;
        SelectedChannel = all[(idx - 1 + all.Count) % all.Count];
    }

    [RelayCommand]
    private void SelectNextChannel()
    {
        var all = Channels.Concat(DirectMessages).ToList();
        if (all.Count == 0) return;
        var idx = SelectedChannel == null ? -1 : all.FindIndex(c => c.Name.Equals(SelectedChannel.Name, StringComparison.OrdinalIgnoreCase));
        SelectedChannel = all[(idx + 1 + all.Count) % all.Count];
    }

    [RelayCommand]
    private void SelectChannelByIndex(int index)
    {
        var all = Channels.Concat(DirectMessages).ToList();
        if (all.Count == 0) return;
        var normalized = index == 0 ? 10 : index;
        var target = normalized - 1;
        if (target < 0 || target >= all.Count) return;
        SelectedChannel = all[target];
    }

    [RelayCommand]
    private void ToggleMute(ChannelModel? channel)
    {
        if (channel == null) return;
        channel.IsMuted = !channel.IsMuted;

        if (channel.IsMuted)
            _settings.MutedChannels.Add(channel.Name);
        else
            _settings.MutedChannels.Remove(channel.Name);

        _settings.Save();
        NotifyToast(channel.IsMuted ? $"Muted {channel.Name}" : $"Unmuted {channel.Name}");
    }

    [RelayCommand]
    private void RequestChannelList()
    {
        ServerChannels.Clear();
        _irc.RequestList();
    }

    [RelayCommand]
    private void RequestPins()
    {
        if (SelectedChannel == null) return;
        PinnedMessages.Clear();
        _irc.RequestPins(SelectedChannel.Name);
    }

    [RelayCommand]
    private void SetTopic(string topic)
    {
        if (SelectedChannel == null) return;
        _irc.SetTopic(SelectedChannel.Name, topic);
        CurrentTopic = topic;
    }

    [RelayCommand]
    private void ToggleMemberList()
    {
        IsMemberListVisible = !IsMemberListVisible;
    }

    [RelayCommand]
    private void ToggleFavorite(ChannelModel? channel)
    {
        if (channel == null) return;
        channel.IsFavorite = !channel.IsFavorite;
        if (channel.IsFavorite)
        {
            if (!FavoriteChannels.Contains(channel))
                FavoriteChannels.Add(channel);
        }
        else
        {
            FavoriteChannels.Remove(channel);
        }
    }

    private void OnStateChanged(ConnectionState state)
    {
        _dispatcher.TryEnqueue(() =>
        {
            var wasConnected = _wasConnected;
            ConnectionState = state;
            ConnectionStatus = state switch
            {
                ConnectionState.Disconnected => "Disconnected",
                ConnectionState.Connecting => "Connecting...",
                ConnectionState.Connected => "Connected",
                ConnectionState.Authenticating => "Authenticating...",
                ConnectionState.Authenticated => "Authenticated",
                _ => "Unknown"
            };
            IsConnected = state is ConnectionState.Connected or ConnectionState.Authenticated;
            _wasConnected = IsConnected;

            if (state == ConnectionState.Authenticated)
            {
                if (!string.IsNullOrEmpty(_desiredNickname) &&
                    !_irc.Nick.Equals(_desiredNickname, StringComparison.OrdinalIgnoreCase))
                {
                    _irc.Send($"NICK {_desiredNickname}");
                }

                Nickname = _irc.Nick;
                ShowConnectDialog = false;
                ShowReconnectBanner = false;

                if (!string.IsNullOrWhiteSpace(_lastAuthenticatedDid) && string.IsNullOrWhiteSpace(_irc.Did))
                {
                    ShowReconnectBanner = true;
                    ReconnectBannerText = "Reconnected as guest. Your authenticated identity was not restored.";
                }

                if (!string.IsNullOrWhiteSpace(_irc.Did))
                    _lastAuthenticatedDid = _irc.Did;

                var toJoin = _pendingJoinChannels.ToList();
                _pendingJoinChannels.Clear();
                foreach (var ch in toJoin)
                    _irc.JoinChannel(ch);
            }
            else if (state == ConnectionState.Disconnected)
            {
                ShowConnectDialog = true;
                _pendingJoinChannels.Clear();
                _typingTimers.Clear();
                TypingText = "";
                if (wasConnected)
                {
                    ShowReconnectBanner = true;
                    ReconnectBannerText = "Connection lost. Reconnecting or reconnect manually.";
                }
            }
        });
    }

    private void OnMessageReceived(string channel, string nick, string message, string? msgid, DateTimeOffset? serverTime)
    {
        _dispatcher.TryEnqueue(() =>
        {
            EnsureChannel(channel);

            var msg = new MessageModel
            {
                Id = msgid ?? Guid.NewGuid().ToString(),
                Nick = nick,
                Content = message,
                Timestamp = serverTime ?? DateTimeOffset.Now,
            };

            AddMessage(channel, msg);

            msg.Did = _irc.GetAccount(nick);
            var isMention = message.Contains(_irc.Nick, StringComparison.OrdinalIgnoreCase);

            if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) != true)
            {
                var ch = FindChannel(channel);
                if (ch != null)
                {
                    ch.UnreadCount++;
                    if (isMention)
                    {
                        ch.MentionCount++;
                        UnreadMentionCount++;
                    }
                }
            }

            if (isMention && !IsAppForeground)
                {
                    if (EnableWindowsNotifications)
                        WindowsToastRequested?.Invoke($"Mention from {nick}: {message}");

                    if (EnableNotificationSounds)
                        NotifyToast("New mention");
                }
        });
    }

    public void AddBookmark(MessageModel msg)
    {
        if (SelectedChannel == null) return;
        if (Bookmarks.Any(b => b.MessageId == msg.Id && b.Channel.Equals(SelectedChannel.Name, StringComparison.OrdinalIgnoreCase)))
        {
            NotifyToast("Message is already bookmarked");
            return;
        }

        var bookmark = new BookmarkEntry
        {
            Channel = SelectedChannel.Name,
            MessageId = msg.Id,
            Nick = msg.Nick,
            Content = msg.Content,
            MessageTimestamp = msg.Timestamp,
            BookmarkedAt = DateTimeOffset.Now,
        };
        Bookmarks.Insert(0, bookmark);
        PersistBookmarks();
        NotifyToast("Bookmarked message");
    }

    public void RemoveBookmark(BookmarkEntry bookmark)
    {
        Bookmarks.Remove(bookmark);
        PersistBookmarks();
    }

    public void JumpToBookmark(BookmarkEntry bookmark)
    {
        JumpToMessage(bookmark.Channel, bookmark.MessageId);
    }

    public void SetChannelMode(char mode, bool enabled)
    {
        if (SelectedChannel == null || !SelectedChannel.Name.StartsWith('#')) return;
        _irc.Send($"MODE {SelectedChannel.Name} {(enabled ? "+" : "-")}{mode}");
    }

    public void AddBanMask(string mask)
    {
        if (SelectedChannel == null || string.IsNullOrWhiteSpace(mask)) return;
        _irc.Send($"MODE {SelectedChannel.Name} +b {mask.Trim()}");
    }

    public void RemoveBanMask(ChannelMaskEntry entry)
    {
        if (SelectedChannel == null) return;
        _irc.Send($"MODE {SelectedChannel.Name} -b {entry.Mask}");
    }

    public void AddInviteMask(string mask)
    {
        if (SelectedChannel == null || string.IsNullOrWhiteSpace(mask)) return;
        _irc.Send($"MODE {SelectedChannel.Name} +I {mask.Trim()}");
    }

    public void RemoveInviteMask(ChannelMaskEntry entry)
    {
        if (SelectedChannel == null) return;
        _irc.Send($"MODE {SelectedChannel.Name} -I {entry.Mask}");
    }

    public string GetSafetyNumber(string nick)
    {
        var peer = _irc.GetAccount(nick) ?? nick;
        var me = _irc.Did ?? _irc.Nick;
        var raw = string.CompareOrdinal(me, peer) <= 0
            ? $"{me}|{peer}"
            : $"{peer}|{me}";
        using var sha = SHA256.Create();
        var digest = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
        var hex = Convert.ToHexString(digest);
        return string.Join(" ", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 4, 4)));
    }

    private void OnMessageEdited(string channel, string originalMsgId, string newContent, DateTimeOffset? serverTime)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (!_messagesByChannel.TryGetValue(channel, out var msgs)) return;
            var msg = msgs.FirstOrDefault(m => m.Id == originalMsgId);
            if (msg != null)
            {
                msg.Content = newContent;
                msg.IsEdited = true;
            }
        });
    }

    private void OnMessageDeleted(string channel, string msgId)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (!_messagesByChannel.TryGetValue(channel, out var msgs)) return;
            var msg = msgs.FirstOrDefault(m => m.Id == msgId);
            if (msg != null)
                msg.IsDeleted = true;
        });
    }

    private void OnTypingChanged(string channel, string nick, bool isTyping)
    {
        // Ignore echoes of our own typing
        if (nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase)) return;

        _dispatcher.TryEnqueue(() =>
        {
            if (!_typingTimers.ContainsKey(channel))
                _typingTimers[channel] = new Dictionary<string, System.Threading.Timer>(StringComparer.OrdinalIgnoreCase);

            var channelTimers = _typingTimers[channel];

            if (isTyping)
            {
                if (channelTimers.TryGetValue(nick, out var existing))
                    existing.Dispose();

                channelTimers[nick] = new System.Threading.Timer(_ =>
                {
                    _dispatcher.TryEnqueue(() =>
                    {
                        RemoveTypingNick(channel, nick);
                        UpdateTypingText(channel);
                    });
                }, null, TimeSpan.FromSeconds(10), Timeout.InfiniteTimeSpan);
            }
            else
            {
                RemoveTypingNick(channel, nick);
            }

            UpdateTypingText(channel);
        });
    }

    private void OnReactionReceived(string channel, string nick, string emoji, string? targetMsgId)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (!_messagesByChannel.TryGetValue(channel, out var msgs) || msgs.Count == 0) return;

            MessageModel? target = null;
            if (!string.IsNullOrWhiteSpace(targetMsgId))
                target = msgs.FirstOrDefault(m => m.Id == targetMsgId);

            target ??= msgs.LastOrDefault(m => !m.IsDeleted);
            if (target == null) return;

            target.AddReaction(emoji, nick, nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase));
        });
    }

    private void RemoveTypingNick(string channel, string nick)
    {
        if (!_typingTimers.TryGetValue(channel, out var timers)) return;
        if (timers.TryGetValue(nick, out var t))
        {
            t.Dispose();
            timers.Remove(nick);
        }
    }

    private void UpdateTypingText(string channel)
    {
        if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) != true) return;

        if (!_typingTimers.TryGetValue(channel, out var timers) || timers.Count == 0)
        {
            TypingText = "";
            return;
        }

        var nicks = timers.Keys.ToList();
        TypingText = nicks.Count switch
        {
            1 => $"{nicks[0]} is typing…",
            2 => $"{nicks[0]} and {nicks[1]} are typing…",
            _ => "Several people are typing…"
        };
    }

    private void OnJoinReceived(string channel, string nick)
    {
        _dispatcher.TryEnqueue(() =>
        {
            EnsureChannel(channel);

            if (nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase))
            {
                var ch = FindChannel(channel);
                if (ch != null)
                    SelectedChannel = ch;

                AddMemberToChannel(channel, nick);
            }
            else
            {
                AddMemberToChannel(channel, nick);
            }

            AddPresenceMessage(channel, nick, joined: true, $"{nick} has joined {channel}");
        });
    }

    private void OnPartReceived(string channel, string nick, string reason)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (nick.Equals(_irc.Nick, StringComparison.OrdinalIgnoreCase))
            {
                var ch = FindChannel(channel);
                if (ch != null)
                {
                    Channels.Remove(ch);
                    FavoriteChannels.Remove(ch);
                    _messagesByChannel.Remove(channel);
                    _membersByChannel.Remove(channel);
                    if (SelectedChannel == ch)
                        SelectedChannel = Channels.FirstOrDefault();
                }
            }
            else
            {
                RemoveMemberFromChannel(channel, nick);
                AddPresenceMessage(channel, nick, joined: false, $"{nick} has left {channel}" + (string.IsNullOrEmpty(reason) ? "" : $" ({reason})"));
            }
        });
    }

    private void OnQuitReceived(string nick, string reason)
    {
        _dispatcher.TryEnqueue(() =>
        {
            foreach (var kvp in _membersByChannel)
            {
                kvp.Value.RemoveAll(n => n.TrimStart('@', '%', '+').Equals(nick, StringComparison.OrdinalIgnoreCase));
            }
            if (SelectedChannel != null)
                RefreshMemberList(SelectedChannel.Name);
        });
    }

    private void OnTopicReceived(string channel, string topic)
    {
        _dispatcher.TryEnqueue(() =>
        {
            var ch = FindChannel(channel);
            if (ch != null)
                ch.Topic = topic;
            if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) == true)
                CurrentTopic = topic;

            AddAuditEvent(channel, NickFromPrefix(_irc.Nick), "topic", topic);
        });
    }

    private void OnRawReceived(string line)
    {
        var parsed = IrcClient.ParseIrcMessage(line);
        _dispatcher.TryEnqueue(() =>
        {
            switch (parsed.Command)
            {
                case "324":
                    // RPL_CHANNELMODEIS: <me> <channel> <modes> [mode params]
                    if (parsed.Params.Length >= 3)
                        HandleModeState(parsed.Params[1], parsed.Params[2]);
                    break;
                case "MODE":
                    HandleModeChange(parsed);
                    break;
                case "367":
                    // RPL_BANLIST: <me> <channel> <mask> [setter] [time]
                    if (parsed.Params.Length >= 3)
                    {
                        var ch = parsed.Params[1];
                        if (!_bansByChannel.ContainsKey(ch)) _bansByChannel[ch] = [];
                        var setBy = parsed.Params.Length >= 4 ? parsed.Params[3] : "";
                        var setAt = parsed.Params.Length >= 5 && long.TryParse(parsed.Params[4], out var ts)
                            ? DateTimeOffset.FromUnixTimeSeconds(ts)
                            : DateTimeOffset.Now;
                        var entry = new ChannelMaskEntry { Mask = parsed.Params[2], SetBy = setBy, SetAt = setAt };
                        if (!_bansByChannel[ch].Any(x => x.Mask.Equals(entry.Mask, StringComparison.OrdinalIgnoreCase)))
                            _bansByChannel[ch].Add(entry);
                        RefreshGovernancePanels(ch);
                    }
                    break;
                case "346":
                    // RPL_INVITELIST: <me> <channel> <mask> [setter] [time]
                    if (parsed.Params.Length >= 3)
                    {
                        var ch = parsed.Params[1];
                        if (!_invitesByChannel.ContainsKey(ch)) _invitesByChannel[ch] = [];
                        var setBy = parsed.Params.Length >= 4 ? parsed.Params[3] : "";
                        var setAt = parsed.Params.Length >= 5 && long.TryParse(parsed.Params[4], out var ts)
                            ? DateTimeOffset.FromUnixTimeSeconds(ts)
                            : DateTimeOffset.Now;
                        var entry = new ChannelMaskEntry { Mask = parsed.Params[2], SetBy = setBy, SetAt = setAt };
                        if (!_invitesByChannel[ch].Any(x => x.Mask.Equals(entry.Mask, StringComparison.OrdinalIgnoreCase)))
                            _invitesByChannel[ch].Add(entry);
                        RefreshGovernancePanels(ch);
                    }
                    break;
                case "KICK":
                    if (parsed.Params.Length >= 2)
                        AddAuditEvent(parsed.Params[0], NickFromPrefix(parsed.Prefix), "kick", $"{parsed.Params[1]} {parsed.Params.ElementAtOrDefault(2) ?? ""}".Trim());
                    break;
                case "INVITE":
                    if (parsed.Params.Length >= 2)
                        AddAuditEvent(parsed.Params[1], NickFromPrefix(parsed.Prefix), "invite", parsed.Params[0]);
                    break;
            }
        });
    }

    private void OnAwayChanged(string nick, bool isAway, string? message)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (isAway)
                _awayByNick[nick] = message;
            else
                _awayByNick.Remove(nick);

            if (SelectedChannel != null)
                RefreshMemberList(SelectedChannel.Name);
        });
    }

    private void OnSelfAwayStateChanged(bool isAway, string? message)
    {
        _dispatcher.TryEnqueue(() =>
        {
            IsAway = isAway;
            AwayMessage = message ?? "";
            NotifyToast(isAway ? "Away status enabled" : "Away status cleared");
        });
    }

    private void OnListEntryReceived(string channel, int memberCount, string topic)
    {
        _dispatcher.TryEnqueue(() =>
        {
            var existing = ServerChannels.FirstOrDefault(c => c.Name.Equals(channel, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                ServerChannels.Add(new ChannelListEntry { Name = channel, MemberCount = memberCount, Topic = topic });
            }
            else
            {
                existing.MemberCount = memberCount;
                existing.Topic = topic;
            }
        });
    }

    private void OnPinEntryReceived(string channel, string msgId, string pinnedBy, long pinnedAt)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) != true) return;
            PinnedMessages.Add(new PinEntry
            {
                Channel = channel,
                MsgId = msgId,
                PinnedBy = pinnedBy,
                PinnedAt = DateTimeOffset.FromUnixTimeSeconds(pinnedAt),
            });
            AddAuditEvent(channel, pinnedBy, "pin", msgId);
        });
    }

    private void OnMotdReceived(string motd)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (_hasShownMotd) return;
            _hasShownMotd = true;
            MotdText = motd;
            ShowMotdBanner = true;

            EnsureChannel("server");
            AddSystemMessage("server", motd.Replace("\n", " | "));
        });
    }

    private void OnNamesReceived(string channel, List<string> nicks)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (!_membersByChannel.ContainsKey(channel))
                _membersByChannel[channel] = [];

            var list = _membersByChannel[channel];
            foreach (var nick in nicks)
            {
                var bare = nick.TrimStart('@', '%', '+');
                list.RemoveAll(n => n.TrimStart('@', '%', '+').Equals(bare, StringComparison.OrdinalIgnoreCase));
                list.Add(nick);
            }

            if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) == true)
                RefreshMemberList(channel);
        });
    }

    private void OnAccountChanged(string nick, string? account)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (SelectedChannel != null)
                RefreshMemberList(SelectedChannel.Name);
        });
    }

    private void OnNickChanged(string oldNick, string newNick)
    {
        _dispatcher.TryEnqueue(() =>
        {
            if (oldNick.Equals(Nickname, StringComparison.OrdinalIgnoreCase))
                Nickname = newNick;

            foreach (var kvp in _membersByChannel)
            {
                for (int i = 0; i < kvp.Value.Count; i++)
                {
                    var bare = kvp.Value[i].TrimStart('@', '%', '+');
                    if (bare.Equals(oldNick, StringComparison.OrdinalIgnoreCase))
                    {
                        var prefix = kvp.Value[i][..^bare.Length];
                        kvp.Value[i] = prefix + newNick;
                    }
                }
            }
            if (SelectedChannel != null)
                RefreshMemberList(SelectedChannel.Name);
        });
    }

    private void OnError(string error)
    {
        _dispatcher.TryEnqueue(() =>
        {
            ErrorMessage = error;
            if (!ShowConnectDialog)
                ShowConnectDialog = true;
        });
    }

    private void EnsureChannel(string channel)
    {
        if (FindChannel(channel) != null) return;

        var kind = channel.Equals("server", StringComparison.OrdinalIgnoreCase)
            ? ChannelKind.Server
            : (channel.StartsWith('#') ? ChannelKind.Channel : ChannelKind.DirectMessage);
        var ch = new ChannelModel
        {
            Name = channel,
            Kind = kind,
            IsMuted = _settings.MutedChannels.Contains(channel),
        };

        if (kind == ChannelKind.DirectMessage)
            DirectMessages.Add(ch);
        else
            Channels.Add(ch);
    }

    private ChannelModel? FindChannel(string name)
    {
        return Channels.FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            ?? DirectMessages.FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    private void AddMessage(string channel, MessageModel msg)
    {
        if (!_messagesByChannel.ContainsKey(channel))
            _messagesByChannel[channel] = [];

        _messagesByChannel[channel].Add(msg);

        if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) == true)
            Messages.Add(msg);
    }

    // The join/part events folded into a grouped summary line, keyed by that
    // line's message id. Only the newest line of a channel is ever extended.
    private readonly Dictionary<string, List<(string Nick, bool Joined)>> _presenceRuns = new();

    private void AddPresenceMessage(string channel, string nick, bool joined, string text)
    {
        if (JoinPartDisplay == JoinPartDisplay.Hidden)
            return;

        if (JoinPartDisplay == JoinPartDisplay.Grouped
            && _messagesByChannel.TryGetValue(channel, out var list)
            && list.Count > 0
            && _presenceRuns.TryGetValue(list[^1].Id, out var run))
        {
            run.Add((nick, joined));
            list[^1].Content = SummarizePresence(run);
            return;
        }

        AddSystemMessage(channel, text);
        if (_messagesByChannel.TryGetValue(channel, out var added) && added.Count > 0)
            _presenceRuns[added[^1].Id] = [(nick, joined)];
    }

    /// "nap reconnected 2×" for one person's churn, else
    /// "alice, bob and 2 more joined · carol left".
    private static string SummarizePresence(List<(string Nick, bool Joined)> run)
    {
        var joins = run.Count(e => e.Joined);
        var leaves = run.Count - joins;
        var first = run[0].Nick;
        if (run.All(e => e.Nick.Equals(first, StringComparison.OrdinalIgnoreCase)))
        {
            if (joins > 0 && leaves > 0) return $"{first} reconnected {Math.Min(joins, leaves)}×";
            return joins > 0 ? $"{first} joined {joins}×" : $"{first} left {leaves}×";
        }

        static string Names(IEnumerable<string> nicks)
        {
            var list = nicks.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var shown = string.Join(", ", list.Take(3));
            return list.Count > 3 ? $"{shown} and {list.Count - 3} more" : shown;
        }

        var said = new List<string>();
        if (joins > 0) said.Add($"{Names(run.Where(e => e.Joined).Select(e => e.Nick))} joined");
        if (leaves > 0) said.Add($"{Names(run.Where(e => !e.Joined).Select(e => e.Nick))} left");
        return string.Join(" · ", said);
    }

    private void AddSystemMessage(string channel, string text)
    {
        AddMessage(channel, new MessageModel
        {
            Id = Guid.NewGuid().ToString(),
            Nick = "*",
            Content = text,
            Timestamp = DateTimeOffset.Now,
        });
    }

    private void AddMemberToChannel(string channel, string nick)
    {
        if (!_membersByChannel.ContainsKey(channel))
            _membersByChannel[channel] = [];

        if (!_membersByChannel[channel].Any(n => n.TrimStart('@', '%', '+').Equals(nick, StringComparison.OrdinalIgnoreCase)))
            _membersByChannel[channel].Add(nick);

        if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) == true)
            RefreshMemberList(channel);
    }

    private void RemoveMemberFromChannel(string channel, string nick)
    {
        if (_membersByChannel.TryGetValue(channel, out var list))
            list.RemoveAll(n => n.TrimStart('@', '%', '+').Equals(nick, StringComparison.OrdinalIgnoreCase));

        if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) == true)
            RefreshMemberList(channel);
    }

    private static (MemberRole role, string nick) ParseMemberPrefix(string raw)
    {
        var role = MemberRole.Regular;
        var nick = raw.TrimStart('@', '%', '+');
        var prefix = raw[..^nick.Length];

        if (prefix.Contains('@')) role = MemberRole.Operator;
        else if (prefix.Contains('%')) role = MemberRole.HalfOp;
        else if (prefix.Contains('+')) role = MemberRole.Voiced;

        return (role, nick);
    }

    private void RefreshMemberList(string channel)
    {
        Operators.Clear();
        Voiced.Clear();
        Members.Clear();

        if (!_membersByChannel.TryGetValue(channel, out var nicks)) return;

        foreach (var raw in nicks.OrderBy(n => n.TrimStart('@', '%', '+')))
        {
            var (role, nick) = ParseMemberPrefix(raw);
            var member = new MemberModel { Nick = nick, Role = role, Did = _irc.GetAccount(nick) };
            if (_awayByNick.TryGetValue(nick, out var awayMessage))
            {
                member.Status = PresenceStatus.Away;
                member.AwayMessage = awayMessage;
            }

            switch (role)
            {
                case MemberRole.Operator:
                case MemberRole.HalfOp:
                    Operators.Add(member);
                    break;
                case MemberRole.Voiced:
                    Voiced.Add(member);
                    break;
                default:
                    Members.Add(member);
                    break;
            }
        }
    }

    public int TotalMemberCount => Operators.Count + Voiced.Count + Members.Count;

    private void PersistBookmarks()
    {
        _settings.Bookmarks = Bookmarks.ToList();
        _settings.Save();
    }

    private static string NickFromPrefix(string? prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix)) return "server";
        var bang = prefix.IndexOf('!');
        return bang >= 0 ? prefix[..bang] : prefix;
    }

    private void HandleModeState(string channel, string modes)
    {
        if (!_channelModes.ContainsKey(channel))
            _channelModes[channel] = new HashSet<char>();

        var set = _channelModes[channel];
        var adding = true;
        foreach (var ch in modes)
        {
            if (ch == '+') { adding = true; continue; }
            if (ch == '-') { adding = false; continue; }
            if ("nitmE".Contains(ch))
            {
                if (adding) set.Add(ch);
                else set.Remove(ch);
            }
        }

        RefreshGovernancePanels(channel);
    }

    private void HandleModeChange(IrcMessage parsed)
    {
        if (parsed.Params.Length < 2) return;
        var channel = parsed.Params[0];
        var modes = parsed.Params[1];
        var actor = NickFromPrefix(parsed.Prefix);
        HandleModeState(channel, modes);

        var args = parsed.Params.Skip(2).ToList();
        var argIdx = 0;
        var adding = true;
        foreach (var ch in modes)
        {
            if (ch == '+') { adding = true; continue; }
            if (ch == '-') { adding = false; continue; }
            if ("ovbIkl".Contains(ch) && argIdx < args.Count)
            {
                var target = args[argIdx++];
                if (ch == 'b')
                {
                    if (!_bansByChannel.ContainsKey(channel)) _bansByChannel[channel] = [];
                    if (adding)
                    {
                        if (!_bansByChannel[channel].Any(x => x.Mask.Equals(target, StringComparison.OrdinalIgnoreCase)))
                            _bansByChannel[channel].Add(new ChannelMaskEntry { Mask = target, SetBy = actor, SetAt = DateTimeOffset.Now });
                    }
                    else
                    {
                        _bansByChannel[channel].RemoveAll(x => x.Mask.Equals(target, StringComparison.OrdinalIgnoreCase));
                    }
                }
                else if (ch == 'I')
                {
                    if (!_invitesByChannel.ContainsKey(channel)) _invitesByChannel[channel] = [];
                    if (adding)
                    {
                        if (!_invitesByChannel[channel].Any(x => x.Mask.Equals(target, StringComparison.OrdinalIgnoreCase)))
                            _invitesByChannel[channel].Add(new ChannelMaskEntry { Mask = target, SetBy = actor, SetAt = DateTimeOffset.Now });
                    }
                    else
                    {
                        _invitesByChannel[channel].RemoveAll(x => x.Mask.Equals(target, StringComparison.OrdinalIgnoreCase));
                    }
                }
            }
        }

        AddAuditEvent(channel, actor, "mode", string.Join(' ', parsed.Params.Skip(1)));
        RefreshGovernancePanels(channel);
    }

    private void AddAuditEvent(string channel, string actor, string action, string detail)
    {
        if (string.IsNullOrWhiteSpace(channel)) return;
        if (!_auditByChannel.ContainsKey(channel))
            _auditByChannel[channel] = [];

        _auditByChannel[channel].Add(new GovernanceEvent
        {
            Timestamp = DateTimeOffset.Now,
            Channel = channel,
            Actor = actor,
            Action = action,
            Detail = detail,
        });

        if (_auditByChannel[channel].Count > 200)
            _auditByChannel[channel].RemoveAt(0);

        RefreshGovernancePanels(channel);
    }

    private void RefreshGovernancePanels(string channel)
    {
        if (SelectedChannel?.Name.Equals(channel, StringComparison.OrdinalIgnoreCase) != true) return;

        ChannelBans.Clear();
        if (_bansByChannel.TryGetValue(channel, out var bans))
        {
            foreach (var entry in bans.OrderBy(x => x.Mask, StringComparer.OrdinalIgnoreCase))
                ChannelBans.Add(entry);
        }

        ChannelInvites.Clear();
        if (_invitesByChannel.TryGetValue(channel, out var invites))
        {
            foreach (var entry in invites.OrderBy(x => x.Mask, StringComparer.OrdinalIgnoreCase))
                ChannelInvites.Add(entry);
        }

        AuditTimeline.Clear();
        if (_auditByChannel.TryGetValue(channel, out var events))
        {
            foreach (var entry in events.OrderByDescending(x => x.Timestamp))
                AuditTimeline.Add(entry);
        }

        if (!_channelModes.TryGetValue(channel, out var modeSet))
            modeSet = [];

        IsChannelNoExternal = modeSet.Contains('n');
        IsChannelInviteOnly = modeSet.Contains('i');
        IsChannelTopicProtected = modeSet.Contains('t');
        IsChannelModerated = modeSet.Contains('m');
        IsChannelEncrypted = modeSet.Contains('E')
            || (SelectedChannel?.Kind == ChannelKind.DirectMessage && !string.IsNullOrWhiteSpace(_irc.Did));
        SelectedChannelSafetyText = IsChannelEncrypted ? "E2EE enabled" : "E2EE not enabled";
    }

    public void SetSaslCredentials(string token, string did, string pdsUrl, string method)
    {
        _irc.SetSaslCredentials(token, did, pdsUrl, method);
        _settings.ApiBearerToken = token;
        _settings.Save();
    }

    private void NotifyToast(string text)
    {
        ToastRequested?.Invoke(text);
    }
}
