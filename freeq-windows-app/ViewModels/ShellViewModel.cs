using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Freeq.Windows.Auth;
using Freeq.Windows.Interop;
using Freeq.Windows.Models;
using Freeq.Windows.Services;

namespace Freeq.Windows.ViewModels;

/// <summary>
/// Root ViewModel for the application shell.
/// Manages connection state, channel list, active conversation, and event dispatch.
/// </summary>
public partial class ShellViewModel : ObservableObject, IDisposable
{
    private readonly CoreBridge _bridge = new();
    private readonly Dispatcher _dispatcher;
    private readonly AppSettings _settings;
    private BrokerAuth? _brokerAuth;

    // ── Connection state ──

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsConnected))]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private string _connectionState = "disconnected";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private string _nick = "";

    [ObservableProperty]
    private string? _authDid;

    [ObservableProperty]
    private string? _authError;

    public bool IsConnected => ConnectionState == "connected";
    public string StatusText => ConnectionState switch
    {
        "connected" => AuthDid != null ? $"{Nick} ({AuthDid})" : Nick,
        "connecting" => "Connecting...",
        "reconnecting" => _reconnectStatusText ?? "Reconnecting...",
        _ => "Disconnected"
    };

    // ── Connect form ──

    [ObservableProperty]
    private string _serverAddress = "irc.freeq.at:6697";

    [ObservableProperty]
    private string _connectNick = "freeq_user";

    [ObservableProperty]
    private string _autoJoinChannels = "#lobby";

    [ObservableProperty]
    private bool _useTls = true;

    [ObservableProperty]
    private bool _showConnectPanel = true;

    // ── AT Proto auth ──

    [ObservableProperty]
    private string _loginMode = "guest"; // "guest" or "atproto"

    [ObservableProperty]
    private string _atHandle = "";

    [ObservableProperty]
    private string _brokerBase = "https://auth.freeq.at";

    [ObservableProperty]
    private bool _isAuthenticating;

    [ObservableProperty]
    private string? _authStep; // "Resolving...", "Authorizing...", "Connecting..."

    // ── Reconnect ──

    private System.Timers.Timer? _reconnectTimer;
    private int _reconnectAttempt;
    private double _reconnectDelay;
    private string? _reconnectStatusText;
    private bool _userDisconnected;

    // ── Batch buffering ──

    private readonly Dictionary<string, List<IrcMessage>> _batchBuffers = new();
    private readonly Dictionary<string, string> _batchTargets = new();

    // ── Echo dedup ──

    private readonly HashSet<string> _sentMsgIds = new();
    private const int MaxSentMsgIdHistory = 500;

    // ── Typing ──

    private System.Timers.Timer? _typingTimer;
    private bool _isTyping;
    private readonly Dictionary<string, Dictionary<string, DateTime>> _typingUsers = new();

    // ── Reply / Edit mode ──

    [ObservableProperty]
    private string? _replyToMessageId;

    [ObservableProperty]
    private string? _replyToPreview;

    [ObservableProperty]
    private string? _editingMessageId;

    [ObservableProperty]
    private string? _editingPreview;

    public bool IsInReplyMode => ReplyToMessageId != null;
    public bool IsInEditMode => EditingMessageId != null;

    // ── Channels ──

    public ObservableCollection<ChannelViewModel> Channels { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveChannel))]
    private ChannelViewModel? _activeChannel;

    public bool HasActiveChannel => ActiveChannel != null;

    // ── Compose ──

    [ObservableProperty]
    private string _composeText = "";

    // ── Pinned messages ──

    [ObservableProperty]
    private bool _showPinnedBar;

    public ShellViewModel()
    {
        _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;
        _bridge.EventReceived += OnEvent;

        // Load settings
        _settings = AppSettings.Load();
        ServerAddress = _settings.ServerAddress;
        AutoJoinChannels = _settings.Channels;
        UseTls = _settings.UseTls;
        LoginMode = _settings.LoginMode;
        AtHandle = _settings.Handle ?? "";
        BrokerBase = _settings.BrokerBase;
    }

    /// <summary>
    /// Called after the window loads. Attempts auto-login if a broker token is saved.
    /// </summary>
    public async Task TryAutoLoginAsync()
    {
        if (string.IsNullOrEmpty(_settings.BrokerToken)) return;

        AuthStep = "Reconnecting session...";
        IsAuthenticating = true;

        try
        {
            var session = await BrokerAuth.RefreshSessionAsync(_settings.BrokerBase, _settings.BrokerToken);
            if (session?.Token != null && session.Did != null)
            {
                var nick = BrokerAuth.NickFromHandle(session.Handle ?? _settings.Handle ?? session.Nick ?? "freeq_user");
                ConnectWithToken(session.Token, nick);
                return;
            }
        }
        catch { /* fall through to show connect panel */ }

        IsAuthenticating = false;
        AuthStep = null;
        // Clear stale broker token
        _settings.BrokerToken = null;
        _settings.Save();
    }

    // ── Commands ──

    [RelayCommand]
    private void Connect()
    {
        AuthError = null;
        SaveSettings();

        if (!_bridge.Create(ServerAddress, ConnectNick, UseTls))
        {
            AuthError = "Failed to create client";
            return;
        }

        _bridge.SubscribeEvents();
        ConnectionState = "connecting";
        ShowConnectPanel = false;
        _userDisconnected = false;

        var result = _bridge.Connect();
        if (result != 0)
        {
            AuthError = $"Connect failed (code {result})";
            ConnectionState = "disconnected";
            ShowConnectPanel = true;
        }
    }

    [RelayCommand]
    private async Task LoginWithAtProto()
    {
        var handle = AtHandle.Trim();
        if (string.IsNullOrWhiteSpace(handle))
        {
            AuthError = "Enter your AT Protocol handle";
            return;
        }

        AuthError = null;
        IsAuthenticating = true;
        AuthStep = "Checking broker...";

        // Save settings
        _settings.Handle = handle;
        _settings.LoginMode = "atproto";
        _settings.BrokerBase = BrokerBase;
        _settings.Channels = AutoJoinChannels;
        _settings.Save();

        try
        {
            // Health check
            if (!await BrokerAuth.HealthCheckAsync(BrokerBase))
            {
                AuthError = "Authentication service unavailable. Try again later or connect as guest.";
                IsAuthenticating = false;
                AuthStep = null;
                return;
            }

            AuthStep = "Opening browser...";
            _brokerAuth = new BrokerAuth();
            _brokerAuth.StartLogin(handle, BrokerBase);

            AuthStep = "Waiting for authorization...";
            var result = await _brokerAuth.WaitForCallbackAsync(TimeSpan.FromMinutes(3));

            if (result?.Did == null || result.EffectiveToken == null)
            {
                AuthError = "Authentication failed or was cancelled.";
                IsAuthenticating = false;
                AuthStep = null;
                return;
            }

            // Save broker token for persistent login
            if (!string.IsNullOrEmpty(result.BrokerToken))
            {
                _settings.BrokerToken = result.BrokerToken;
                _settings.Save();
            }

            var nick = BrokerAuth.NickFromHandle(result.Handle ?? handle);
            AuthStep = "Connecting...";
            ConnectWithToken(result.EffectiveToken, nick);
        }
        catch (Exception ex)
        {
            AuthError = $"OAuth error: {ex.Message}";
            IsAuthenticating = false;
            AuthStep = null;
        }
    }

    private void ConnectWithToken(string token, string nick)
    {
        AuthError = null;
        ConnectNick = nick;

        if (!_bridge.Create(ServerAddress, nick, UseTls))
        {
            AuthError = "Failed to create client";
            IsAuthenticating = false;
            AuthStep = null;
            return;
        }

        _bridge.SubscribeEvents();
        _bridge.SetWebToken(token);
        ConnectionState = "connecting";
        ShowConnectPanel = false;
        _userDisconnected = false;

        var result = _bridge.Connect();
        if (result != 0)
        {
            AuthError = $"Connect failed (code {result})";
            ConnectionState = "disconnected";
            ShowConnectPanel = true;
        }

        IsAuthenticating = false;
        AuthStep = null;
    }

    [RelayCommand]
    private void Disconnect()
    {
        _userDisconnected = true;
        StopReconnect();
        _bridge.Disconnect();
        ConnectionState = "disconnected";
        Nick = "";
        AuthDid = null;
        Channels.Clear();
        ActiveChannel = null;
        ShowConnectPanel = true;
        _sentMsgIds.Clear();
        _batchBuffers.Clear();
        _batchTargets.Clear();
    }

    [RelayCommand]
    private void CancelReconnect()
    {
        StopReconnect();
        ConnectionState = "disconnected";
        ShowConnectPanel = true;
    }

    [RelayCommand]
    private void CancelAuth()
    {
        _brokerAuth?.Cancel();
        IsAuthenticating = false;
        AuthStep = null;
    }

    [RelayCommand]
    private void JoinChannel(string? channelName)
    {
        if (string.IsNullOrWhiteSpace(channelName) || !IsConnected) return;
        var name = channelName.Trim();
        if (!name.StartsWith('#')) name = "#" + name;
        _bridge.Join(name);
    }

    [RelayCommand]
    private void SwitchChannel(ChannelViewModel? channel)
    {
        if (channel == null) return;
        ActiveChannel = channel;
        channel.UnreadCount = 0;
    }

    [RelayCommand]
    private void SendMessage()
    {
        if (string.IsNullOrWhiteSpace(ComposeText) || ActiveChannel == null || !IsConnected) return;

        var text = ComposeText.Trim();
        ComposeText = "";

        // Handle slash commands
        if (text.StartsWith('/'))
        {
            HandleSlashCommand(text);
            return;
        }

        // Stop typing indicator
        StopTypingIndicator();

        // Edit mode
        if (EditingMessageId != null)
        {
            _bridge.EditMessage(ActiveChannel.Name, EditingMessageId, text);
            ClearEditMode();
            return;
        }

        // Reply mode
        if (ReplyToMessageId != null)
        {
            _bridge.Reply(ActiveChannel.Name, ReplyToMessageId, text);
            ClearReplyMode();
            return;
        }

        _bridge.SendMessage(ActiveChannel.Name, text);
    }

    [RelayCommand]
    private void PartChannel(ChannelViewModel? channel)
    {
        if (channel == null || !IsConnected) return;
        _bridge.SendRaw($"PART {channel.Name}");
    }

    [RelayCommand]
    private void ClearReplyMode()
    {
        ReplyToMessageId = null;
        ReplyToPreview = null;
        OnPropertyChanged(nameof(IsInReplyMode));
    }

    [RelayCommand]
    private void ClearEditMode()
    {
        EditingMessageId = null;
        EditingPreview = null;
        OnPropertyChanged(nameof(IsInEditMode));
    }

    [RelayCommand]
    private void StartReply(IrcMessage? msg)
    {
        if (msg == null || ActiveChannel == null) return;
        ClearEditMode();
        ReplyToMessageId = msg.Id;
        ReplyToPreview = $"{msg.From}: {(msg.Text.Length > 60 ? msg.Text[..60] + "..." : msg.Text)}";
        OnPropertyChanged(nameof(IsInReplyMode));
    }

    [RelayCommand]
    private void StartEdit(IrcMessage? msg)
    {
        if (msg == null || !msg.IsSelf || ActiveChannel == null) return;
        ClearReplyMode();
        EditingMessageId = msg.Id;
        EditingPreview = msg.Text.Length > 60 ? msg.Text[..60] + "..." : msg.Text;
        ComposeText = msg.Text;
        OnPropertyChanged(nameof(IsInEditMode));
    }

    [RelayCommand]
    private void DeleteMessage(IrcMessage? msg)
    {
        if (msg == null || !msg.IsSelf || ActiveChannel == null || !IsConnected) return;
        _bridge.DeleteMessage(ActiveChannel.Name, msg.Id);
    }

    [RelayCommand]
    private void ReactToMessage(string? param)
    {
        // param format: "emoji|msgid"
        if (param == null || ActiveChannel == null || !IsConnected) return;
        var parts = param.Split('|', 2);
        if (parts.Length != 2) return;
        _bridge.React(ActiveChannel.Name, parts[0], parts[1]);
    }

    [RelayCommand]
    private void PinMessage(IrcMessage? msg)
    {
        if (msg == null || ActiveChannel == null || !IsConnected) return;
        _bridge.Pin(ActiveChannel.Name, msg.Id);
    }

    [RelayCommand]
    private void UnpinMessage(IrcMessage? msg)
    {
        if (msg == null || ActiveChannel == null || !IsConnected) return;
        _bridge.Unpin(ActiveChannel.Name, msg.Id);
    }

    [RelayCommand]
    private void LoadMoreHistory()
    {
        if (ActiveChannel == null || !IsConnected || ActiveChannel.IsLoadingHistory) return;
        if (!ActiveChannel.HasMoreHistory) return;

        var oldest = ActiveChannel.OldestMsgId;
        if (string.IsNullOrEmpty(oldest)) return;

        ActiveChannel.IsLoadingHistory = true;
        _bridge.HistoryBefore(ActiveChannel.Name, oldest, 50);
    }

    [RelayCommand]
    private void SwitchToChannelByIndex(string? indexStr)
    {
        if (!int.TryParse(indexStr, out var idx)) return;
        if (idx >= 0 && idx < Channels.Count)
            SwitchChannel(Channels[idx]);
    }

    [RelayCommand]
    private void PreviousChannel()
    {
        if (ActiveChannel == null || Channels.Count <= 1) return;
        var idx = Channels.IndexOf(ActiveChannel);
        SwitchChannel(Channels[idx > 0 ? idx - 1 : Channels.Count - 1]);
    }

    [RelayCommand]
    private void NextChannel()
    {
        if (ActiveChannel == null || Channels.Count <= 1) return;
        var idx = Channels.IndexOf(ActiveChannel);
        SwitchChannel(Channels[(idx + 1) % Channels.Count]);
    }

    [RelayCommand]
    private void EditLastOwnMessage()
    {
        if (ActiveChannel == null || !string.IsNullOrEmpty(ComposeText)) return;
        for (int i = ActiveChannel.Messages.Count - 1; i >= 0; i--)
        {
            var msg = ActiveChannel.Messages[i];
            if (msg.IsSelf && !msg.IsSystem && !msg.Deleted)
            {
                StartEdit(msg);
                return;
            }
        }
    }

    [RelayCommand]
    private void CancelComposeMode()
    {
        if (IsInEditMode) ClearEditMode();
        else if (IsInReplyMode) ClearReplyMode();
        else ComposeText = "";
    }

    /// <summary>
    /// Called on compose text changes to manage typing indicators.
    /// </summary>
    public void OnComposeTextChanged()
    {
        if (!IsConnected || ActiveChannel == null) return;

        if (!string.IsNullOrEmpty(ComposeText))
        {
            if (!_isTyping)
            {
                _isTyping = true;
                _bridge.TypingStart(ActiveChannel.Name);
            }
            // Reset the auto-stop timer
            _typingTimer?.Stop();
            _typingTimer = new System.Timers.Timer(5000) { AutoReset = false };
            _typingTimer.Elapsed += (_, _) =>
            {
                _isTyping = false;
                _dispatcher.BeginInvoke(() =>
                {
                    if (IsConnected && ActiveChannel != null)
                        _bridge.TypingStop(ActiveChannel.Name);
                });
            };
            _typingTimer.Start();
        }
    }

    private void StopTypingIndicator()
    {
        if (_isTyping && IsConnected && ActiveChannel != null)
        {
            _bridge.TypingStop(ActiveChannel.Name);
            _isTyping = false;
            _typingTimer?.Stop();
        }
    }

    private void HandleSlashCommand(string text)
    {
        var parts = text.Split(' ', 2);
        var cmd = parts[0].ToLowerInvariant();
        var arg = parts.Length > 1 ? parts[1] : "";

        switch (cmd)
        {
            case "/join":
                if (!string.IsNullOrWhiteSpace(arg))
                    JoinChannel(arg.Trim());
                break;
            case "/part":
                if (!string.IsNullOrWhiteSpace(arg))
                    _bridge.SendRaw($"PART {arg.Trim()}");
                else if (ActiveChannel != null)
                    _bridge.SendRaw($"PART {ActiveChannel.Name}");
                break;
            case "/nick":
                if (!string.IsNullOrWhiteSpace(arg))
                    _bridge.SendRaw($"NICK {arg.Trim()}");
                break;
            case "/topic":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                    _bridge.SendRaw($"TOPIC {ActiveChannel.Name} :{arg}");
                break;
            case "/me":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                    _bridge.SendMessage(ActiveChannel.Name, $"\x01ACTION {arg}\x01");
                break;
            case "/msg":
                var msgParts = arg.Split(' ', 2);
                if (msgParts.Length == 2)
                    _bridge.SendMessage(msgParts[0], msgParts[1]);
                break;
            case "/raw":
                if (!string.IsNullOrWhiteSpace(arg))
                    _bridge.SendRaw(arg);
                break;
            case "/edit":
                // /edit — edit last own message with new text
                if (ActiveChannel != null)
                {
                    var editParts = arg.Split(' ', 2);
                    if (editParts.Length == 2)
                    {
                        _bridge.EditMessage(ActiveChannel.Name, editParts[0], editParts[1]);
                    }
                    else if (string.IsNullOrWhiteSpace(arg))
                    {
                        EditLastOwnMessage();
                    }
                }
                break;
            case "/delete":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                    _bridge.DeleteMessage(ActiveChannel.Name, arg.Trim());
                break;
            case "/react":
                // /react <emoji> <msgid>
                if (ActiveChannel != null)
                {
                    var reactParts = arg.Split(' ', 2);
                    if (reactParts.Length == 2)
                        _bridge.React(ActiveChannel.Name, reactParts[0], reactParts[1]);
                }
                break;
            case "/pin":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                    _bridge.Pin(ActiveChannel.Name, arg.Trim());
                break;
            case "/unpin":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                    _bridge.Unpin(ActiveChannel.Name, arg.Trim());
                break;
            case "/mode":
                if (ActiveChannel != null && !string.IsNullOrWhiteSpace(arg))
                {
                    var modeParts = arg.Split(' ', 2);
                    _bridge.Mode(ActiveChannel.Name, modeParts[0], modeParts.Length > 1 ? modeParts[1] : null);
                }
                break;
            default:
                // Unknown command — send as raw
                _bridge.SendRaw(text[1..]);
                break;
        }
    }

    // ── Event handling ──

    private void OnEvent(EventEnvelope envelope)
    {
        // Marshal to UI thread
        _dispatcher.BeginInvoke(() => ApplyEvent(envelope));
    }

    private void ApplyEvent(EventEnvelope envelope)
    {
        var type = envelope.EventType;
        switch (type)
        {
            case "connected":
                ConnectionState = "connecting"; // still need registration
                break;

            case "registered":
                ConnectionState = "connected";
                ResetReconnectState();
                Nick = envelope.GetDataString("nick") ?? Nick;
                // Auto-join channels
                foreach (var ch in AutoJoinChannels.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var name = ch.StartsWith('#') ? ch : "#" + ch;
                    _bridge.Join(name);
                }
                break;

            case "authenticated":
                AuthDid = envelope.GetDataString("did");
                OnPropertyChanged(nameof(StatusText));
                break;

            case "auth_failed":
                AuthError = envelope.GetDataString("reason") ?? "Authentication failed";
                break;

            case "joined":
                HandleJoined(envelope);
                break;

            case "parted":
                HandleParted(envelope);
                break;

            case "message":
                HandleMessage(envelope);
                break;

            case "tag_msg":
                HandleTagMsg(envelope);
                break;

            case "names":
                HandleNames(envelope);
                break;

            case "topic_changed":
                HandleTopicChanged(envelope);
                break;

            case "mode_changed":
                HandleModeChanged(envelope);
                break;

            case "nick_changed":
                HandleNickChanged(envelope);
                break;

            case "kicked":
                HandleKicked(envelope);
                break;

            case "user_quit":
                HandleUserQuit(envelope);
                break;

            case "away_changed":
                HandleAwayChanged(envelope);
                break;

            case "batch_start":
                HandleBatchStart(envelope);
                break;

            case "batch_end":
                HandleBatchEnd(envelope);
                break;

            case "notice":
                HandleNotice(envelope);
                break;

            case "disconnected":
                HandleDisconnected(envelope);
                break;
        }
    }

    private void HandleJoined(EventEnvelope e)
    {
        var channel = e.GetDataString("channel");
        var nick = e.GetDataString("nick");
        if (channel == null || nick == null) return;

        var vm = GetOrCreateChannel(channel);

        if (string.Equals(nick, Nick, StringComparison.OrdinalIgnoreCase))
        {
            vm.IsJoined = true;
            if (ActiveChannel == null)
                ActiveChannel = vm;
            // Request history
            _bridge.HistoryLatest(channel, 50);
        }
        else
        {
            vm.AddMember(new IrcMember { Nick = nick });
            AddPresenceMessage(vm, nick, joined: true, $"{nick} joined {channel}");
        }
    }

    private void HandleParted(EventEnvelope e)
    {
        var channel = e.GetDataString("channel");
        var nick = e.GetDataString("nick");
        if (channel == null || nick == null) return;

        var vm = FindChannel(channel);
        if (vm == null) return;

        if (string.Equals(nick, Nick, StringComparison.OrdinalIgnoreCase))
        {
            Channels.Remove(vm);
            if (ActiveChannel == vm)
                ActiveChannel = Channels.FirstOrDefault();
        }
        else
        {
            vm.RemoveMember(nick);
            AddPresenceMessage(vm, nick, joined: false, $"{nick} left {channel}");
        }
    }

    private void HandleMessage(EventEnvelope e)
    {
        var data = e.EventData;
        if (data is not JsonElement d) return;

        var from = d.GetProperty("from_nick").GetString() ?? "";
        var target = d.GetProperty("target").GetString() ?? "";
        var text = d.GetProperty("text").GetString() ?? "";
        var isAction = d.TryGetProperty("is_action", out var ia) && ia.GetBoolean();
        var msgid = d.TryGetProperty("msgid", out var mid) && mid.ValueKind != JsonValueKind.Null
            ? mid.GetString() : null;
        var editOf = d.TryGetProperty("edit_of", out var eo) && eo.ValueKind != JsonValueKind.Null
            ? eo.GetString() : null;
        var replyTo = d.TryGetProperty("reply_to", out var rt) && rt.ValueKind != JsonValueKind.Null
            ? rt.GetString() : null;
        var batchId = d.TryGetProperty("batch_id", out var bi) && bi.ValueKind != JsonValueKind.Null
            ? bi.GetString() : null;
        var tsMs = d.TryGetProperty("timestamp_ms", out var ts) ? ts.GetInt64() : 0;

        // Echo dedup: if this is our own message echoed back, skip
        var isSelf = string.Equals(from, Nick, StringComparison.OrdinalIgnoreCase);
        if (isSelf && msgid != null && _sentMsgIds.Remove(msgid))
            return; // Already displayed optimistically

        // For DMs, the channel is the other user's nick
        var channelName = target.StartsWith('#') ? target : from;
        if (isSelf && !target.StartsWith('#'))
            channelName = target; // Our outgoing DM

        var vm = GetOrCreateChannel(channelName);

        // Handle edits — update existing message in-place
        if (editOf != null)
        {
            var existing = vm.Messages.FirstOrDefault(m => m.Id == editOf);
            if (existing != null)
            {
                existing.Text = isAction ? $"* {from} {text}" : text;
                existing.IsEdited = true;
                // Force UI refresh
                var idx = vm.Messages.IndexOf(existing);
                if (idx >= 0)
                {
                    vm.Messages.RemoveAt(idx);
                    vm.Messages.Insert(idx, existing);
                }
                return;
            }
        }

        var msg = new IrcMessage
        {
            Id = msgid ?? Guid.NewGuid().ToString(),
            From = from,
            Target = target,
            Text = isAction ? $"* {from} {text}" : text,
            Timestamp = tsMs > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds(tsMs).UtcDateTime
                : DateTime.UtcNow,
            IsAction = isAction,
            IsSelf = isSelf,
            EditOf = editOf,
            ReplyTo = replyTo,
        };

        // If this is a reply, find the original message preview
        if (replyTo != null)
        {
            var original = vm.Messages.FirstOrDefault(m => m.Id == replyTo);
            if (original != null)
                msg.ReplyPreview = $"{original.From}: {(original.Text.Length > 50 ? original.Text[..50] + "..." : original.Text)}";
        }

        // Batch buffering
        if (batchId != null && _batchBuffers.ContainsKey(batchId))
        {
            _batchBuffers[batchId].Add(msg);
            return;
        }

        vm.Messages.Add(msg);
        vm.ScrollToBottom = true;

        // Unread tracking (skip batch messages and own messages)
        if (vm != ActiveChannel && !isSelf)
            vm.UnreadCount++;
    }

    private void HandleTagMsg(EventEnvelope e)
    {
        var data = e.EventData;
        if (data is not JsonElement d) return;

        var from = d.TryGetProperty("from", out var f) ? f.GetString() ?? "" : "";
        var target = d.TryGetProperty("target", out var t) ? t.GetString() ?? "" : "";

        if (!d.TryGetProperty("tags", out var tagsEl)) return;

        // Typing indicators
        if (tagsEl.TryGetProperty("+typing", out var typingVal))
        {
            var typingState = typingVal.GetString();
            HandleTypingEvent(from, target, typingState);
            return;
        }

        // Reactions
        if (tagsEl.TryGetProperty("+draft/react", out var reactVal) &&
            tagsEl.TryGetProperty("+draft/reply", out var reactTarget))
        {
            var emoji = reactVal.GetString() ?? "";
            var targetMsgId = reactTarget.GetString() ?? "";
            HandleReaction(from, target, emoji, targetMsgId);
            return;
        }

        // Deletion
        if (tagsEl.TryGetProperty("+draft/delete", out var delVal))
        {
            var deletedMsgId = delVal.GetString() ?? "";
            HandleDeletion(target, deletedMsgId);
        }
    }

    private void HandleTypingEvent(string from, string target, string? state)
    {
        if (string.Equals(from, Nick, StringComparison.OrdinalIgnoreCase)) return;

        var channelName = target.StartsWith('#') ? target : from;
        var vm = FindChannel(channelName);
        if (vm == null) return;

        if (state == "active")
        {
            vm.AddTypingUser(from);
        }
        else
        {
            vm.RemoveTypingUser(from);
        }
    }

    private void HandleReaction(string from, string target, string emoji, string targetMsgId)
    {
        var channelName = target.StartsWith('#') ? target : from;
        var vm = FindChannel(channelName);
        if (vm == null) return;

        var msg = vm.Messages.FirstOrDefault(m => m.Id == targetMsgId);
        if (msg == null) return;

        msg.AddReaction(emoji, from);
        // Force UI refresh
        var idx = vm.Messages.IndexOf(msg);
        if (idx >= 0)
        {
            vm.Messages.RemoveAt(idx);
            vm.Messages.Insert(idx, msg);
        }
    }

    private void HandleDeletion(string target, string msgId)
    {
        // Find the channel — could be any we're in
        foreach (var ch in Channels)
        {
            var msg = ch.Messages.FirstOrDefault(m => m.Id == msgId);
            if (msg != null)
            {
                msg.Deleted = true;
                msg.Text = "(message deleted)";
                // Force UI refresh
                var idx = ch.Messages.IndexOf(msg);
                if (idx >= 0)
                {
                    ch.Messages.RemoveAt(idx);
                    ch.Messages.Insert(idx, msg);
                }
                return;
            }
        }
    }

    private void HandleBatchStart(EventEnvelope e)
    {
        var id = e.GetDataString("id");
        var target = e.GetDataString("target") ?? "";
        if (id == null) return;

        _batchBuffers[id] = new List<IrcMessage>();
        _batchTargets[id] = target;
    }

    private void HandleBatchEnd(EventEnvelope e)
    {
        var id = e.GetDataString("id");
        if (id == null || !_batchBuffers.TryGetValue(id, out var messages)) return;

        _batchBuffers.Remove(id);
        var target = _batchTargets.GetValueOrDefault(id, "");
        _batchTargets.Remove(id);

        if (messages.Count == 0) return;

        // Find the target channel from the first message
        var channelName = !string.IsNullOrEmpty(target) ? target : messages[0].Target;
        if (!channelName.StartsWith('#') && messages.Count > 0)
            channelName = messages[0].Target.StartsWith('#') ? messages[0].Target : messages[0].From;

        var vm = FindChannel(channelName);
        if (vm == null) return;

        // Insert batch messages at the beginning (history) or end (live)
        // CHATHISTORY batches should prepend
        if (vm.Messages.Count > 0 && messages.Count > 0
            && messages[0].Timestamp < vm.Messages[0].Timestamp)
        {
            // History batch — prepend
            for (int i = 0; i < messages.Count; i++)
            {
                messages[i].IsBatchMessage = true;
                // Resolve reply previews
                if (messages[i].ReplyTo != null)
                {
                    var orig = messages.FirstOrDefault(m => m.Id == messages[i].ReplyTo)
                               ?? vm.Messages.FirstOrDefault(m => m.Id == messages[i].ReplyTo);
                    if (orig != null)
                        messages[i].ReplyPreview = $"{orig.From}: {(orig.Text.Length > 50 ? orig.Text[..50] + "..." : orig.Text)}";
                }
                vm.Messages.Insert(i, messages[i]);
            }
            // Update oldest ID for load-more
            vm.OldestMsgId = messages.FirstOrDefault()?.Id;
            vm.HasMoreHistory = messages.Count >= 50; // Might be more
        }
        else
        {
            // Live batch or initial history — append
            foreach (var msg in messages)
            {
                msg.IsBatchMessage = true;
                if (msg.ReplyTo != null)
                {
                    var orig = messages.FirstOrDefault(m => m.Id == msg.ReplyTo)
                               ?? vm.Messages.FirstOrDefault(m => m.Id == msg.ReplyTo);
                    if (orig != null)
                        msg.ReplyPreview = $"{orig.From}: {(orig.Text.Length > 50 ? orig.Text[..50] + "..." : orig.Text)}";
                }
                vm.Messages.Add(msg);
            }
            vm.ScrollToBottom = true;
            // Set oldest for future load-more
            if (vm.OldestMsgId == null && messages.Count > 0)
            {
                vm.OldestMsgId = messages[0].Id;
                vm.HasMoreHistory = messages.Count >= 50;
            }
        }

        vm.IsLoadingHistory = false;
    }

    private void HandleNames(EventEnvelope e)
    {
        var channel = e.GetDataString("channel");
        var data = e.EventData;
        if (channel == null || data is not JsonElement d) return;

        var vm = GetOrCreateChannel(channel);

        if (d.TryGetProperty("members", out var membersEl) && membersEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var m in membersEl.EnumerateArray())
            {
                var nick = m.GetProperty("nick").GetString() ?? "";
                var isOp = m.TryGetProperty("is_op", out var op) && op.GetBoolean();
                var isHalfOp = m.TryGetProperty("is_halfop", out var ho) && ho.GetBoolean();
                var isVoiced = m.TryGetProperty("is_voiced", out var vo) && vo.GetBoolean();

                vm.AddMember(new IrcMember
                {
                    Nick = nick,
                    IsOp = isOp,
                    IsHalfOp = isHalfOp,
                    IsVoiced = isVoiced,
                });
            }
        }
    }

    private void HandleTopicChanged(EventEnvelope e)
    {
        var data = e.EventData;
        if (data is not JsonElement d) return;

        var channel = d.GetProperty("channel").GetString();
        var text = d.GetProperty("text").GetString() ?? "";
        if (channel == null) return;

        var vm = FindChannel(channel);
        if (vm != null)
        {
            vm.Topic = text;
            AddSystemMessage(vm, $"Topic: {text}");
        }
    }

    private void HandleModeChanged(EventEnvelope e)
    {
        var channel = e.GetDataString("channel");
        var mode = e.GetDataString("mode");
        var arg = e.GetDataStringOrNull("arg");
        var setBy = e.GetDataString("set_by") ?? "";
        if (channel == null || mode == null) return;

        var vm = FindChannel(channel);
        if (vm == null) return;

        // Handle user modes (+o, +v, etc.)
        if (arg != null && (mode == "+o" || mode == "-o"))
        {
            var member = vm.FindMember(arg);
            if (member != null) member.IsOp = mode == "+o";
            vm.RefreshMembers();
        }
        else if (arg != null && (mode == "+v" || mode == "-v"))
        {
            var member = vm.FindMember(arg);
            if (member != null) member.IsVoiced = mode == "+v";
            vm.RefreshMembers();
        }

        AddSystemMessage(vm, $"{setBy} sets mode {mode} {arg ?? ""}".TrimEnd());
    }

    private void HandleNickChanged(EventEnvelope e)
    {
        var oldNick = e.GetDataString("old_nick") ?? "";
        var newNick = e.GetDataString("new_nick") ?? "";

        if (string.Equals(oldNick, Nick, StringComparison.OrdinalIgnoreCase))
        {
            Nick = newNick;
            OnPropertyChanged(nameof(StatusText));
        }

        // Update member lists
        foreach (var ch in Channels)
        {
            var member = ch.FindMember(oldNick);
            if (member != null)
            {
                member.Nick = newNick;
                ch.RefreshMembers();
                AddSystemMessage(ch, $"{oldNick} is now known as {newNick}");
            }
        }
    }

    private void HandleKicked(EventEnvelope e)
    {
        var channel = e.GetDataString("channel");
        var nick = e.GetDataString("nick");
        var by = e.GetDataString("by") ?? "";
        var reason = e.GetDataString("reason") ?? "";
        if (channel == null || nick == null) return;

        var vm = FindChannel(channel);
        if (vm == null) return;

        if (string.Equals(nick, Nick, StringComparison.OrdinalIgnoreCase))
        {
            AddSystemMessage(vm, $"You were kicked by {by}: {reason}");
            vm.IsJoined = false;
        }
        else
        {
            vm.RemoveMember(nick);
            AddSystemMessage(vm, $"{nick} was kicked by {by}: {reason}");
        }
    }

    private void HandleUserQuit(EventEnvelope e)
    {
        var nick = e.GetDataString("nick") ?? "";
        var reason = e.GetDataString("reason") ?? "";

        foreach (var ch in Channels)
        {
            if (ch.FindMember(nick) != null)
            {
                ch.RemoveMember(nick);
                AddPresenceMessage(ch, nick, joined: false, $"{nick} quit: {reason}");
            }
        }
    }

    private void HandleAwayChanged(EventEnvelope e)
    {
        var nick = e.GetDataString("nick") ?? "";
        var awayMsg = e.GetDataStringOrNull("away_msg");

        foreach (var ch in Channels)
        {
            var member = ch.FindMember(nick);
            if (member != null)
            {
                member.AwayMsg = awayMsg;
                ch.RefreshMembers();
            }
        }
    }

    private void HandleNotice(EventEnvelope e)
    {
        var text = e.GetDataString("text");
        if (string.IsNullOrEmpty(text)) return;

        // Route to Server pseudo-channel
        var serverCh = GetOrCreateServerChannel();
        serverCh.Messages.Add(new IrcMessage
        {
            Id = Guid.NewGuid().ToString(),
            From = "server",
            Text = text,
            Timestamp = DateTime.UtcNow,
            IsSystem = true,
        });
        serverCh.ScrollToBottom = true;

        // Also show in active channel if there is one
        if (ActiveChannel != null && !ActiveChannel.IsServerChannel)
            AddSystemMessage(ActiveChannel, text);
    }

    private void HandleDisconnected(EventEnvelope e)
    {
        var reason = e.GetDataString("reason") ?? "Connection lost";
        ConnectionState = "disconnected";
        AddSystemMessage(ActiveChannel, $"Disconnected: {reason}");

        // Auto-reconnect unless user explicitly disconnected
        if (!_userDisconnected)
            StartReconnect();
    }

    // ── Reconnect ──

    private void StartReconnect()
    {
        if (_reconnectAttempt >= 20)
        {
            ShowConnectPanel = true;
            AddSystemMessage(ActiveChannel, "Maximum reconnect attempts reached.");
            return;
        }

        _reconnectAttempt++;
        // Exponential backoff: 1, 2, 4, 8, 16, 30 (cap)
        _reconnectDelay = Math.Min(Math.Pow(2, _reconnectAttempt - 1), 30);
        _reconnectStatusText = $"Reconnecting in {_reconnectDelay:0}s... (attempt {_reconnectAttempt})";
        ConnectionState = "reconnecting";
        OnPropertyChanged(nameof(StatusText));

        _reconnectTimer = new System.Timers.Timer(_reconnectDelay * 1000) { AutoReset = false };
        _reconnectTimer.Elapsed += async (_, _) =>
        {
            await _dispatcher.InvokeAsync(async () =>
            {
                _reconnectStatusText = $"Reconnecting... (attempt {_reconnectAttempt})";
                OnPropertyChanged(nameof(StatusText));

                // Refresh broker token if available
                if (!string.IsNullOrEmpty(_settings.BrokerToken))
                {
                    try
                    {
                        var session = await BrokerAuth.RefreshSessionAsync(_settings.BrokerBase, _settings.BrokerToken);
                        if (session?.Token != null)
                        {
                            ConnectWithToken(session.Token, ConnectNick);
                            return;
                        }
                    }
                    catch { /* fall through to guest reconnect */ }
                }

                // Guest reconnect
                Connect();
            });
        };
        _reconnectTimer.Start();
    }

    private void StopReconnect()
    {
        _reconnectTimer?.Stop();
        _reconnectTimer?.Dispose();
        _reconnectTimer = null;
    }

    private void ResetReconnectState()
    {
        StopReconnect();
        _reconnectAttempt = 0;
        _reconnectDelay = 0;
        _reconnectStatusText = null;
    }

    // ── Helpers ──

    private ChannelViewModel GetOrCreateChannel(string name)
    {
        var vm = FindChannel(name);
        if (vm == null)
        {
            vm = new ChannelViewModel { Name = name, IsJoined = true };
            Channels.Add(vm);
        }
        return vm;
    }

    private ChannelViewModel GetOrCreateServerChannel()
    {
        var vm = Channels.FirstOrDefault(c => c.IsServerChannel);
        if (vm == null)
        {
            vm = new ChannelViewModel { Name = "Server", IsJoined = true, IsServerChannel = true };
            Channels.Insert(0, vm);
        }
        return vm;
    }

    private ChannelViewModel? FindChannel(string name)
    {
        return Channels.FirstOrDefault(c =>
            string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    // The join/part events behind a grouped summary line, keyed by that
    // line's id. Only a channel's newest line is ever extended.
    private readonly Dictionary<string, List<(string Nick, bool Joined)>> _presenceRuns = new();

    /// A join/part/quit line, shown per the `join_part` setting: hidden
    /// (default), grouped into one summary per run, or all.
    private void AddPresenceMessage(ChannelViewModel channel, string nick, bool joined, string text)
    {
        var mode = _settings.JoinPart.ToLowerInvariant();
        if (mode != "grouped" && mode != "all")
            return;

        if (mode == "grouped"
            && channel.Messages.Count > 0
            && _presenceRuns.TryGetValue(channel.Messages[^1].Id, out var run))
        {
            run.Add((nick, joined));
            var last = channel.Messages[^1];
            last.Text = SummarizePresence(run);
            last.Timestamp = DateTime.UtcNow;
            // Replace so the list redraws the row (IrcMessage doesn't notify).
            channel.Messages[^1] = last;
            return;
        }

        AddSystemMessage(channel, text);
        _presenceRuns[channel.Messages[^1].Id] = [(nick, joined)];
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

    private void AddSystemMessage(ChannelViewModel? channel, string text)
    {
        if (channel == null) return;
        channel.Messages.Add(new IrcMessage
        {
            Id = Guid.NewGuid().ToString(),
            From = "*",
            Text = text,
            Timestamp = DateTime.UtcNow,
            IsSystem = true,
        });
        channel.ScrollToBottom = true;
    }

    private void SaveSettings()
    {
        _settings.ServerAddress = ServerAddress;
        _settings.Channels = AutoJoinChannels;
        _settings.UseTls = UseTls;
        _settings.LoginMode = LoginMode;
        _settings.Handle = string.IsNullOrWhiteSpace(AtHandle) ? null : AtHandle;
        _settings.BrokerBase = BrokerBase;
        _settings.Save();
    }

    public void SaveWindowBounds(double left, double top, double width, double height)
    {
        _settings.WindowLeft = left;
        _settings.WindowTop = top;
        _settings.WindowWidth = width;
        _settings.WindowHeight = height;
        _settings.Save();
    }

    public (double? left, double? top, double? width, double? height) GetSavedWindowBounds()
    {
        return (_settings.WindowLeft, _settings.WindowTop, _settings.WindowWidth, _settings.WindowHeight);
    }

    public void Dispose()
    {
        StopReconnect();
        _typingTimer?.Dispose();
        _bridge.Dispose();
    }
}
