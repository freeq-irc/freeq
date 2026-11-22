using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;

namespace Freeq.WinUI.Services;

public enum ConnectionState
{
    Disconnected,
    Connecting,
    Connected,
    Authenticating,
    Authenticated
}

public record IrcMessage(string? Prefix, string Command, string[] Params, Dictionary<string, string> Tags);

/// <summary>An agent's last structured PRESENCE: its state, and the status text it published.</summary>
public record AgentPresence(string State, string? Status);

public class IrcClient : IDisposable
{
    private ClientWebSocket? _ws;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentQueue<string> _sendQueue = new();

    public string Nick { get; private set; } = string.Empty;
    public string? Did { get; private set; }
    public ConnectionState State { get; private set; } = ConnectionState.Disconnected;

    // SASL credentials
    private string? _saslToken;
    private string? _saslDid;
    private string? _saslPdsUrl;
    private string? _saslMethod;

    public bool IsEchoMessageAcked => _ackedCaps.Contains("echo-message");

    public event Action<ConnectionState>? StateChanged;
    public event Action<string, string, string, string?, DateTimeOffset?>? MessageReceived; // channel, nick, message, msgid, serverTime
    public event Action<string, string, string, DateTimeOffset?>? MessageEdited;            // channel, originalMsgId, newContent, serverTime
    public event Action<string, string>? MessageDeleted;                                    // channel, msgId
    public event Action<string, string, string, string?>? ReactionReceived;                 // channel, nick, emoji, targetMsgId
    public event Action<string, string, bool>? TypingChanged;                              // channel, nick, isTyping
    public event Action<string, bool, string?>? AwayChanged;                               // nick, isAway, message
    public event Action<bool, string?>? SelfAwayStateChanged;                              // isAway, message
    public event Action<string, string>? JoinReceived; // channel, nick
    public event Action<string, string, string>? PartReceived; // channel, nick, reason
    public event Action<string, string>? QuitReceived; // nick, reason
    public event Action<string, string>? TopicReceived; // channel, topic
    public event Action<string, List<string>>? NamesReceived; // channel, nicks
    public event Action<string, string>? NickChanged; // oldNick, newNick
    public event Action<string, string?>? AccountChanged; // nick, account (null = logged out)
    /// <summary>A member's actor class or structured presence changed ("*" = several at once).</summary>
    public event Action<string>? ActorInfoChanged; // nick
    public event Action<string>? RawReceived;
    public event Action<string>? ErrorReceived;
    /// <summary>Fired for each RPL_LIST (322) entry: channel, memberCount, topic.</summary>
    public event Action<string, int, string>? ListEntryReceived;
    /// <summary>Fired when RPL_LISTEND (323) is received.</summary>
    public event Action? ListEndReceived;
    /// <summary>Fired for each PINS response line: channel, msgid, pinnedBy, pinnedAt.</summary>
    public event Action<string, string, string, long>? PinEntryReceived;
    /// <summary>Fired once when MOTD (375/372/376) is completed for this session.</summary>
    public event Action<string>? MotdReceived;

    // Nick → account (DID) mapping, populated from extended-join and ACCOUNT messages
    private readonly ConcurrentDictionary<string, string> _accounts = new(StringComparer.OrdinalIgnoreCase);

    // Nick → actor class ("agent" / "external_agent"). Absent means human.
    // Learned from the JOIN tag, the 674 roster numeric, WHOIS 673 and PRESENCE.
    private readonly ConcurrentDictionary<string, string> _actorClasses = new(StringComparer.OrdinalIgnoreCase);
    // Nick → last structured PRESENCE (agents only publish one).
    private readonly ConcurrentDictionary<string, AgentPresence> _presence = new(StringComparer.OrdinalIgnoreCase);

    // Caps matching freeq-app/src/irc/client.ts
    private static readonly string[] WantedCaps =
    [
        "message-tags",
        "server-time",
        "batch",
        "multi-prefix",
        "echo-message",
        "account-notify",
        "extended-join",
        "away-notify",
        "draft/chathistory",
    ];

    private readonly HashSet<string> _ackedCaps = new();
    private readonly List<string> _motdLines = [];

    public string? GetAccount(string nick) =>
        _accounts.TryGetValue(nick, out var account) ? account : null;

    /// <summary>"agent" / "external_agent", or null for a person (or unknown).</summary>
    public string? GetActorClass(string nick) =>
        _actorClasses.TryGetValue(nick, out var c) ? c : null;

    public AgentPresence? GetPresence(string nick) =>
        _presence.TryGetValue(nick, out var p) ? p : null;

    /// <summary>Record a member's class. "human" (or anything unknown) clears it: absent means human.</summary>
    private bool SetActorClass(string nick, string? actorClass)
    {
        if (string.IsNullOrEmpty(nick)) return false;
        if (actorClass is "agent" or "external_agent")
        {
            var changed = !_actorClasses.TryGetValue(nick, out var old) || old != actorClass;
            _actorClasses[nick] = actorClass;
            return changed;
        }
        if (actorClass == "human")
            return _actorClasses.TryRemove(nick, out _);
        return false;
    }

    /// <summary>
    /// Parse a PRESENCE payload (<c>state=…;status=…;task=…</c>). Null without a
    /// state. The status may itself contain '=' (it is usually key=value pairs),
    /// so each part splits on its first '=' only. Mirrors freeq-sdk parse_presence.
    /// </summary>
    internal static AgentPresence? ParsePresence(string raw)
    {
        string? state = null, status = null;
        foreach (var part in raw.Split(';'))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = part[..eq].Trim();
            var value = part[(eq + 1)..];
            if (key == "state") state = value.Trim();
            else if (key == "status" && value.Length > 0) status = value;
        }
        return string.IsNullOrEmpty(state) ? null : new AgentPresence(state, status);
    }

    public void SetSaslCredentials(string token, string did, string pdsUrl, string method)
    {
        _saslToken = token;
        _saslDid = did;
        _saslPdsUrl = pdsUrl;
        _saslMethod = method;
    }

    public async Task ConnectAsync(string url, string nick, string? password = null)
    {
        // Clean up any previous connection first
        _cts?.Cancel();
        try { _ws?.Dispose(); } catch { /* ignore */ }

        Nick = nick;
        _ackedCaps.Clear();
        SetState(ConnectionState.Connecting);
        OAuthLog.Write($"IrcClient.ConnectAsync: url={url} nick={nick} hasSasl={!string.IsNullOrEmpty(_saslToken)}");

        _cts = new CancellationTokenSource();
        _ws = new ClientWebSocket();
        // No subprotocol — matches the web app's plain WebSocket connection

        try
        {
            await _ws.ConnectAsync(new Uri(url), _cts.Token);
            OAuthLog.Write("WebSocket connected");
            SetState(ConnectionState.Connected);

            _ = Task.Run(() => ReceiveLoop(_cts.Token));
            _ = Task.Run(() => SendLoop(_cts.Token));

            // IRC registration — same sequence as freeq-app client.ts
            Send("CAP LS 302");
            if (!string.IsNullOrEmpty(password))
                Send($"PASS {password}");
            Send($"NICK {nick}");
            Send($"USER {nick} 0 * :freeq desktop app");
            OAuthLog.Write("IRC registration commands sent");
        }
        catch (Exception ex)
        {
            OAuthLog.Write($"ConnectAsync failed: {ex.Message}");
            ErrorReceived?.Invoke($"Connection failed: {ex.Message}");
            SetState(ConnectionState.Disconnected);
        }
    }

    public void Send(string raw)
    {
        _sendQueue.Enqueue(raw);
    }

    public void SendMessage(string target, string message)
    {
        Send($"PRIVMSG {target} :{message}");
    }

    /// <summary>Request the server channel list (triggers ListEntryReceived / ListEndReceived).</summary>
    public void RequestList() => Send("LIST");

    /// <summary>Set the topic for a channel.</summary>
    public void SetTopic(string channel, string topic) => Send($"TOPIC {channel} :{topic}");

    /// <summary>Request pinned messages for a channel (triggers PinEntryReceived).</summary>
    public void RequestPins(string channel) => Send($"PINS {channel}");

    /// <summary>Send a message edit. The server patches the original message in history.</summary>
    public void SendEditMessage(string target, string originalMsgId, string newContent)
    {
        Send($"@+draft/edit={originalMsgId} PRIVMSG {target} :{newContent}");
    }

    /// <summary>Soft-delete a message by msgid via TAGMSG.</summary>
    public void SendDeleteMessage(string target, string msgId)
    {
        Send($"@+draft/delete={msgId} TAGMSG {target} :");
    }

    /// <summary>Send typing indicator to a channel. active=true while typing, false when done.</summary>
    public void SendTyping(string channel, bool active)
    {
        Send($"@+typing={(active ? "active" : "done")} TAGMSG {channel} :");
    }

    public void JoinChannel(string channel)
    {
        Send($"JOIN {channel}");
    }

    public void PartChannel(string channel, string? reason = null)
    {
        Send(reason != null ? $"PART {channel} :{reason}" : $"PART {channel}");
    }

    public void Disconnect()
    {
        _saslToken = null;
        _saslDid = null;
        _saslPdsUrl = null;
        _saslMethod = null;
        Did = null;
        _ackedCaps.Clear();
        _accounts.Clear();
        _actorClasses.Clear();
        _presence.Clear();
        _motdLines.Clear();
        _cts?.Cancel();
        _ws?.Dispose();
        _ws = null;
        SetState(ConnectionState.Disconnected);
    }

    private void SetState(ConnectionState state)
    {
        OAuthLog.Write($"IrcClient state: {state}");
        State = state;
        StateChanged?.Invoke(state);
    }

    private async Task SendLoop(CancellationToken ct)
    {
        OAuthLog.Write("SendLoop started");
        try
        {
            while (!ct.IsCancellationRequested && _ws?.State == WebSocketState.Open)
            {
                if (_sendQueue.TryDequeue(out var msg))
                {
                    OAuthLog.Write($"SEND: {msg}");
                    var bytes = Encoding.UTF8.GetBytes(msg + "\r\n");
                    await _ws.SendAsync(bytes, WebSocketMessageType.Text, true, ct);
                }
                else
                {
                    await Task.Delay(10, ct);
                }
            }
            OAuthLog.Write($"SendLoop exited: cancelled={ct.IsCancellationRequested} wsState={_ws?.State}");
        }
        catch (Exception ex)
        {
            OAuthLog.Write($"SendLoop exception: {ex.Message}");
        }
    }

    private async Task ReceiveLoop(CancellationToken ct)
    {
        OAuthLog.Write("ReceiveLoop started");
        var buffer = new byte[8192];
        var sb = new StringBuilder();

        while (!ct.IsCancellationRequested && _ws?.State == WebSocketState.Open)
        {
            try
            {
                var result = await _ws.ReceiveAsync(buffer, ct);
                OAuthLog.Write($"ReceiveLoop: got {result.Count} bytes, type={result.MessageType}");
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    OAuthLog.Write("ReceiveLoop: server closed connection");
                    SetState(ConnectionState.Disconnected);
                    return;
                }

                sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));

                // Process complete lines — handle both \r\n-terminated and
                // bare WebSocket messages (server may send one IRC line per WS message
                // without \r\n terminators)
                if (result.EndOfMessage)
                {
                    var text = sb.ToString();
                    sb.Clear();

                    var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        OAuthLog.Write($"RECV: {line}");
                        ProcessLine(line);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                OAuthLog.Write("ReceiveLoop: cancelled");
                break;
            }
            catch (Exception ex)
            {
                OAuthLog.Write($"ReceiveLoop exception: {ex.Message}");
                ErrorReceived?.Invoke($"Receive error: {ex.Message}");
                SetState(ConnectionState.Disconnected);
                break;
            }
        }
        OAuthLog.Write($"ReceiveLoop exited: cancelled={ct.IsCancellationRequested} wsState={_ws?.State}");
    }

    internal void ProcessLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;

        RawReceived?.Invoke(line);
        var msg = ParseIrcMessage(line);

        switch (msg.Command)
        {
            case "PING":
                Send($"PONG :{(msg.Params.Length > 0 ? msg.Params[0] : "")}");
                break;

            case "001": // RPL_WELCOME
                OAuthLog.Write($"001 RPL_WELCOME: nick={msg.Params.FirstOrDefault()}");
                if (msg.Params.Length >= 1)
                    Nick = msg.Params[0];
                SetState(ConnectionState.Authenticated);
                break;

            case "PRIVMSG":
                HandlePrivmsg(msg);
                break;

            case "TAGMSG":
                HandleTagMsg(msg);
                break;

            case "JOIN":
                if (msg.Params.Length >= 1)
                {
                    var nick = msg.Prefix?.Split('!')[0] ?? "unknown";
                    // extended-join: JOIN #channel account :realname
                    if (msg.Params.Length >= 2 && msg.Params[1] != "*")
                    {
                        _accounts[nick] = msg.Params[1];
                        AccountChanged?.Invoke(nick, msg.Params[1]);
                    }
                    // A joiner's class rides the JOIN as a tag (674 only covers
                    // members already there). Recorded before JoinReceived so the
                    // member list built for the join already badges it.
                    if (msg.Tags.TryGetValue("+freeq.at/actor-class", out var joinClass)
                        || msg.Tags.TryGetValue("freeq.at/actor-class", out joinClass))
                        SetActorClass(nick, joinClass);
                    JoinReceived?.Invoke(msg.Params[0], nick);
                }
                break;

            case "ACCOUNT":
            {
                // account-notify: :nick!user@host ACCOUNT accountname (* = logged out)
                var aNick = msg.Prefix?.Split('!')[0] ?? "";
                if (!string.IsNullOrEmpty(aNick))
                {
                    var account = msg.Params.Length >= 1 ? msg.Params[0] : "*";
                    if (account == "*")
                    {
                        _accounts.TryRemove(aNick, out _);
                        AccountChanged?.Invoke(aNick, null);
                    }
                    else
                    {
                        _accounts[aNick] = account;
                        AccountChanged?.Invoke(aNick, account);
                    }
                }
                break;
            }

            case "PART":
                if (msg.Params.Length >= 1)
                {
                    var nick = msg.Prefix?.Split('!')[0] ?? "unknown";
                    var reason = msg.Params.Length >= 2 ? msg.Params[1] : "";
                    PartReceived?.Invoke(msg.Params[0], nick, reason);
                }
                break;

            case "QUIT":
            {
                var nick = msg.Prefix?.Split('!')[0] ?? "unknown";
                var reason = msg.Params.Length >= 1 ? msg.Params[0] : "";
                // Gone from the network: a person reusing the nick is not this agent.
                _actorClasses.TryRemove(nick, out _);
                _presence.TryRemove(nick, out _);
                QuitReceived?.Invoke(nick, reason);
                break;
            }

            case "322": // RPL_LIST: <client> <channel> <count> :<topic>
                if (msg.Params.Length >= 3)
                {
                    var listTopic = msg.Params.Length >= 4 ? msg.Params[3] : "";
                    _ = int.TryParse(msg.Params[2], out var listCount);
                    ListEntryReceived?.Invoke(msg.Params[1], listCount, listTopic);
                }
                break;

            case "323": // RPL_LISTEND
                ListEndReceived?.Invoke();
                break;

            case "NOTICE":
                HandleNotice(msg);
                break;

            case "AWAY":
            {
                // away-notify: :nick!user@host AWAY [:reason]
                var awayNick = msg.Prefix?.Split('!')[0] ?? "";
                if (!string.IsNullOrWhiteSpace(awayNick))
                {
                    var awayMessage = msg.Params.Length >= 1 ? msg.Params[0] : null;
                    AwayChanged?.Invoke(awayNick, !string.IsNullOrWhiteSpace(awayMessage), awayMessage);
                }
                break;
            }

            case "PRESENCE":
            {
                // Structured agent presence: :nick!u@h PRESENCE :state=…;status=…;task=…
                // Unlike AWAY it carries a status for every state, including the
                // active ones where "back from away" is parameterless.
                var pNick = msg.Prefix?.Split('!')[0] ?? "";
                if (!string.IsNullOrEmpty(pNick) && msg.Params.Length >= 1
                    && ParsePresence(msg.Params[^1]) is { } presence)
                {
                    _presence[pNick] = presence;
                    // Only agents publish presence, so it also proves the class.
                    _actorClasses.TryAdd(pNick, "agent");
                    ActorInfoChanged?.Invoke(pNick);
                }
                break;
            }

            case "674": // freeq RPL_ACTORCLASSES: <me> <channel> :nick=agent nick2=external_agent …
                if (msg.Params.Length >= 3)
                {
                    foreach (var entry in msg.Params[2].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var eq = entry.LastIndexOf('=');
                        if (eq <= 0 || eq == entry.Length - 1) continue;
                        SetActorClass(entry[..eq], entry[(eq + 1)..]);
                    }
                    ActorInfoChanged?.Invoke("*");
                }
                break;

            case "673": // freeq WHOIS actor class: <me> <nick> :actor_class=agent
                if (msg.Params.Length >= 3 && msg.Params[2].StartsWith("actor_class=", StringComparison.Ordinal))
                {
                    if (SetActorClass(msg.Params[1], msg.Params[2]["actor_class=".Length..]))
                        ActorInfoChanged?.Invoke(msg.Params[1]);
                }
                break;

            case "332": // RPL_TOPIC
                if (msg.Params.Length >= 3)
                    TopicReceived?.Invoke(msg.Params[1], msg.Params[2]);
                break;

            case "TOPIC":
                if (msg.Params.Length >= 2)
                    TopicReceived?.Invoke(msg.Params[0], msg.Params[1]);
                break;

            case "353": // RPL_NAMREPLY
                if (msg.Params.Length >= 4)
                {
                    var nicks = msg.Params[3].Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                    NamesReceived?.Invoke(msg.Params[2], nicks);
                }
                break;

            case "352": // RPL_WHOREPLY: <client> <channel> <user> <host> <server> <nick> <flags> :<hopcount> <realname>
                if (msg.Params.Length >= 7)
                {
                    var whoNick = msg.Params[5];
                    // Check host for freeq DID cloaking: freeq/plc/xxxxx or account from extended info
                    var whoHost = msg.Params[3];
                    if (whoHost.StartsWith("freeq/plc/", StringComparison.OrdinalIgnoreCase) ||
                        whoHost.StartsWith("freeq/web/", StringComparison.OrdinalIgnoreCase))
                    {
                        // User has a DID-based cloak — mark as verified
                        if (!_accounts.ContainsKey(whoNick))
                        {
                            _accounts[whoNick] = whoHost; // Use cloak as identifier
                            AccountChanged?.Invoke(whoNick, whoHost);
                        }
                    }
                }
                break;

            case "315": // RPL_ENDOFWHO
                // Refresh member list to pick up newly discovered accounts
                AccountChanged?.Invoke("*", null); // Signal refresh
                break;

            case "305": // RPL_UNAWAY
                SelfAwayStateChanged?.Invoke(false, null);
                break;

            case "306": // RPL_NOWAWAY
                SelfAwayStateChanged?.Invoke(true, null);
                break;

            case "366": // RPL_ENDOFNAMES — send WHO to discover accounts, request history
                if (msg.Params.Length >= 2)
                {
                    Send($"WHO {msg.Params[1]}");
                    if (_ackedCaps.Contains("draft/chathistory"))
                        Send($"CHATHISTORY LATEST {msg.Params[1]} * 50");
                }
                break;

            case "NICK":
            {
                var oldNick = msg.Prefix?.Split('!')[0] ?? "";
                var newNick = msg.Params.Length >= 1 ? msg.Params[0] : "";
                // Transfer account mapping to new nick
                if (_accounts.TryRemove(oldNick, out var acct))
                    _accounts[newNick] = acct;
                // …and the actor class and presence: a renamed agent is still an agent.
                if (_actorClasses.TryRemove(oldNick, out var cls))
                    _actorClasses[newNick] = cls;
                if (_presence.TryRemove(oldNick, out var pres))
                    _presence[newNick] = pres;
                NickChanged?.Invoke(oldNick, newNick);
                if (oldNick.Equals(Nick, StringComparison.OrdinalIgnoreCase))
                    Nick = newNick;
                break;
            }

            case "CAP":
                HandleCap(msg);
                break;

            case "AUTHENTICATE":
                HandleAuthenticate(msg);
                break;

            case "900": // RPL_LOGGEDIN
                if (msg.Params.Length >= 3)
                {
                    Did = msg.Params[2]; // account name (DID)
                    _accounts[Nick] = Did;
                }
                break;

            case "903": // SASL success
                OAuthLog.Write("903 SASL SUCCESS");
                Send("CAP END");
                break;

            case "904": // SASL failure
                OAuthLog.Write("904 SASL FAILURE");
                Send("CAP END");
                ErrorReceived?.Invoke("SASL authentication failed");
                break;

            case "375": // RPL_MOTDSTART
                _motdLines.Clear();
                break;

            case "372": // RPL_MOTD
                if (msg.Params.Length >= 2)
                {
                    var motdLine = msg.Params[1].TrimStart('-', ' ');
                    if (!string.IsNullOrWhiteSpace(motdLine))
                        _motdLines.Add(motdLine);
                }
                break;

            case "376": // RPL_ENDOFMOTD
            case "422": // ERR_NOMOTD
                if (_motdLines.Count > 0)
                    MotdReceived?.Invoke(string.Join("\n", _motdLines));
                _motdLines.Clear();
                break;
        }
    }

    private void HandlePrivmsg(IrcMessage msg)
    {
        if (msg.Params.Length < 2) return;

        var nick = msg.Prefix?.Split('!')[0] ?? "unknown";

        // When echo-message is acked, let server echoes through — they carry the real msgid.
        // When echo-message is not acked, drop self-messages.
        if (!_ackedCaps.Contains("echo-message") && nick.Equals(Nick, StringComparison.OrdinalIgnoreCase))
            return;

        var msgid = msg.Tags.TryGetValue("msgid", out var mid) ? mid : null;
        DateTimeOffset? serverTime = msg.Tags.TryGetValue("time", out var timeStr)
            && DateTimeOffset.TryParse(timeStr, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dto)
            ? dto : null;

        // Message edit: PRIVMSG with +draft/edit tag carries the original message ID
        if (msg.Tags.TryGetValue("+draft/edit", out var editOriginalMsgId))
        {
            MessageEdited?.Invoke(msg.Params[0], editOriginalMsgId, msg.Params[1], serverTime);
            return;
        }

        MessageReceived?.Invoke(msg.Params[0], nick, msg.Params[1], msgid, serverTime);
    }

    private void HandleTagMsg(IrcMessage msg)
    {
        if (msg.Params.Length < 1) return;

        var target = msg.Params[0];
        var nick = msg.Prefix?.Split('!')[0] ?? "unknown";

        // Typing indicator: @+typing=active TAGMSG #channel :
        if (msg.Tags.TryGetValue("+typing", out var typingVal))
        {
            bool isTyping = typingVal is "active" or "paused";
            TypingChanged?.Invoke(target, nick, isTyping);
        }

        // Message deletion: @+draft/delete=<msgid> TAGMSG #channel :
        if (msg.Tags.TryGetValue("+draft/delete", out var deleteMsgId))
        {
            MessageDeleted?.Invoke(target, deleteMsgId);
        }

        // Reactions: @+react=<emoji>[;+reply=<msgid>] TAGMSG <target> :
        if (msg.Tags.TryGetValue("+react", out var emoji))
        {
            msg.Tags.TryGetValue("+reply", out var targetMsgId);
            ReactionReceived?.Invoke(target, nick, emoji, targetMsgId);
        }
    }

    private void HandleNotice(IrcMessage msg)
    {
        // PINS response: NOTICE <nick> :PIN <channel> <msgid> <pinned_by> <pinned_at>
        if (msg.Params.Length < 2) return;
        var body = msg.Params[1];
        if (body.StartsWith("PIN ", StringComparison.Ordinal))
        {
            var parts = body.Split(' ', 5);
            // parts: ["PIN", "#channel", "<msgid>", "<pinned_by>", "<pinned_at>"]
            if (parts.Length >= 5
                && long.TryParse(parts[4], out var pinnedAt))
            {
                PinEntryReceived?.Invoke(parts[1], parts[2], parts[3], pinnedAt);
            }
        }
    }

    private void HandleCap(IrcMessage msg)
    {
        if (msg.Params.Length < 2) return;

        var subcommand = msg.Params[1].ToUpperInvariant();
        OAuthLog.Write($"CAP {subcommand}: params=[{string.Join(", ", msg.Params)}]");

        if (subcommand == "LS")
        {
            var available = string.Join(" ", msg.Params.Skip(2));
            var requested = new List<string>();

            foreach (var cap in WantedCaps)
            {
                if (available.Contains(cap))
                    requested.Add(cap);
            }

            // Add sasl only if we have a token AND server supports it
            if (!string.IsNullOrEmpty(_saslToken) && available.Contains("sasl"))
                requested.Add("sasl");

            OAuthLog.Write($"CAP REQ: [{string.Join(", ", requested)}] (saslToken={!string.IsNullOrEmpty(_saslToken)}, serverHasSasl={available.Contains("sasl")})");

            if (requested.Count > 0)
                Send($"CAP REQ :{string.Join(" ", requested)}");
            else
                Send("CAP END");
        }
        else if (subcommand == "ACK")
        {
            if (msg.Params.Length >= 3)
            {
                var acked = msg.Params[^1].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var cap in acked)
                    _ackedCaps.Add(cap);
            }

            OAuthLog.Write($"CAP ACK caps: [{string.Join(", ", _ackedCaps)}]");

            // Start SASL if we have both capability and token
            if (_ackedCaps.Contains("sasl") && !string.IsNullOrEmpty(_saslToken))
            {
                OAuthLog.Write("Starting SASL ATPROTO-CHALLENGE");
                SetState(ConnectionState.Authenticating);
                Send("AUTHENTICATE ATPROTO-CHALLENGE");
            }
            else
            {
                OAuthLog.Write("No SASL — sending CAP END");
                Send("CAP END");
            }
        }
        else if (subcommand == "NAK")
        {
            OAuthLog.Write("CAP NAK — sending CAP END");
            Send("CAP END");
        }
    }

    private void HandleAuthenticate(IrcMessage msg)
    {
        var param = msg.Params.Length > 0 ? msg.Params[0] : "";
        OAuthLog.Write($"AUTHENTICATE received: param length={param.Length}, starts with={param[..Math.Min(param.Length, 20)]}");
        if (param == "+" || string.IsNullOrEmpty(param))
        {
            OAuthLog.Write("AUTHENTICATE '+' or empty — ignoring");
            return;
        }

        // Server sent challenge — respond with our credentials
        // Build JSON payload matching freeq-app client.ts
        var payload = System.Text.Json.JsonSerializer.Serialize(new
        {
            did = _saslDid ?? "",
            method = _saslMethod ?? "pds-session",
            signature = _saslToken ?? "",
            pds_url = _saslPdsUrl ?? "",
        });

        // Base64url encode (unpadded)
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        // Send in 400-byte chunks if needed
        if (encoded.Length <= 400)
        {
            Send($"AUTHENTICATE {encoded}");
        }
        else
        {
            for (int i = 0; i < encoded.Length; i += 400)
            {
                var chunk = encoded.Substring(i, Math.Min(400, encoded.Length - i));
                Send($"AUTHENTICATE {chunk}");
            }
            Send("AUTHENTICATE +");
        }
    }

    internal static IrcMessage ParseIrcMessage(string line)
    {
        var tags = new Dictionary<string, string>();
        var pos = 0;

        // Parse tags
        if (line.StartsWith('@'))
        {
            var spaceIdx = line.IndexOf(' ');
            if (spaceIdx < 0) return new IrcMessage(null, line, [], tags);
            var tagStr = line[1..spaceIdx];
            foreach (var tag in tagStr.Split(';'))
            {
                var eqIdx = tag.IndexOf('=');
                if (eqIdx >= 0)
                    tags[tag[..eqIdx]] = tag[(eqIdx + 1)..];
                else
                    tags[tag] = "";
            }
            pos = spaceIdx + 1;
        }

        while (pos < line.Length && line[pos] == ' ') pos++;

        // Parse prefix
        string? prefix = null;
        if (pos < line.Length && line[pos] == ':')
        {
            var spaceIdx = line.IndexOf(' ', pos);
            if (spaceIdx < 0) return new IrcMessage(line[(pos + 1)..], "", [], tags);
            prefix = line[(pos + 1)..spaceIdx];
            pos = spaceIdx + 1;
        }

        while (pos < line.Length && line[pos] == ' ') pos++;

        // Parse command
        var cmdEnd = line.IndexOf(' ', pos);
        string command;
        if (cmdEnd < 0)
        {
            command = line[pos..];
            return new IrcMessage(prefix, command, [], tags);
        }
        command = line[pos..cmdEnd];
        pos = cmdEnd + 1;

        // Parse params
        var parms = new List<string>();
        while (pos < line.Length)
        {
            while (pos < line.Length && line[pos] == ' ') pos++;
            if (pos >= line.Length) break;

            if (line[pos] == ':')
            {
                parms.Add(line[(pos + 1)..]);
                break;
            }

            var nextSpace = line.IndexOf(' ', pos);
            if (nextSpace < 0)
            {
                parms.Add(line[pos..]);
                break;
            }
            parms.Add(line[pos..nextSpace]);
            pos = nextSpace + 1;
        }

        return new IrcMessage(prefix, command, [.. parms], tags);
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _ws?.Dispose();
        GC.SuppressFinalize(this);
    }
}
