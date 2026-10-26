using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Freeq.Windows.Services;

/// <summary>
/// Persistent settings stored at %LOCALAPPDATA%\Freeq\settings.json.
/// </summary>
public class AppSettings
{
    private static readonly string SettingsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Freeq");
    private static readonly string SettingsPath = Path.Combine(SettingsDir, "settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    [JsonPropertyName("server_address")]
    public string ServerAddress { get; set; } = "irc.freeq.at:6697";

    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    [JsonPropertyName("channels")]
    public string Channels { get; set; } = "#lobby";

    [JsonPropertyName("broker_token")]
    public string? BrokerToken { get; set; }

    [JsonPropertyName("broker_base")]
    public string BrokerBase { get; set; } = "https://auth.freeq.at";

    [JsonPropertyName("use_tls")]
    public bool UseTls { get; set; } = true;

    [JsonPropertyName("window_left")]
    public double? WindowLeft { get; set; }

    [JsonPropertyName("window_top")]
    public double? WindowTop { get; set; }

    [JsonPropertyName("window_width")]
    public double? WindowWidth { get; set; }

    [JsonPropertyName("window_height")]
    public double? WindowHeight { get; set; }

    [JsonPropertyName("login_mode")]
    public string LoginMode { get; set; } = "guest";

    /// Join/part/quit lines: "hidden" (default), "grouped" or "all".
    /// Kicks and moderation always show.
    [JsonPropertyName("join_part")]
    public string JoinPart { get; set; } = "hidden";

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            }
        }
        catch { /* ignore corrupt settings */ }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch { /* ignore write errors */ }
    }
}
