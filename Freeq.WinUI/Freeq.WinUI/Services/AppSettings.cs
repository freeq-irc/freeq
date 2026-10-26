using System.Text.Json;
using Freeq.WinUI.Models;

namespace Freeq.WinUI.Services;

/// <summary>
/// Persists user preferences to %LOCALAPPDATA%\Freeq\settings.json.
/// </summary>
public class AppSettings
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Freeq", "settings.json");

    private SettingsData _data = new();

    public AppSettings()
    {
        Load();
    }

    public HashSet<string> MutedChannels => _data.MutedChannels;
    public string ThemeMode
    {
        get => _data.ThemeMode;
        set => _data.ThemeMode = value;
    }

    public string MessageDensity
    {
        get => _data.MessageDensity;
        set => _data.MessageDensity = value;
    }

    public string JoinPartDisplay
    {
        get => _data.JoinPartDisplay;
        set => _data.JoinPartDisplay = value;
    }

    public bool AutoLoadExternalMedia
    {
        get => _data.AutoLoadExternalMedia;
        set => _data.AutoLoadExternalMedia = value;
    }

    public bool EnableWindowsNotifications
    {
        get => _data.EnableWindowsNotifications;
        set => _data.EnableWindowsNotifications = value;
    }

    public bool EnableNotificationSounds
    {
        get => _data.EnableNotificationSounds;
        set => _data.EnableNotificationSounds = value;
    }

    public string? ApiBearerToken
    {
        get => _data.ApiBearerToken;
        set => _data.ApiBearerToken = value;
    }

    public List<BookmarkEntry> Bookmarks
    {
        get => _data.Bookmarks;
        set => _data.Bookmarks = value;
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(_data, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            OAuthLog.Write($"AppSettings.Save failed: {ex.Message}");
        }
    }

    private void Load()
    {
        if (!File.Exists(FilePath)) return;
        try
        {
            var json = File.ReadAllText(FilePath);
            _data = JsonSerializer.Deserialize<SettingsData>(json) ?? new();
        }
        catch (Exception ex)
        {
            OAuthLog.Write($"AppSettings.Load failed: {ex.Message}");
        }
    }

    private class SettingsData
    {
        public HashSet<string> MutedChannels { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public string ThemeMode { get; set; } = "System";
        public string MessageDensity { get; set; } = "Default";
        public string JoinPartDisplay { get; set; } = "Hidden";
        public bool AutoLoadExternalMedia { get; set; } = true;
        public bool EnableWindowsNotifications { get; set; } = true;
        public bool EnableNotificationSounds { get; set; } = false;
        public string? ApiBearerToken { get; set; }
        public List<BookmarkEntry> Bookmarks { get; set; } = [];
    }
}
