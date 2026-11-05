namespace Freeq.WinUI.Models;

public enum ThemeMode
{
    System,
    Dark,
    Light,
}

public enum MessageDensity
{
    Cozy,
    Default,
    Compact,
}

/// How join/part lines are shown. Kicks and moderation always show.
public enum JoinPartDisplay
{
    Hidden,
    Grouped,
    All,
}
