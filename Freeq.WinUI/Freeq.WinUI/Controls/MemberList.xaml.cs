using Freeq.WinUI.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace Freeq.WinUI.Controls;

public sealed partial class MemberList : UserControl
{
    private MainViewModel? _vm;

    public MemberList()
    {
        InitializeComponent();
    }

    public void Bind(MainViewModel vm)
    {
        _vm = vm;
        OpsList.ItemsSource = vm.Operators;
        VoicedList.ItemsSource = vm.Voiced;
        MembersList.ItemsSource = vm.Members;
        AgentsList.ItemsSource = vm.Agents;

        vm.Operators.CollectionChanged += (s, e) =>
        {
            OpsSection.Visibility = vm.Operators.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            OpsHeader.Text = $"OPERATORS — {vm.Operators.Count}";
        };

        vm.Voiced.CollectionChanged += (s, e) =>
        {
            VoicedSection.Visibility = vm.Voiced.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            VoicedHeader.Text = $"VOICED — {vm.Voiced.Count}";
        };

        vm.Members.CollectionChanged += (s, e) =>
        {
            MembersHeader.Text = $"MEMBERS — {vm.Members.Count}";
        };

        vm.Agents.CollectionChanged += (s, e) =>
        {
            AgentsSection.Visibility = vm.Agents.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            AgentsHeader.Text = $"AGENTS — {vm.Agents.Count}";
        };
    }

    private async void OnMemberClick(object sender, ItemClickEventArgs e)
    {
        if (_vm == null || e.ClickedItem is not Models.MemberModel member) return;

        var profile = _vm.GetUserProfile(member.Nick);
        var panel = new StackPanel { Spacing = 6, MinWidth = 220 };
        panel.Children.Add(new TextBlock { Text = profile.Nick, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, FontSize = 14 });
        if (profile.ActorLabel is { } actorLabel)
            panel.Children.Add(new TextBlock { Text = actorLabel, FontSize = 12, Foreground = ThemeBrush("BlueBrush") });

        // Status: "Working" for an agent at work (never "Away"), "Away: …" for a person.
        panel.Children.Add(new TextBlock
        {
            Text = profile.StatusText,
            TextWrapping = TextWrapping.Wrap,
            Foreground = ThemeBrush(
                profile.IsAgent && !Models.AgentStatus.ShowsAway(true, profile.PresenceState, profile.AwayMessage, profile.IsAway)
                    ? "BlueBrush"
                    : profile.IsAway ? "WarningBrush" : "SuccessBrush"),
        });
        if (profile.Agent is { } agent)
            panel.Children.Add(BuildActivity(agent));
        panel.Children.Add(new TextBlock { Text = $"DID: {profile.DisplayDid}", TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = $"Bluesky: {profile.DisplayHandle}", TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = $"Safety number: {_vm.GetSafetyNumber(profile.Nick)}", TextWrapping = TextWrapping.Wrap });

        var openBtn = new Button { Content = "Open on Bluesky", HorizontalAlignment = HorizontalAlignment.Left };
        openBtn.Click += async (_, _) =>
        {
            var id = string.IsNullOrWhiteSpace(profile.BlueskyHandle) ? profile.Did : profile.BlueskyHandle;
            if (!string.IsNullOrWhiteSpace(id))
                await Launcher.LaunchUriAsync(new Uri($"https://bsky.app/profile/{id}"));
        };
        panel.Children.Add(openBtn);

        if (profile.CanModerate)
        {
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
            var opBtn = new Button { Content = "Op" };
            var deopBtn = new Button { Content = "Deop" };
            var voiceBtn = new Button { Content = "Voice" };
            var devoBtn = new Button { Content = "Devoice" };
            opBtn.Click += (_, _) => _vm.SetMemberOperator(member.Nick, true);
            deopBtn.Click += (_, _) => _vm.SetMemberOperator(member.Nick, false);
            voiceBtn.Click += (_, _) => _vm.SetMemberVoice(member.Nick, true);
            devoBtn.Click += (_, _) => _vm.SetMemberVoice(member.Nick, false);
            actions.Children.Add(opBtn);
            actions.Children.Add(deopBtn);
            actions.Children.Add(voiceBtn);
            actions.Children.Add(devoBtn);
            panel.Children.Add(actions);
        }

        var dialog = new ContentDialog
        {
            Title = "User Profile",
            PrimaryButtonText = "Close",
            XamlRoot = this.XamlRoot,
            Content = panel,
        };

        await dialog.ShowAsync();
    }

    /// <summary>
    /// What an agent is doing, as a sentence, then where — wrapped, never cut
    /// off, each value selectable so a long branch can be copied.
    /// </summary>
    private static UIElement BuildActivity(Models.AgentStatus agent)
    {
        var card = new StackPanel { Spacing = 4 };
        card.Children.Add(new TextBlock
        {
            Text = "ACTIVITY",
            FontSize = 10,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            CharacterSpacing = 120,
            Foreground = ThemeBrush("FgDimBrush"),
        });
        if (agent.Doing is { } doing)
            card.Children.Add(new TextBlock { Text = doing, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });

        var facts = agent.Facts;
        if (facts.Count > 0)
        {
            var grid = new Grid { ColumnSpacing = 10, RowSpacing = 2 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            for (var i = 0; i < facts.Count; i++)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var label = new TextBlock { Text = facts[i].Label, FontSize = 12, Foreground = ThemeBrush("FgDimBrush") };
                var value = new TextBlock
                {
                    Text = facts[i].Value,
                    FontSize = 12,
                    FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                };
                Grid.SetRow(label, i);
                Grid.SetRow(value, i);
                Grid.SetColumn(value, 1);
                grid.Children.Add(label);
                grid.Children.Add(value);
            }
            card.Children.Add(grid);
        }

        return new Border
        {
            Padding = new Thickness(10),
            CornerRadius = new CornerRadius(8),
            Background = ThemeBrush("BlueDimBrush"),
            Child = card,
        };
    }

    private static Microsoft.UI.Xaml.Media.Brush ThemeBrush(string key)
    {
        try
        {
            if (Application.Current.Resources[key] is Microsoft.UI.Xaml.Media.Brush brush) return brush;
        }
        catch { /* missing key */ }
        return new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public static Visibility BoolToVis(bool value) =>
        value ? Visibility.Visible : Visibility.Collapsed;

    public static Visibility AwayToVisibility(Models.PresenceStatus status) =>
        status == Models.PresenceStatus.Away ? Visibility.Visible : Visibility.Collapsed;
}
