using System;
using System.Linq;
using Freeq.WinUI.Models;
using Freeq.WinUI.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Freeq.WinUI.Controls;

public sealed partial class TopBar : UserControl
{
    public MainViewModel? ViewModel { get; set; }
    public event Action? MemberListToggled;

    public TopBar()
    {
        InitializeComponent();
    }

    public void Bind(MainViewModel vm)
    {
        ViewModel = vm;
        vm.PropertyChanged += (s, e) =>
        {
            switch (e.PropertyName)
            {
                case nameof(MainViewModel.SelectedChannel):
                    UpdateChannel(vm.SelectedChannel);
                    break;
                case nameof(MainViewModel.CurrentTopic):
                    TopicText.Text = vm.CurrentTopic;
                    break;
                case nameof(MainViewModel.IsChannelEncrypted):
                case nameof(MainViewModel.SelectedChannelSafetyText):
                    E2eeIndicatorText.Text = vm.IsChannelEncrypted ? $"🔒 {vm.SelectedChannelSafetyText}" : "";
                    break;
            }
        };

        vm.Operators.CollectionChanged += (s, e) => UpdateMemberCount();
        vm.Voiced.CollectionChanged += (s, e) => UpdateMemberCount();
        vm.Members.CollectionChanged += (s, e) => UpdateMemberCount();
    }

    private void UpdateChannel(ChannelModel? channel)
    {
        if (channel == null)
        {
            ChannelName.Text = "";
            TopicText.Text = "";
            ChannelIcon.Text = "";
            return;
        }

        ChannelIcon.Text = channel.Kind == ChannelKind.DirectMessage ? "\U0001F4AC" : "#";
        ChannelName.Text = channel.DisplayName;
        TopicText.Text = channel.Topic;
        E2eeIndicatorText.Text = ViewModel?.IsChannelEncrypted == true ? $"🔒 {ViewModel.SelectedChannelSafetyText}" : "";
    }

    private void UpdateMemberCount()
    {
        if (ViewModel == null) return;
        MemberCountText.Text = ViewModel.TotalMemberCount.ToString();
    }

    private void OnMemberToggleClick(object sender, RoutedEventArgs e)
    {
        MemberListToggled?.Invoke();
    }

    private async void OnTopicClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedChannel == null) return;

        var input = new TextBox
        {
            Text = ViewModel.CurrentTopic,
            PlaceholderText = "Channel topic",
            Width = 400,
        };

        var dialog = new ContentDialog
        {
            Title = $"Set Topic for {ViewModel.SelectedChannel.Name}",
            PrimaryButtonText = "Set",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = this.XamlRoot,
            Content = input,
        };

        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
            ViewModel.SetTopicCommand.Execute(input.Text);
    }

    private async void OnPinsClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedChannel == null) return;

        // Clear previous results and request fresh pins from server
        ViewModel.RequestPinsCommand.Execute(null);

        // Give the server a moment to respond before showing the dialog
        await Task.Delay(300);

        var listView = new ListView
        {
            ItemsSource = ViewModel.PinnedMessages,
            MinHeight = 80,
            MaxHeight = 400,
        };
        listView.ItemTemplate = BuildPinTemplate();

        var emptyHint = new TextBlock
        {
            Text = "No pinned messages.",
            Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray),
            Visibility = ViewModel.PinnedMessages.Count == 0 ? Visibility.Visible : Visibility.Collapsed,
        };
        ViewModel.PinnedMessages.CollectionChanged += (_, _) =>
        {
            emptyHint.Visibility = ViewModel.PinnedMessages.Count == 0
                ? Visibility.Visible : Visibility.Collapsed;
        };

        var panel = new StackPanel { Spacing = 4 };
        panel.Children.Add(emptyHint);
        panel.Children.Add(listView);

        var dialog = new ContentDialog
        {
            Title = $"Pinned Messages — {ViewModel.SelectedChannel.Name}",
            CloseButtonText = "Close",
            XamlRoot = this.XamlRoot,
            Content = panel,
        };

        await dialog.ShowAsync();
    }

    private static DataTemplate BuildPinTemplate()
    {
        return (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <StackPanel Padding="4,6" Spacing="2">
                    <TextBlock Text="{Binding Label}" FontWeight="SemiBold" />
                    <TextBlock Text="{Binding PinnedAtDisplay}" Foreground="Gray" FontSize="11" />
                </StackPanel>
            </DataTemplate>
            """);
    }

    private async void OnSettingsClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel == null) return;

        var theme = new ComboBox
        {
            ItemsSource = Enum.GetValues(typeof(ThemeMode)).Cast<ThemeMode>().ToList(),
            SelectedItem = ViewModel.ThemeMode,
            Width = 180,
        };

        var density = new ComboBox
        {
            ItemsSource = Enum.GetValues(typeof(MessageDensity)).Cast<MessageDensity>().ToList(),
            SelectedItem = ViewModel.MessageDensity,
            Width = 180,
        };

        var joinPart = new ComboBox
        {
            Header = "Join & leave messages",
            ItemsSource = Enum.GetValues(typeof(JoinPartDisplay)).Cast<JoinPartDisplay>().ToList(),
            SelectedItem = ViewModel.JoinPartDisplay,
            Width = 180,
        };
        var autoLoadMedia = new ToggleSwitch { Header = "Auto-load external media", IsOn = ViewModel.AutoLoadExternalMedia };
        var windowsToasts = new ToggleSwitch { Header = "Enable Windows notifications", IsOn = ViewModel.EnableWindowsNotifications };
        var sounds = new ToggleSwitch { Header = "Enable notification sounds", IsOn = ViewModel.EnableNotificationSounds };

        var shortcutsHint = new TextBlock
        {
            Text = "Keyboard shortcuts: Ctrl+K quick switch, Ctrl+F search, Ctrl+/ help, Alt+1..0 channel jump.",
            TextWrapping = TextWrapping.Wrap,
            FontSize = 12,
            Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray),
        };

        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(new TextBlock { Text = "Theme" });
        panel.Children.Add(theme);
        panel.Children.Add(new TextBlock { Text = "Message density" });
        panel.Children.Add(density);
        panel.Children.Add(joinPart);
        panel.Children.Add(autoLoadMedia);
        panel.Children.Add(windowsToasts);
        panel.Children.Add(sounds);
        panel.Children.Add(shortcutsHint);

        var dialog = new ContentDialog
        {
            Title = "Settings",
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot,
            Content = panel,
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            ViewModel.UpdatePreferences(
                (ThemeMode)(theme.SelectedItem ?? ThemeMode.System),
                (MessageDensity)(density.SelectedItem ?? MessageDensity.Default),
                (JoinPartDisplay)(joinPart.SelectedItem ?? JoinPartDisplay.Hidden),
                autoLoadMedia.IsOn,
                windowsToasts.IsOn,
                sounds.IsOn);

            ViewModel.ShowToast("Settings updated");
        }
    }

    private async void OnChannelSettingsClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedChannel == null || !ViewModel.SelectedChannel.Name.StartsWith('#')) return;

        ViewModel.RequestPinsCommand.Execute(null);

        var noExternal = new ToggleSwitch { Header = "+n no external messages", IsOn = ViewModel.IsChannelNoExternal };
        var inviteOnly = new ToggleSwitch { Header = "+i invite only", IsOn = ViewModel.IsChannelInviteOnly };
        var topicProtected = new ToggleSwitch { Header = "+t topic set by ops", IsOn = ViewModel.IsChannelTopicProtected };
        var moderated = new ToggleSwitch { Header = "+m moderated", IsOn = ViewModel.IsChannelModerated };
        var encrypted = new ToggleSwitch { Header = "+E encrypted channel", IsOn = ViewModel.IsChannelEncrypted };
        var topicInput = new TextBox { Header = "Topic", Text = ViewModel.CurrentTopic, PlaceholderText = "Set channel topic" };

        var banInput = new TextBox { PlaceholderText = "Add ban mask (nick!*@* or did:plc:...)", Width = 340 };
        var addBan = new Button { Content = "Add ban" };
        addBan.Click += (_, _) =>
        {
            ViewModel.AddBanMask(banInput.Text);
            banInput.Text = "";
        };

        var banList = new ListView { ItemsSource = ViewModel.ChannelBans, MinHeight = 80, MaxHeight = 180 };
        banList.ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <TextBlock Text="{Binding Label}" VerticalAlignment="Center" />
            </DataTemplate>
            """);
        var removeBan = new Button { Content = "Remove selected ban", HorizontalAlignment = HorizontalAlignment.Left };
        removeBan.Click += (_, _) =>
        {
            if (banList.SelectedItem is ChannelMaskEntry entry)
                ViewModel.RemoveBanMask(entry);
        };

        var inviteInput = new TextBox { PlaceholderText = "Add invite mask (did:plc:... or nick)", Width = 340 };
        var addInvite = new Button { Content = "Add invite" };
        addInvite.Click += (_, _) =>
        {
            ViewModel.AddInviteMask(inviteInput.Text);
            inviteInput.Text = "";
        };

        var inviteList = new ListView { ItemsSource = ViewModel.ChannelInvites, MinHeight = 80, MaxHeight = 180 };
        inviteList.ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <TextBlock Text="{Binding Label}" VerticalAlignment="Center" />
            </DataTemplate>
            """);
        var removeInvite = new Button { Content = "Remove selected invite", HorizontalAlignment = HorizontalAlignment.Left };
        removeInvite.Click += (_, _) =>
        {
            if (inviteList.SelectedItem is ChannelMaskEntry entry)
                ViewModel.RemoveInviteMask(entry);
        };

        var panel = new StackPanel { Spacing = 10, MinWidth = 420 };
        panel.Children.Add(noExternal);
        panel.Children.Add(inviteOnly);
        panel.Children.Add(topicProtected);
        panel.Children.Add(moderated);
        panel.Children.Add(encrypted);
        panel.Children.Add(topicInput);
        panel.Children.Add(new TextBlock { Text = "Ban list", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        panel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Children = { banInput, addBan } });
        panel.Children.Add(banList);
        panel.Children.Add(removeBan);
        panel.Children.Add(new TextBlock { Text = "Invite exceptions", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        panel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Children = { inviteInput, addInvite } });
        panel.Children.Add(inviteList);
        panel.Children.Add(removeInvite);

        var dialog = new ContentDialog
        {
            Title = $"Channel Settings — {ViewModel.SelectedChannel.Name}",
            PrimaryButtonText = "Apply",
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot,
            Content = new ScrollViewer { Content = panel, MaxHeight = 620 },
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            if (!string.Equals(topicInput.Text, ViewModel.CurrentTopic, StringComparison.Ordinal))
                ViewModel.SetTopicCommand.Execute(topicInput.Text);
            ViewModel.SetChannelMode('n', noExternal.IsOn);
            ViewModel.SetChannelMode('i', inviteOnly.IsOn);
            ViewModel.SetChannelMode('t', topicProtected.IsOn);
            ViewModel.SetChannelMode('m', moderated.IsOn);
            ViewModel.SetChannelMode('E', encrypted.IsOn);
            ViewModel.ShowToast("Channel settings updated");
        }
    }

    private async void OnAuditClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedChannel == null) return;

        var list = new ListView { ItemsSource = ViewModel.AuditTimeline, MinHeight = 160, MaxHeight = 520 };
        list.ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <StackPanel Padding="4,6" Spacing="2">
                    <TextBlock Text="{Binding Label}" FontWeight="SemiBold" />
                    <TextBlock Text="{Binding Description}" Foreground="Gray" TextWrapping="Wrap" />
                </StackPanel>
            </DataTemplate>
            """);

        var dialog = new ContentDialog
        {
            Title = $"Audit Timeline — {ViewModel.SelectedChannel.Name}",
            CloseButtonText = "Close",
            XamlRoot = XamlRoot,
            Content = list,
        };

        await dialog.ShowAsync();
    }

    private async void OnBookmarksClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel == null) return;

        var list = new ListView { ItemsSource = ViewModel.Bookmarks, MinHeight = 160, MaxHeight = 520 };
        list.ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <StackPanel Padding="4,6" Spacing="2">
                    <TextBlock Text="{Binding Label}" FontWeight="SemiBold" />
                    <TextBlock Text="{Binding Preview}" Foreground="Gray" TextWrapping="Wrap" MaxLines="2" />
                </StackPanel>
            </DataTemplate>
            """);

        var jumpButton = new Button { Content = "Jump to selected", HorizontalAlignment = HorizontalAlignment.Left };
        jumpButton.Click += (_, _) =>
        {
            if (list.SelectedItem is BookmarkEntry bookmark)
                ViewModel.JumpToBookmark(bookmark);
        };

        var removeButton = new Button { Content = "Remove selected", HorizontalAlignment = HorizontalAlignment.Left };
        removeButton.Click += (_, _) =>
        {
            if (list.SelectedItem is BookmarkEntry bookmark)
                ViewModel.RemoveBookmark(bookmark);
        };

        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(list);
        panel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { jumpButton, removeButton } });

        var dialog = new ContentDialog
        {
            Title = "Bookmarks",
            CloseButtonText = "Close",
            XamlRoot = XamlRoot,
            Content = panel,
        };

        await dialog.ShowAsync();
    }
}
