"""Maps executable names to a friendly app name and a category."""

BROWSER = "Browser"
GAME = "Game"
COMMS = "Communication"
SYSTEM = "System"
BACKGROUND = "Background"
DEV = "Development"
MEDIA = "Media"
SECURITY = "Security"
INSTALLED = "Installed app"   # in Program Files etc.: probably legit, but not in our list
UNKNOWN = "Unknown"           # anywhere else (AppData, Temp, user folders): worth a look
PROTECTED = "Protected"       # Windows hides its path from us (often a service): can't vouch for it
WATCHED = (UNKNOWN, PROTECTED)  # categories that get the stricter rules

# exe name (lowercase) -> (display name, category)
KNOWN_APPS = {
    # browsers
    "chrome.exe": ("Google Chrome", BROWSER),
    "firefox.exe": ("Firefox", BROWSER),
    "msedge.exe": ("Microsoft Edge", BROWSER),
    "brave.exe": ("Brave", BROWSER),
    "opera.exe": ("Opera", BROWSER),
    "vivaldi.exe": ("Vivaldi", BROWSER),
    # games & launchers
    "steam.exe": ("Steam", GAME),
    "steamwebhelper.exe": ("Steam", GAME),
    "epicgameslauncher.exe": ("Epic Games Launcher", GAME),
    "eadesktop.exe": ("EA App", GAME),
    "battle.net.exe": ("Battle.net", GAME),
    "riotclientservices.exe": ("Riot Client", GAME),
    "leagueclient.exe": ("League of Legends", GAME),
    "valorant.exe": ("Valorant", GAME),
    "robloxplayerbeta.exe": ("Roblox", GAME),
    "minecraft.exe": ("Minecraft", GAME),
    "javaw.exe": ("Java (Minecraft?)", GAME),
    "fortniteclient-win64-shipping.exe": ("Fortnite", GAME),
    "cs2.exe": ("Counter-Strike 2", GAME),
    # communication
    "discord.exe": ("Discord", COMMS),
    "teams.exe": ("Microsoft Teams", COMMS),
    "ms-teams.exe": ("Microsoft Teams", COMMS),
    "zoom.exe": ("Zoom", COMMS),
    "slack.exe": ("Slack", COMMS),
    "telegram.exe": ("Telegram", COMMS),
    "whatsapp.exe": ("WhatsApp", COMMS),
    "outlook.exe": ("Outlook", COMMS),
    # development
    "code.exe": ("VS Code", DEV),
    "python.exe": ("Python", DEV),
    "pythonw.exe": ("Python", DEV),
    "node.exe": ("Node.js", DEV),
    "git.exe": ("Git", DEV),
    "powershell.exe": ("PowerShell", DEV),
    "pwsh.exe": ("PowerShell", DEV),
    "cmd.exe": ("Command Prompt", DEV),
    "windowsterminal.exe": ("Windows Terminal", DEV),
    "claude.exe": ("Claude", DEV),
    # media
    "notepad.exe": ("Notepad", DEV),
    "winword.exe": ("Microsoft Word", DEV),
    "excel.exe": ("Microsoft Excel", DEV),
    "powerpnt.exe": ("Microsoft PowerPoint", DEV),
    "spotify.exe": ("Spotify", MEDIA),
    "vlc.exe": ("VLC", MEDIA),
    "obs64.exe": ("OBS Studio", MEDIA),
    # background / often unnecessary
    "onedrive.exe": ("OneDrive", BACKGROUND),
    "dropbox.exe": ("Dropbox", BACKGROUND),
    "googledrivefs.exe": ("Google Drive", BACKGROUND),
    "adobearm.exe": ("Adobe Updater", BACKGROUND),
    "acrocef.exe": ("Adobe Acrobat", BACKGROUND),
    "creative cloud.exe": ("Adobe Creative Cloud", BACKGROUND),
    "msedgewebview2.exe": ("Edge WebView2", BACKGROUND),
    "phoneexperiencehost.exe": ("Phone Link", BACKGROUND),
    "widgets.exe": ("Windows Widgets", BACKGROUND),
    "searchhost.exe": ("Windows Search", BACKGROUND),
    "nvcontainer.exe": ("NVIDIA Container", BACKGROUND),
    "nvidia app.exe": ("NVIDIA App", BACKGROUND),
    "razer synapse 3.exe": ("Razer Synapse", BACKGROUND),
    # security
    "msmpeng.exe": ("Microsoft Defender", SECURITY),
    "mpdefendercoreservice.exe": ("Microsoft Defender", SECURITY),
    "defendersessionhelper.exe": ("Microsoft Defender", SECURITY),
    "mpcmdrun.exe": ("Microsoft Defender", SECURITY),
    "nissrv.exe": ("Microsoft Defender", SECURITY),
    "securityhealthservice.exe": ("Windows Security", SECURITY),
}

# Core Windows processes; shown as System.
SYSTEM_EXES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "runtimebroker.exe",
    "spoolsv.exe", "audiodg.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe",
    "searchindexer.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "lockapp.exe", "memory compression", "secure system",
    "applicationframehost.exe", "systemsettings.exe", "taskmgr.exe", "dashost.exe",
    "useroobebroker.exe", "smartscreen.exe", "sgrmbroker.exe", "lsaiso.exe",
    "wudfhost.exe", "msiexec.exe", "trustedinstaller.exe", "tiworker.exe",
    "systemd", "init", "kthreadd", "xorg", "gnome-shell", "dbus-daemon",  # Linux basics
}


INSTALL_DIRS = ("\\program files\\", "\\program files (x86)\\", "\\windowsapps\\",
                "\\appdata\\local\\programs\\", "\\windows\\", "/usr/", "/opt/", "/snap/")


def classify(exe_name: str, exe_path: str = "") -> tuple[str, str]:
    """Return (display_name, category) for a process."""
    key = (exe_name or "").lower()
    if key in KNOWN_APPS:
        return KNOWN_APPS[key]
    if key in SYSTEM_EXES:
        return exe_name, SYSTEM
    path = (exe_path or "").lower()
    if "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path:
        return exe_name, SYSTEM
    if "steamapps\\common" in path or "\\epic games\\" in path or "\\riot games\\" in path:
        return exe_name, GAME
    if any(d in path for d in INSTALL_DIRS):
        return exe_name, INSTALLED
    return exe_name or "?", UNKNOWN
