on run {daemon_file, agent_file, user}

  set prefs_dir to "/Users/" & user & "/Library/Preferences/com.telemost.Telemost/"
  set prefs_toml to quoted form of (prefs_dir & "Telemost.toml")
  set prefs2_toml to quoted form of (prefs_dir & "Telemost2.toml")

  set sh1 to "echo " & quoted form of daemon_file & " > /Library/LaunchDaemons/com.telemost.desktop.service.plist && chown root:wheel /Library/LaunchDaemons/com.telemost.desktop.service.plist;"

  set sh2 to "echo " & quoted form of agent_file & " > /Library/LaunchAgents/com.telemost.desktop.agent.plist && chown root:wheel /Library/LaunchAgents/com.telemost.desktop.agent.plist;"

  set sh3 to "mkdir -p /var/root/Library/Preferences/com.telemost.Telemost && cp -f " & prefs_toml & " /var/root/Library/Preferences/com.telemost.Telemost/;"

  set sh4 to "cp -f " & prefs2_toml & " /var/root/Library/Preferences/com.telemost.Telemost/;"

  set sh5 to "launchctl bootout system/com.telemost.desktop.service 2>/dev/null || launchctl unload -w /Library/LaunchDaemons/com.telemost.desktop.service.plist 2>/dev/null || true; launchctl bootstrap system /Library/LaunchDaemons/com.telemost.desktop.service.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/com.telemost.desktop.service.plist;"

  set sh to sh1 & sh2 & sh3 & sh4 & sh5

  do shell script sh with prompt "Telemost wants to install daemon and agent" with administrator privileges
end run
