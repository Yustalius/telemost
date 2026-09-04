set sh1 to "launchctl unload -w /Library/LaunchDaemons/com.telemost.desktop.service.plist;"
set sh2 to "/bin/rm /Library/LaunchDaemons/com.telemost.desktop.service.plist;"
set sh3 to "/bin/rm /Library/LaunchAgents/com.telemost.desktop.agent.plist;"

set sh to sh1 & sh2 & sh3
do shell script sh with prompt "Telemost wants to unload daemon" with administrator privileges
