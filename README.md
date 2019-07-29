# zeek-notice-mattermost
Script extending Zeek Notice framework, adding Mattermost notifications.

## Usage
Append to zeek_install/share/zeek/site/local.zeek:
```
@load ./notice_mattermost.zeek

redef Notice::mattermost_webhook_url = "https://your-mattermost-server/hooks/xxx-generatedkey-xxx";
redef Notice::mattermost_channel = "#zeek-channel";
redef Notice::mattermost_username = "Big Brother";

hook Notice::policy(n: Notice::Info)
{
    add n$actions[Notice::ACTION_MATTERMOST];
}
```
## TODO
- Add timeout block with Reporter::warning after when block  
- ...
