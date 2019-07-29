##! This script is providing mattermost notifications for notices

@load base/frameworks/notice
@load base/utils/active-http

module Notice;

export {
    redef enum Action += {
        ACTION_MATTERMOST,
    };

    # a Mattermost_message an enum which will be converted to JSON format
    # to be sent to the Mattermost Incoming Webhook
    type Mattermost_message: record {
        text: string;
        channel: string &optional;
        username: string &optional;
    };

    # Needs to be redefined to match your Mattermost Incoming Webhook URL
    const mattermost_webhook_url = "https://your-mattermost-server/hooks/xxx-generatedkey-xxx" &redef;

    # Can be redefined to add a different public channel and username
    const mattermost_channel = "" &redef;
    const mattermost_username = "Big Brother" &redef;

    # creates the Mattermost_message
    global mattermost_payload: function(n: Notice::Info, channel: string, username: string): Notice::Mattermost_message;
    # converts the Mattermost_message to JSON and sends it to the Mattermost Incoming Webhook
    global mattermost_send_notice: function(webhook: string, payload: Notice::Mattermost_message);

}

function mattermost_send_notice(webhook: string, payload: Notice::Mattermost_message)
    {
    local request: ActiveHTTP::Request = ActiveHTTP::Request(
        $url=webhook,
        $method="POST",
	$addl_curl_args="-H 'Content-Type: application/json'",
        $client_data=to_json(payload)
    );

    when ( local result = ActiveHTTP::request(request) )
        {
        if ( result$code != 200 )
            Reporter::warning(fmt("Mattermost notice received an error status code: %d", result$code));
        }
    }

function mattermost_payload(n: Notice::Info, channel: string, username: string): Notice::Mattermost_message
    {
    local text = fmt("%s: %s", n$note, n$msg);
    if ( n?$sub )
        {
        text = string_cat(text,
            fmt(" (%s)", n$sub));
        }
    if ( n?$id )
        {
        text = string_cat(text, ", Connection: ",
            fmt("%s", n$id$orig_h), ":", fmt("%d", n$id$orig_p), " -> ",
            fmt("%s", n$id$resp_h), ":", fmt("%d", n$id$resp_p));
        if ( n?$uid )
            text = string_cat(text, ", Connection uid: ", n$uid);
        }
    else if ( n?$src )
        text = string_cat(text, fmt(", Source: %s", n$src));

    local message: Mattermost_message = Mattermost_message($text=text, $channel=channel, $username=username);
    return message;
    }

hook notice(n: Notice::Info)
    {
        if ( ACTION_MATTERMOST in n$actions )
            mattermost_send_notice(mattermost_webhook_url, mattermost_payload(n, mattermost_channel, mattermost_username));
    }
