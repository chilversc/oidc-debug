Mostly learning some GO. Hopefully this will be a useful tool to check what claims are being issued by an identity server.

This is designed to support a flow similar to the gcloud command, or gkectl.

The local client will listen on `http://localhost:<PORT>/callback` for the oauth token. This URL will need to be configured as the callback for the client.
