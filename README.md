# go-outlook-oauth-graph
Golang example on how to do Oauth2 on an Outlook account and use Microsoft Graph API

#### Running with Docker

$ cd <project_folder>

$ docker build -t go-outlook-oauth-graph .

$docker run -it -p 8080:8080 -e MSFT_CLIENT_ID='your-microsoft-app-id' -e MSFT_CLIENT_SECRET='your-microsoft-app-secret' -v app:/go/src/github.com/user/yourProject/app go-outlook-oauth-graph:latest

then browse to
http://localhost:8080

check terminal for outputs.

