FROM golang

ARG app_env
ENV APP_ENV $app_env
ARG msft_client_id
ENV MSFT_CLIENT_ID $msft_client_id
ARG msft_client_secret
ENV MSFT_CLIENT_SECRET $msft_client_secret

COPY ./app /go/src/github.com/user/yourProject/app
WORKDIR /go/src/github.com/user/yourProject/app

RUN go get ./
RUN go build

CMD if [ ${APP_ENV} = production ]; \
	then \
	app; \
	else \
	go get github.com/pilu/fresh && \
	fresh; \
	fi
	
EXPOSE 8080