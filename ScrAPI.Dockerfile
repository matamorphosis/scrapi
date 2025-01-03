FROM golang:1.23

RUN mkdir -p /app/certs
RUN mkdir -p /app/teamfiles
RUN mkdir -p /var/log
WORKDIR /app

#----------------------------------------------------------------------------------------------------
# If using the above conditions to add custom a certificate pair, please ensure the names are correctly reflected below:
#----------------------------------------------------------------------------------------------------
ENV PRIVATE_KEY="/app/certs/PrivateKey.key"
ENV CERTIFICATE_FILE="/app/certs/Certificate.crt"
#----------------------------------------------------------------------------------------------------

RUN go mod init scrapi
RUN go mod tidy
RUN go mod download && go mod verify

COPY . .

#----------------------------------------------------------------------------------------------------
# If using the above conditions to add custom a certificate pair, please comment out the below lines
#----------------------------------------------------------------------------------------------------
ENV country=AU
ENV state=NSW
ENV locality=Sydney
ENV commonname=Scrapi
ENV organization=Scrapi
ENV organizationalunit=Scrapi
ENV email=Scrapi@Scrapi.com
#----------------------------------------------------------------------------------------------------
RUN openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $PRIVATE_KEY -out $CERTIFICATE_FILE -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

RUN go build -v -o /app/app ./

CMD ["/app/app"]