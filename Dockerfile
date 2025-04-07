FROM golang:1.23-alpine AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o spire-csi-provider cmd/spire-csi-provider/main.go

FROM alpine:3.18

RUN apk add --no-cache ca-certificates bash curl

COPY --from=builder /workspace/spire-csi-provider /bin/spire-csi-provider

ENTRYPOINT ["/bin/spire-csi-provider"]