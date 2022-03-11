module github.com/influxdata/influxdb/v2

go 1.17

require (
	github.com/gin-gonic/gin v1.6.0
	github.com/BurntSushi/toml v0.3.1
)

require github.com/influxdata/influx-cli/v2 v2.2.1-0.20211129214229-4c0fae3a4c0d

require (
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
)

replace github.com/nats-io/nats-streaming-server v0.11.2 => github.com/influxdata/nats-streaming-server v0.11.3-0.20201112040610-c277f7560803
