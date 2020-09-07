module github.com/zmap/zgrab2

go 1.12

require (
	github.com/gopcua/opcua v0.1.6
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/zmap/zcrypto v0.0.0-20200508204656-27de22294d44
	github.com/zmap/zflags v1.4.0-beta.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20190912160710-24e19bdeb0f2
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd
	golang.org/x/text v0.3.2
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.2.2
)

replace github.com/gopcua/opcua => ../../gopcua/opcua
