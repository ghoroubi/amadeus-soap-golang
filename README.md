# amadeus-soap-golang
This library is a fork of goWSDL library, which has customized for using in Amadeus EPower SOAP service.
The amadeus specific Authorization Headers , and setting Session-ID as a cookie in request are implemented gracefully in this library.
Feel free to leave any comments and issues
# Usage
## Installation
go get github.com/ghoroubi/amadeus-soap-golang
import in your project.

`
package min 
import soap "github.com/ghoroubi/amadeus-go-soap"
type impl struct {
	client *soap.Client
	logger *logrus.Logger
}

// NewEPowerServiceSoap ...
func NewEPowerServiceSoap(client *soap.Client, logger *logrus.Logger) IAmadeus {
	return &impl{
		client: client,
		logger:logger,
	}
}

// Ping , pings the server with at least an echo data
func (service *impl) Ping(request *Ping) (*PingResponse, error) {
	response := new(PingResponse)
	err := service.client.Call("http://epowerv5.amadeus.com.tr/WS/Ping", request, response)
	if err != nil {
		return nil, err
	}
	
	return response, nil
}
`
