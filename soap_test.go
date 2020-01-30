package amadeus_soap_golang

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
)

type Ping struct {
	XMLName xml.Name `xml:"http://example.com/service.xsd Ping"`

	Request *PingRequest `xml:"request,omitempty"`
}

type PingRequest struct {
	Message string `xml:"Message,omitempty"`
}

type PingResponse struct {
	XMLName xml.Name `xml:"http://example.com/service.xsd PingResponse"`
	PingResult *PingReply `xml:"PingResult,omitempty"`
}

type PingReply struct {
	Message string `xml:"Message,omitempty"`
}

func TestClient_Call(t *testing.T) {
	var pingRequest = new(Ping)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_=xml.NewDecoder(r.Body).Decode(pingRequest)
		rsp := `<?xml version="1.0" encoding="utf-8"?>
		<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
			<soap:Body>
				<PingResponse xmlns="http://example.com/service.xsd">
					<PingResult>
						<Message>Echo your message</Message>
					</PingResult>
				</PingResponse>
			</soap:Body>
		</soap:Envelope>`
		_, _ = w.Write([]byte(rsp))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.AddHeader(
		&AuthenticationSoapHeader{
			WSUserName: "USERNAME",
			WSPassword: "PASSWORD",
		},
	)
	
	req := &Ping{Request: &PingRequest{Message: "Hi"}}
	reply := &PingResponse{}
	if err := client.Call("GetData", req, reply); err != nil {
		t.Fatalf("couln't call service: %v", err)
	}

	wantedMsg := "Echo your message"
	if reply.PingResult.Message != wantedMsg {
		t.Errorf("got msg %s wanted %s", reply.PingResult.Message, wantedMsg)
	}
}
