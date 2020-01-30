package amadeus_soap_golang
import (
"bytes"
"crypto/tls"
"encoding/xml"
"io/ioutil"
"log"
"net"
"net/http"
"strings"
"time"
)

// SOAPEnvelope , Root level of XML
type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  *SOAPHeader
	Body    SOAPBody
}

// SOAPHeader , generic soap header
type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	
	Items []interface{} `xml:",omitempty"`
}

// AuthenticationSoapHeader ...
type AuthenticationSoapHeader struct {
	XMLName       xml.Name `xml:"http://epowerv5.amadeus.com.tr/WS AuthenticationSoapHeader"`
	WSUserName    string   `xml:"WSUserName,omitempty"`
	WSPassword    string   `xml:"WSPassword,omitempty"`
	WSCultureInfo string   `xml:"WSCultureInfo,omitempty"`
}

// SOAPBody , Soap body
type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	
	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

// UnmarshalXML , deserialize SOAPBody xml
func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}
	
	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}
		
		if token == nil {
			break
		}
		
		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil
				
				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}
				
				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}
				
				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}
	
	return nil
}

// SOAPFault ...
type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

// Error interface implementation
func (f *SOAPFault) Error() string {
	return f.String
}
// Predefined WSS namespaces to be used in
const (
	WssNsWSSE string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	WssNsWSU  string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WssNsType string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

// WSSSecurityHeader ...
type WSSSecurityHeader struct {
	XMLName   xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ wsse:Security"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	MustUnderstand string `xml:"mustUnderstand,attr,omitempty"`
	Token *WSSUsernameToken `xml:",omitempty"`
}

// WSSUsernameToken ...
type WSSUsernameToken struct {
	XMLName   xml.Name `xml:"wsse:UsernameToken"`
	XmlNSWsu  string   `xml:"xmlns:wsu,attr"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	Id string `xml:"wsu:Id,attr,omitempty"`
	Username *WSSUsername `xml:",omitempty"`
	Password *WSSPassword `xml:",omitempty"`
}

// WSSUsername ...
type WSSUsername struct {
	XMLName   xml.Name `xml:"wsse:Username"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	
	Data string `xml:",chardata"`
}

// WSSPassword ...
type WSSPassword struct {
	XMLName   xml.Name `xml:"wsse:Password"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	XmlNSType string   `xml:"Type,attr"`
	
	Data string `xml:",chardata"`
}

// NewWSSSecurityHeader creates WSSSecurityHeader instance
func NewWSSSecurityHeader(user, pass, tokenID, mustUnderstand string) *WSSSecurityHeader {
	hdr := &WSSSecurityHeader{XmlNSWsse: WssNsWSSE, MustUnderstand: mustUnderstand}
	hdr.Token = &WSSUsernameToken{XmlNSWsu: WssNsWSU, XmlNSWsse: WssNsWSSE, Id: tokenID}
	hdr.Token.Username = &WSSUsername{XmlNSWsse: WssNsWSSE, Data: user}
	hdr.Token.Password = &WSSPassword{XmlNSWsse: WssNsWSSE, XmlNSType: WssNsType, Data: pass}
	return hdr
}

type basicAuth struct {
	Login    string
	Password string
}

type options struct {
	tlsCfg      *tls.Config
	auth        *basicAuth
	timeout     time.Duration
	httpHeaders map[string]string
}

var defaultOptions = options{
	timeout: time.Duration(30 * time.Second),
}

// A Option sets options such as credentials, tls, etc.
type Option func(*options)

// WithBasicAuth is an Option to set BasicAuth
func WithBasicAuth(login, password string) Option {
	return func(o *options) {
		o.auth = &basicAuth{Login: login, Password: password}
	}
}

// WithTLS is an Option to set tls config
func WithTLS(tls *tls.Config) Option {
	return func(o *options) {
		o.tlsCfg = tls
	}
}

// WithTimeout is an Option to set default HTTP dial timeout
func WithTimeout(t time.Duration) Option {
	return func(o *options) {
		o.timeout = t
	}
}

// WithHTTPHeaders is an Option to set global HTTP headers for all requests
func WithHTTPHeaders(headers map[string]string) Option {
	return func(o *options) {
		o.httpHeaders = headers
	}
}

// Client is soap client
type Client struct {
	url     string
	opts    *options
	headers []interface{}
	Cookies *http.Cookie
}

// NewClient creates new SOAP client instance
func NewClient(url string, opt ...Option) *Client {
	opts := defaultOptions
	for _, o := range opt {
		o(&opts)
	}
	return &Client{
		url:  url,
		opts: &opts,
	}
}

// AddHeader adds envelope header
func (s *Client) AddHeader(header interface{}) {
	s.headers = append(s.headers, header)
}

// Call performs HTTP POST request
func (s *Client) Call(soapAction string, request, response interface{}) error {
	
	envelope := SOAPEnvelope{}
	if s.headers != nil && len(s.headers) > 0 {
		soapHeader := &SOAPHeader{Items: make([]interface{}, len(s.headers))}
		copy(soapHeader.Items, s.headers)
		envelope.Header = soapHeader
	}
	
	envelope.Body.Content = request
	buffer := new(bytes.Buffer)
	
	encoder := xml.NewEncoder(buffer)
	
	if err := encoder.Encode(envelope); err != nil {
		return err
	}
	
	if err := encoder.Flush(); err != nil {
		return err
	}
	
	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	
	if s.opts.auth != nil {
		req.SetBasicAuth(s.opts.auth.Login, s.opts.auth.Password)
	}
	
	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("SOAPAction", soapAction)
	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Header.Set("Host", "staging-ws.epower.amadeus.com")
	
	if s.Cookies != nil {
		c := &http.Cookie{
			Name:  s.Cookies.Name,
			Value: s.Cookies.Value,}
		req.Header.Set("cookie", c.String())
	}
	
	if s.opts.httpHeaders != nil {
		for k, v := range s.opts.httpHeaders {
			req.Header.Set(k, v)
		}
	}
	
	req.Close = true
	
	tr := &http.Transport{
		TLSClientConfig: s.opts.tlsCfg,
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, s.opts.timeout)
		},
	}
	
	client := &http.Client{
		Transport: tr,
	}
	start := time.Now()
	
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	log.Printf("\nMethod=[Parsing raw response]\nResponse time:[%v] milliseconds\n", time.Now().Sub(start).Milliseconds())
	if s.Cookies == nil && strings.Contains(soapAction, "/SearchFlight") && len(res.Cookies()) > 0 {
		s.Cookies = res.Cookies()[0]
	}
	
	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		return nil
	}
	
	respEnvelope := new(SOAPEnvelope)
	respEnvelope.Body = SOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}
	
	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}
	
	return nil
}

func getSessionId(cookie string) string {
	// ASP.NET_SessionId=moxuzygi33fiqqd5opjffmyy; path=/; secure; HttpOnly
	parts := strings.Split(cookie, ";")
	t := strings.Split(parts[0], "=")
	return t[1]
	
}

