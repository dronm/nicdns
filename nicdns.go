// Package nicdns provides access to nic.ru dns API
package nicdns

import(
	"time"
	"net/http"
	"net/url"
	"io/ioutil"
	"io"
	"encoding/xml"
	"encoding/json"
	"strings"
	"errors"
	"fmt"
	"bytes"
	"os"
)

const (
	DEF_AUTH_FILE = "nicdns_auth.json"
	
	HOST = "https://api.nic.ru"
	AUTH_ENTRY = "/oauth/token"
	API_ENTRY = "/dns-master"
	Q_SERVICE_PAR = "/services/%s"
	Q_ZONE_PAR = "/zones/%s"
	
	METH_TTL = "/default-ttl"
	METH_ROLLBACK = "/rollback"
	METH_COMMIT = "/commit"
	METH_REVIS = "/revisions"
	METH_REC = "/records"
	
	//to identify response type
	CONTENT_TYPE_JSON = "application/json"
	CONTENT_TYPE_XML = "text/xml"
	CONTENT_TYPE_TXT = "text/plain"
	
	XML_HEADER = `<?xml version="1.0" encoding="UTF-8" ?>`
)

type requestType int
const (
    REQUEST_CT_FORM requestType = iota
    REQUEST_CT_TEXT
    REQUEST_CT_XML
)

//APIResponseErrorJSON holds API JSON error
type APIResponseErrorJSON struct {
	Error string `json:"error"`
}

//APIResponseError holds API XML errors
type APIResponseError struct {
	XMLName xml.Name `xml:"response"`
	Status string `xml:"status"`
	Errors []struct {
		Error struct {
			Descr  string `xml:",chardata"`
			Code string `xml:"code,attr"`			
		} `xml:"error"`
		Validator string `xml:"validator-output"`
	} `xml:"errors"`
}
func (e *APIResponseError) String() string {
	var err_s strings.Builder
	if e.Errors != nil {
		err_s.WriteString("errors: ")
		for i, err := range e.Errors {
			if i > 0 {
				err_s.WriteString(", ")
			}
			t := err.Error.Descr
			if err.Validator != "" {
				t+= ", validator-output: " + err.Validator
			}
			err_s.WriteString(fmt.Sprintf("%s (%s)", t, err.Error.Code));
		}
	}
	return err_s.String()
}

type APIResponseTTL struct {
	Data struct {
		DefaultTTL int64 `xml:"default-ttl"`
	} `xml:"data"`		
}

type DomainZone struct {
	Admin  string `xml:"admin,attr"`
	Enable bool `xml:"enable,attr"`
	HasChanges bool `xml:"has-changes,attr"`
	HasPrimary bool `xml:"has-primary,attr"`
	Id string `xml:"id,attr"`
	IdnName string `xml:"idn-name,attr"`
	Name string `xml:"name,attr"`
	Payer string `xml:"payer,attr"`
	Service string `xml:"service,attr"`
}

type APIResponseDomainZones struct {
	XMLName xml.Name `xml:"response"`	
	Data struct {		
		Zones []DomainZone `xml:"zone"`
	} `xml:"data"`
}

type ZoneRevision struct {
	Date  string `xml:"date,attr"`
	IP string `xml:"ip,attr"`
	Number int `xml:"number,attr"`		
}

type APIResponseZoneRevisions struct {
	XMLName xml.Name `xml:"response"`
	Data struct {		
		Revisions []ZoneRevision `xml:"revision"`
	} `xml:"data"`
}


type ZoneRecordSOA struct {
	XMLName xml.Name `xml:"soa"`
	MName  struct {
		Name  string `xml:"name,omitempty"`
		IdnName  string `xml:"idn-name,omitempty"`
	} `xml:"mname,omitempty"`
	RName  struct {
		Name  string `xml:"name,omitempty"`
		IdnName  string `xml:"idn-name,omitempty"`
	} `xml:"rname,omitempty"`
	Serial int `xml:"serial,omitempty"`
	Refresh int `xml:"refresh,omitempty"`
	Retry int `xml:"retry,omitempty"`
	Expire int `xml:"expire,omitempty"`
	Minimum int `xml:"minimum,omitempty"`
}

type ZoneRecord struct {
	XMLName xml.Name `xml:"rr"`
	Id  string `xml:"id,attr,omitempty"`
	Name  string `xml:"name,omitempty"`
	IdnName  string `xml:"idn-name,omitempty"`
	Type  string `xml:"type,omitempty"`
	Ttl  string `xml:"ttl,omitempty"`
	A  string `xml:"a,omitempty"`
	Aaaa  string `xml:"aaaa,omitempty"`
	Soa  *ZoneRecordSOA `xml:"soa,omitempty"`
	Cname *struct {
		Name  string `xml:"name"`
	} `xml:"cname,omitempty"`
	Ns *struct {
		Name  string `xml:"name"`
	} `xml:"ns,omitempty"`
	Mx *struct {
		Preference  string `xml:"preference"`
		Exchange struct {
			Name  string `xml:"name"`
		} `xml:"exchange"`
	} `xml:"mx,omitempty"`	
	Srv *struct {
		Priority string `xml:"priority"`
		Weight string `xml:"weight"`
		Port string `xml:"port"`
		Target struct {
			Name  string `xml:"name"`
		} `xml:"target"`
	} `xml:"srv,omitempty"`		
	Ptr *struct {
		Name  string `xml:"name"`
	} `xml:"ptr"`	
	Txt *ZoneRecordTXTVal`xml:"txt,omitempty"`	
	DName *struct {
		Name  string `xml:"name"`
	} `xml:"dname,omitempty"`	
	HIinfo *struct {
		Hardware string `xml:"hardware"`
		Os string `xml:"os"`
	} `xml:"hinfo,omitempty"`	
}

type ZoneRecordTXTVal struct {
	XMLName xml.Name `xml:"txt"`
	String string `xml:"string"`
}

type APIResponseZoneRecords struct {
	XMLName xml.Name `xml:"response"`
	Data struct {		
		Zone struct {
			Records []ZoneRecord `xml:"rr"`
		} `xml:"zone"`		
	} `xml:"data"`
}

type APIRequestZoneRecords struct {
	XMLName xml.Name `xml:"request"`
	Records []ZoneRecord `xml:"rr-list>rr"`		
}

//**************************************************
type APIResponseAuth struct {
	AccessToken string `json:"access_token"`
	ExpiresIn int `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenTime time.Time `json:"token_time"`
}
func NewAPIResponseAuth() *APIResponseAuth {
	return &APIResponseAuth{TokenTime: time.Now()}
}

func getAPICmdEntry(service, zone string) string {
	return API_ENTRY + fmt.Sprintf(Q_SERVICE_PAR, service) + fmt.Sprintf(Q_ZONE_PAR, zone)	
}

type DNSManagerAuth struct {
	AppLogin string `json:"app_login"`
	AppPwd string `json:"app_pwd"`
	ContractLogin string `json:"contract_login"`
	ContractPwd string `json:"contract_pwd"`
}
// Load loads auth data from json file
func (a *DNSManagerAuth) Load(fileName string) error {
	if fileName == "" {
		fileName = DEF_AUTH_FILE
	}
	return LoadFromJSONFile(fileName, a)
}

// DNSManager is the main object structure
type DNSManager struct {
	APIAuth *APIResponseAuth
	Auth *DNSManagerAuth
	Service string
	Zone string
	GrantType string
	Scope string
	Debug bool
}

//
func NewDNSManager(auth *DNSManagerAuth, service, zone string, debug bool) *DNSManager {
	return &DNSManager{APIAuth: &APIResponseAuth{}, Auth: auth, Service: service, Zone: zone, Debug: debug}
}

func (m *DNSManager) getQueryFileName() string {
	return fmt.Sprintf("~%s-%s.json", m.Service, m.Zone)	
}

func (m *DNSManager) sendRequest(method string, reqType requestType, apiEntry string, body io.Reader, respStruct interface{}, isAuthRequest bool) (*http.Response, error) {
	if m.Debug {
		fmt.Println("sendRequest url:", HOST + apiEntry)
	}
	if !isAuthRequest {
		if err := m.checkAPIAuth(); err != nil {
			return nil, err
		}
	}
	r, err := http.NewRequest(method, HOST + apiEntry, body)
	if err != nil {
		return nil, err
	}
	
	//request content type
	if reqType == REQUEST_CT_FORM {
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		
	}else if reqType == REQUEST_CT_TEXT {
		r.Header.Add("Content-Type", "text/plain; charset=UTF-8")
		
	}else if reqType == REQUEST_CT_XML {
		r.Header.Add("Content-Type", "text/xml; charset=UTF-8")		
	}
	
	if !isAuthRequest {
		r.Header.Add("Authorization", "Bearer " + m.APIAuth.AccessToken)
	}
	
	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body_resp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	
	ct := resp.Header.Get("Content-Type")
	
	//if m.Debug {
		//fmt.Println("Response body:", string(body_resp))
		//fmt.Println("Response headers:", resp.Header)		
	//}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {		
		//error
		if strings.Index(ct, CONTENT_TYPE_JSON) >= 0 {
			b := APIResponseErrorJSON{}
			err := json.Unmarshal(body_resp, &b)
			if err != nil {
				return resp, err
			}			
			return resp, errors.New(fmt.Sprintf("HTTP status: %d, error: %s", resp.StatusCode, b.Error))
			
		}else if strings.Index(ct, CONTENT_TYPE_XML) >= 0 {
			b := APIResponseError{}
			err := xml.Unmarshal(body_resp, &b)
			if err != nil {
				return resp, err
			}
			return resp, errors.New(b.String())
			
		}else{
			return resp, errors.New(fmt.Sprintf("error body content type %s not supported. HTTP status: %d, body: %s", ct, resp.StatusCode, string(body_resp)))
		}
	}
	
	if respStruct != nil {
		if strings.Index(ct, CONTENT_TYPE_JSON) >= 0 {
			err := json.Unmarshal(body_resp, respStruct)
			if err != nil {
				return resp, err
			}
			
		}else if strings.Index(ct, CONTENT_TYPE_XML) >= 0 {
			err := xml.Unmarshal(body_resp, respStruct)
			if err != nil {
				return resp, err
			}
			
		}else if strings.Index(ct, CONTENT_TYPE_TXT) >= 0 {		
			if s, ok := respStruct.(*string); ok {
				*s = string(body_resp)

			}else if s, ok := respStruct.(*[]byte); ok {
				*s = body_resp

			}else{
				return resp, errors.New("respStruct.(*string) fail")
			}
			
			
		}else{
			return resp, errors.New(fmt.Sprintf("body content type %s not supported. HTTP status: %d", ct, resp.StatusCode))
		}
	}
	return resp, nil
}

// checkAPIAuth loads api auth and checks expiration. Calls Login() if needed
func (m *DNSManager) checkAPIAuth() error {
	query_fn := m.getQueryFileName()
	if fileExists(query_fn) {
		_ = LoadFromJSONFile(query_fn, m.APIAuth) //discard error
	}
	//no token or expired
	if m.APIAuth.AccessToken == "" || (m.APIAuth.ExpiresIn > 0 && m.APIAuth.TokenTime.Add(time.Duration(m.APIAuth.ExpiresIn) * time.Second).Before(time.Now())) {
		if m.Debug {
			fmt.Println("checkAPIAuth token is expired, calling Login()")
		}
		if err := m.Login(m.GrantType, m.Scope); err != nil {
			return err
		}
	}	
	return nil
}


// Login updates access token and writes data to temp query file.
// grantType has a default value password
// scope's default value is .*
func (m *DNSManager) Login(grantType, scope string) error {
	m.APIAuth = NewAPIResponseAuth()
	
	if grantType == "" {
		grantType = "password"
	}
	if scope == "" {
		scope = ".*"
	}
	
	m.GrantType = grantType
	m.Scope = scope
		
	fields := url.Values{}
	fields.Set("grant_type", grantType)
	fields.Set("password", m.Auth.ContractPwd)
	fields.Set("username", m.Auth.ContractLogin)
	fields.Set("client_id", m.Auth.AppLogin)
	fields.Set("client_secret", m.Auth.AppPwd)
	fields.Set("scope", scope)
	
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_FORM, AUTH_ENTRY, strings.NewReader(fields.Encode()), m.APIAuth, true)
	if err != nil {
		return err
	}
	
	SaveToJSONFile(m.getQueryFileName(), m.APIAuth)
	
	return nil
}

// DefaultTTL provides access to default-ttl API method
// Returns TTL as int64
// If service, zone parameters are empty strings, then default values of DNSManager will be used.
func (m *DNSManager) GetDefaultTTL() (int64, error) {
	resp_api := &APIResponseTTL{}
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_TTL, nil, resp_api, false)
	if err != nil {
		return 0, err
	}
	
	return resp_api.Data.DefaultTTL, nil
}

func (m *DNSManager) SetDefaultTTL(ttl int64) error {
	ttl_str := fmt.Sprintf("<request><default-ttl>%d</default-ttl></request>", ttl)
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_XML, getAPICmdEntry(m.Service, m.Zone) + METH_TTL, bytes.NewBufferString(ttl_str), nil, false)
	if err != nil {
		return err
	}
	
	return nil
}

func (m *DNSManager) GetZones() ([]DomainZone, error) {
	resp_api := APIResponseDomainZones{}
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, ""), nil, &resp_api, false)
	if err != nil {
		return nil, err
	}
	
	return resp_api.Data.Zones, nil 
}

func (m *DNSManager) GetFile() ([]byte, error) {
	var resp_api []byte
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone), nil, &resp_api, false)
	if err != nil {
		return []byte{}, err
	}
	
	return resp_api, nil 
}

func (m *DNSManager) PutFile(zoneFileData []byte) error {
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone), bytes.NewBuffer(zoneFileData), nil, false)
	if err != nil {
		return err
	}
	
	return nil 
}

func (m *DNSManager) Rollback() error {
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_ROLLBACK, nil, nil, false)
	if err != nil {
		return err
	}
	
	return nil 
}

func (m *DNSManager) Commit() error {
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_COMMIT, nil, nil, false)
	if err != nil {
		return err
	}
	
	return nil 
}

func (m *DNSManager) GetRevisions() ([]ZoneRevision, error) {
	resp_api := APIResponseZoneRevisions{}
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_REVIS, nil, &resp_api, false)
	if err != nil {
		return nil, err
	}
	
	return resp_api.Data.Revisions, nil 
}

func (m *DNSManager) GetRevision(revisNumber int) (string, error) {
	var resp_api string
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_REVIS + fmt.Sprintf("/%d", revisNumber), nil, &resp_api, false)
	if err != nil {
		return "", err
	}
	
	return resp_api, nil 
}

func (m *DNSManager) SetRevision(revisNumber int) error {
	_, err := m.sendRequest(http.MethodPost, REQUEST_CT_XML, getAPICmdEntry(m.Service, m.Zone) + METH_REVIS + fmt.Sprintf("/%d", revisNumber), nil, nil, false)
	if err != nil {
		return err
	}
	
	return nil 
}

func (m *DNSManager) GetZoneRecords() ([]ZoneRecord, error) {
	resp_api := APIResponseZoneRecords{}
	_, err := m.sendRequest(http.MethodGet, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_REC, nil, &resp_api, false)
	if err != nil {
		return nil, err
	}
	
	return resp_api.Data.Zone.Records, nil 
}

func (m *DNSManager) DeleteZoneRecord(recordId string) error {
	_, err := m.sendRequest(http.MethodDelete, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_REC + fmt.Sprintf("/%s", recordId), nil, nil, false)
	if err != nil {
		return err
	}
	
	return nil 
}

func (m *DNSManager) AddZoneRecord(rec *APIRequestZoneRecords) error {
	rec_xml := []byte(XML_HEADER) 
	rec_b, err := xml.Marshal(rec)
	if err != nil {
		return err
	}
	rec_xml =  append(rec_xml, rec_b...)

	_, err = m.sendRequest(http.MethodPut, REQUEST_CT_TEXT, getAPICmdEntry(m.Service, m.Zone) + METH_REC, bytes.NewBuffer(rec_xml), nil, false)
	if err != nil {
		return err
	}

	
	return nil
}

//**********************************************************************************************************
//
// LoadFromFile loads data from json init file
func LoadFromJSONFile(fileName string, target interface{}) error {
	file, err := ioutil.ReadFile(fileName)
	if err == nil {
		file = bytes.TrimPrefix(file, []byte("\xef\xbb\xbf"))
		err = json.Unmarshal([]byte(file), target)		
	}
	return err	
}

func SaveToJSONFile(fileName string, source interface{}) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	
	b, err := json.MarshalIndent(source, "", "	")
	if err != nil {
		return err
	}	
	_, err = f.Write(b)
	if err != nil {
		return err
	}	
	return nil	
}

func fileExists(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}
