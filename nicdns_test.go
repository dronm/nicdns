package nicdns

import(
	"testing"
	"fmt"
	"encoding/xml"
)

const REVIS_NUM = 140
const DEF_TTL = 3600

func CreateFromFile() *DNSManager {
	serv := struct {
		Service string `json:"service"`
		Zone string `json:"zone"`
	}{}	
	if err := LoadFromJSONFile(DEF_AUTH_FILE, &serv); err != nil {
		panic(fmt.Sprintf("LoadFromJSONFile() failed: %v",err))
	}

	auth := DNSManagerAuth{}
	if err := auth.Load(""); err != nil {
		panic(fmt.Sprintf("auth.Load() failed: %v",err))
	}
	

	return NewDNSManager(&auth, serv.Service, serv.Zone, true)
}

func TestGetDefaultTTL(t *testing.T) {
	man := CreateFromFile()	
	
	ttl, err := man.GetDefaultTTL()
	if err != nil {
		panic(fmt.Sprintf("GetDefaultTTL() failed: %v",err))
	}
	
	fmt.Println("TTL:", ttl)
}

func TestSetDefaultTTL(t *testing.T) {
	man := CreateFromFile()	
	
	err := man.SetDefaultTTL(DEF_TTL)
	if err != nil {
		panic(fmt.Sprintf("SetDefaultTTL() failed: %v",err))
	}
}

func TestLogin(t *testing.T) {
	man := CreateFromFile()	
	
	err := man.Login("", "")
	if err != nil {
		panic(fmt.Sprintf("Login() failed: %v",err))
	}
	
	fmt.Println("Manager:", man)
}

func TestCreate(t *testing.T) {
	man := CreateFromFile()	
	fmt.Println(man)
}

func TestGetZones(t *testing.T) {	
	man := CreateFromFile()	
	
	zones, err := man.GetZones()
	if err != nil {
		panic(fmt.Sprintf("GetZones() failed: %v",err))
	}
	
	fmt.Println("zones:", zones)

}

func TestGetFile(t *testing.T) {	
	man := CreateFromFile()		
	zone_file, err := man.GetFile()
	if err != nil {
		panic(fmt.Sprintf("GetFile() failed: %v",err))
	}	
	fmt.Println("zone_file:")
	fmt.Println(string(zone_file))
}

func TestGetRevisionsParse(t *testing.T) {	
	s := `<?xml version="1.0" encoding="UTF-8" ?> <response>
	<status>success</status>
	<data><revision date="2013-04-01 18:36:57" ip="192.168.125.12" number="3" />
	<revision date="2013-04-01 18:36:57" ip="192.168.125.12" number="2" />
	<revision date="2013-04-01 18:36:56" ip="no data" number="1" />
	</data>
	</response>`
	str := APIResponseZoneRevisions{}
	err := xml.Unmarshal([]byte(s), &str)
	if err != nil {
		panic(fmt.Sprintf("xml.Unmarshal() failed: %v",err))
	}
	fmt.Println(str)
}

func TestGetRevisions(t *testing.T) {	
	man := CreateFromFile()		
	revisions, err := man.GetRevisions()
	if err != nil {
		panic(fmt.Sprintf("GetRevisions() failed: %v",err))
	}	
	fmt.Println("revisions:", revisions)
}

func TestGetRevisionByNum(t *testing.T) {	
	man := CreateFromFile()		
	revision, err := man.GetRevision(REVIS_NUM)
	if err != nil {
		panic(fmt.Sprintf("GetRevisions() failed: %v",err))
	}	
	fmt.Println("revision:")
	fmt.Println(revision)
}

func TestZoneRecordsParse(t *testing.T) {	
	s := `<?xml version="1.0" encoding="UTF-8" ?>
<response>
<status>success</status>
<data>
<zone admin="123/NIC-REG" has-changes="true" id="228095" idn-name="test.ru" name="test.ru" service="myservice">
<rr id="210074">
	<name>@</name>
	<idn-name>@</idn-name>
	<type>SOA</type>
	<soa>
		<mname>
			<name>ns3-l2.nic.ru.</name>
			<idn-name>ns3-l2.nic.ru.</idn-name>
		</mname>
		<rname>
			<name>dns.nic.ru.</name>
			<idn-name>dns.nic.ru.</idn-name>
		</rname>
		<serial>2011112002</serial>
		<refresh>1440</refresh>
		<retry>3600</retry>
		<expire>2592000</expire>
		<minimum>600</minimum>
	</soa>
</rr>
<rr id="210075"><name>@</name><idn-name>@</idn-name><type>NS</type><ns><name>ns3-l2.nic.ru.</name><idn-name>ns3-l2.nic.ru.</idn-name></ns></rr>
<rr id="210076"><name>@</name><idn-name>@</idn-name><type>NS</type><ns><name>ns4-l2.nic.ru.</name><idn-name>ns4-l2.nic.ru.</idn-name></ns></rr>
<rr id="210077"><name>@</name><idn-name>@</idn-name><type>NS</type><ns><name>ns8-l2.nic.ru.</name><idn-name>ns8-l2.nic.ru.</idn-name></ns></rr>
</zone>
</data>
</response>`
	str := APIResponseZoneRecords{}
	err := xml.Unmarshal([]byte(s), &str)
	if err != nil {
		panic(fmt.Sprintf("xml.Unmarshal() failed: %v",err))
	}
	fmt.Println(str)
}

func TestGetZoneRecords(t *testing.T) {	
	man := CreateFromFile()		
	records, err := man.GetZoneRecords()
	if err != nil {
		panic(fmt.Sprintf("TestGetZoneRecords() failed: %v",err))
	}	
	//fmt.Println("rec:")
	//fmt.Println(rec)
	for _, rec := range records {
		if rec.Ttl != "0" {
			//fmt.Println(rec.Id)
			fmt.Printf("Rec: %+v\n", rec)
		}
	}	
}

func TestAddTextZoneRecord(t *testing.T) {	
	man := CreateFromFile()	
	/*rec_t1 := ZoneRecord{Name: "test.katren.org.",
		//Ttl: "0",
		Type: "TXT",
		A: "Aaaa",
		Txt: &ZoneRecordTXTVal{String: "TestRecordValue1"},
	}
	*/
	rec_t1 := ZoneRecord{Name: "test2.katren.org.",
		//Ttl:3600,
		Type: "A",
		A: "178.46.157.185",
	}
	
	rec:= APIRequestZoneRecords{Records: []ZoneRecord{rec_t1}}
	err := man.AddZoneRecord(&rec)
	if err != nil {
		panic(fmt.Sprintf("AddZoneRecord() failed: %v",err))
	}	
}

func TestRollback(t *testing.T) {	
	man := CreateFromFile()		
	err := man.Rollback()
	if err != nil {
		panic(fmt.Sprintf("TestRollback() failed: %v",err))
	}	
}

func TestCommit(t *testing.T) {	
	man := CreateFromFile()		
	err := man.Commit()
	if err != nil {
		panic(fmt.Sprintf("Commit() failed: %v",err))
	}	
}

