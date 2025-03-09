package test

import (
	"AutoScan/pkg/commonVul/sqli"
	Spider "AutoScan/pkg/spider"
	"encoding/json"
	"fmt"
	"github.com/agnivade/levenshtein"
	"github.com/go-resty/resty/v2"
	"math"
	"math/rand"
	"os"
	"testing"
)

func TestRunSqlScan(t *testing.T) {
	rawData := getData()
	results := sqli.RunSqlScan(rawData)
	i := 0
	for _, result := range results {
		if result.IsSqli {
			t.Log(result.URL, result.Method, result.IsSqli, result.SqlParams, result.Note)
			i++
		}
	}

}

func TestGetRequest(t *testing.T) {
	client := resty.New()
	resp, err := client.R().SetQueryParams(map[string]string{
		"id": "1",
	}).Get("http://127.0.0.1/pikachu/index.php")
	if err != nil {
		t.Error("Error:", err)
	}
	t.Log("resp string:", resp.String())
	t.Log("resp StatusCode:", resp.StatusCode())
	t.Log("resp Status:", resp.Status())
	t.Log("resp Header:", resp.Header())
	t.Log("resp Time:", resp.Time())
	t.Log("resp Error:", err)
}
func TestPostRequest(t *testing.T) {
	client := resty.New()
	//client.SetProxy("http://127.0.0.1:8080")
	resp, err := client.R().
		SetFormData(map[string]string{
			"xml":    "a",
			"submit": "submit",
		}).Post("http://127.0.0.1/pikachu/vul/xxe/xxe_1.php")
	if err != nil {
		t.Error("Error:", err)
		return
	}
	t.Log("resp String:", resp.String())
	t.Log("resp StatusCode:", resp.StatusCode())
	t.Log("resp Status:", resp.Status())
	t.Log("resp Header:", resp.Header())
	t.Log("resp Time:", resp.Time())
	t.Log("resp Error:", err)
	resp, err = client.R().
		SetBody(map[string]string{
			"xml":    "a",
			"submit": "submit",
		}).Post("http://127.0.0.1/pikachu/vul/xxe/xxe_1.php")
	if err != nil {
		t.Error("Error:", err)
		return
	}
	t.Log("resp String:", resp.String())
	t.Log("resp StatusCode:", resp.StatusCode())
	t.Log("resp Status:", resp.Status())
	t.Log("resp Header:", resp.Header())
	t.Log("resp Time:", resp.Time())
	t.Log("resp Error:", err)
}

func getRandData() Spider.RequestInfo {
	getData := getData()
	num := rand.Intn(len(getData) - 1)
	return getData[num]
}
func getOneData() Spider.RequestInfo {
	getData := getData()
	return getData[0]
}
func getData() []Spider.RequestInfo {
	rawData := []Spider.RequestInfo{}
	jsonFile, err := os.Open("pikachu.json")
	if err != nil {
		fmt.Println("Error opening JSON file:", err)
	}
	defer jsonFile.Close()
	decoder := json.NewDecoder(jsonFile)
	err = decoder.Decode(&rawData)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
	}
	Pdata := []Spider.RequestInfo{}
	for _, data := range rawData {
		if len(data.Params) > 0 {
			Pdata = append(Pdata, data)
		}
	}
	return Pdata
}
func TestErrorSqli(t *testing.T) {
	spider := Spider.RequestInfo{
		URL:    "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php",
		Method: "GET",
		Params: map[string][]string{
			"name": {"test_data"},
		},
		RequestType: "application/x-www-form-urlencoded",
	}
	result, target := sqli.ErrorSqli(spider)
	if !result {
		t.Error("ErrorSqli failed")
	}
	t.Log("URL:", spider.URL)
	t.Log("target:", target)
}
func TestCheckBool(t *testing.T) {
	str1 := "test_data13sdfasasdfasdferr23412341asdfasdfasdfasdfasdf23qwerwqe1234123erwqerqwer1221341234wqerqwcacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13caca"
	str2 := "test_data2cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13cacatest_data13caca"
	distance := levenshtein.ComputeDistance(str1, str2)
	maxLen := math.Max(float64(len(str1)), float64(len(str2)))
	SIMILARITY := 0.99
	distanceF := float64(distance)
	t.Log("distance:", distance)
	t.Log("maxLen:", maxLen)
	t.Log("similarity:", 1-distanceF/maxLen)
	t.Log("similarity:", 1-distanceF/maxLen > SIMILARITY)
	t.Log("similarity:", 1-distanceF/maxLen < SIMILARITY)
}
func TestBoolSqli(t *testing.T) {
	spider := Spider.RequestInfo{
		URL:    "http://127.0.0.1/pikachu/vul/sqli/sqli_id.php",
		Method: "POST",
		Params: map[string][]string{
			"id": {"2"},
		},
		RequestType: "application/x-www-form-urlencoded",
	}
	result, target := sqli.BoolSqli(spider)
	if !result {
		t.Error("ErrorSqli failed")
	}
	t.Log("URL:", spider.URL)
	t.Log("target:", target)
}
func TestTimeSqli(t *testing.T) {
	spider := Spider.RequestInfo{
		URL:    "http://127.0.0.1/pikachu/vul/sqli/sqli_search.php",
		Method: "GET",
		Params: map[string][]string{
			"name": {"test"},
		},
		RequestType: "application/x-www-form-urlencoded",
	}
	result, target := sqli.TimeSqli(spider)
	if !result {
		t.Error("ErrorSqli failed")
	}
	t.Log("URL:", spider.URL)
	t.Log("target:", target)
}
func TestCalcTime(t *testing.T) {
	spider := Spider.RequestInfo{
		URL:    "http://127.0.0.1/pikachu/vul/sqli/sqli_str.php",
		Method: "GET",
		Params: map[string][]string{
			"name": {"test"},
		},
		RequestType: "application/x-www-form-urlencoded",
	}
	timeSqlInfo := sqli.TimeSqlInfo{}
	timeSqlInfo.CalcTime(spider)
	t.Log("Average:", timeSqlInfo.Average)
	t.Log("Deviation:", timeSqlInfo.Deviation)
}
