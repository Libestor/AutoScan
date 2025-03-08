package spider_test

import (
	"encoding/json"
	"os"
	"testing"
)
import "AutoScan/pkg/spider"

func TestNewSpider(t *testing.T) {
	s, err := Spider.NewSpider()
	if err != nil {
		t.Error("Error creating spider:", err)
	}
	t.Log(s)
	s.Stop()

}

func TestSpider(t *testing.T) {
	t.Log("开始测试Spider")
	errors := false
	spider, err := Spider.NewSpider()
	if err != nil {
		t.Error("Error creating spider:", err)
		errors = true
	}
	err = spider.Start("http://127.0.0.1/pikachu", "http://127.0.0.1/pikachu")
	if err != nil {
		t.Error("Error starting spider:", err)
		errors = true
	}
	defer spider.Stop()

	postNum := 0
	getNum := 0
	postParamsNum := make(map[string]bool)
	getParamsNum := make(map[string]bool)
	for _, result := range spider.Results {

		if result.Method == "POST" {
			postNum++
			if len(result.Params) > 0 {
				postParamsNum[result.URL] = true
			}
		} else if result.Method == "GET" {
			getNum++
			if len(result.Params) > 0 {
				getParamsNum[result.URL] = true
			}
		}
	}
	if len(postParamsNum) != 18 {
		t.Error("POST带参请求存在错误，应该有18个，实际有", len(postParamsNum))
		errors = true
	}
	if len(getParamsNum) != 26 {
		t.Error("GET带参请求存在错误，应该有26个，实际有", len(getParamsNum))
		errors = true
	}
	t.Log("接口数量：", len(spider.Results))
	t.Log("POST请求数量（参考值：21）：", postNum)
	t.Log("GET请求数量：", getNum)
	t.Log("POST带参请求数量（参考值：18）：", len(postParamsNum))
	t.Log("GET带参请求数量（参考值：26）：", len(getParamsNum))
	t.Log("总有参接口数量（参考值：44）：", len(getParamsNum)+len(postParamsNum))
	//保存文件
	if errors == true {
		t.Log("保存文件")
		file, err := os.OpenFile("pikachu.json", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Error(err)
		}
		encoder := json.NewEncoder(file)
		err = encoder.Encode(spider.Results)
		if err != nil {
			t.Error(err)
		}
	}

}

func TestGetURL(t *testing.T) {
	url := "http://127.0.0.1/a/v/c#"
	url = Spider.GetURL(url)
	t.Log(url)

}
func TestParseQuery(t *testing.T) {
	query := "a=1&b=2&c=3"
	params, requestType := Spider.ParseQuery(query)
	if params["a"][0] != "1" || params["b"][0] != "2" || params["c"][0] != "3" || requestType != "application/x-www-form-urlencoded" {
		t.Error("Error parsing query")
	}

	query2 := `{"a":"1","b":"2","c":"3"}`
	params2, requestType := Spider.ParseQuery(query2)
	if params2["a"][0] != "1" || params2["b"][0] != "2" || params2["c"][0] != "3" || requestType != "application/json" {
		t.Error("Error parsing query2")
	}

}
