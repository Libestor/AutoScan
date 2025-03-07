package spider_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)
import "AutoScan/pkg/spider"

func TestNewSpider(t *testing.T) {
	s, err := Spider.NewSpider()
	if err != nil {
		t.Error("Error creating spider:", err)
	}
	t.Error("hi")
	t.Error(s)
	s.Stop()

}

func TestSpider(t *testing.T) {
	t.Error("开始测试Spider")
	spider, err := Spider.NewSpider()
	if err != nil {
		t.Error("Error creating spider:", err)
	}
	err = spider.Start("http://127.0.0.1/pikachu", "http://127.0.0.1/pikachu")
	if err != nil {
		t.Error("Error starting spider:", err)
	}

	t.Errorf("发现 %d 个端点：\n", len(spider.Results))
	for i, item := range spider.Results {
		t.Errorf("%d. %s %s\n", i+1, item.Method, item.URL)
		params, _ := json.MarshalIndent(item.Params, "", "  ")
		t.Errorf("参数: %s\n", params)
		t.Errorf(strings.Repeat("-", 50))
	}

	if err != nil {
		t.Error(err)
	}
	file, err := os.OpenFile("pikachu.json", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	encoder := json.NewEncoder(file)
	err = encoder.Encode(spider.Results)
	if err != nil {
		t.Error(err)
	}
	defer spider.Stop()
}
func TestGetURL(t *testing.T) {
	url := "http://127.0.0.1/a/v/c#"
	url = Spider.GetURL(url)
	t.Error(url)

}
func TestParseQuery(t *testing.T) {
	query := "a=1&b=2&c=3"
	params := Spider.ParseQuery(query)
	t.Error(params)
}
