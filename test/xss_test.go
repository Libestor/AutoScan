package test

import (
	Spider "AutoScan/pkg/spider"
	xss "AutoScan/pkg/vul/xss"
	"net/url"
	"strings"
	"testing"
)

func TestRunXssScan(t *testing.T) {
	datas := getData()
	var xssData []Spider.RequestInfo
	for _, data := range datas {
		if strings.Contains(data.URL, "xss") {
			xssData = append(xssData, data)
		}
	}
	flag := true
	results := xss.RunXssScan(xssData)
	for _, i := range results {
		if i.IsXss {
			flag = false
			t.Log(i.URL, i.Method, i.XssParams)
		}
	}
	if flag {
		t.Error("xss注入测试失败")
	}
}
func TestCheckReflectXss(t *testing.T) {
	url := "http://127.0.0.1/pikachu/vul/xss/xss_reflected_get.php?message=<script>prompt('cqupt');</script>&submit=submit"
	text := "cqupt"
	xssResult := xss.XssResult{
		Driver: xss.GetDriver(),
		URL:    url,
		Method: "GET",
	}
	result := xssResult.CheckReflectXss(url, text)
	if !result {
		t.Errorf("CheckReflectXss() = %v, want %v", result, true)
	}
}
func TestGetRandomString(t *testing.T) {
	for i := 0; i < 10; i++ {
		result := xss.GetRandString()
		t.Logf("GetRandomString() = %s", result)
	}
	// 目标 URL
	apiUrl := "http://example.com/api"

	// 1. 创建 url.Values 实例
	params := url.Values{}

	// 2. 添加键值对（模拟字典数据）
	params.Set("name", "a")
	params.Set("age", "18")

	// 3. 解析原始 URL 并附加参数
	u, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		panic("URL 解析失败")
	}
	u.RawQuery = params.Encode() // 编码并附加查询参数

	// 输出最终 URL
	t.Log(u.String())
}
func TestGetReflectXssPayloads(t *testing.T) {
	// 目标 URL
	xssResult := xss.XssResult{
		URL:    "http://127.0.0.1/pikachu/vul/xss/xss_01.php",
		Method: "GET",
		Params: map[string]string{
			"message": "a",
			"submit":  "submit",
		},
	}
	payloads := xssResult.GetReflectXssPayloads()
	// 输出最终 URL
	for url1, text := range payloads {
		t.Log(url1, text)
	}
}
func TestXss(t *testing.T) {
	xssResult := xss.XssResult{
		Driver: xss.GetDriver(),
		URL:    "http://127.0.0.1/pikachu/vul/xss/xss_01.php",
		Method: "GET",
		Params: map[string]string{
			"message": "a",
			"submit":  "submit",
		},
	}
	xssResult.TestXSS()
	if xssResult.IsXss {
		t.Log("XSS 注入成功")
		t.Log("Xssparams:", xssResult.XssParams)
	} else {
		t.Error("xss注入失败")
	}
}

func TestGetStoreXssPayloads(t *testing.T) {
	xssResult := xss.XssResult{
		Driver: xss.GetDriver(),
		URL:    "http://127.0.0.1/pikachu/vul/xss/xss_01.php",
		Method: "POST",
		Params: map[string]string{
			"message": "a",
			"submit":  "submit",
		},
	}
	payloads := xssResult.GetStoreXssPayloads()
	for url1, text := range payloads {
		for k, v := range text {
			t.Log(url1, k, v)
		}
	}
	if len(payloads) == 0 {
		t.Error("payloads is empty")
	}
}
