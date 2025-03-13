package xss

import (
	"AutoScan/pkg/configs"
	Spider "AutoScan/pkg/spider"
	"AutoScan/pkg/utils"
	"encoding/xml"
	"fmt"
	"github.com/fatih/color"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"log"
	"net/url"
	"os"
	"sync"
)

type XssResult struct {
	Driver      selenium.WebDriver
	URL         string
	Method      string
	Params      map[string]string
	RequestType string
	IsXss       bool
	XssParams   string
	Note        string
}
type WebDriverServer struct {
	//Driver  selenium.WebDriver
	Service *selenium.Service
	caps    selenium.Capabilities
}

var (
	chromeDriverPath = ""
	chromePath       = ""
	MaxGoroutines    = 10
	server           WebDriverServer
	client           utils.Client
	PAYLOADS         []string
	BROWSER_ARGS     []string
)

func InitConfig() {
	if !configs.CheckChrome() {
		fmt.Printf("[%s] Chrome 模块初始化失败，XSS模块退出\n", color.RedString("ERROR"))
		return
	}
	var err error
	// 读取配置文件
	xmlFile, err := os.ReadFile(configs.GetConfig().VulConfig.XssConfig.PayloadFiles)
	if err != nil {
		fmt.Println("Error reading XML file:", err)
		return
	}

	// 解析 XML 数据
	var config Config
	err = xml.Unmarshal(xmlFile, &config)
	if err != nil {
		fmt.Println("Error unmarshalling XML:", err)
		return
	}
	PAYLOADS = config.PAYLOADS.Items
	BROWSER_ARGS = config.BROWSER_ARGS.Items
	chromeDriverPath = configs.GetConfig().ChromeDriverPath
	chromePath = configs.GetConfig().ChromePath
	MaxGoroutines = configs.GetConfig().VulConfig.XssConfig.MaxGoroutines
	// 初始化浏览器驱动

	server.Service, err = selenium.NewChromeDriverService(chromeDriverPath, 4444)
	if err != nil {
		fmt.Println("Init ChromeDriver server:", err)
	}
	server.caps = selenium.Capabilities{
		"browserName": "chrome",
		"goog:loggingPrefs": map[string]interface{}{
			"performance": "ALL",
		},
	}
	chromeCaps := chrome.Capabilities{
		Path: chromePath,
		Args: BROWSER_ARGS,
	}
	server.caps.AddChrome(chromeCaps)
	client.InitClient()
}

type Config struct {
	XMLName      xml.Name `xml:"xss"`
	BOOLNUMDIR   MapData  `xml:"BOOLNUMDIR"`
	BOOLCHAR     MapData  `xml:"BOOLCHAR"`
	TIMEDIR      MapData  `xml:"TIMEDIR"`
	ERRORDIR     ListData `xml:"ERRORDIR"`
	PAYLOADS     ListData `xml:"PAYLOADS"`
	BROWSER_ARGS ListData `xml:"BROWSER_ARGS"`
}
type MapData struct {
	Items []Item `xml:"item"`
}

type ListData struct {
	Items []string `xml:"item"`
}

type Item struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func init() {

}

// GetDriver 获得一个浏览器驱动
func GetDriver() selenium.WebDriver {
	Driver, err := selenium.NewRemote(server.caps, "")
	if err != nil {
		log.Fatal("Error creating web driver:", err)
	}
	return Driver
}

// RunXssScan 启动XSS扫描
func RunXssScan(rawData []Spider.RequestInfo) []XssResult {
	InitConfig()
	data := []*XssResult{}
	wg := sync.WaitGroup{}
	// 用信号量来控制并发数量
	sem := make(chan struct{}, MaxGoroutines)
	defer close(sem)
	// 并发测试
	for _, info := range rawData {
		sem <- struct{}{}
		params := utils.GetParams(&info)
		result := &XssResult{
			Driver:      GetDriver(),
			URL:         info.URL,
			Method:      info.Method,
			Params:      params,
			RequestType: info.RequestType,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result.TestXSS()
			<-sem
		}()
		data = append(data, result)
	}
	wg.Wait()
	fmt.Println("xss注入测试完毕")
	results := []XssResult{}
	for _, i := range data {
		results = append(results, *i)
	}
	return results
}

// TestXSS 单个XSS测试的核心函数
func (r *XssResult) TestXSS() {
	// Get请求使用反射型XSS
	if r.Method == "GET" {
		for payload, text := range r.GetReflectXssPayloads() {
			if r.CheckReflectXss(payload, text) {
				r.IsXss = true
				r.XssParams = payload
				r.Note = "反射型XSS"
				return
			}

		}
	} else {
		payloads := r.GetStoreXssPayloads()
		for _, payload := range payloads {
			_, err := client.Request(r.URL, r.Method, payload, r.RequestType)
			if err != nil {
				fmt.Println("GetStoreXssPayloads Request error:", err)
				continue
			}
		}
		keys := make([]string, 0, len(payloads))
		for key := range payloads {
			keys = append(keys, key)
		}
		res, text := r.CheckStoreXss(r.URL, keys)
		if res {
			params := ""
			for k, v := range payloads[text] {
				params += k + "=" + v
				params += "&"
			}
			r.IsXss = true
			r.XssParams = params
			r.Note = "存储型XSS"
			return
		}

	}
	err := r.Driver.Close()
	if err != nil {
		fmt.Println("Close driver error:", err)
	}
}

// GetReflectXssPayloads 获取反射型XSS的payload
func (r *XssResult) GetReflectXssPayloads() map[string]string {
	payloads := make(map[string]string)
	for key := range r.Params {
		for _, payload := range PAYLOADS {
			rStr := utils.GetRandString()
			value := url.Values{}
			for k, v := range r.Params {
				if k == key {
					value.Add(k, v+fmt.Sprintf(payload, rStr))
				} else {
					value.Add(k, v)
				}
			}
			u, err := url.ParseRequestURI(r.URL)
			if err != nil {
				fmt.Println("GetReflectXssPayloads URL 解析失败")
				continue
			}
			u.RawQuery = value.Encode() // 编码并附加查询参数
			payloads[u.String()] = rStr
		}
	}
	return payloads
}

// GetStoreXssPayloads 获取xss储存型的payload
func (r *XssResult) GetStoreXssPayloads() map[string]map[string]string {
	payloads := make(map[string]map[string]string)
	for key := range r.Params {
		for _, payload := range PAYLOADS {
			rStr := utils.GetRandString()
			value := map[string]string{}
			for k, v := range r.Params {
				if k == key {
					value[k] = v + fmt.Sprintf(payload, rStr)
				} else {
					value[k] = v
				}
			}
			payloads[rStr] = value
		}
	}
	return payloads
}

// CheckReflectXss 检查是否为反射型XSS
func (r *XssResult) CheckReflectXss(url string, text string) bool {

	err := r.Driver.Get(url)
	if err != nil {
		fmt.Println("Get url error:", err)
		return false
	}
	// 检查是否存在alert弹窗

	res, alsertText := r.CheckAlert()
	if res {
		// 检查alert弹窗内容是否为text
		for _, v := range alsertText {
			if v == text {
				return true
			}
		}
		//fmt.Println("CheckReflectXss alert弹窗内容不一致")
		return false
	} else {
		return false
	}
}

// CheckAlert 检查是否存在alert弹窗
func (r *XssResult) CheckAlert() (bool, []string) {
	result := []string{}
	for {
		alert, err := r.Driver.AlertText()
		err = r.Driver.AcceptAlert()
		if err != nil { // 无弹窗时退出循环
			break
		}
		result = append(result, alert)
	}
	if len(result) == 0 {
		return false, result
	} else {
		return true, result
	}
}

// CheckStoreXss 检查是否为存储型XSS
func (r *XssResult) CheckStoreXss(url string, AlertText []string) (bool, string) {
	err := r.Driver.Get(url)
	if err != nil {
		fmt.Println("CheckStoreXss Get url error:", err)
		return false, ""
	}
	// 检查是否存在alert弹窗
	alert, texts := r.CheckAlert()

	if alert {
		for _, text := range texts {
			for _, Alert := range AlertText {
				if text == Alert {
					return true, text
				}
			}
		}
	}
	return false, ""
}
