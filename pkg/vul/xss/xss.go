package xss

import (
	Spider "AutoScan/pkg/spider"
	"AutoScan/pkg/utils"
	"fmt"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"log"
	"math/rand"
	"net/url"
	"sync"
	"time"
)

const (
	chromeDriverPath = "C:\\Users\\你好，五月\\Desktop\\实验组\\毕业设计\\chromedriver-win64\\chromedriver-win64\\chromedriver.exe"
	chromePath       = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
	MAX_GOROUTINES   = 10
	CHAARSET         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var PAYLOADS = []string{
	"<SCRiPT>alert('%s')</SCRiPT>",
	"<scrIpt>prompt('%s');</scrIpt>",
	"<scrIpt>confirm('%s');</scrIpt>",
	"';alert('%s');//",
	"\" onmouseover=alert('%s')\"",
	"<img src=\"#\" οnerrοr=alert('%s')>",
}

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
	Rand    *rand.Rand
	caps    selenium.Capabilities
}

var randXss *rand.Rand
var server WebDriverServer
var client utils.Client

func init() {
	// 初始化浏览器驱动
	var err error
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
		Args: []string{
			"--disable-notifications",
			"--disable-popup-blocking",
			"--disable-dev-shm-usage",
			"--headless",
		},
	}
	server.caps.AddChrome(chromeCaps)
	server.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	client.InitClient()
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
	data := []*XssResult{}
	wg := sync.WaitGroup{}
	// 用信号量来控制并发数量
	sem := make(chan struct{}, MAX_GOROUTINES)
	defer close(sem)
	// 并发测试
	for _, info := range rawData {
		sem <- struct{}{}
		params := utils.GetParams(info)
		result := &XssResult{
			Driver:      GetDriver(),
			URL:         info.URL,
			Method:      info.Method,
			Params:      params,
			RequestType: info.RequestType,
		}
		go func() {
			wg.Add(1)
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
	for key, _ := range r.Params {
		for _, payload := range PAYLOADS {
			rStr := GetRandString()
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
	for key, _ := range r.Params {
		for _, payload := range PAYLOADS {
			rStr := GetRandString()
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
	r.Driver.Get(url)
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

// GetRandString 获取随机四位的字符串
func GetRandString() string {
	b := make([]byte, 4)
	for i := range b {
		b[i] = CHAARSET[server.Rand.Intn(len(CHAARSET))]
	}
	return string(b)
}
