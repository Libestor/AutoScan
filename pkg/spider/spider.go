package Spider

import (
	"encoding/json"
	"fmt"
	"log"
	URL "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

type RequestInfo struct {
	URL    string
	Method string
	Params map[string][]string
}

type Spider struct {
	service    *selenium.Service
	driver     selenium.WebDriver
	Results    []RequestInfo
	visited    map[string]bool
	added      map[string]bool
	urlQueue   chan string
	baseDomain string
	mu         sync.Mutex
}

const (
	chromeDriverPath = "C:\\Users\\你好，五月\\Desktop\\实验组\\毕业设计\\chromedriver-win64\\chromedriver-win64\\chromedriver.exe"
	chromePath       = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
)

func NewSpider() (*Spider, error) {
	// 初始化Chrome驱动
	service, err := selenium.NewChromeDriverService(chromeDriverPath, 4444)
	if err != nil {
		log.Fatal("Error starting driver:", err)
	}
	//defer service.Stop()

	caps := selenium.Capabilities{
		"browserName": "chrome",
		"goog:loggingPrefs": map[string]interface{}{
			"performance": "ALL",
		},
	}

	// Chrome选项配置
	chromeCaps := chrome.Capabilities{
		Path: chromePath,
		Args: []string{
			"--disable-notifications",
			"--disable-popup-blocking",
			"--disable-dev-shm-usage",
			//"--headless",
		},
		Prefs: map[string]interface{}{
			"profile.default_content_setting_values.popups":        2,
			"profile.default_content_setting_values.notifications": 2,
		},
		ExcludeSwitches: []string{
			"enable-logging",
			"disable-popup-blocking",
		},
	}
	caps.AddChrome(chromeCaps)

	driver, err := selenium.NewRemote(caps, "")
	if err != nil {
		log.Fatal("Error creating web driver:", err)
	}

	// 初始化爬虫
	spider := &Spider{
		service:  service,
		driver:   driver,
		visited:  make(map[string]bool),
		added:    make(map[string]bool),
		urlQueue: make(chan string, 100),
	}
	return spider, nil
}

func (s *Spider) Start(startUrl string, baseDomain string) error {
	s.baseDomain = baseDomain
	s.addurlQueue(startUrl)
	s.urlQueue <- startUrl
	s.driver.Get(startUrl)
	// 设置Cookie
	err := s.setCookies()
	if err != nil {
		return err
	}
	// 关闭弹窗
	s.disablePrompt()
	// 开始爬取
	s.dynamicSpider()
	// 去重
	s.deduplicate()
	return nil
}
func (s *Spider) Stop() {
	close(s.urlQueue)
	s.driver.Quit()
	s.service.Stop()
}

// 设置cookie
func (s *Spider) setCookies() error {
	cookies := []selenium.Cookie{
		{Name: "token", Value: ""},
		{Name: "JSESSIONID", Value: ""},
	}

	for _, cookie := range cookies {
		if err := s.driver.AddCookie(&cookie); err != nil {
			return err
		}
	}
	return nil
}

// 关闭弹窗
func (s *Spider) disablePrompt() {
	// 关闭弹窗
	_, err := s.driver.ExecuteScript("window.alert = function() {};", nil)
	if err != nil {
		fmt.Println(err)
	}
	_, err = s.driver.ExecuteScript("window.confirm = function() { return true; };", nil)
	if err != nil {
		fmt.Println(err)
	}
	_, err = s.driver.ExecuteScript("window.prompt = function() { return ''; };", nil)
	if err != nil {
		fmt.Println(err)
	}

}

// 开始循环进行动态爬取
func (s *Spider) dynamicSpider() {
	for {
		select {
		case v := <-s.urlQueue:
			s.spiderPage(v)
		default:
			return
		}
	}

}

// 对当前页面进行爬取
func (s *Spider) spiderPage(url string) {
	url = GetURL(url)
	s.mu.Lock()
	if s.visited[url] {
		s.mu.Unlock()
		return
	}
	s.visited[url] = true
	s.mu.Unlock()

	if !strings.Contains(url, s.baseDomain) {
		return
	}

	fmt.Printf("[+]当前页面为：%s\n", url)
	if err := s.driver.Get(url); err != nil {
		fmt.Printf("Error loading page: %v", err)
		return
	}

	// 处理网络请求
	//log.Println("开始处理网络请求")
	s.processNetworkRequests()
	// 提交页面表单
	//log.Println("开始提交表单")
	s.processForms()
	// 模拟点击页面
	//log.Println("开始模拟点击")
	s.handleInteractiveElements()
	// 页面信息抓取
	//log.Println("开始抓取页面信息")
	s.processPageContent()

}

func (s *Spider) processNetworkRequests() {
	logs, err := s.driver.Log("performance")
	if err != nil {
		fmt.Printf("Error getting logs: %v", err)
		return
	}

	for _, logEntry := range logs {
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(logEntry.Message), &msg); err != nil {
			continue
		}

		if message, ok := msg["message"].(map[string]interface{}); ok {
			if method, ok := message["method"].(string); ok && method == "Network.requestWillBeSent" {
				params, _ := message["params"].(map[string]interface{})
				request, _ := params["request"].(map[string]interface{})
				s.processRequest(request)
			}
		}
	}
}

// 处理网络日志中的请求
func (s *Spider) processRequest(request map[string]interface{}) {
	url, _ := request["url"].(string)
	if !strings.Contains(url, s.baseDomain) {
		return
	}
	method, _ := request["method"].(string)
	var params map[string][]string
	// 过滤静态资源
	if isStaticResource(url) {
		return
	}
	if method == "POST" {
		//fmt.Printf("[+]发现POST请求：%s\n", url)
		//params = request["postData"].(map[string][]string)
		params = ParseQuery(request["postData"].(string))
	}
	// 解析参数
	if method == "GET" {
		//fmt.Printf("[+]发现GET请求：%s\n", url)
		parsedURL, _ := URL.Parse(url)
		params = ParseQuery(parsedURL.RawQuery)
	}

	// 添加请求信息
	reqInfo := RequestInfo{
		URL:    GetURL(url),
		Method: strings.ToUpper(method),
		Params: params,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.Results = append(s.Results, reqInfo)
}

// 处理表单
func (s *Spider) processForms() {
	s.disablePrompt()
	forms, err := s.driver.FindElements(selenium.ByTagName, "form")
	if err != nil {
		fmt.Printf("processForms Error finding forms: %v\n", err)
		return
	}

	for _, form := range forms {
		inputs, _ := form.FindElements(selenium.ByXPATH, ".//input | .//textarea | .//select")
		for _, input := range inputs {
			tagName, _ := input.TagName()
			inputType, _ := input.GetAttribute("type")

			switch tagName {
			case "input":
				switch inputType {
				case "text", "email", "search", "password":
					input.SendKeys("test_data")
				case "checkbox", "radio":
					input.Click()
				}
			case "textarea":
				input.SendKeys("sample_text_content")
			case "select":
				options, _ := input.FindElements(selenium.ByTagName, "option")
				if len(options) > 0 {
					options[0].Click()
				}
			}

		}

		if err := form.Submit(); err == nil {
			time.Sleep(100 * time.Millisecond)
			s.driver.Back()
		}
	}
}

// 模拟用户点击
func (s *Spider) handleInteractiveElements() {
	selectors := []string{
		"a", "button", "[role='button']", "[onclick]",
		"[data-toggle]", ".btn", "[href^='javascript']", "[data-target]",
	}

	for _, selector := range selectors {
		elements, err := s.driver.FindElements(selenium.ByCSSSelector, selector)
		if err != nil {
			fmt.Printf("handleInteractiveElements Error finding elements: %v\n", err)
			continue
		}

		for _, elem := range elements {
			if isVisible, _ := elem.IsDisplayed(); isVisible {
				if err := elem.Click(); err == nil {
					time.Sleep(100 * time.Millisecond)
					s.processNetworkRequests()
				}
			}
		}
	}
}

func (s *Spider) processPageContent() {
	s.extractLinks(selenium.ByTagName, "a")

	// 处理iframe
	frames, _ := s.driver.FindElements(selenium.ByTagName, "iframe")
	for _, frame := range frames {
		s.driver.SwitchFrame(frame)
		s.extractLinks(selenium.ByTagName, "a")
		s.driver.SwitchFrame(nil)
	}
}

func (s *Spider) extractLinks(by string, value string) {
	links, err := s.driver.FindElements(by, value)
	if err != nil {
		fmt.Printf("Error finding links: %v\n", err)
		return
	}

	for _, link := range links {
		href, _ := link.GetAttribute("href")
		if href != "" && strings.Contains(href, s.baseDomain) {
			s.mu.Lock()
			s.addurlQueue(href)
			s.mu.Unlock()
		}
	}
}

// 辅助函数
func isStaticResource(url string) bool {
	url = GetURL(url)
	extensions := []string{".css", ".js", ".png", ".jpg", ".gif", ".woff", ".woff2", ".ico"}
	for _, ext := range extensions {
		if strings.HasSuffix(url, ext) {
			return true
		}
	}
	return false
}
func (s *Spider) addurlQueue(url string) {
	url = GetURL(url)
	if !strings.Contains(url, s.baseDomain) {
		return
	}
	if s.visited[url] == false && s.added[url] == false {
		s.urlQueue <- url
		s.added[url] = true
	}
}
func (s *Spider) deduplicate() {

	seen := make(map[string]bool)
	var uniqueResults []RequestInfo
	results := s.Results
	for _, item := range results {
		// 序列化参数并保持键有序
		keys := make([]string, 0, len(item.Params))
		for k := range item.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// 构建有序参数字符串
		var paramsBuilder strings.Builder
		paramsBuilder.WriteString("{")
		for i, k := range keys {
			values := item.Params[k]
			paramsBuilder.WriteString(fmt.Sprintf("%q:[", k))
			for vi, v := range values {
				paramsBuilder.WriteString(fmt.Sprintf("%q", v))
				if vi < len(values)-1 {
					paramsBuilder.WriteString(",")
				}
			}
			paramsBuilder.WriteString("]")
			if i < len(keys)-1 {
				paramsBuilder.WriteString(",")
			}
		}
		paramsBuilder.WriteString("}")

		// 生成唯一标识符
		identifier := fmt.Sprintf("%s|%s|%s",
			item.Method,
			item.URL,
			paramsBuilder.String())

		// 检查是否已存在
		if !seen[identifier] {
			seen[identifier] = true
			uniqueResults = append(uniqueResults, item)
		}
	}

	s.Results = uniqueResults

}
func ParseQuery(query string) map[string][]string {
	params, _ := URL.ParseQuery(query)
	return params
}

func GetURL(url string) string {
	if strings.HasSuffix(url, "#") {
		url = url[:len(url)-1]
	}
	part := strings.Split(url, "?")
	//parsedURL, _ := URL.Parse(url)
	return part[0]
}
