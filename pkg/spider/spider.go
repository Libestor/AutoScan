package Spider

import (
	"AutoScan/pkg/configs"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/fatih/color"
	URL "net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

type RequestInfo struct {
	URL         string
	Method      string
	Params      map[string][]string
	RequestType string
}

type Spider struct {
	service    *selenium.Service
	driver     selenium.WebDriver
	Results    []RequestInfo
	visited    map[string]bool
	added      map[string]bool
	urlQueue   chan string
	elemSha256 map[string]bool
	baseDomain string
}
type Config struct {
	XMLName     xml.Name `xml:"spider"`
	BrowserArgs ListData `xml:"BROWSER_ARGS"`
	Selector    ListData `xml:"SELECTOR"`
}

type ListData struct {
	Items []string `xml:"item"`
}
type Item struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

var (
	chromeDriverPath = ""
	chromePath       = ""
	BrowserArgs      []string
	SELECTOR         []string
	SpiderFillString = "spider_test_data"
)

// NewSpider 初始化爬虫
func NewSpider() (*Spider, error) {
	if !configs.CheckChrome() {
		return nil, fmt.Errorf("chrome 模块初始化失败，Spider模块退出")
	}
	// 初始化变量
	chromeDriverPath = configs.GetConfig().ChromeDriverPath
	chromePath = configs.GetConfig().ChromePath
	SpiderFillString = configs.GetConfig().SpiderConfig.SpiderFillString
	if chromeDriverPath == "" || chromePath == "" {
		return nil, fmt.Errorf("ChromeDriverPath 或 ChromePath 为空")
	}
	// 读取配置文件
	xmlFile, err := os.ReadFile(configs.GetConfig().SpiderConfigFile)
	if err != nil {
		return nil, fmt.Errorf("xml文件读取失败：%s", err)
	}

	// 解析 XML 数据
	var config Config
	err = xml.Unmarshal(xmlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("xml文件解析失败：%s", err)
	}
	BrowserArgs = config.BrowserArgs.Items
	SELECTOR = config.Selector.Items
	// 初始化Chrome驱动
	service, err := selenium.NewChromeDriverService(chromeDriverPath, 4444)
	if err != nil {
		return nil, err
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
		Args: BrowserArgs,
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
		return nil, fmt.Errorf("创建driver失败：%s", err)
	}

	// 初始化爬虫
	spider := &Spider{
		service:    service,
		driver:     driver,
		visited:    make(map[string]bool),
		added:      make(map[string]bool),
		urlQueue:   make(chan string, 100),
		elemSha256: make(map[string]bool),
	}
	return spider, nil
}

// Start 启动爬虫扫描
func (s *Spider) Start(startUrl string, baseDomain string) error {
	s.baseDomain = baseDomain
	s.addurlQueue(startUrl)
	s.urlQueue <- startUrl
	err := s.driver.Get(startUrl)
	if err != nil {
		return fmt.Errorf("尝试访问目标URL失败：%s", err)
	}
	// 设置Cookie
	err = s.setCookies()
	if err != nil {
		return fmt.Errorf("设置cookie失败：%s", err)
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
	err := s.driver.Quit()
	if err != nil {
		fmt.Printf("[%s] 关闭浏览器失败：%s\n", color.RedString("Error"), err)
	}
	err = s.service.Stop()
	if err != nil {
		fmt.Printf("[%s] 关闭浏览器服务失败：%s\n", color.RedString("Error"), err)
	}
}

// setCookies 设置cookie
func (s *Spider) setCookies() error {
	cookies := configs.GetConfig().Cookie
	for k, v := range cookies {
		if err := s.driver.AddCookie(&selenium.Cookie{Name: k, Value: v}); err != nil {
			return err
		}
	}
	return nil
}

// disablePrompt 关闭弹窗
func (s *Spider) disablePrompt() {
	// 关闭弹窗
	_, err := s.driver.ExecuteScript("window.alert = function() {};", nil)
	if err != nil {
		fmt.Printf("[%s] %s", color.RedString("ERROR"), err)
	}
	_, err = s.driver.ExecuteScript("window.confirm = function() { return true; };", nil)
	if err != nil {
		fmt.Printf("[%s] %s", color.RedString("ERROR"), err)
	}
	_, err = s.driver.ExecuteScript("window.prompt = function() { return ''; };", nil)
	if err != nil {
		fmt.Printf("[%s] %s", color.RedString("ERROR"), err)
	}

}

// dynamicSpider 开始循环进行动态爬取
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
	if s.visited[url] {
		return
	}
	s.visited[url] = true
	if !strings.Contains(url, s.baseDomain) {
		return
	}

	fmt.Printf("[%s] [+]当前页面为：%s\n", color.BlueString("INF"), url)
	if err := s.driver.Get(url); err != nil {
		fmt.Printf("[%s] [-] 载入页面失败：%v\n", color.BlueString("INF"), err)
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
		fmt.Printf("[%s] [-] 无法获取网络日志：%v\n", color.RedString("ERROR"), err)
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
	var requestType string
	// 过滤静态资源
	if isStaticResource(url) {
		return
	}
	if method == "POST" {
		//fmt.Printf("[+]发现POST请求：%s\n", url)
		//params = request["postData"].(map[string][]string)
		params, requestType = ParseQuery(request["postData"].(string))
	}
	// 解析参数
	if method == "GET" {
		//fmt.Printf("[+]发现GET请求：%s\n", url)
		parsedURL, _ := URL.Parse(url)
		params, requestType = ParseQuery(parsedURL.RawQuery)
	}

	// 添加请求信息
	reqInfo := RequestInfo{
		URL:         GetURL(url),
		Method:      strings.ToUpper(method),
		Params:      params,
		RequestType: requestType,
	}
	s.Results = append(s.Results, reqInfo)
}

// 处理表单
func (s *Spider) processForms() {
	s.disablePrompt()
	forms, err := s.driver.FindElements(selenium.ByTagName, "form")
	if err != nil {
		fmt.Printf("[%s] [-] 无法获取表单信息：%v\n", color.RedString("ERROR"), err)
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
					err = input.SendKeys(SpiderFillString)
					if err != nil {
						fmt.Printf("[%s] [-] 无法发送数据到输入框：%v\n", color.RedString("ERROR"), err)
					}
				case "checkbox", "radio":
					err = input.Click()
					if err != nil {
						fmt.Printf("[%s] [-] 无法点击复选框或单选框：%v\n", color.RedString("ERROR"), err)
					}
				}
			case "textarea":
				err = input.SendKeys(SpiderFillString)
				if err != nil {
					fmt.Printf("[%s] [-] 无法发送数据到文本框：%v\n", color.RedString("ERROR"), err)
				}
			case "select":
				options, _ := input.FindElements(selenium.ByTagName, "option")
				if len(options) > 0 {
					err = options[0].Click()
					if err != nil {
						fmt.Printf("[%s] [-] 无法选择下拉框选项：%v\n", color.RedString("ERROR"), err)
					}
				}
			}

		}

		if err = form.Submit(); err == nil {
			time.Sleep(100 * time.Millisecond)
			err = s.driver.Back()
			if err != nil {
				fmt.Printf("[%s] [-] 无法返回上一页：%v\n", color.RedString("ERROR"), err)
			}
		}
	}
}

// 点击元素
func (s *Spider) clickWithJS(elem selenium.WebElement) error {
	_, err := s.driver.ExecuteScript("arguments[0].click();", []interface{}{elem})
	time.Sleep(100 * time.Millisecond)
	if err != nil && isStaleError(err) {
		return fmt.Errorf("元素已失效")
	}
	return nil
}

// 检查元素是否失效
func isStaleError(err error) bool {
	return strings.Contains(err.Error(), "stale element reference")
}

// 模拟用户点击
func (s *Spider) handleInteractiveElements() {
	selectors := SELECTOR

	for _, selector := range selectors {
		elements, err := s.driver.FindElements(selenium.ByCSSSelector, selector)
		if err != nil {
			fmt.Printf("[%s] [-] 无法获取元素信息：%v\n", color.RedString("ERROR"), err)
			continue
		}

		for index, elem := range elements {
			currentElements, _ := s.driver.FindElements(selenium.ByCSSSelector, selector)
			if index >= len(currentElements) {
				continue
			}
			// 此处是为了防止页面刷新导致elem元素不对应，所以使用index保存elem
			elem = currentElements[index]
			if isVisible, _ := elem.IsDisplayed(); isVisible && !s.isUnicquElement(elem) {
				initialURL, _ := s.driver.CurrentURL()
				if err = s.clickWithJS(elem); err == nil {
					time.Sleep(100 * time.Millisecond)
					s.processNetworkRequests()
					newURL, _ := s.driver.CurrentURL()
					if newURL != initialURL {
						err = s.driver.Back()
						if err != nil {
							fmt.Printf("[%s] [-] 无法返回上一页：%v\n", color.RedString("ERROR"), err)
						}
					}
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
		err := s.driver.SwitchFrame(frame)
		if err != nil {
			fmt.Printf("[%s] [-] 无法切换到iframe：%v\n", color.RedString("ERROR"), err)
			continue
		}
		s.extractLinks(selenium.ByTagName, "a")
		err = s.driver.SwitchFrame(nil)
		if err != nil {
			fmt.Printf("[%s] [-] 无法切换回父级iframe：%v\n", color.RedString("ERROR"), err)
		}
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
			s.addurlQueue(href)
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
func ParseQuery(query string) (map[string][]string, string) {
	var data map[string]interface{}
	params := make(map[string][]string)
	err := json.Unmarshal([]byte(query), &data)
	if err != nil {
		params, _ := URL.ParseQuery(query)
		return params, "application/x-www-form-urlencoded"
	}
	for dataKey, dataValue := range data {
		params[dataKey] = []string{fmt.Sprintf("%v", dataValue)}
	}
	return params, "application/json"
}

func GetURL(url string) string {
	if strings.HasSuffix(url, "#") {
		url = url[:len(url)-1]
	}
	part := strings.Split(url, "?")
	//parsedURL, _ := URL.Parse(url)
	return part[0]
}

// 获取elem的哈希值
func (s *Spider) isUnicquElement(elem selenium.WebElement) bool {
	// 组合多个特征作为唯一标识
	tag, _ := elem.TagName()
	//text, _ := elem.Text()
	href, _ := elem.GetAttribute("href")
	onclick, _ := elem.GetAttribute("onclick")
	id, _ := elem.GetAttribute("id")
	class, _ := elem.GetAttribute("class")
	if len(href) > 0 && href[len(href)-1] == '#' {
		href = href[:len(href)-1]
	}
	// 使用SHA256生成哈希标识
	keyData := fmt.Sprintf("%s|%s|%s|%s|%s",
		tag, href, onclick, id, class)
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(keyData)))
	base64Str := base64.StdEncoding.EncodeToString([]byte(sha))
	//sha := fmt.Sprintf("%s", sha256.Sum256([]byte(keyData)))
	if s.elemSha256[base64Str] == true {
		return true
	} else {
		s.elemSha256[base64Str] = true
		return false
	}

}

// GetParamRequests 生成去重后的spider结果
func (s *Spider) GetParamRequests() []RequestInfo {
	var paramRequests []RequestInfo
	for _, requestInfo := range s.Results {
		if len(requestInfo.Params) > 0 {
			paramRequests = append(paramRequests, requestInfo)
		}
	}
	uniqueRequests := make(map[string]RequestInfo)
	// 请求去重处理
	for _, req := range paramRequests {
		// 生成唯一标识键
		key := fmt.Sprintf("%s|%s|%s",
			req.URL,
			req.Method,
			generateParamsHash(req.Params))
		// 保留唯一请求
		if _, exists := uniqueRequests[key]; !exists {
			uniqueRequests[key] = req
		}
	}
	// 转换map回切片
	var result []RequestInfo
	for _, req := range uniqueRequests {
		result = append(result, req)
	}
	return result
}

// 生成参数哈希值
func generateParamsHash(params map[string][]string) string {
	// 获取排序后的参数键
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

// GetParams Get 用于实现RequestInfoInterface接口
func (r *RequestInfo) GetParams() map[string][]string {
	return r.Params
}
