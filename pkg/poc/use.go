package poc

import (
	"AutoScan/pkg/utils"
	"fmt"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/jinzhu/copier"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// UseAllPoc 调用所有poc进行验证
func UseAllPoc(targetUrl string, dirPath string) []*Template {
	var (
		wg        sync.WaitGroup
		semaphore = make(chan struct{}, MaxPocGoroutine)
	)
	InitConfig()
	// 加载POC
	template, errors := LoadYamlPoc(dirPath)
	if len(errors) > 0 {
		fmt.Printf("[%s] 加载和验证POC文件时存在错误：", color.YellowString("ERROR"))
		for _, err := range errors {
			fmt.Println(err)
		}
	}
	num := 0
	for _, poc := range *template {
		if poc.FileVail {
			num++
		}
	}
	fmt.Printf("[%s] 本次共检测到poc%d个，合法Poc %d个\n", color.BlueString("INF"), len(*template), num)
	// 解析URL
	parseUrl, err := ParseURL(targetUrl)
	if err != nil {
		fmt.Printf("[%s] URL: %s 解析失败: %s，请重新输入", color.RedString("ERROR"), targetUrl, err)
		return nil
	}
	placeholders := BuildPlaceHolders(parseUrl)
	// 遍历POC并验证
	for _, poc := range *template {
		if poc.FileVail == false {
			continue
		}
		wg.Add(1)
		semaphore <- struct{}{}
		go func(poc *Template) {
			defer wg.Done()
			defer func() { <-semaphore }()
			// map 高并发下存在问题，直接重新复制一份
			var ph map[string]string
			err2 := copier.Copy(&ph, placeholders)
			if err2 != nil {
				fmt.Printf("[%s] 复制占位符失败: %s", color.RedString("ERROR"), err2)
				return
			}
			poc.PocValidate(ph)
		}(poc)
	}
	wg.Wait()
	close(semaphore)
	var result []*Template
	for _, poc := range *template {
		if poc.PocVail {
			result = append(result, poc)
		}
	}
	fmt.Printf("[%s] 所有POC验证完成", color.BlueString("INF"))
	return result
}
func UseOnePoc(targetUrl string, pocPath string) []*Template {
	InitConfig()
	// 加载POC
	template, errors := LoadAndValidateTemplate(pocPath)
	if len(errors) > 0 {
		fmt.Printf("[%s] 加载和验证POC文件时存在错误：", color.YellowString("ERROR"))
		for _, err := range errors {
			fmt.Println(err)
		}
	}
	// 解析URL
	parseUrl, err := ParseURL(targetUrl)
	if err != nil {
		fmt.Printf("[%s] URL:%s 解析失败: %s，请重新输入", color.RedString("ERROR"), targetUrl, err)
		return nil
	}
	placeholders := BuildPlaceHolders(parseUrl)
	// POC并验证
	template.PocValidate(placeholders)
	//fmt.Printf("%s POC验证完成", pocPath)
	if template.PocVail {
		return []*Template{template}
	}
	return nil

}

// PocValidate 验证单个Poc的核心函数
func (t *Template) PocValidate(ph map[string]string) {
	// 构造请求
	for _, request := range t.Requests {
		var (
			client      = resty.New()
			resqs       []*resty.Response
			matchResult []bool
		)
		// 设置header
		if len(request.Headers) > 0 {
			newHeaders := make(map[string]string)
			for k, v := range request.Headers {
				newHeaders[Render(k, ph)] = Render(v, ph)
			}
			client.SetHeaders(newHeaders)
		}
		// 设置body
		if request.Method == "POST" {
			req := client.R().SetBody(Render(request.Body, ph))
			for _, path := range request.Path {
				post, err := req.Post(Render(path, ph))
				if err != nil {
					fmt.Printf("[%s] 请求 %s 出现错误: %s", color.RedString("ERROR"), Render(path, ph), err)
					continue
				}
				resqs = append(resqs, post)
			}
		} else {
			req := client.R()
			for _, path := range request.Path {
				RendPath := Render(path, ph)
				RandMethod := Render(request.Method, ph)
				var oneReps *resty.Response
				var err error
				if RandMethod == "GET" {
					oneReps, err = req.Get(RendPath)
				} else if RandMethod == "DELETE" {
					oneReps, err = req.Delete(RendPath)
				} else if RandMethod == "PUT" {
					oneReps, err = req.Put(RendPath)
				}
				if err != nil {
					fmt.Printf("[%s] 请求 %s 出现错误: %s", color.RedString("ERROR"), Render(path, ph), err)
					continue
				}
				resqs = append(resqs, oneReps)
			}
		}
		// 开始检测返回值是否有漏洞
		for _, resp := range resqs {
			for _, matcher := range request.Matchers {
				var oneMatchResult []bool
				if matcher.Type == "word" {
					for _, word := range matcher.Words {
						if strings.Contains(resp.String(), word) {
							oneMatchResult = append(oneMatchResult, true)
						} else {
							oneMatchResult = append(oneMatchResult, false)
						}
					}
				} else if matcher.Type == "status" {
					for _, status := range matcher.Status {
						if resp.StatusCode() == status {
							oneMatchResult = append(oneMatchResult, true)
						} else {
							oneMatchResult = append(oneMatchResult, false)
						}
					}
				} else if matcher.Type == "regex" {
					for _, regex := range matcher.Regex {
						regex = Render(regex, ph)
						re := regexp.MustCompile(regex)
						oneMatchResult = append(oneMatchResult, re.MatchString(resp.String()))
					}
				}
				// 交并运算
				matchResult = append(matchResult, CalcAndOr(oneMatchResult, matcher.Condition))
			}
		}
		// 交并运算
		if CalcAndOr(matchResult, request.MatchersCondition) {
			t.Print(ph)
			t.PocVail = true
		}
	}
}

// CalcAndOr 交并运算
func CalcAndOr(matchResult []bool, t string) bool {
	if t == "and" {
		for _, result := range matchResult {
			if !result {
				return false
			}
		}
		return true
	} else {
		for _, result := range matchResult {
			if result {
				return true
			}
		}
		return false
	}
}

// Print poc验证成功后打印结果
func (t *Template) Print(ph map[string]string) {
	id := color.GreenString("%s", t.ID)
	var severity string
	if t.Info.Severity == "info" {
		severity = color.BlueString("%s", t.Info.Severity)
	} else if t.Info.Severity == "low" {
		severity = color.BlueString("%s", t.Info.Severity)
	} else if t.Info.Severity == "middle" {
		severity = color.YellowString("%s", t.Info.Severity)
	} else if t.Info.Severity == "high" {
		severity = color.RedString("%s", t.Info.Severity)
	} else if t.Info.Severity == "critical" {
		severity = color.RedString("%s", t.Info.Severity)
	}
	Name := color.BlueString("%s", t.Info.Name)
	fmt.Printf("[%s] [%s] [%s] [%s]\n", id, severity, Name, Render(t.Requests[0].Path[0], ph))
	t.VulUrl = Render(t.Requests[0].Path[0], ph)
}

func BuildPlaceHolders(u *url.URL) map[string]string {
	port := u.Port()
	if port == "" { // 处理默认端口
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	hostname, _, _ := net.SplitHostPort(u.Host) // 兼容无端口的情况
	if hostname == "" {
		hostname = u.Hostname()
	}

	return map[string]string{
		"{{BaseURL}}":  u.String(),
		"{{RootURL}}":  fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		"{{Hostname}}": hostname,
		"{{Host}}":     u.Hostname(),
		"{{Port}}":     port,
		"{{Path}}":     u.Path,
		"{{File}}":     filepath.Base(u.Path),
		"{{Scheme}}":   u.Scheme,
		"{{verify}}":   utils.GetRandString(),
	}
}

// Render 渲染poc
func Render(template string, placeholders map[string]string) string {
	for key, value := range placeholders {
		template = strings.ReplaceAll(template, key, value)
	}
	return template
}
func ParseURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return u, nil
}
