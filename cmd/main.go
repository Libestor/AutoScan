package main

import (
	"AutoScan/pkg/configs"
	"AutoScan/pkg/poc"
	Spider "AutoScan/pkg/spider"
	"AutoScan/pkg/utils"
	"AutoScan/pkg/vul/sqli"
	"AutoScan/pkg/vul/xss"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"os"
	"strings"
)

// StringSlice 实现flag.Value接口的字符串切片，用来从命令行接受多个参数
type StringSlice []string

func (s *StringSlice) String() string {
	return strings.Join(*s, ",")
	//return fmt.Sprintf("%v", *s)
}
func (s *StringSlice) Set(v string) error {
	parts := strings.Split(v, ",")
	for _, param := range parts {
		*s = append(*s, param)
	}
	return nil
}

func (s *StringSlice) Contains(s2 string) bool {
	for _, s1 := range *s {
		if s1 == s2 {
			return true
		}
	}
	return false
}

type UserParam struct {
	Params     StringSlice
	Bodys      StringSlice
	JsonBodys  StringSlice
	Vuls       StringSlice
	TargetURL  *string
	Output     *string
	Config     *string
	FileDir    *string
	Poc        *bool
	Spider     *bool
	VulResults []VulResult
}
type VulResult struct {
	Name     string
	Type     string
	URL      string
	Severity string
}

func main() {
	var (
		output = "spider.json"
		config = "config.yml"
	)
	PrintBanner()
	userParam := UserParam{}
	// 目标设置
	//targetURL := flag.String("u", "", "目标URL")
	userParam.TargetURL = flag.String("u", "", "目标URL")
	flag.Var(&userParam.Params, "p", "get请求的param参数，使用','分割，或者多次使用-p传入")
	flag.Var(&userParam.Bodys, "b", "post请求的body参数，使用','分割，或者多次使用-b传入")
	flag.Var(&userParam.JsonBodys, "j", "post请求的json参数，使用','分割，或者多次使用-j传入")
	// 模式设置
	userParam.Poc = flag.Bool("poc", false, "使用poc进行扫描")
	userParam.FileDir = flag.String("f", "", "指定文件或者目录")
	flag.Var(&userParam.Vuls, "vul", "使用vul选择需要扫描的类型，如sql,xss")
	userParam.Spider = flag.Bool("spider", false, "使用爬虫进行扫描")
	// 输出选择
	userParam.Output = flag.String("out-json", "", "输出为json文件")
	// 帮助信息
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "\nAutoScan有四种扫描模式\n")
		_, _ = fmt.Fprintln(os.Stderr, "全量扫描模式：")
		_, _ = fmt.Fprintln(os.Stderr, "\t\t AutoScan -u http://127.0.0.1 -f ./pocDir [-out-json ./result.json]")
		_, _ = fmt.Fprintln(os.Stderr, "poc扫描模式：")
		_, _ = fmt.Fprintln(os.Stderr, "\t\t AutoScan -u http://127.0.0.1 -poc -f ./pocDir [-out-json ./result.json]")
		_, _ = fmt.Fprintln(os.Stderr, "爬虫扫描模式：")
		_, _ = fmt.Fprintln(os.Stderr, "\t\t AutoScan -u http://127.0.0.1 -spider [-out-json ./spider.json]")
		_, _ = fmt.Fprintln(os.Stderr, "通用漏洞扫描模式：")
		_, _ = fmt.Fprintln(os.Stderr, "\t\t AutoScan -u http://127.0.0.1 -vul sql -p username [-out-json ./spider.json]")
		_, _ = fmt.Fprintln(os.Stderr, "\t\t AutoScan  -vul sql -f ./spider.json [-out-json ./spider.json]")
		_, _ = fmt.Fprintln(os.Stderr, "参数说明：")
		flag.PrintDefaults() // 打印所有参数的默认值和说明
	}
	// 配置文件设置
	configFile := flag.String("c", "", "配置文件的路径")
	// 开始解析
	flag.Parse()
	if configFile != nil && *configFile != "" {
		config = *configFile
	} else {
		configFile = &config
	}
	if !utils.CheckFileDirExists(*configFile) {
		fmt.Printf("[%s] 配置文件config.yml不存在, 请创建或使用-c指定\n", color.RedString("Error"))
		return
	}
	err := configs.InitConfig(*configFile)
	if err != nil {
		fmt.Printf("[%s] 配置文件config.yml解析失败, 请检查\n", color.RedString("Error"))
		return
	}

	// 选择模式
	if userParam.TargetURL == nil || *userParam.TargetURL == "" {
		if userParam.Vuls != nil && len(userParam.Vuls) > 0 {
			// 使用spider文件进行vul扫描
			if !utils.CheckFileDirExists(*userParam.FileDir) {
				flag.Usage()
				return
			}
			var body []Spider.RequestInfo
			fmt.Printf("[%s]使用%s文件进行%s扫描\n", color.GreenString("INF"), *userParam.FileDir, userParam.Vuls.String())
			file, err := os.OpenFile(*userParam.FileDir, os.O_RDONLY, 0644)
			if err != nil {
				fmt.Printf("[%s] 打开文件失败: %v\n", color.RedString("Error"), err)
				return
			}
			decoder := json.NewDecoder(file)
			err = decoder.Decode(&body)
			if err != nil {
				fmt.Printf("[%s] 解析文件失败: %v\n", color.RedString("Error"), err)
				return
			}

			if userParam.Output == nil || *userParam.Output == "" {
				userParam.VulScan(false, body)
			} else {
				userParam.VulScan(true, body)
			}
		} else {
			fmt.Printf("[%s]请输入目标URL\n", color.RedString("Error"))
			flag.Usage()
			return

		}
	} else if userParam.FileDir != nil && *userParam.FileDir != "" {
		if *userParam.Poc == false {
			// 全量扫描
			fmt.Printf("[%s]开始对%s进行全量扫描\n", color.GreenString("INF"), *userParam.TargetURL)
			userParam.AllScan()
		} else {
			// poc扫描
			fmt.Printf("[%s]开始对%s进行poc扫描\n", color.GreenString("INF"), *userParam.TargetURL)
			if userParam.Output == nil || *userParam.Output == "" {
				userParam.PocScan(false)
			} else {
				userParam.PocScan(true)
			}

		}
	} else {
		if *userParam.Spider == true {
			// spider模式
			if userParam.Output == nil || *userParam.Output == "" {
				fmt.Printf("[%s]spider模式输出文件默认为spider.json\n", color.YellowString("Warning"))
				userParam.Output = &output
			} else {
			}
			fmt.Printf("[%s]开始对%s进行爬虫扫描\n", color.GreenString("INF"), *userParam.TargetURL)
			userParam.SpiderScan(true)

		} else {
			// vul模式
			if userParam.Vuls != nil && len(userParam.Vuls) > 0 {
				sr := Spider.RequestInfo{
					Params: make(map[string][]string),
				}
				sr.URL = *userParam.TargetURL
				if userParam.Params != nil && len(userParam.Params) > 0 {
					sr.Method = "GET"
					for _, up := range userParam.Params {
						sr.Params[up] = []string{configs.GetConfig().DefaultParamValue}
					}
				} else if userParam.Bodys != nil && len(userParam.Bodys) > 0 {
					sr.Method = "POST"
					sr.RequestType = "application/x-www-form-urlencoded"
					for _, ub := range userParam.Bodys {
						sr.Params[ub] = []string{configs.GetConfig().DefaultParamValue}
					}
				} else if userParam.JsonBodys != nil && len(userParam.JsonBodys) > 0 {
					sr.Method = "POST"
					sr.RequestType = "application/json"
					for _, ub := range userParam.JsonBodys {
						sr.Params[ub] = []string{configs.GetConfig().DefaultParamValue}
					}
				} else {
					// 无参数输入，报错
					fmt.Printf("[%s] 请%s中具体需要扫描的参数，请通过-p，-b，-j输入\n", color.RedString("Error"), *userParam.TargetURL)
					flag.Usage()
					return
				}
				fmt.Printf("[%s] 开始对%s进行%s扫描\n", color.GreenString("INF"), *userParam.TargetURL, userParam.Vuls.String())
				if userParam.Output == nil || *userParam.Output == "" {
					userParam.VulScan(false, []Spider.RequestInfo{sr})
				} else {
					userParam.VulScan(true, []Spider.RequestInfo{sr})
				}
			} else {
				fmt.Printf("[%s]请指定扫描模式\n", color.RedString("Error"))
				flag.Usage()
				return
			}
		}
	}
}
func (u *UserParam) AllScan() {
	SpiderScanResult := u.SpiderScan(false)
	if len(SpiderScanResult) == 0 {
		fmt.Printf("[%s] 爬虫扫描结果为空, 后续vul的扫描将会停止\n", color.RedString("Error"))
	} else {
		//vul扫描
		u.Vuls = StringSlice{"sql", "xss"}
		var rightVuls []Spider.RequestInfo
		for _, sr := range SpiderScanResult {
			if len(sr.Params) > 0 {
				rightVuls = append(rightVuls, sr)
			}
		}
		u.VulScan(false, rightVuls)
	}
	u.PocScan(false)
	if *u.Output != "" {
		u.SaveResult()
	}
}
func (u *UserParam) PocScan(save bool) {
	fmt.Printf("[%s] 开始poc扫描\n", color.GreenString("INF"))
	var allPoc []*poc.Template
	if strings.HasSuffix(*u.FileDir, ".yml") || strings.HasSuffix(*u.FileDir, ".yaml") {
		allPoc = poc.UseOnePoc(*u.TargetURL, *u.FileDir)
	} else {
		allPoc = poc.UseAllPoc(*u.TargetURL, *u.FileDir)
	}
	if allPoc == nil {
		fmt.Printf("[%s] POC扫描完成,无结果\n", color.GreenString("INF"))
	} else {
		fmt.Printf("[%s] POC扫描完成,本次共扫描到%d个漏洞\n", color.GreenString("INF"), len(allPoc))
	}

	for _, Poc := range allPoc {

		u.VulResults = append(u.VulResults, VulResult{
			Name:     Poc.Info.Name,
			Type:     "POC",
			URL:      Poc.VulUrl,
			Severity: Poc.Info.Severity,
		})

	}
	if save {
		u.SaveResult()
	}

}
func (u *UserParam) SpiderScan(save bool) []Spider.RequestInfo {
	fmt.Printf("[%s] 正在初始化爬虫引擎\n", color.GreenString("INF"))
	spider, err := Spider.NewSpider()
	if err != nil {
		fmt.Printf("[%s] 爬虫引擎初始化失败: %s\n", color.RedString("Error"), err)
		return nil
	}
	fmt.Printf("[%s] 爬虫引擎初始化成功,开始扫描任务\n", color.GreenString("INF"))
	err = spider.Start(*u.TargetURL, *u.TargetURL)
	if err != nil {
		fmt.Printf("[%s] 爬虫引擎启动失败\n", color.RedString("Error"))
		return nil
	}
	fmt.Printf("[%s] 爬虫扫描任务完成\n", color.GreenString("INF"))
	spider.Stop()
	paramRequests := spider.GetParamRequests()
	if save {
		_ = SaveFile(paramRequests, *u.Output)
		return nil
	}
	return paramRequests

}
func SaveFile(body interface{}, fileName string) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[%s] 写入文件失败: %v\n", color.RedString("Error"), err)
		return err
	}
	encoder := json.NewEncoder(file)
	err = encoder.Encode(body)
	if err != nil {
		fmt.Printf("[%s] 保存文件失败: %v\n", color.RedString("Error"), err)
		return err
	}
	return nil
}
func (u *UserParam) VulScan(save bool, s []Spider.RequestInfo) {
	if u.Vuls.Contains("sql") {
		fmt.Printf("[%s] 开始sql注入扫描\n", color.GreenString("INF"))
		sqlResults, err := sqli.RunSqlScan(s)
		if err != nil {
			fmt.Printf("[%s] sql注入引擎启动失败\n", color.RedString("Error"))
			return
		}
		for _, sr := range sqlResults {
			if sr.IsSqli {
				u.VulResults = append(u.VulResults, VulResult{
					Name:     sr.Note,
					Type:     "sql",
					URL:      sr.URL,
					Severity: "critical",
				})
			}
		}
		fmt.Printf("[%s] sql注入扫描完成\n", color.GreenString("INF"))
	}
	if u.Vuls.Contains("xss") {
		fmt.Printf("[%s] 开始进行xss扫描\n", color.GreenString("INF"))
		xssResults, err := xss.RunXssScan(s)
		if err != nil {
			fmt.Printf("[%s] XSS注入引擎启动失败: %s\n", color.RedString("Error"), err)
			return
		}
		for _, sr := range xssResults {
			if sr.IsXss {
				u.VulResults = append(u.VulResults, VulResult{
					Name:     sr.Note,
					Type:     "xss",
					URL:      sr.URL,
					Severity: "middle",
				})
			}
		}
		fmt.Printf("[%s] xss扫描完成\n", color.GreenString("INF"))
	}
	for _, vul := range u.VulResults {
		if vul.Type == "sql" {
			fmt.Printf("[%s] 发现SQL注入漏洞: %s\n", color.RedString("SQL"), vul.URL)
		} else if vul.Type == "xss" {
			fmt.Printf("[%s] 发现XSS漏洞: %s\n", color.RedString("XSS"), vul.URL)
		}

	}
	if save {
		u.SaveResult()
	}
}
func (u *UserParam) SaveResult() {
	fmt.Printf("[%s] 开始保存扫描结果\n", color.GreenString("INF"))
	err := SaveFile(u.VulResults, *u.Output)
	if err != nil {
		fmt.Printf("[%s] 保存扫描结果失败\n", color.RedString("Error"))
		return
	}
	fmt.Printf("[%s] 扫描结果已保存到%s\n", color.GreenString("INF"), *u.Output)
}
func PrintBanner() {
	// 获取当前工作目录的绝对路径
	// 构建banner文件的绝对路径（假设可执行文件在项目根目录的bin目录下）
	bannerPath := "configs/banner.txt"
	if !utils.CheckFileDirExists(bannerPath) {
		return
	}
	// 读取banner文件内容
	data, err := os.ReadFile(bannerPath)
	if err != nil {
		fmt.Printf("[%s] 加载banner失败: %v\n", color.YellowString("Warning"), err)
		return
	}
	// 打印banner内容并添加一个换行
	fmt.Printf("\n%s\n", string(data))
}
