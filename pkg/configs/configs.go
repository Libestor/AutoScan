package configs

import (
	"AutoScan/pkg/utils"
	"fmt"
	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Cookie            map[string]string `yaml:"cookie"`
	VulConfig         vulConfig
	PocConfig         pocConfig
	ChromeDriverPath  string `yaml:"chrome_driver_path" `
	ChromePath        string `yaml:"chrome_path"`
	DefaultParamValue string `yaml:"default_param_value" default:"1"`
}
type vulConfig struct {
	SqliConfig sqliConfig
	XssConfig  xssConfig
}
type sqliConfig struct {
	TimeRequestTimes int     `yaml:"time_request_times" default:"30"`
	MaxGoroutines    int     `yaml:"max_goroutines" default:"10"`
	Similarity       float64 `yaml:"similarity" default:"0.99999"`
	PayloadFiles     string  `yaml:"payload_file" default:"configs/sqli.xml"`
}
type xssConfig struct {
	MaxGoroutines int    `yaml:"max_goroutines" default:"10"`
	PayloadFiles  string `yaml:"payload_file" default:"configs/xss.xml"`
}
type pocConfig struct {
	MaxReadFileGoroutine int `yaml:"max_read_file_goroutine" default:"100"`
	MaxPocGoroutine      int `yaml:"max_poc_goroutine" default:"100"`
}

var (
	instance   Config
	configPath string // 存储动态传入的路径
)

func init() {
	pocConfig_ := pocConfig{
		MaxReadFileGoroutine: 100,
		MaxPocGoroutine:      100,
	}
	xssConfig_ := xssConfig{
		MaxGoroutines: 10,
		PayloadFiles:  "configs/xss.xml",
	}
	sqliConfig_ := sqliConfig{
		TimeRequestTimes: 30,
		MaxGoroutines:    10,
		Similarity:       0.99999,
		PayloadFiles:     "configs/sqli.xml",
	}
	vulConfig_ := vulConfig{
		XssConfig:  xssConfig_,
		SqliConfig: sqliConfig_,
	}
	instance = Config{
		Cookie:            make(map[string]string),
		VulConfig:         vulConfig_,
		PocConfig:         pocConfig_,
		DefaultParamValue: "1",
		ChromeDriverPath:  "",
		ChromePath:        "",
	}
}

// InitConfig Init 初始化配置模块，传入配置文件路径
func InitConfig(path string) error {
	if path == "" {
		path = "config.yml"
	}
	var err error

	if !utils.CheckFileDirExists(path) {
		err = os.ErrNotExist
	}
	configPath = path
	// 读取 YAML 文件
	data, readErr := os.ReadFile(configPath)
	if readErr != nil {
		err = readErr
		return err
	}
	// 解析到结构体
	if parseErr := yaml.Unmarshal(data, &instance); parseErr != nil {
		err = parseErr
		return err
	}

	return err
}

func CheckChrome() bool {
	if instance.ChromeDriverPath == "" || instance.ChromePath == "" {
		fmt.Printf("[%s] ChromeDriverPath or ChromePath 配置空缺，无法启动浏览器\n", color.RedString("Error"))
		return false
	}
	return true
}

// GetConfig 获取单例配置实例
func GetConfig() *Config {
	return &instance
}
