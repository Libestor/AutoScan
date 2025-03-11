package utils

import (
	Spider "AutoScan/pkg/spider"
	"github.com/go-resty/resty/v2"
	"math/rand"
	"sync"
	"time"
)

const (
	DefaultParam = "1"
	CHAARSET     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

type Client struct {
	Client *resty.Client
	mu     *sync.Mutex
}

// InitClient 初始化客户端
func (c *Client) InitClient() {
	client := resty.New()
	client.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

	mu := sync.Mutex{}
	c.Client = client
	c.mu = &mu
}

// GetParams 获取请求
func GetParams(info Spider.RequestInfo) map[string]string {
	params := make(map[string]string)
	//params := make(sync.Map)
	for param := range info.Params {
		if len(info.Params[param]) == 0 || info.Params[param][0] == "" {
			params[param] = DefaultParam
		}
		params[param] = info.Params[param][0]
	}
	// 适配pikachu
	params["submit"] = "submit"
	return params
}

// Request 发送数据包
func (c *Client) Request(url string, method string, param map[string]string, requestType string) (*resty.Response, error) {
	c.mu.Lock()
	param["submit"] = "submit"
	c.mu.Unlock()
	if method == "GET" {
		return c.Get(url, param)
	} else {
		return c.Post(url, param, requestType)
	}
}
func (c *Client) Get(url string, param map[string]string) (*resty.Response, error) {
	tmp := c.Client.R()
	c.mu.Lock()
	tmp.SetQueryParams(param)
	c.mu.Unlock()
	return tmp.Get(url)

}
func (c *Client) Post(url string, param map[string]string, requestType string) (*resty.Response, error) {
	tmp := c.Client.R()
	c.mu.Lock()
	if requestType == "application/json" {
		tmp.SetBody(param)
	} else {
		tmp.SetFormData(param)
	}
	c.mu.Unlock()
	return tmp.Post(url)
}

// GetRandString 获取随机四位的字符串
func GetRandString() string {
	b := make([]byte, 4)
	for i := range b {
		b[i] = CHAARSET[Rand.Intn(len(CHAARSET))]
	}
	return string(b)
}
