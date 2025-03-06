package main

import (
	"encoding/json"
	"fmt"
	"strings"
)
import "AutoScan/pkg/spider"

func main() {
	spider, err := Spider.NewSpider()
	if err != nil {
		fmt.Println("Error creating spider:", err)
	}
	spider.Start("http://127.0.0.1/pikachu/vul/ssrf/ssrf.php", "http://127.0.0.1/pikachu/vul/ssrf")
	fmt.Printf("发现 %d 个端点：\n", len(spider.Results))
	for i, item := range spider.Results {
		fmt.Printf("%d. %s %s\n", i+1, item.Method, item.URL)
		params, _ := json.MarshalIndent(item.Params, "", "  ")
		fmt.Printf("参数: %s\n", params)
		fmt.Printf(strings.Repeat("-", 50))
		fmt.Println()
	}
	//file, err := os.OpenFile("pikachu.json", os.O_CREATE|os.O_WRONLY, 0644)
	//if err != nil {
	//
	//}
	//encoder := json.NewEncoder(file)
	//err = encoder.Encode(spider.Results)
	if err != nil {

	}
	defer spider.Stop()
}
