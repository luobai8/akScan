package oss

import (
	"crypto/tls"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"vul/config"
)

func OssKeyScan() {

	banner :=
		`
		
			__      _________                     	此工具用于从网站js文件中检索泄露的云存储桶Access Key
		_____  |  | __ /   _____/ ____ _____    ____  
		\__  \ |  |/ / \_____  \_/ ___\\__  \  /    \ 
		 / __ \|    <  /        \  \___ / __ \|   |  \
		(____  /__|_ \/_______  /\___  >____  /___|  /
		     \/     \/        \/     \/     \/     \/ 			Author: K7
										https://github.com/luobai8
		

`
	fmt.Println(color.GreenString(banner))
	// 判断是否输入了参数
	if len(os.Args) < 2 || (os.Args[1] != "-t" && os.Args[1] != "-l") {
		fmt.Println(" [*] ------------------------------------" + color.GreenString(" akScan ") + "-------------------------------------------")
		fmt.Println(color.GreenString(" [*] akscan -t <url>"))
		fmt.Println(color.GreenString(" [*] eg: akScan -t http://example.com "))
		fmt.Println(color.GreenString(" [*] eg: akScan -t http://example.com/test/login.php "))
		//fmt.Println(" ")
		//fmt.Println(color.YellowString(" [*] 从文件中按行读取url进行批量扫描"))
		//fmt.Println(color.YellowString(" [*] eg: akScan -l url.txt "))
		fmt.Println(" [*] ---------------------------------------------------------------------------------------")
		fmt.Println("")
		fmt.Println("")
		fmt.Println(color.GreenString("			<--- 请输入正确的参数 --->"))
		os.Exit(0)
	} else if len(os.Args) < 3 {
		fmt.Println(" [*] ------------------------------------" + color.GreenString(" akScan ") + "-------------------------------------------")
		fmt.Println(color.GreenString(" [*] akscan -t <url>"))
		fmt.Println(color.GreenString(" [*] eg: akScan -t http://example.com "))
		fmt.Println(color.GreenString(" [*] eg: akScan -t http://example.com/test/login.php "))
		//fmt.Println(" ")
		//fmt.Println(color.YellowString(" [*] 从文件中按行读取url进行批量扫描"))
		//fmt.Println(color.YellowString(" [*] eg: akScan -l url.txt "))
		fmt.Println(" [*] ---------------------------------------------------------------------------------------")
		fmt.Println("")
		fmt.Println("")
		fmt.Println(color.RedString("			<--- 未给参数传值，请输入目标 --->"))
		os.Exit(0)
	}

	target := os.Args[2]

	//对输入的第一个参数进行判断
	if os.Args[1] == "-t" {
		// 接收第二个参数,作为单个目标的值
		if !strings.Contains(target, "http:") && !strings.Contains(target, "https:") {
			fmt.Println(color.RedString("			<--- 目标格式输入输入错误 --->"))
			os.Exit(0)
		}
		jsFind(target)

	} else if os.Args[1] == "-l" {
		targets := config.ReadFile(target)
		// 使用 WaitGroup 来等待所有 goroutine 完成
		var wg sync.WaitGroup

		resultChan := make(chan string, len(targets)) // 创建通道

		for _, target := range targets {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				// 调用 jsFind 对目标进行处理
				jsFind(t)
				resultChan <- t // 发送目标名称
			}(target) // 每个 goroutine 获取独立的 target
		}

		wg.Wait()
		close(resultChan) // 关闭通道

	}

}

func jsFind(target string) {
	// 对url进行拆分为协议、域名、路径等多个部分，便于后面进行拼接
	parsedUrl, err := url.Parse(target)
	if err != nil {
		fmt.Println("url分割错误:", err)
		return
	}

	// 创建一个 HTTP 客户端，设置超时时间
	// 创建一个自定义的Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书验证
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second, // 设置超时时间为 10 秒
	}

	fmt.Println(" [*] 测试url: ", target)
	req, err := client.Get(target)
	if err != nil {
		fmt.Println(" [-]", target, "目标无法访问：")
		return
	}
	defer req.Body.Close()
	//code := req.StatusCode
	//fmt.Println(code)
	//if code != 201 {
	//	fmt.Println("目标无法访问")
	//	return
	//}

	//body, err := ioutil.ReadAll(req.Body)
	//if err != nil {
	//	fmt.Println("获取请求体失败：", err)
	//	return
	//}
	//fmt.Println(string(body))

	// 解析 HTML 内容
	doc, err := html.Parse(req.Body)
	if err != nil {
		fmt.Println(" [-] 解析 HTML 失败: ", err)
		return
	}
	//fmt.Println(doc)

	// 提取链接
	var js_links []string
	extractLinks(doc, &js_links)
	//for _, link := range js_links {
	//	fmt.Println(link)
	//}

	var js_urls []string
	for _, js := range js_links {
		if strings.Contains(js, "http://") || strings.Contains(js, "https://") || strings.Contains(js, "//") {
			if strings.Contains(js, "http") {
				js_urls = append(js_urls, js)
			} else {
				js_urls = append(js_urls, "http:"+js)
			}

		} else if !strings.Contains(js, "http://") && !strings.Contains(js, "https://") {
			if string(js[0]) == "/" {
				js_urls = append(js_urls, parsedUrl.Scheme+"://"+parsedUrl.Host+js)
			} else if strings.Contains(js, "./") {
				js_urls = append(js_urls, parsedUrl.Scheme+"://"+parsedUrl.Host+strings.TrimPrefix(js, "."))
			} else {
				js_urls = append(js_urls, parsedUrl.Scheme+"://"+parsedUrl.Host+"/"+js)
			}

		}
	}

	fmt.Println(" [*] -------------------------------" + color.YellowString("发现js文件") + "----------------------------------")
	for _, js_url := range js_urls {
		fmt.Println(color.GreenString(" [+] " + js_url))
	}

	num := 0
	jsBodyScan(js_urls, &num)

	if num == 0 {
		fmt.Println("")
		fmt.Println(" [-] ", target, color.MagentaString(" 未发现泄露的Access Key"))
		fmt.Println("")
	}

}

func jsBodyScan(js_urls []string, num *int) {
	fmt.Println("")
	fmt.Println(" [*] ---------------------------" + color.YellowString("正在检索js文件内容") + "------------------------------")

	//正则表达式对每个js文件内容进行检索，检索出来的key值进行输出
	// 编译正则表达式
	// 创建一个 map，键为 string 类型，值为 string 类型
	patternMap := make(map[string]string)

	// 正则表达式规则参考：https://wiki.teamssix.com/CloudService/more/
	// 向 map 中添加键值对
	// 正则表达式规则参考：https://wiki.teamssix.com/CloudService/more/
	// 向 map 中添加键值对
	patternMap["敏感键值"] = `(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]`
	patternMap["阿里云"] = `["'=:,.;](LTAI[A-Za-z0-9]{12,24})["'=:,.;]` // 阿里云 (Alibaba Cloud) 的 Access Key 开头标识一般是 "LTAI"。
	patternMap["腾讯云"] = `["'=:,.;](AKID[A-Za-z0-9]{13,20})["'=:,.;]` // 腾讯云 (Tencent Cloud) 的 Access Key 开头标识一般是 "AKID"。
	//patternMap["华为云"] = `["'=:,.;]([A-Z0-9]{20})["'=:,.;]`                                 // 华为云 (Huawei Cloud) 的 Access Key 是20个随机大写字母和数字组成，较难用正则表达式匹配。
	patternMap["百度云"] = `["'=:,.;](AK[A-CD-Ha-z0-9]{10,12}|AK[A-Za-z0-9]{21,40})["'=:,.;]` // 百度云 (Baidu Cloud) 的 Access Key 开头标识一般是 "AK"。
	patternMap["京东云"] = `["'=:,.;](JDC_[A-Z0-9]{28,32})["'=:,.;]`                          // 京东云 (JD Cloud) 的 Access Key 开头标识一般是 "JDC_"。
	patternMap["字节跳动火山引擎"] = `["'=:,.;](AKLT[a-zA-Z0-9-_]{0,252})["'=:,.;]`                // 字节跳动火山引擎 (Volcengine) 的 Access Key 开头标识一般是 "AKLT"，长度小于256位。
	patternMap["UCloud"] = `["'=:,.;](UC[A-Za-z0-9]{10,40})["'=:,.;]`                      // UCloud (UCloud) 的 Access Key 开头标识一般是 "UC"
	patternMap["青云"] = `["'=:,.;](QY[A-Za-z0-9]{10,40})["'=:,.;]`                          // 青云 (QingCloud) 的 Access Key 开头标识一般是 "QY"。
	patternMap["金山云"] = `["'=:,.;](AKLT[a-zA-Z0-9-_]{16,28})["'=:,.;]`                     // 金山云 (Kingsoft Cloud) 的 Access Key 开头标识一般是 "AKLT"。
	patternMap["联通云"] = `["'=:,.;](LTC[A-Za-z0-9]{10,60})["'=:,.;]`                        // 联通云 (China Unicom Cloud) 的 Access Key 开头标识一般是 "LTC"。
	patternMap["移动云"] = `["'=:,.;](YD[A-Za-z0-9]{10,60})["'=:,.;]`                         // 移动云 (China Mobile Cloud) 的 Access Key 开头标识一般是 "YD"。
	patternMap["电信云"] = `["'=:,.;](CTC[A-Za-z0-9]{10,60})["'=:,.;]`                        // 电信云 (China Telecom Cloud) 的 Access Key 开头标识一般是 "CTC"。
	patternMap["一云通"] = `["'=:,.;](YYT[A-Za-z0-9]{10,60})["'=:,.;]`                        // 一云通 (YiYunTong Cloud) 的 Access Key 开头标识一般是 "YYT"。
	patternMap["用友云"] = `["'=:,.;](YY[A-Za-z0-9]{10,40})["'=:,.;]`                         // 用友云 (Yonyou Cloud) 的 Access Key 开头标识一般是 "YY"。
	patternMap["南大通用云"] = `["'=:,.;](CI[A-Za-z0-9]{10,40})["'=:,.;]`                       // 南大通用云 (OUCDC) 的 Access Key 开头标识一般是 "CI"。
	patternMap["G-Core Labs"] = `["'=:,.;](gcore[A-Za-z0-9]{10,30})["'=:,.;]`              // G-Core Labs 的 Access Key 开头标识一般是 "gcore"
	patternMap["亚马逊云"] = `["'=:,.;](AKIA[A-Za-z0-9]{16,30})["'=:,.;]`                      // 亚马逊云计算服务 (Amazon Web Services, AWS) 的 Access Key 开头标识一般是 "AKIA"。
	patternMap["Google Cloud"] = `["'=:,.;](GOOG[\w\W]{10,30})["'=:,.;]`                   // Google Cloud Platform (GCP) 的 Access Key 开头标识一般是 "GOOG"。
	patternMap["Microsoft Azure"] = `["'=:,.;](AZ[A-Za-z0-9]{30,40})["'=:,.;]`             // Microsoft Azure 的 Access Key 开头标识一般是 "AZ"。
	patternMap["IBM Cloud"] = `["'=:,.;](IBM[A-Za-z0-9]{10,40})["'=:,.;]`                  // IBM 云 (IBM Cloud) 的 Access Key 开头标识一般是 "IBM"。
	//patternMap["IBM Cloud"] = `["'=:,.;][a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}["'=:,.;]` // 或者是这种规则
	patternMap["Oracle云"] = `["'=:,.;](OCID[A-Za-z0-9]{10,40})["'=:,.;]` // Oracle云 (Oracle Cloud) 的 Access Key 开头标识一般是 "OCID"。

	for _, js_url := range js_urls {
		//遍历切片里面的js文件地址，对他们进行http请求
		//创建一个自定义的Transport
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书验证
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second, // 设置超时时间为 10 秒
		}
		req, err := client.Get(js_url)
		//fmt.Println(req.StatusCode)
		if err != nil {
			//fmt.Println(" [-] "+js_url, " 请求失败：", err)
			continue
		}
		defer req.Body.Close()

		if req.StatusCode != 200 {
			//fmt.Println(" [-] "+js_url, " 请求失败：", req.StatusCode)
			continue
		}

		//获取响应内容
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			//fmt.Println(js_url, "获取请求体失败：", err)
			return
		}
		//fmt.Println(string(body))

		for key, value := range patternMap {
			re, err := regexp.Compile(value)
			if err != nil {
				fmt.Println("正则表达式编译错误:", err)
				return
			}

			// 使用 FindAllString 方法查找所有匹配
			result_list := re.FindAllString(string(body), -1)
			//fmt.Println(result_list)
			//fmt.Println(js_url)
			if len(result_list) > 0 {
				// 创建一个map用来存储已去重的结果
				unique := make(map[string]struct{})

				// 遍历输入切片，添加到 map 中
				for _, item := range result_list {
					unique[item] = struct{}{} // 使用空结构体作为值，节省内存
				}

				// 将去重后的结果存入切片
				var result []string
				for key := range unique {
					result = append(result, key)
				}

				// 输出去重后的切片
				for _, s := range result {
					if key == "敏感键值" {
						fmt.Println(color.BlueString(" [+] 发现敏感键值: " + s))
						fmt.Println(color.MagentaString(" [*] 文件: " + js_url))
						fmt.Println(" ")
						continue
					}
					fmt.Println(color.GreenString(" [+] 发现 " + key + " Access Key: " + s))
					fmt.Println(color.MagentaString(" [*] 文件: " + js_url))
					config.WriteFile("result.txt", js_url+":"+key+":"+s)
					fmt.Println(" ")
					*num++

				}

			}

		}

	}

}

// extractLinks 解析 HTML 节点，提取关键标签的 href 和 src 属性
func extractLinks(n *html.Node, jsLinks *[]string) {
	if n.Type == html.ElementNode && (n.Data == "a" || n.Data == "script" || n.Data == "link") {
		for _, attr := range n.Attr {
			if (attr.Key == "href" || attr.Key == "src") && strings.Contains(attr.Val, ".js") {
				//fmt.Println(attr.Val) // 打印出链接
				*jsLinks = append(*jsLinks, attr.Val)
			}
		}
	}

	// 递归处理子节点
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractLinks(c, jsLinks)
	}
}
