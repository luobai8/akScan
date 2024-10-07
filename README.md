# AKscan
从网站JS文件中检索泄露的云存储桶Access Key

## (自行搭建环境测试)

./akScan

![image](https://github.com/user-attachments/assets/f4a3ee35-ac5a-4e7b-bc0b-60d32ebddcc7)

./akScan -t http://10.10.21.208:8000/

![image](https://github.com/user-attachments/assets/ef745834-56a2-4d18-8fe6-7f6aae8b1986)

![image](https://github.com/user-attachments/assets/446d4935-b87b-4571-8c7c-7ef225b0f223)


![image](https://github.com/user-attachments/assets/3bcb85ec-152c-4572-9678-c5765380c575)


## 各云厂商存储桶特征正则检测规则
参考：https://wiki.teamssix.com/CloudService/more/

（华为云的Access Key较难匹配，为了降低误报率，排除了对华为云的检测）

	patternMap["阿里云"] = `["'=:,.;](LTAI[A-Za-z0-9]{12,24})["'=:,.;]` // 阿里云 (Alibaba Cloud) 的 Access Key 开头标识一般是 "LTAI"。
	patternMap["腾讯云"] = `["'=:,.;](AKID[A-Za-z0-9]{13,20})["'=:,.;]` // 腾讯云 (Tencent Cloud) 的 Access Key 开头标识一般是 "AKID"。
	patternMap["华为云"] = `["'=:,.;]([A-Z0-9]{20})["'=:,.;]`                                 // 华为云 (Huawei Cloud) 的 Access Key 是20个随机大写字母和数字组成，较难用正则表达式匹配。
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
	patternMap["IBM Cloud"] = `["'=:,.;][a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}["'=:,.;]` // IBM 云或者是这种规则
	patternMap["Oracle云"] = `["'=:,.;](OCID[A-Za-z0-9]{10,40})["'=:,.;]` // Oracle云 (Oracle Cloud) 的 Access Key 开头标识一般是 "OCID"。
![image](https://github.com/user-attachments/assets/804c6389-3858-49c8-af48-15ab93b4db27)

