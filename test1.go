package main

import (
	"crypto/md5"
	"fmt"
)

func main1() {
	// 假设的用户名和密码
	username := "postgres"
	password := "postgres"

	// 第一步：连接用户名和密码
	firstConcat := fmt.Sprintf("%s%s", password, username)

	// 第二步：对连接后的字符串应用MD5哈希函数
	firstMD5 := fmt.Sprintf("%x", md5.Sum([]byte(firstConcat)))

	fmt.Println(firstMD5)
}
