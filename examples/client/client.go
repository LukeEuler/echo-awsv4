package main

import (
	"fmt"
	"io"
	"net/http"

	awsv4 "github.com/LukeEuler/echo-awsv4/aws/v4"
)

func main() {
	region, name := "universal", "echo_server"
	// key := &awsv4.Key{
	// 	AccessKey: "some_key_id_2",
	// 	SecretKey: `abcc`,
	// }
	key := &awsv4.Key{
		AccessKey: "some_key_id",
		SecretKey: `iQfiTM4xAPC3N@y26*vlVa^Yb&Vxa35Y`,
	}

	url := "http://localhost:12306/hi"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	// same as SignRequestWithAwsV4UseQueryString
	_, err = awsv4.SignRequestWithAwsV4(req, key, region, name)
	if err != nil {
		panic(err)
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	result, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}
