# echo-awsv4

Middleware for Echo Framework and AwsV4

### Installation

Requires Go 1.12 or later.

```shell
go get github.com/LukeEuler/echo-awsv4
```

### Usage Examples

Server

```go
package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	am "github.com/LukeEuler/echo-awsv4"
)

func main() {
	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", hello)

	conf := am.AwsV4Config{
		Region:         "universial",
		Name:           "echo_server",
		Keys:           map[string]string{"some_key_id": `iQfiTM4xAPC3N@y26*vlVa^Yb&Vxa35Y`},
		ContextHandler: am.DefaultAwsV4ContextHandler,
	}

	e.GET("/hi", hello, am.AwsV4(conf))

	// Start server
	e.Logger.Fatal(e.Start("127.0.0.1:12306"))
}

func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}
```

Client

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	awsv4 "github.com/LukeEuler/echo-awsv4/aws/v4"
)

func main() {
	region, name := "universial", "echo_server"
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
	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}
```

