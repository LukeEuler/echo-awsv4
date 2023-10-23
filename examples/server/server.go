package main

import (
	"net/http"
	"time"

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
		Region:           "universal",
		Name:             "echo_server",
		AwsCheckHandler:  am.DefaultAwsV4ContextHandler,
		RateCheckHandler: am.DefaultAwsV4ContextHandler,
	}
	err := conf.AddKey("some_key_id", `iQfiTM4xAPC3N@y26*vlVa^Yb&Vxa35Y`, 10*time.Second, 3)
	if err != nil {
		panic(err)
	}
	err = conf.AddKey("some_key_id_2", `abcc`, 10*time.Second, 2)
	if err != nil {
		panic(err)
	}

	e.GET("/hi", hello, am.AwsV4(conf))

	// Start server
	e.Logger.Fatal(e.Start("127.0.0.1:12306"))
}

func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}
