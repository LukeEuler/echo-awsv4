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
