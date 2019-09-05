package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"

	awsv4 "github.com/LukeEuler/echo-awsv4/aws/v4"
)

// AwsV4Config ...
type AwsV4Config struct {
	Region, Name   string
	Keys           map[string]string
	ContextHandler func(c echo.Context, err error)
}

// DefaultAwsV4ContextHandler ...
func DefaultAwsV4ContextHandler(c echo.Context, err error) {
	_ = c.String(http.StatusBadRequest, err.Error())
}

// AwsV4 ...
func AwsV4(conf AwsV4Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			_, _, err = awsv4.CheckRequestWithAwsV4KeyMaps(c.Request(), conf.Keys, conf.Region, conf.Name)
			if err != nil {
				conf.ContextHandler(c, err)
				return
			}

			if err = next(c); err != nil {
				c.Error(err)
			}
			return
		}
	}
}
