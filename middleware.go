package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"

	awsv4 "github.com/LukeEuler/echo-awsv4/aws/v4"
)

// AwsV4Config make base config for awsv4
type AwsV4Config struct {
	Region, Name   string
	Keys           map[string]string
	ContextHandler func(c echo.Context, err error)
}

// DefaultAwsV4ContextHandler return simple err message where check failed
func DefaultAwsV4ContextHandler(c echo.Context, err error) {
	_ = c.String(http.StatusBadRequest, err.Error())
}

// AwsV4 gives the MiddlewareFunc with AwsV4Config
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
