package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	awsv4 "github.com/LukeEuler/echo-awsv4/aws/v4"
)

type AwsV4Config struct {
	Region, Name     string
	AwsCheckHandler  func(c echo.Context, err error)
	RateCheckHandler func(c echo.Context, err error)

	keys     map[string]string
	limiters map[string]*rate.Limiter
}

func (c *AwsV4Config) AddKey(accessKey, secretKey string, duration time.Duration, times int) error {
	if len(c.keys) == 0 {
		c.keys = make(map[string]string, 10)
		c.limiters = make(map[string]*rate.Limiter, 10)
	}
	_, ok := c.keys[accessKey]
	if ok {
		return fmt.Errorf("repeated key: %s", accessKey)
	}
	c.keys[accessKey] = secretKey
	c.limiters[accessKey] = rate.NewLimiter(rate.Every(duration), times)
	return nil
}

func DefaultAwsV4ContextHandler(c echo.Context, err error) {
	_ = c.String(http.StatusBadRequest, err.Error())
}

func AwsV4(conf AwsV4Config) echo.MiddlewareFunc {
	if conf.AwsCheckHandler == nil {
		conf.AwsCheckHandler = DefaultAwsV4ContextHandler
	}
	if conf.RateCheckHandler == nil {
		conf.RateCheckHandler = DefaultAwsV4ContextHandler
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth, _, err := awsv4.CheckRequestWithAwsV4KeyMaps(c.Request(), conf.keys, conf.Region, conf.Name)
			if err != nil {
				conf.AwsCheckHandler(c, err)
				return err
			}
			limiter := conf.limiters[auth.AccessKeyID]
			allow := limiter.Allow()
			if !allow {
				ll := limiter.Limit()
				fmt.Println(ll)
				err := fmt.Errorf("match rate limit. key: %s", auth.AccessKeyID)
				conf.RateCheckHandler(c, err)
				return err
			}

			if err = next(c); err != nil {
				c.Error(err)
			}
			return err
		}
	}
}
