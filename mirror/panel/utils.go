package panel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
)

// Debug set the client debug for client
func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) assembleURL(path string) string {
	return strings.TrimRight(c.APIHost, "/") + "/" + strings.TrimLeft(path, "/")
}
func (c *Client) checkResponse(res *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s failed: %s", c.assembleURL(path), redactPanelSecrets(err.Error()))
	}
	if res == nil {
		return fmt.Errorf("request %s failed: empty response", c.assembleURL(path))
	}
	if res.StatusCode() >= 400 {
		body := res.Body()
		return fmt.Errorf("request %s failed: %s", c.assembleURL(path), redactPanelSecrets(string(body)))
	}
	return nil
}

type redactingRestyLogger struct{}

func (redactingRestyLogger) Errorf(format string, v ...interface{}) {
	logrus.Errorf("RESTY %s", formatRestyLog(format, v...))
}

func (redactingRestyLogger) Warnf(format string, v ...interface{}) {
	logrus.Warnf("RESTY %s", formatRestyLog(format, v...))
}

func (redactingRestyLogger) Debugf(format string, v ...interface{}) {
	logrus.Debugf("RESTY %s", formatRestyLog(format, v...))
}

func formatRestyLog(format string, v ...interface{}) string {
	message := format
	if len(v) > 0 {
		message = fmt.Sprintf(format, v...)
	}
	return redactPanelSecrets(message)
}

var panelSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile("(?i)([?&](?:token|apikey|api_key|key)=)[^&\\s\"'<>)}\\]]+"),
	regexp.MustCompile("(?i)(\"(?:token|apikey|api_key|key)\"\\s*:\\s*\")[^\"]+"),
}

func redactPanelSecrets(value string) string {
	for _, pattern := range panelSecretPatterns {
		value = pattern.ReplaceAllString(value, "$1<redacted>")
	}
	return value
}
