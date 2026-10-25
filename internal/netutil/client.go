package netutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/model"
)

const MaxBody = 8 << 20

func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func Do(ctx context.Context, c *http.Client, method, target string, body []byte, headers http.Header) (model.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return model.Response{}, errors.New("request_invalid")
	}
	req.Header = headers.Clone()
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return model.Response{}, errors.New("upstream_unavailable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil || len(data) > MaxBody {
		return model.Response{}, errors.New("upstream_body_invalid")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return model.Response{}, errors.New("upstream_redirect")
	}
	return model.Response{Status: resp.StatusCode, Body: data}, nil
}

func Decode(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(out); err != nil {
		return errors.New("response_invalid")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("response_invalid")
	}
	return nil
}
