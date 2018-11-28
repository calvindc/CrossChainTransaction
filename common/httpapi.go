package common

import (
	"net/http"
	"github.com/opentracing/opentracing-go"
	"github.com/CrossChainTransaction/util"
	"encoding/json"
	"bytes"
	"io/ioutil"
)

//MakeRequest broadcast the result of sharding-calc to other authorized servers.
func MakeRequest(method string, httpURL string, reqBody interface{}, resBody interface{}) ([]byte, error) {
	client := &http.Client{}
	var req *http.Request
	var err error
	if reqBody != nil {
		var jsonStr []byte
		jsonStr, err = json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, httpURL, bytes.NewBuffer(jsonStr))
	} else {
		req, err = http.NewRequest(method, httpURL, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if resBody != nil {
		if err = json.Unmarshal(contents, &resBody); err != nil {
			return nil, err
		}
	}
	return contents, nil
}

func MakeExternalAPI(Name string, f func(*http.Request) util.JSONResponse) http.Handler {
	h := util.MakeJSONAPI(util.NewJSONRequestHandler(f))
	withSpan := func(w http.ResponseWriter, req *http.Request) {
		span := opentracing.StartSpan(Name)
		defer span.Finish()
		req = req.WithContext(opentracing.ContextWithSpan(req.Context(), span))
		h.ServeHTTP(w, req)
	}

	return http.HandlerFunc(withSpan)
}

func WrapHandlerInCORS(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.WriteHeader(http.StatusOK)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}
