package clientapi

import (
	"net/http"
	"github.com/CrossChainTransaction/util"
	"github.com/gorilla/mux"
	"github.com/CrossChainTransaction/common"
)

func SetupClientAPI(apiMux *mux.Router,) {

	apiMux.Handle("/cct/versions",
		common.MakeExternalAPI("versions", func(req *http.Request) util.JSONResponse {
			return util.JSONResponse{
				Code: http.StatusOK,
				JSON: struct {
					Versions []string `json:"versions"`
				}{[]string{
					"CCT DEMO VERSION 1.0",
					"CCT DEMO VERSION 2.0",
				}},
			}
		}),
	).Methods(http.MethodGet, http.MethodOptions)
	vmux := apiMux.PathPrefix("/cct").Subrouter()
	//=================================================lock-in==========================================================
	// "/lockin"
	vmux.Handle("/lockin_user",
		common.MakeExternalAPI("user request of lockin", func(req *http.Request) util.JSONResponse {
			return LockInUser()
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockin_notify_calc
	vmux.Handle("/lockin_notify_calc",
		common.MakeExternalAPI("nofify other prover to calc key of lockin", func(req *http.Request) util.JSONResponse {
			return CalaShardingKey()
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockin_req_check
	vmux.Handle("/lockin_req_check",
		common.MakeExternalAPI("request prove of lockin", func(req *http.Request) util.JSONResponse {
			return CheckCommitAndZKP(req)
		}),
	).Methods(http.MethodGet, http.MethodOptions)
	//=================================================lock-out=========================================================
	// "/lockout"
	vmux.Handle("/lockout_user",
		common.MakeExternalAPI("user request of lockout", func(req *http.Request) util.JSONResponse {
			return LockoutUser()
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockout_notify_calc
	vmux.Handle("/lockout_notify_calc",
		common.MakeExternalAPI("nofify other prover to calc commit of lockout", func(req *http.Request) util.JSONResponse {
			return CalaProversCommit()
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockout_req_check
	vmux.Handle("/lockout_req_check",
		common.MakeExternalAPI("request check prover of lockout", func(req *http.Request) util.JSONResponse {
			return CheckProverCommitAndZKP(req)
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockout_req_sign_check
	vmux.Handle("/lockout_req_sign_check",
		common.MakeExternalAPI("request check prover sign of lockout", func(req *http.Request) util.JSONResponse {
			return CheckProverSignCommitAndZKP(req)
		}),
	).Methods(http.MethodGet, http.MethodOptions)

	//lockout_notify_calc
	vmux.Handle("/lockout_notify_sign_calc",
		common.MakeExternalAPI("nofify other prover to calc sign-commit of lockout", func(req *http.Request) util.JSONResponse {
			return CalaProversSignCommit(req)
		}),
	).Methods(http.MethodGet, http.MethodOptions)
}