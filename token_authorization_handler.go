package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type TokenAuthorizationHandler struct {
	sortedPrivilege bool
	exact           bool
}

func NewTokenAuthorizationHandler(sortedPrivilege bool, exact bool) *TokenAuthorizationHandler {
	return &TokenAuthorizationHandler{sortedPrivilege, exact}
}

func (h *TokenAuthorizationHandler) Authorize(privilegeId string, action int32) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		privileges := GetPrivilegesFromGinContext(ctx)
		if privileges == nil || len(privileges) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission: Require privileges for this user")
			return
		}

		privilegeAction := GetAction(privileges, privilegeId, h.sortedPrivilege)
		if privilegeAction == ActionNone {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission for this user.")
			return
		}
		if action == ActionNone || action == ActionAll {
			ctx.Next()
			return
		}
		sum := action & privilegeAction
		if h.exact {
			if sum == action {
				ctx.Next()
				return
			}
		} else {
			if sum >= action {
				ctx.Next()
				return
			}
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
	}
}
