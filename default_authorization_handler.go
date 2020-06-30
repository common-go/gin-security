package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type DefaultAuthorizationHandler struct {
	PrivilegeService PrivilegeService
	Exact            bool
}

func NewAuthorizationHandler(privilegeService PrivilegeService, exact bool) *DefaultAuthorizationHandler {
	return &DefaultAuthorizationHandler{PrivilegeService: privilegeService, Exact: exact}
}

func (h *DefaultAuthorizationHandler) Authorize(privilegeId string, action int32) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId := h.getUserIdFromContext(ctx)
		if len(userId) == 0 {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Invalid User Id")
		}
		p := h.PrivilegeService.GetPrivilege(userId, privilegeId)
		if p == ActionNone {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission for this user")
		}
		if action == ActionNone || action == ActionAll {
			ctx.Next()
		}
		sum := action & p
		if h.Exact {
			if sum == action {
				ctx.Next()
				return
			}
		} else if sum >= action {
			ctx.Next()
			return
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission")
	}
}

func (h *DefaultAuthorizationHandler) getUserIdFromContext(ctx *gin.Context) string {
	if token, exist := ctx.Get(Authorization); exist {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			return GetUserId(authorizationToken)
		}
	}
	return ""
}
