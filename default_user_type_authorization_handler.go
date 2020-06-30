package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type DefaultUserTypeAuthorizationHandler struct {
}

func NewUserTypeAuthorizationHandler() *DefaultUserTypeAuthorizationHandler {
	return &DefaultUserTypeAuthorizationHandler{}
}

func (h *DefaultUserTypeAuthorizationHandler) Authorize(userTypes []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userType := h.getUserTypeFromContext(ctx)
		if userType == nil || len(*userType) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission: Require User Type")
			return
		}
		if h.hasUserType(userTypes, *userType) {
			ctx.Next()
		} else {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
		}
	}
}

func (h *DefaultUserTypeAuthorizationHandler) hasUserType(userTypes []string, userType string) bool {
	for _, rt := range userTypes {
		if rt == userType {
			return true
		}
	}
	return false
}

func (h *DefaultUserTypeAuthorizationHandler) getUserTypeFromContext(ctx *gin.Context) *string {
	if token, exist := ctx.Get(Authorization); exist {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			t := GetUserType(authorizationToken)
			return &t
		}
	}
	return nil
}
