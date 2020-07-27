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
		userType := GetUserTypeFromGinContext(ctx)
		if userType == nil || len(*userType) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission: Require User Type")
			return
		}
		if HasUserType(userTypes, *userType) {
			ctx.Next()
		} else {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
		}
	}
}

func HasUserType(userTypes []string, userType string) bool {
	for _, rt := range userTypes {
		if rt == userType {
			return true
		}
	}
	return false
}

func GetUserTypeFromGinContext(ctx *gin.Context) *string {
	if token, exist := ctx.Get(Authorization); exist {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			t := GetUserType(authorizationToken)
			return &t
		}
	}
	return nil
}

func GetUserTypeFromContext(r *http.Request) *string {
	token := r.Context().Value(Authorization)
	if token != nil {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			t := GetUserType(authorizationToken)
			return &t
		}
	}
	return nil
}
