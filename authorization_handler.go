package security

import "github.com/gin-gonic/gin"

type AuthorizationHandler interface {
	Authorize(privilege string, action int32) gin.HandlerFunc
}
