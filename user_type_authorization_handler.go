package security

import "github.com/gin-gonic/gin"

type UserTypeAuthorizationHandler interface {
	Authorize(userTypes []string) gin.HandlerFunc
}
