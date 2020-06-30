package security

import "github.com/gin-gonic/gin"

type UserAuthorizationHandler interface {
	Authorize(users []string) gin.HandlerFunc
}
