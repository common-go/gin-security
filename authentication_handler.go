package security

import "github.com/gin-gonic/gin"

type AuthenticationHandler interface {
	Authenticate() gin.HandlerFunc
}
