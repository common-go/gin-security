package security

import (
	"context"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

const (
	Authorization = "authorization"
)

type DefaultAuthenticationHandler struct {
	TokenBlacklistService TokenBlacklistService
	TokenVerifier         TokenVerifier
	Secret                string
}

func NewAuthenticationHandler(tokenBlacklistService TokenBlacklistService, tokenVerifier TokenVerifier, secret string) *DefaultAuthenticationHandler {
	return &DefaultAuthenticationHandler{TokenBlacklistService: tokenBlacklistService, TokenVerifier: tokenVerifier, Secret: secret}
}

func (h *DefaultAuthenticationHandler) Authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		data := ctx.Request.Header["Authorization"]
		if len(data) == 0 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, "'Authorization' is required in http request header.")
		}
		authorization := data[0]
		if strings.HasPrefix(authorization, "Bearer ") != true {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid 'Authorization' format. The format must be 'Authorization: Bearer [token]'")
		}
		token := authorization[7:]
		if data, issuedAt, _, err := h.TokenVerifier.VerifyToken(token, h.Secret); err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid Authorization Token")
		} else {
			if h.TokenBlacklistService != nil {
				if data != nil {
					iat := time.Unix(issuedAt, 0)
					userId := GetUserId(data)
					reason := h.TokenBlacklistService.Check(userId, token, iat)
					if len(reason) == 0 {
						ctx.Set("token", token)
						ctx.Set("issuedAt", iat)
						ctx.Set(Authorization, data)
						c := context.WithValue(ctx.Request.Context(), Authorization, data)
						ctx.Request = ctx.Request.WithContext(c)
						ctx.Next()
					} else {
						ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Token is not valid anymore")
					}
				} else {
					ctx.Set(Authorization, data)
					c := context.WithValue(ctx.Request.Context(), Authorization, data)
					ctx.Request = ctx.Request.WithContext(c)
					ctx.Next()
				}
			} else {
				ctx.Set(Authorization, data)
				c := context.WithValue(ctx.Request.Context(), Authorization, data)
				ctx.Request = ctx.Request.WithContext(c)
				ctx.Next()
			}
		}
	}
}
