# Gin Security 
AuthenticationHandler
- Implementation of TokenVerifier: [DefaultTokenService](https://github.com/common-go/jwt/blob/master/default_token_service.go) of [common-go/jwt](https://github.com/common-go/jwt) v0.0.7 or above
- Implementation of CacheService: [RedisService](https://github.com/common-go/redis/blob/master/redis_service.go) of [common-go/redis](https://github.com/common-go/redis) v1.0.0 or above

## Installation

Please make sure to initialize a Go module before installing common-go/gin-security:

```shell
go get -u github.com/common-go/gin-security
```

Import:

```go
import "github.com/common-go/gin-security"
```

#### You can optimize the import by version:
##### v0.0.1: Authentication Handler
##### v0.0.5: Authorization Handler
##### v0.0.7: Token Authorization Handler
- Privilege Authorization Handler
- Role Authorization Handler
- User Authorization Handler
- User Type Authorization Handler

## Details:
#### authentication_handler
```go
package security

import "github.com/gin-gonic/gin"

type AuthenticationHandler interface {
	Authenticate() gin.HandlerFunc
}
```